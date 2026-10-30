// SPDX-License-Identifier: AGPL-3.0-only

//! `[dns.request]` and `[dns.response]` routing.
//!
//! # Request routing: which upstream answers this query
//!
//! Rules are evaluated top to bottom, the first match wins, and the fallback applies
//! when nothing matches. That much is the same as IP routing. Three things are not:
//!
//! * **The predicates are DNS-shaped**: `qname(...)` and `qtype(...)`. Reusing the IP
//!   router would mean inventing fake facts for names, so request routing is its own
//!   small evaluator over its own facts.
//! * **`asis` is not an upstream.** It means "let the client's own resolver do it",
//!   which is a distinct outcome from forwarding, not a group with no nodes.
//! * **`reject` is a legitimate answer.** Blocking a name is a first-class verdict.
//!
//! The outbound names in `[dns.request]` are therefore `asis`, `reject`, or a tag
//! declared in `dns.upstream` — a typo must fail at load time, not per query.
//!
//! # Response routing: what to do with the answer
//!
//! `[dns.response]` decides whether an answer is accepted, rejected, or sent to a
//! different upstream after all. The distinction that matters operationally is
//! **`accept` versus everything else**: `accept` is the common case and must cost
//! nothing, while a rule that inspects IPs runs only for the answers it can affect.

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;

use daer_config::{Config, Function, FunctionOrString, Param, RoutingRule};
use ipnet::IpNet;
use regex::Regex;

use crate::wire::{Message, Name, RecordType};

/// Where a DNS request goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Forward to the named upstream (a tag from `dns.upstream`).
    Upstream(String),
    /// Answer from the client's own resolver: hand the query back untouched.
    AsIs,
    /// Refuse to answer.
    Reject,
}

impl Decision {
    /// The decision named by a rule's outbound.
    ///
    /// # Errors
    ///
    /// Returns [`RoutingError`] for any name that is not `asis`, `reject`, or a declared
    /// upstream tag.
    pub fn parse(name: &str, upstreams: &[String]) -> Result<Self, RoutingError> {
        match name {
            "asis" => Ok(Self::AsIs),
            "reject" => Ok(Self::Reject),
            other if upstreams.iter().any(|tag| tag == other) => {
                Ok(Self::Upstream(other.to_owned()))
            }
            other => Err(RoutingError::UnknownUpstream(other.to_owned())),
        }
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Upstream(tag) => f.write_str(tag),
            Self::AsIs => f.write_str("asis"),
            Self::Reject => f.write_str("reject"),
        }
    }
}

/// What to do with a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseAction {
    /// Serve it to the client (the common case).
    Accept,
    /// Drop it and answer the client with a refusal.
    Reject,
    /// Ask this upstream instead. A second round, not a rewrite.
    Failover(String),
}

impl ResponseAction {
    /// The action named by a rule's outbound.
    ///
    /// # Errors
    ///
    /// Returns [`RoutingError`] for an unknown name.
    pub fn parse(name: &str, upstreams: &[String]) -> Result<Self, RoutingError> {
        match name {
            "accept" => Ok(Self::Accept),
            "reject" => Ok(Self::Reject),
            other if upstreams.iter().any(|tag| tag == other) => {
                Ok(Self::Failover(other.to_owned()))
            }
            other => Err(RoutingError::UnknownUpstream(other.to_owned())),
        }
    }
}

impl fmt::Display for ResponseAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accept => f.write_str("accept"),
            Self::Reject => f.write_str("reject"),
            Self::Failover(tag) => f.write_str(tag),
        }
    }
}

/// A routing configuration error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingError {
    /// A rule named an upstream that `dns.upstream` does not declare.
    UnknownUpstream(String),
    /// A predicate this selector does not support, in this block.
    UnsupportedFunction { block: &'static str, name: String },
    /// A domain key that is not `full`, `suffix`, `keyword` or `regex`.
    UnknownDomainKey(String),
    /// A parameter given to a function that takes bare values only.
    UnexpectedParameter { function: String, key: String },
    /// A regular expression that does not compile.
    BadRegex { pattern: String, message: String },
    /// A CIDR that does not parse.
    BadNetwork(String),
    /// A record type that does not parse.
    BadRecordType(String),
    /// A rule with no predicates, which would match everything.
    EmptyRule,
    /// The fallback is missing where one is required.
    MissingFallback(&'static str),
}

impl fmt::Display for RoutingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownUpstream(name) => write!(
                f,
                "upstream {name:?} not found; please define it in section \"dns.upstream\" \
                 or use \"asis\"/\"reject\""
            ),
            Self::UnsupportedFunction { block, name } => {
                write!(
                    f,
                    "{name}() is not a selector this block understands ({block})"
                )
            }
            Self::UnknownDomainKey(key) => write!(
                f,
                "unsupported qname key {key:?}; use full, suffix, keyword or regex"
            ),
            Self::UnexpectedParameter { function, key } => write!(
                f,
                "{function}: unsupported parameter key {key:?}; {function} takes bare values only"
            ),
            Self::BadRegex { pattern, message } => {
                write!(f, "bad regexp {pattern:?}: {message}")
            }
            Self::BadNetwork(cidr) => write!(f, "invalid CIDR {cidr:?}"),
            Self::BadRecordType(text) => write!(f, "unknown DNS record type {text:?}"),
            Self::EmptyRule => f.write_str("a routing rule needs at least one predicate"),
            Self::MissingFallback(block) => write!(f, "section \"{block}\" requires a fallback"),
        }
    }
}

impl std::error::Error for RoutingError {}

/// How a `qname` matcher compares.
///
/// No `PartialEq`: `regex::Regex` has none, and comparing compiled matchers has no
/// caller that needs it. Two routers are compared by what they decide, in tests.
#[derive(Debug, Clone)]
enum NameMatch {
    Full(Name),
    Suffix(Name),
    Keyword(String),
    Regex(Regex),
}

impl NameMatch {
    fn matches(&self, name: &Name) -> bool {
        match self {
            Self::Full(expected) => name.eq_ignore_case(expected),
            Self::Suffix(suffix) => name.ends_with(suffix),
            Self::Keyword(needle) => name.to_text().to_lowercase().contains(needle),
            Self::Regex(regex) => regex.is_match(&name.to_text()),
        }
    }
}

/// What a request selector looks at.
#[derive(Debug, Clone)]
enum RequestSelector {
    /// Any of these name matchers.
    Names(Vec<NameMatch>),
    /// Any of these record types.
    Types(Vec<RecordType>),
}

impl RequestSelector {
    fn matches(&self, question: &crate::wire::Question) -> bool {
        match self {
            Self::Names(matchers) => matchers
                .iter()
                .any(|matcher| matcher.matches(&question.name)),
            Self::Types(types) => types.contains(&question.qtype),
        }
    }
}

/// What a response selector looks at. Response rules can see the whole message.
#[derive(Debug, Clone)]
enum ResponseSelector {
    Names(Vec<NameMatch>),
    Types(Vec<RecordType>),
    /// Any answer address inside one of these networks.
    Ips(Vec<IpNet>),
    /// The answer came from one of these upstreams (by tag).
    Upstream(Vec<String>),
}

impl ResponseSelector {
    fn matches(&self, answer: &AnswerFacts<'_>) -> bool {
        match self {
            Self::Names(matchers) => matchers.iter().any(|matcher| matcher.matches(&answer.name)),
            Self::Types(types) => types.contains(&answer.qtype),
            Self::Ips(networks) => answer
                .addresses
                .iter()
                .any(|address| networks.iter().any(|network| network.contains(address))),
            Self::Upstream(tags) => answer
                .upstream
                .is_some_and(|produced_by| tags.iter().any(|tag| tag == produced_by)),
        }
    }
}

/// A compiled request rule.
#[derive(Debug, Clone)]
struct RequestRule {
    selectors: Vec<RequestSelector>,
    decision: Decision,
}

/// A compiled response rule.
#[derive(Debug, Clone)]
struct ResponseRule {
    selectors: Vec<ResponseSelector>,
    action: ResponseAction,
}

/// The facts a response rule can see.
#[derive(Debug, Clone)]
pub struct AnswerFacts<'a> {
    pub name: Name,
    pub qtype: RecordType,
    pub addresses: Vec<IpAddr>,
    /// The upstream that produced the answer, when known.
    pub upstream: Option<&'a str>,
    /// The response code, for a rule that keys on failure.
    pub code: crate::wire::ResponseCode,
}

impl AnswerFacts<'_> {
    /// Extracts the facts from a response message.
    #[must_use]
    pub fn from_message<'a>(
        question: &crate::wire::Question,
        message: &'a Message,
        upstream: Option<&'a str>,
    ) -> AnswerFacts<'a> {
        AnswerFacts {
            name: question.name.clone(),
            qtype: question.qtype,
            addresses: message.answer_addresses(),
            upstream,
            code: message.response_code(),
        }
    }
}

/// Compiled `[dns.request]` routing.
#[derive(Debug, Clone)]
pub struct RequestRouter {
    rules: Vec<RequestRule>,
    fallback: Decision,
}

impl RequestRouter {
    /// Compiles a configuration's `[dns.request]`.
    ///
    /// # Errors
    ///
    /// Returns [`RoutingError`] for an unknown predicate, an unknown upstream, a bad
    /// regex/CIDR/record type, or a missing fallback.
    pub fn compile(config: &Config) -> Result<Self, RoutingError> {
        let upstreams: Vec<String> = config
            .dns
            .upstream
            .iter()
            .map(|entry| {
                entry
                    .split_once(':')
                    .map_or(entry.as_str(), |(tag, _)| tag)
                    .to_owned()
            })
            .collect();

        let block = "dns.request";
        let mut rules = Vec::with_capacity(config.dns.request.rules.len());
        for rule in &config.dns.request.rules {
            rules.push(RequestRule {
                selectors: compile_selectors(rule, block)?,
                decision: Decision::parse(&rule.outbound.name, &upstreams)?,
            });
        }

        let fallback = config
            .dns
            .request
            .fallback
            .as_ref()
            .ok_or(RoutingError::MissingFallback(block))?;
        let fallback = Decision::parse(&fallback_name(fallback)?, &upstreams)?;

        Ok(Self { rules, fallback })
    }

    /// The decision for one query.
    ///
    /// A query with no question, or with several, cannot be routed by name: it gets the
    /// fallback, which is the only honest answer.
    #[must_use]
    pub fn decide(&self, message: &Message) -> Decision {
        let Some(question) = message.single_question() else {
            return self.fallback.clone();
        };
        for rule in &self.rules {
            if rule
                .selectors
                .iter()
                .all(|selector| selector.matches(question))
            {
                return rule.decision.clone();
            }
        }
        self.fallback.clone()
    }

    /// The fallback decision.
    #[must_use]
    pub fn fallback(&self) -> &Decision {
        &self.fallback
    }

    /// Number of compiled rules.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// True when only the fallback applies.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// Compiled `[dns.response]` routing.
#[derive(Debug, Clone)]
pub struct ResponseRouter {
    rules: Vec<ResponseRule>,
    fallback: ResponseAction,
}

impl ResponseRouter {
    /// Compiles a configuration's `[dns.response]`.
    ///
    /// # Errors
    ///
    /// Returns [`RoutingError`] for an unknown predicate, an unknown upstream, a bad
    /// regex/CIDR/record type, or a missing fallback.
    pub fn compile(config: &Config) -> Result<Self, RoutingError> {
        let upstreams: Vec<String> = config
            .dns
            .upstream
            .iter()
            .map(|entry| {
                entry
                    .split_once(':')
                    .map_or(entry.as_str(), |(tag, _)| tag)
                    .to_owned()
            })
            .collect();

        let block = "dns.response";
        let mut rules = Vec::with_capacity(config.dns.response.rules.len());
        for rule in &config.dns.response.rules {
            let mut selectors = Vec::new();
            for function in &rule.and_functions {
                selectors.push(compile_response_selector(function, block)?);
            }
            if selectors.is_empty() {
                return Err(RoutingError::EmptyRule);
            }
            rules.push(ResponseRule {
                selectors,
                action: ResponseAction::parse(&rule.outbound.name, &upstreams)?,
            });
        }

        let fallback = config
            .dns
            .response
            .fallback
            .as_ref()
            .ok_or(RoutingError::MissingFallback(block))?;
        let fallback = ResponseAction::parse(&fallback_name(fallback)?, &upstreams)?;

        Ok(Self { rules, fallback })
    }

    /// The action for one answer.
    ///
    /// `accept` is the fallback and costs one comparison; a rule that inspects addresses
    /// only runs when the answer has any.
    #[must_use]
    pub fn decide(&self, facts: &AnswerFacts<'_>) -> ResponseAction {
        for rule in &self.rules {
            if rule
                .selectors
                .iter()
                .all(|selector| selector.matches(facts))
            {
                return rule.action.clone();
            }
        }
        self.fallback.clone()
    }

    /// The fallback action.
    #[must_use]
    pub fn fallback(&self) -> &ResponseAction {
        &self.fallback
    }

    /// Number of compiled rules.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// True when only the fallback applies.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// The outbound name of a fallback, which may be written as a function.
fn fallback_name(fallback: &FunctionOrString) -> Result<String, RoutingError> {
    Ok(fallback
        .as_function()
        .map_err(RoutingError::UnknownUpstream)?
        .name)
}

fn compile_selectors(
    rule: &RoutingRule,
    block: &'static str,
) -> Result<Vec<RequestSelector>, RoutingError> {
    if rule.and_functions.is_empty() {
        return Err(RoutingError::EmptyRule);
    }
    rule.and_functions
        .iter()
        .map(|function| compile_request_selector(function, block))
        .collect()
}

fn compile_request_selector(
    function: &Function,
    block: &'static str,
) -> Result<RequestSelector, RoutingError> {
    match function.name.as_str() {
        "qname" => Ok(RequestSelector::Names(compile_name_matchers(function)?)),
        "qtype" => Ok(RequestSelector::Types(compile_types(function)?)),
        other => Err(RoutingError::UnsupportedFunction {
            block,
            name: other.to_owned(),
        }),
    }
}

fn compile_response_selector(
    function: &Function,
    block: &'static str,
) -> Result<ResponseSelector, RoutingError> {
    match function.name.as_str() {
        "qname" => Ok(ResponseSelector::Names(compile_name_matchers(function)?)),
        "qtype" => Ok(ResponseSelector::Types(compile_types(function)?)),
        "ip" => Ok(ResponseSelector::Ips(compile_networks(function)?)),
        "upstream" => {
            let tags = bare_values(function)?;
            if tags.is_empty() {
                return Err(RoutingError::EmptyRule);
            }
            Ok(ResponseSelector::Upstream(tags))
        }
        other => Err(RoutingError::UnsupportedFunction {
            block,
            name: other.to_owned(),
        }),
    }
}

fn compile_name_matchers(function: &Function) -> Result<Vec<NameMatch>, RoutingError> {
    let mut matchers = Vec::new();
    for param in &function.params {
        if param.key.is_empty() {
            return Err(RoutingError::UnknownDomainKey(String::new()));
        }
        let value = param.value.to_string();
        matchers.push(match param.key.as_str() {
            "full" => {
                NameMatch::Full(Name::parse(&value).map_err(|error| RoutingError::BadRegex {
                    pattern: value.clone(),
                    message: error.to_string(),
                })?)
            }
            "suffix" => {
                NameMatch::Suffix(Name::parse(&value).map_err(|error| RoutingError::BadRegex {
                    pattern: value.clone(),
                    message: error.to_string(),
                })?)
            }
            "keyword" => NameMatch::Keyword(value.to_lowercase()),
            "regex" => {
                NameMatch::Regex(Regex::new(&value).map_err(|error| RoutingError::BadRegex {
                    pattern: value,
                    message: error.to_string(),
                })?)
            }
            other => return Err(RoutingError::UnknownDomainKey(other.to_owned())),
        });
    }
    if matchers.is_empty() {
        return Err(RoutingError::EmptyRule);
    }
    Ok(matchers)
}

fn compile_types(function: &Function) -> Result<Vec<RecordType>, RoutingError> {
    let mut types = Vec::new();
    for param in &function.params {
        if !param.key.is_empty() {
            return Err(RoutingError::UnexpectedParameter {
                function: function.name.clone(),
                key: param.key.clone(),
            });
        }
        types.push(
            RecordType::parse(&param.value.to_string())
                .map_err(|_| RoutingError::BadRecordType(param.value.to_string()))?,
        );
    }
    if types.is_empty() {
        return Err(RoutingError::EmptyRule);
    }
    Ok(types)
}

fn compile_networks(function: &Function) -> Result<Vec<IpNet>, RoutingError> {
    let mut networks = Vec::new();
    for param in &function.params {
        if !param.key.is_empty() {
            return Err(RoutingError::UnexpectedParameter {
                function: function.name.clone(),
                key: param.key.clone(),
            });
        }
        let text = param.value.to_string();
        let network: IpNet = text
            .parse()
            .map_err(|_| RoutingError::BadNetwork(text.clone()))?;
        networks.push(network);
    }
    if networks.is_empty() {
        return Err(RoutingError::EmptyRule);
    }
    Ok(networks)
}

fn bare_values(function: &Function) -> Result<Vec<String>, RoutingError> {
    let mut values = Vec::new();
    for param in &function.params {
        if !param.key.is_empty() {
            return Err(RoutingError::UnexpectedParameter {
                function: function.name.clone(),
                key: param.key.clone(),
            });
        }
        values.push(param.value.to_string());
    }
    Ok(values)
}

/// Upstream tags declared in `dns.upstream`, in declaration order.
///
/// `upstream` entries are `tag:protocol://host:port`; the tag is the part before the
/// first colon. Returns an index for callers that want to validate a rule target.
#[must_use]
pub fn upstream_tags(config: &Config) -> BTreeMap<String, String> {
    config
        .dns
        .upstream
        .iter()
        .filter_map(|entry| {
            entry
                .split_once(':')
                .map(|(tag, url)| (tag.to_owned(), url.to_owned()))
        })
        .collect()
}

/// A parameter rendered for an error message, used by tests and diagnostics.
#[must_use]
pub fn describe_param(param: &Param) -> String {
    if param.key.is_empty() {
        param.value.to_string()
    } else {
        format!("{}: {}", param.key, param.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Flags, Message, Name, Question};

    fn config(src: &str) -> Config {
        daer_config::toml_config::load_str(src).expect("config loads")
    }

    fn query(name: &str, qtype: RecordType) -> Message {
        Message {
            id: 1,
            flags: Flags(0x0100),
            questions: vec![Question::internet(Name::parse(name).expect("name"), qtype)],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    const UPSTREAMS: &str = r#"
[dns]
upstream = ["local:udp://223.5.5.5:53", "remote:tcp+udp://8.8.8.8:53"]
"#;

    #[test]
    fn upstream_tags_are_declaration_order_and_strip_the_protocol() {
        let tags = upstream_tags(&config(UPSTREAMS));
        assert_eq!(
            tags.get("local").map(String::as_str),
            Some("udp://223.5.5.5:53")
        );
        assert_eq!(
            tags.get("remote").map(String::as_str),
            Some("tcp+udp://8.8.8.8:53")
        );
    }

    #[test]
    fn the_first_matching_request_rule_wins() {
        let router = RequestRouter::compile(&config(&format!(
            r#"{UPSTREAMS}
[dns.request]
rules = [
    "qname(keyword: ads) -> reject",
    "qname(suffix: cn) -> local",
    "qtype(AAAA) -> reject",
]
fallback = "remote"
"#
        )))
        .expect("compiles");

        assert_eq!(
            router.decide(&query("ads.example.cn", RecordType::A)),
            Decision::Reject,
            "the earlier rule wins over the suffix rule"
        );
        assert_eq!(
            router.decide(&query("www.example.cn", RecordType::A)),
            Decision::Upstream("local".to_owned())
        );
        assert_eq!(
            router.decide(&query("www.example.com", RecordType::AAAA)),
            Decision::Reject
        );
        assert_eq!(
            router.decide(&query("www.example.com", RecordType::A)),
            Decision::Upstream("remote".to_owned()),
            "the fallback"
        );
    }

    #[test]
    fn asis_is_a_decision_not_an_upstream() {
        let router = RequestRouter::compile(&config(&format!(
            r#"{UPSTREAMS}
[dns.request]
rules = ["qname(suffix: lan) -> asis"]
fallback = "remote"
"#
        )))
        .expect("compiles");
        assert_eq!(
            router.decide(&query("host.lan", RecordType::A)),
            Decision::AsIs
        );
        assert_eq!(Decision::AsIs.to_string(), "asis");
    }

    #[test]
    fn a_rule_naming_an_undeclared_upstream_fails_at_compile_time() {
        // A typo must not become "this rule silently never routes anywhere".
        let error = RequestRouter::compile(&config(&format!(
            r#"{UPSTREAMS}
[dns.request]
rules = ["qname(suffix: a) -> remtoe"]
fallback = "remote"
"#
        )))
        .expect_err("must reject");
        assert!(matches!(error, RoutingError::UnknownUpstream(ref name) if name == "remtoe"));
        assert!(error.to_string().contains("dns.upstream"), "{error}");
    }

    #[test]
    fn a_missing_fallback_is_an_error_not_an_empty_router() {
        // `daer config validate` and the daemon must agree: no fallback, no router.
        let mut parsed = config(UPSTREAMS);
        parsed.dns.request.fallback = None;
        let error = RequestRouter::compile(&parsed).expect_err("must reject");
        assert!(matches!(
            error,
            RoutingError::MissingFallback("dns.request")
        ));
    }

    #[test]
    fn unsupported_predicates_are_named_with_their_block() {
        let error = RequestRouter::compile(&config(&format!(
            r#"{UPSTREAMS}
[dns.request]
rules = ["dport(53) -> remote"]
fallback = "remote"
"#
        )))
        .expect_err("must reject");
        let rendered = error.to_string();
        match error {
            RoutingError::UnsupportedFunction { block, name } => {
                assert_eq!(block, "dns.request");
                assert_eq!(name, "dport");
            }
            other => panic!("unexpected error: {other}"),
        }
        assert!(rendered.contains("dns.request"), "{rendered}");
    }

    #[test]
    fn a_query_without_a_single_question_gets_the_fallback() {
        // Forwarding by name is impossible; the honest answer is the fallback rather
        // than a guessed name.
        let router = RequestRouter::compile(&config(&format!(
            r#"{UPSTREAMS}
[dns.request]
rules = ["qname(suffix: example.com) -> reject"]
fallback = "remote"
"#
        )))
        .expect("compiles");

        let empty = Message {
            id: 1,
            flags: Flags(0x0100),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        };
        assert_eq!(
            router.decide(&empty),
            Decision::Upstream("remote".to_owned())
        );

        let doubled = Message {
            questions: vec![
                Question::internet(Name::parse("a.example.com").expect("name"), RecordType::A),
                Question::internet(Name::parse("b.example.com").expect("name"), RecordType::A),
            ],
            ..empty
        };
        assert_eq!(
            router.decide(&doubled),
            Decision::Upstream("remote".to_owned())
        );
    }

    #[test]
    fn response_rules_can_key_on_addresses_and_upstream() {
        let router = ResponseRouter::compile(&config(&format!(
            r#"{UPSTREAMS}
[dns.response]
rules = [
    "ip(10.0.0.0/8) -> reject",
    "upstream(local) && qname(suffix: example.com) -> remote",
]
fallback = "accept"
"#
        )))
        .expect("compiles");

        let name = Name::parse("a.example.com").expect("name");
        let private = AnswerFacts {
            name: name.clone(),
            qtype: RecordType::A,
            addresses: vec!["10.1.2.3".parse().expect("ip")],
            upstream: Some("remote"),
            code: crate::wire::ResponseCode::NOERROR,
        };
        assert_eq!(router.decide(&private), ResponseAction::Reject);

        let public = AnswerFacts {
            addresses: vec!["93.184.216.34".parse().expect("ip")],
            ..private.clone()
        };
        assert_eq!(
            router.decide(&public),
            ResponseAction::Accept,
            "the address rule does not match"
        );

        let from_local = AnswerFacts {
            upstream: Some("local"),
            ..public.clone()
        };
        assert_eq!(
            router.decide(&from_local),
            ResponseAction::Failover("remote".to_owned()),
            "both predicates held"
        );

        let other_name = AnswerFacts {
            name: Name::parse("b.example.org").expect("name"),
            ..from_local
        };
        assert_eq!(
            router.decide(&other_name),
            ResponseAction::Accept,
            "the qname predicate did not hold"
        );
    }

    #[test]
    fn accept_is_the_cheap_default_and_structured_as_such() {
        let router = ResponseRouter::compile(&config(UPSTREAMS)).expect("compiles");
        assert!(router.is_empty(), "no rules");
        let facts = AnswerFacts {
            name: Name::parse("example.com").expect("name"),
            qtype: RecordType::A,
            addresses: Vec::new(),
            upstream: None,
            code: crate::wire::ResponseCode::NOERROR,
        };
        assert_eq!(router.decide(&facts), ResponseAction::Accept);
        assert_eq!(router.fallback(), &ResponseAction::Accept);
    }

    #[test]
    fn a_bad_regex_or_cidr_is_rejected_with_the_offending_text() {
        let regex_error = RequestRouter::compile(&config(&format!(
            r#"{UPSTREAMS}
[dns.request]
rules = ["qname(regex: '[') -> remote"]
fallback = "remote"
"#
        )))
        .expect_err("must reject");
        assert!(
            regex_error.to_string().contains("bad regexp"),
            "{regex_error}"
        );

        let cidr_error = ResponseRouter::compile(&config(&format!(
            r#"{UPSTREAMS}
[dns.response]
rules = ["ip(10.0.0.0/33) -> reject"]
"#
        )))
        .expect_err("must reject");
        assert!(matches!(cidr_error, RoutingError::BadNetwork(_)));
    }

    #[test]
    fn qtype_accepts_mnemonics_and_numbers_and_rejects_nonsense() {
        let router = RequestRouter::compile(&config(&format!(
            r#"{UPSTREAMS}
[dns.request]
rules = ["qtype(AAAA, 65) -> remote"]
fallback = "local"
"#
        )))
        .expect("compiles");
        assert_eq!(
            router.decide(&query("a.example", RecordType::AAAA)),
            Decision::Upstream("remote".to_owned())
        );
        assert_eq!(
            router.decide(&query("a.example", RecordType::HTTPS)),
            Decision::Upstream("remote".to_owned())
        );
        assert_eq!(
            router.decide(&query("a.example", RecordType::A)),
            Decision::Upstream("local".to_owned())
        );

        let error = RequestRouter::compile(&config(&format!(
            r#"{UPSTREAMS}
[dns.request]
rules = ["qtype(BOGUS) -> remote"]
fallback = "local"
"#
        )))
        .expect_err("must reject");
        assert!(matches!(error, RoutingError::BadRecordType(_)));
    }
}
