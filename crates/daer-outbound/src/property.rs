// SPDX-License-Identifier: AGPL-3.0-only

//! Node properties.

use daer_common::SelectionPolicy;
use daer_config::{Function, FunctionOrString};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protocol {
    Direct,
    Http,
    Https,
    Socks5,
    /// Shadowsocks AEAD (SIP004). Stream ciphers are not represented: see
    /// [`crate::shadowsocks::crypto::Cipher`] for why.
    ShadowSocks,
    /// Trojan: a password-authenticated session inside TLS to the node.
    Trojan,
    /// AnyTLS: multiplexed session with traffic obfuscation inside TLS.
    AnyTls,
    /// Hysteria 2: proxy over QUIC with HTTP/3 authentication and UDP datagrams.
    Hysteria2,
    /// VLESS: a UUID-authenticated session, with any of the three security layers
    /// (ADR-0028). The identity is the protocol, not the handshake: `vless` over TLS and `vless`
    /// over REALITY are the same protocol.
    Vless,
    /// VMess AEAD (ADR-0030).
    Vmess,
    /// Any other link scheme; kept verbatim until the protocol layer claims it.
    Other(String),
}

impl Protocol {
    pub fn from_scheme(scheme: &str) -> Self {
        match scheme.to_ascii_lowercase().as_str() {
            "direct" => Self::Direct,
            "http" => Self::Http,
            "https" => Self::Https,
            "socks5" | "socks" => Self::Socks5,
            "ss" | "shadowsocks" => Self::ShadowSocks,
            "trojan" | "trojan-go" => Self::Trojan,
            "anytls" => Self::AnyTls,
            "hysteria2" | "hy2" => Self::Hysteria2,
            "vless" => Self::Vless,
            "vmess" => Self::Vmess,
            other => Self::Other(other.to_owned()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Direct => "direct",
            Self::Http => "http",
            Self::Https => "https",
            Self::Socks5 => "socks5",
            Self::ShadowSocks => "ss",
            Self::Trojan => "trojan",
            Self::AnyTls => "anytls",
            Self::Hysteria2 => "hysteria2",
            Self::Vless => "vless",
            Self::Vmess => "vmess",
            Self::Other(other) => other,
        }
    }
}

impl From<daer_proxy_protocols::ProxyProtocol> for Protocol {
    fn from(proto: daer_proxy_protocols::ProxyProtocol) -> Self {
        match proto {
            daer_proxy_protocols::ProxyProtocol::ShadowSocks => Self::ShadowSocks,
            daer_proxy_protocols::ProxyProtocol::Trojan => Self::Trojan,
            daer_proxy_protocols::ProxyProtocol::AnyTls => Self::AnyTls,
            daer_proxy_protocols::ProxyProtocol::Hysteria2 => Self::Hysteria2,
            daer_proxy_protocols::ProxyProtocol::Vless => Self::Vless,
            daer_proxy_protocols::ProxyProtocol::Vmess => Self::Vmess,
        }
    }
}

/// What a dialer is, independent of how it connects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Property {
    pub name: String,
    /// `host:port` of the proxy server; empty for the direct dialer.
    pub address: String,
    pub protocol: Protocol,
    pub udp: bool,
    pub subscription_tag: String,
    /// How this node protects the session, for diagnostics.
    ///
    /// Derived from the link **without reading the secret**: it names the cipher or the TLS
    /// profile, never the password. A diagnostic that printed a credential would make a bug
    /// report a credential leak.
    pub security: Security,
}

/// The protection a node provides, as a diagnostic identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Security {
    /// No protection: a `direct` node.
    None,
    /// Plaintext to a proxy (`socks5`, `http`): credentials, if any, are on the wire.
    Plaintext,
    /// TLS to the node.
    Tls {
        /// The name presented in the handshake.
        server_name: String,
        /// Whether the link asked to skip verification, which this build refuses to honor.
        allow_insecure_requested: bool,
    },
    /// An authenticated cipher inside the proxy protocol.
    Cipher {
        /// The cipher as the link spells it, or the reason it could not be parsed.
        name: String,
        /// True when the cipher provides integrity protection.
        authenticated: bool,
    },
    /// REALITY: authenticated by the ClientHello tag, not by the certificate chain.
    ///
    /// Deliberately its own variant rather than [`Self::Tls`]. The certificate a REALITY
    /// server presents belongs to the impersonated site, so reporting `tls sni=…` would
    /// claim a guarantee the session does not provide. See ADR-0010.
    Reality {
        /// The site being impersonated.
        server_name: String,
    },
    /// A scheme this build does not implement.
    ///
    /// Deliberately **not** reported as [`Self::Plaintext`]. `vmess://` and
    /// `vless://` protect the session with their own cryptography; calling them
    /// plaintext would be a false alarm in a security report, and an operator who
    /// learns to ignore that alarm is worse off than one who never saw it. Whether
    /// an unimplemented protocol is safe to send is a question this build cannot
    /// answer, so it says so.
    Unimplemented {
        /// The scheme as written.
        scheme: String,
    },
}

impl Security {
    /// A one-line description, safe to log and to print.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::None => "none".to_owned(),
            Self::Plaintext => "plaintext".to_owned(),
            Self::Tls {
                server_name,
                allow_insecure_requested,
            } => {
                let mut text = format!("tls sni={server_name}");
                if *allow_insecure_requested {
                    // Say it rather than honor it: the link asked for something this build
                    // does not do, and an operator reading a log must see that.
                    text.push_str(" (allowInsecure ignored)");
                }
                text
            }
            Self::Cipher {
                name,
                authenticated,
            } => {
                if *authenticated {
                    format!("cipher {name}")
                } else {
                    format!("cipher {name} (unauthenticated, rejected)")
                }
            }
            Self::Reality { server_name } => {
                format!("reality impersonating {server_name}")
            }
            Self::Unimplemented { scheme } => {
                format!("{scheme} (not implemented by this build)")
            }
        }
    }

    /// True when this build can vouch that the session is protected.
    ///
    /// An unimplemented scheme is `false` because "unknown" is not "safe": an
    /// operator asking "is anything going out in the clear?" must get a report that
    /// lists every node this build cannot vouch for.
    #[must_use]
    pub const fn is_confidential(&self) -> bool {
        matches!(
            self,
            Self::Tls { .. } | Self::Cipher { .. } | Self::Reality { .. }
        )
    }

    /// True when the node's protection is unknown rather than absent.
    #[must_use]
    pub const fn is_unimplemented(&self) -> bool {
        matches!(self, Self::Unimplemented { .. })
    }
}

impl Property {
    /// Builds properties directly from a typed configuration [`daer_config::Node`].
    pub fn from_node(node: &daer_config::Node) -> Self {
        let name = node.tag.clone().unwrap_or_else(|| node.default_name());
        let (protocol, address, udp, security) = match &node.endpoint {
            daer_config::NodeEndpoint::Direct(_) => {
                (Protocol::Direct, String::new(), true, Security::None)
            }
            daer_config::NodeEndpoint::Socks5(n) => (
                Protocol::Socks5,
                format!("{}:{}", n.server, n.port),
                true,
                Security::Plaintext,
            ),
            daer_config::NodeEndpoint::Http(n) => (
                Protocol::Http,
                format!("{}:{}", n.server, n.port),
                false,
                Security::Plaintext,
            ),
            daer_config::NodeEndpoint::Shadowsocks(n) => (
                Protocol::ShadowSocks,
                format!("{}:{}", n.server, n.port),
                false,
                Security::Cipher {
                    name: n.method.clone(),
                    authenticated: true,
                },
            ),
            daer_config::NodeEndpoint::Trojan(n) => (
                Protocol::Trojan,
                format!("{}:{}", n.server, n.port),
                false,
                Security::Tls {
                    server_name: n.sni.clone().unwrap_or_else(|| n.server.clone()),
                    allow_insecure_requested: n.allow_insecure,
                },
            ),
            daer_config::NodeEndpoint::AnyTls(n) => (
                Protocol::AnyTls,
                format!("{}:{}", n.server, n.port),
                true,
                Security::Tls {
                    server_name: n.sni.clone().unwrap_or_else(|| n.server.clone()),
                    allow_insecure_requested: n.allow_insecure,
                },
            ),
            daer_config::NodeEndpoint::Hysteria2(n) => (
                Protocol::Hysteria2,
                format!("{}:{}", n.server, n.ports.to_link_port()),
                true,
                Security::Tls {
                    server_name: n.sni.clone().unwrap_or_else(|| n.server.clone()),
                    allow_insecure_requested: n.allow_insecure,
                },
            ),
            // The security layer decides what is reported, not the protocol: a `vless` node over
            // plain TLS is not REALITY, and claiming it is would be a false statement about the
            // wire (ADR-0028).
            daer_config::NodeEndpoint::Vless(n) => (
                Protocol::Vless,
                format!("{}:{}", n.server, n.port),
                n.flow.is_vision(),
                security_property(&n.security, &n.server),
            ),
            daer_config::NodeEndpoint::Vmess(n) => (
                Protocol::Vmess,
                format!("{}:{}", n.server, n.port),
                true,
                security_property(&n.security, &n.server),
            ),
            daer_config::NodeEndpoint::Unsupported { scheme, .. } => (
                Protocol::Other(scheme.clone()),
                String::new(),
                false,
                Security::None,
            ),
        };

        Self {
            name,
            address,
            protocol,
            udp,
            subscription_tag: node.subscription_tag().to_owned(),
            security,
        }
    }

    /// Derives the static properties of a node link (`node { name: link }`).
    ///
    /// The address is the proxy's `host:port`; a link this build does not speak
    /// yet keeps its scheme in [`Protocol::Other`] instead of being rejected, so
    /// the node list can still be displayed.
    pub fn from_link(
        name: impl Into<String>,
        link: &str,
        subscription_tag: impl Into<String>,
    ) -> Self {
        let link = link.trim();
        let (protocol, address) = if link.is_empty() || link == "direct" {
            (Protocol::Direct, String::new())
        } else {
            match link.split_once("://") {
                Some((scheme, rest)) => (Protocol::from_scheme(scheme), authority_of(rest)),
                None => (Protocol::Other(link.to_owned()), String::new()),
            }
        };
        let udp = matches!(
            protocol,
            Protocol::Direct | Protocol::Socks5 | Protocol::AnyTls | Protocol::Hysteria2
        );
        let security = security_of(&protocol, link, &address);
        Self {
            name: name.into(),
            address,
            protocol,
            udp,
            subscription_tag: subscription_tag.into(),
            security,
        }
    }

    pub fn direct() -> Self {
        Self {
            name: "direct".to_owned(),
            address: String::new(),
            protocol: Protocol::Direct,
            udp: true,
            subscription_tag: String::new(),
            security: Security::None,
        }
    }
}

/// Derives a node's security identity from its link.
///
/// Deliberately structural: it reads the scheme, the cipher name and the `sni` parameter, and
/// nothing else. The password, the key and the certificate are not touched, so this cannot leak
/// them even if its output is pasted into a bug report.
fn security_of(protocol: &Protocol, link: &str, address: &str) -> Security {
    match protocol {
        Protocol::Direct => Security::None,
        Protocol::Socks5 | Protocol::Http | Protocol::Https => Security::Plaintext,
        Protocol::ShadowSocks => {
            // A shadowsocks link carries the cipher in its base64 credentials; only the name is
            // needed, and an unparseable link reports why rather than a guess.
            match daer_proxy_protocols::shadowsocks::Link::parse(link) {
                Ok(parsed) => Security::Cipher {
                    name: parsed.cipher.to_string(),
                    authenticated: true,
                },
                Err(_) => {
                    // Fall back to the scheme-visible part: the cipher is in the credentials,
                    // which did not parse, so nothing is claimed about authenticity.
                    Security::Cipher {
                        name: "unparseable".to_owned(),
                        authenticated: false,
                    }
                }
            }
        }
        Protocol::Trojan => match daer_proxy_protocols::trojan::Link::parse(link) {
            Ok(parsed) => Security::Tls {
                server_name: parsed.server_name,
                allow_insecure_requested: parsed.allow_insecure,
            },
            Err(_) => Security::Tls {
                server_name: address.split(':').next().unwrap_or_default().to_owned(),
                allow_insecure_requested: false,
            },
        },
        Protocol::AnyTls => {
            let sni = link
                .split_once('?')
                .and_then(|(_, q)| {
                    q.split('&').find_map(|pair| {
                        let (k, v) = pair.split_once('=')?;
                        if k == "sni" || k == "peer" {
                            Some(v.to_owned())
                        } else {
                            None
                        }
                    })
                })
                .unwrap_or_else(|| address.split(':').next().unwrap_or_default().to_owned());
            Security::Tls {
                server_name: sni,
                allow_insecure_requested: link.contains("allowInsecure=1")
                    || link.contains("allow_insecure=1")
                    || link.contains("insecure=1")
                    || link.contains("insecure=true"),
            }
        }
        Protocol::Hysteria2 => {
            let sni = link
                .split_once('?')
                .and_then(|(_, q)| {
                    q.split('&').find_map(|pair| {
                        let (k, v) = pair.split_once('=')?;
                        if k == "sni" || k == "peer" {
                            Some(v.to_owned())
                        } else {
                            None
                        }
                    })
                })
                .unwrap_or_else(|| address.split(':').next().unwrap_or_default().to_owned());
            Security::Tls {
                server_name: sni,
                allow_insecure_requested: link.contains("insecure=1")
                    || link.contains("insecure=true")
                    || link.contains("allowInsecure=1")
                    || link.contains("allow_insecure=1"),
            }
        }
        // An unknown scheme is not evidence of plaintext. `vmess://` and
        // `vless://` carry their own cryptography; reporting them as plaintext
        // would be a false alarm that trains an operator to ignore the report.
        Protocol::Vless | Protocol::Vmess => match daer_config::NodeEndpoint::from_link(link) {
            Ok(endpoint) => match &endpoint {
                daer_config::NodeEndpoint::Vless(node) => {
                    security_property(&node.security, &node.server)
                }
                daer_config::NodeEndpoint::Vmess(node) => {
                    security_property(&node.security, &node.server)
                }
                _ => Security::Unimplemented {
                    scheme: "not a vless/vmess link".to_owned(),
                },
            },
            Err(error) => Security::Unimplemented {
                scheme: format!("vless/vmess ({error})"),
            },
        },
        Protocol::Other(scheme) => Security::Unimplemented {
            scheme: scheme.clone(),
        },
    }
}

/// Strips `user:pass@`, the path, and the query from a link's remainder.
fn authority_of(rest: &str) -> String {
    let authority = rest
        .rsplit_once('@')
        .map_or(rest, |(_, authority)| authority);
    authority
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// A group's `policy`, including the index a `fixed` policy needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupPolicy {
    Random,
    /// `policy: fixed(<index>)` — the index is into the group's filtered dialer
    /// list.
    Fixed {
        index: usize,
    },
    MinLastLatency,
    MinAverage10,
    MinMovingAverage,
}

impl GroupPolicy {
    pub fn selection_policy(self) -> SelectionPolicy {
        match self {
            Self::Random => SelectionPolicy::Random,
            Self::Fixed { .. } => SelectionPolicy::Fixed,
            Self::MinLastLatency => SelectionPolicy::MinLastLatency,
            Self::MinAverage10 => SelectionPolicy::MinAverage10,
            Self::MinMovingAverage => SelectionPolicy::MinMovingAverage,
        }
    }
}

/// Parses `group { policy: … }` exactly like
/// `NewDialerSelectionPolicyFromGroupParam`.
pub fn parse_group_policy(policy: &FunctionOrString) -> Result<GroupPolicy, String> {
    let function = match policy {
        FunctionOrString::Name(name) => Function::new(name.clone()),
        FunctionOrString::Functions(functions) if functions.len() == 1 => functions[0].clone(),
        FunctionOrString::Functions(functions) => {
            return Err(format!(
                "policy should be exact 1 function: got {}",
                functions.len()
            ));
        }
    };

    // Both spellings mean the same policy: `min-moving-avg` is the canonical TOML
    // spelling, `min_moving_avg` is accepted from existing rule text.
    match function.name.replace('-', "_").as_str() {
        "random" => Ok(GroupPolicy::Random),
        "min" => Ok(GroupPolicy::MinLastLatency),
        "min_avg10" => Ok(GroupPolicy::MinAverage10),
        "min_moving_avg" => Ok(GroupPolicy::MinMovingAverage),
        "fixed" => {
            if function.negated {
                return Err(format!(
                    "policy param does not support not operator: !{}()",
                    function.name
                ));
            }
            if function.params.len() != 1 || !function.params[0].key.is_empty() {
                return Err(format!("invalid \"{}\" param format", function.name));
            }
            let value = function.params[0].as_literal().unwrap_or_default();
            let index = value
                .parse::<usize>()
                .map_err(|error| format!("invalid \"{}\" param format: {error}", function.name))?;
            Ok(GroupPolicy::Fixed { index })
        }
        _ => Err(format!("unexpected policy: {}", function.name)),
    }
}

/// Reports what security layer a parsed node actually applies.
///
/// A report that called every `vless` node REALITY would be wrong for a node over plain TLS,
/// and a wrong report about which handshake is on the wire trains an operator to ignore the
/// report (ADR-0028).
fn security_property(security: &daer_config::SecurityConfig, server: &str) -> Security {
    match security {
        daer_config::SecurityConfig::None {} => Security::None,
        daer_config::SecurityConfig::Tls(tls) => Security::Tls {
            server_name: tls.sni.clone().unwrap_or_else(|| server.to_owned()),
            allow_insecure_requested: tls.allow_insecure,
        },
        // REALITY's ClientHello is built by `daer-proxy-protocols` byte by byte, not by a
        // netune fingerprint preset: `RealityParams` carries an SNI, a public key, a short-id
        // and an ALPN list, and no fingerprint. Reporting `fp=<alpn[0]>` here (which is what
        // this did) put a value in a report that no code path reads, and reading `h2` where a
        // fingerprint belongs is worse than reading nothing. The honest report is what the
        // layer actually holds.
        daer_config::SecurityConfig::Reality(reality) => Security::Reality {
            server_name: reality.sni.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_protocol_schemes() {
        assert_eq!(Protocol::from_scheme("SOCKS5"), Protocol::Socks5);
        assert_eq!(Protocol::from_scheme("socks"), Protocol::Socks5);
        // `vmess` and `vless` are protocols now (ADR-0028/ADR-0030), not "other". A scheme with
        // no layer behind it stays `Other`, which is what the report uses to say "unimplemented"
        // rather than guessing.
        assert_eq!(Protocol::from_scheme("vmess"), Protocol::Vmess);
        assert_eq!(Protocol::from_scheme("vless"), Protocol::Vless);
        assert_eq!(
            Protocol::from_scheme("tuic"),
            Protocol::Other("tuic".to_owned())
        );
    }

    #[test]
    fn derives_properties_from_links() {
        let property = Property::from_link("HK", "socks5://u:p@1.2.3.4:1080/?x=1", "sub");
        assert_eq!(property.protocol, Protocol::Socks5);
        assert_eq!(property.address, "1.2.3.4:1080");
        assert!(property.udp);
        assert_eq!(property.subscription_tag, "sub");

        let property = Property::from_link("web", "http://proxy.example:8080", "");
        assert_eq!(property.protocol, Protocol::Http);
        assert_eq!(property.address, "proxy.example:8080");
        assert!(!property.udp);

        // A `vmess://` payload that is not base64 JSON still reports the *protocol* correctly:
        // the report's job is to name what the link claims, and the dial-time refusal names why
        // it cannot be used.
        let property = Property::from_link("future", "vmess://eyJhZGQiOiJ4In0", "");
        assert_eq!(property.protocol, Protocol::Vmess);
        assert!(
            matches!(
                property.security,
                Security::Unimplemented { ref scheme } if scheme.contains("vmess")
            ),
            "{:?}",
            property.security
        );
    }

    #[test]
    fn parses_group_policies() {
        let parse = |value: &str| parse_group_policy(&FunctionOrString::Name(value.to_owned()));

        assert_eq!(parse("min_moving_avg"), Ok(GroupPolicy::MinMovingAverage));
        assert_eq!(parse("random"), Ok(GroupPolicy::Random));
        assert!(parse("fastest").is_err());

        // `fixed` needs its index and is written as a function.
        let fixed = FunctionOrString::Functions(vec![Function::with_params(
            "fixed",
            vec![daer_config::Param::bare("2")],
        )]);
        assert_eq!(
            parse_group_policy(&fixed),
            Ok(GroupPolicy::Fixed { index: 2 })
        );

        let missing = FunctionOrString::Functions(vec![Function::new("fixed")]);
        assert!(parse_group_policy(&missing).is_err());

        let too_many =
            FunctionOrString::Functions(vec![Function::new("random"), Function::new("min")]);
        assert!(parse_group_policy(&too_many).is_err());
    }
}
