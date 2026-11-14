use super::*;
use crate::wire::{Flags, Question, Record, RecordType};
use std::sync::atomic::AtomicUsize;

/// A transport that answers from a table and counts how often it was asked.
#[derive(Debug)]
struct FakeUpstream {
    addresses: Vec<[u8; 4]>,
    ttl: u32,
    calls: AtomicUsize,
    fail: bool,
}

impl FakeUpstream {
    fn answering(addresses: &[[u8; 4]], ttl: u32) -> Arc<Self> {
        Arc::new(Self {
            addresses: addresses.to_vec(),
            ttl,
            calls: AtomicUsize::new(0),
            fail: false,
        })
    }

    fn failing() -> Arc<Self> {
        Arc::new(Self {
            addresses: Vec::new(),
            ttl: 0,
            calls: AtomicUsize::new(0),
            fail: true,
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
}

impl Upstream for FakeUpstream {
    fn exchange<'a>(&'a self, query: &'a Message) -> ExchangeFuture<'a> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if self.fail {
                return Err(UpstreamError::Failed("upstream is down".to_owned()));
            }
            let question = query
                .single_question()
                .ok_or_else(|| UpstreamError::Failed("no question".to_owned()))?;
            Ok(Message {
                id: query.id,
                flags: Flags(0x8180),
                questions: vec![question.clone()],
                answers: self
                    .addresses
                    .iter()
                    .map(|octets| Record {
                        name: question.name.clone(),
                        rtype: RecordType::A,
                        class: Question::CLASS_IN,
                        ttl: self.ttl,
                        rdata: octets.to_vec(),
                    })
                    .collect(),
                authorities: Vec::new(),
                additionals: Vec::new(),
            })
        })
    }
}

fn query(name: &str, qtype: RecordType) -> Message {
    Message {
        id: 0x1234,
        flags: Flags(0x0100),
        questions: vec![Question::internet(Name::parse(name).expect("name"), qtype)],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    }
}

const BASE: &str = r#"
[dns]
upstream = ["local:udp://127.0.0.1:53", "remote:udp://127.0.0.1:54"]

[dns.request]
rules = ["qname(blocked) -> reject", "qname(lan) -> asis"]
default = "local"

[dns.response]
rules = []
default = "accept"
"#;

fn resolver(src: &str, local: Arc<FakeUpstream>) -> Resolver {
    let config = daer_config::toml_config::load_str(src).expect("config loads");
    // `remote` is declared by `BASE` and never asked by these cases; registering it
    // keeps the fixture honest now that a declared tag without a transport is a load
    // error rather than a transport that fails per query.
    Resolver::new(
        &config,
        [
            ("local".to_owned(), local as Arc<dyn Upstream>),
            (
                "remote".to_owned(),
                FakeUpstream::answering(&[[1, 1, 1, 1]], 60) as Arc<dyn Upstream>,
            ),
        ],
    )
    .expect("resolver builds")
}

fn answer_of(resolution: Resolution) -> Message {
    match resolution {
        Resolution::Answer(message) => message,
        other => panic!("expected an answer, got {other:?}"),
    }
}

#[tokio::test]
async fn an_answer_is_served_and_then_cached() {
    let upstream = FakeUpstream::answering(&[[93, 184, 216, 34]], 300);
    let resolver = resolver(BASE, Arc::clone(&upstream));
    let query = query("example.com", RecordType::A);

    let first = answer_of(resolver.resolve_test(&query).await.expect("resolves"));
    assert_eq!(first.id, query.id, "the client's id is echoed");
    assert!(first.is_response());
    assert_eq!(first.answer_addresses().len(), 1);
    assert_eq!(upstream.calls(), 1);

    let second = answer_of(resolver.resolve_test(&query).await.expect("resolves"));
    assert_eq!(upstream.calls(), 1, "the second answer came from the cache");
    assert_eq!(second.answer_addresses(), first.answer_addresses());

    let stats = resolver.stats().snapshot();
    assert_eq!(stats.misses, 1);
    assert_eq!(stats.hits, 1);
    assert_eq!(stats.upstream_calls, 1);
    assert!((stats.hit_ratio().expect("ratio") - 0.5).abs() < f64::EPSILON);
}

#[tokio::test]
async fn a_cached_answer_carries_the_remaining_ttl() {
    let upstream = FakeUpstream::answering(&[[1, 2, 3, 4]], 300);
    let resolver = resolver(BASE, upstream);
    let query = query("ttl.example.com", RecordType::A);
    let _ = resolver.resolve_test(&query).await.expect("resolves");

    // Reach into the cache with a synthetic clock so the assertion is deterministic.
    let key = Key::of(&query).expect("key");
    let mut cache = resolver.cache.lock().expect("cache");
    let hit = cache
        .lookup(&key, Instant::now() + std::time::Duration::from_secs(100))
        .expect("hit");
    // A few microseconds elapse between `store` and `lookup`, so the remaining TTL is
    // 199 or 200 depending on where the truncation lands. The property under test is
    // "the remaining time, not the original 300", so assert a band rather than a
    // second that a loaded machine could shift.
    let ttl = hit.ttl();
    assert!(
        (199..=200).contains(&ttl),
        "remaining ttl should be ~200, not the original 300; got {ttl}"
    );

    let mut message = (**hit.message()).clone();
    cap_ttls(&mut message, ttl);
    assert_eq!(message.answers[0].ttl, ttl);
}

#[tokio::test]
async fn a_reject_rule_answers_refused_without_asking_anyone() {
    let upstream = FakeUpstream::answering(&[[1, 2, 3, 4]], 60);
    let resolver = resolver(BASE, Arc::clone(&upstream));
    let answer = answer_of(
        resolver
            .resolve_test(&query("tracker.blocked", RecordType::A))
            .await
            .expect("resolves"),
    );
    assert_eq!(answer.response_code(), ResponseCode::REFUSED);
    assert_eq!(upstream.calls(), 0, "no upstream was asked");
    assert_eq!(resolver.stats().snapshot().rejects, 1);
}

#[tokio::test]
async fn an_asis_rule_hands_the_query_back() {
    let upstream = FakeUpstream::answering(&[[1, 2, 3, 4]], 60);
    let resolver = resolver(BASE, Arc::clone(&upstream));
    assert!(matches!(
        resolver
            .resolve_test(&query("nas.lan", RecordType::A))
            .await
            .expect("resolves"),
        Resolution::AsIs
    ));
    assert_eq!(upstream.calls(), 0);
    assert_eq!(resolver.stats().snapshot().as_is, 1);
}

#[tokio::test]
async fn an_upstream_failure_becomes_servfail_rather_than_nothing() {
    // A client that gets no answer retries and holds its slot; SERVFAIL ends that.
    let resolver = resolver(BASE, FakeUpstream::failing());
    let answer = answer_of(
        resolver
            .resolve_test(&query("example.com", RecordType::A))
            .await
            .expect("resolves"),
    );
    assert_eq!(answer.response_code(), ResponseCode::SERVFAIL);
    assert_eq!(resolver.stats().snapshot().upstream_errors, 1);
}

#[test]
fn a_query_trace_is_joinable_by_id() {
    // Every event about one query carries this ID. It is created at the server boundary,
    // not reconstructed from the question text or the peer address.
    let resolver = resolver(BASE, FakeUpstream::answering(&[[1, 2, 3, 4]], 60));
    let peer = "127.0.0.1:5353".parse().expect("peer");
    let first = resolver.begin_query(peer);
    let second = resolver.begin_query(peer);
    assert_ne!(first.id, second.id);
    assert_eq!(first.peer, peer);
    assert_eq!(second.peer, peer);
}

#[test]
fn a_declared_upstream_without_a_transport_is_a_load_error() {
    // The stronger contract, and the one that cannot mislead: a resolver that loads and
    // then fails every query looks like a working resolver to an operator who only sees
    // "it started".
    let src = r#"
[dns]
upstream = ["remote:udp://127.0.0.1:54"]

[dns.request]
rules = []
default = "remote"
"#;
    let config = daer_config::toml_config::load_str(src).expect("config loads");
    let error = Resolver::new(&config, []).expect_err("must refuse to build");
    let message = error.to_string();
    assert!(message.contains("no transport"), "{message}");
    assert!(message.contains("remote"), "{message}");
}

#[tokio::test]
async fn a_failover_rule_asks_a_second_upstream() {
    let first = FakeUpstream::answering(&[[10, 0, 0, 1]], 60);
    let second = FakeUpstream::answering(&[[93, 184, 216, 34]], 60);
    let src = r#"
[dns]
upstream = ["first:udp://127.0.0.1:53", "second:udp://127.0.0.1:54"]

[dns.request]
rules = []
default = "first"

[dns.response]
rules = ["ip(10.0.0.0/8) -> second"]
"#;
    let config = daer_config::toml_config::load_str(src).expect("config loads");
    let resolver = Resolver::new(
        &config,
        [
            ("first".to_owned(), first.clone() as Arc<dyn Upstream>),
            ("second".to_owned(), second.clone() as Arc<dyn Upstream>),
        ],
    )
    .expect("builds");

    let answer = answer_of(
        resolver
            .resolve_test(&query("example.com", RecordType::A))
            .await
            .expect("resolves"),
    );
    assert_eq!(first.calls(), 1);
    assert_eq!(second.calls(), 1, "the failover upstream was asked");
    assert_eq!(
        answer.answer_addresses(),
        vec!["93.184.216.34".parse::<std::net::IpAddr>().expect("ip")],
        "the client sees the second answer"
    );
    assert_eq!(resolver.stats().snapshot().failovers, 1);
}

#[tokio::test]
async fn a_failover_to_the_same_upstream_is_ignored_not_looped() {
    let upstream = FakeUpstream::answering(&[[10, 0, 0, 1]], 60);
    let src = r#"
[dns]
upstream = ["only:udp://127.0.0.1:53"]

[dns.request]
rules = []
default = "only"

[dns.response]
rules = ["ip(10.0.0.0/8) -> only"]
"#;
    let config = daer_config::toml_config::load_str(src).expect("config loads");
    let resolver = Resolver::new(
        &config,
        [("only".to_owned(), upstream.clone() as Arc<dyn Upstream>)],
    )
    .expect("builds");

    let answer = answer_of(
        resolver
            .resolve_test(&query("example.com", RecordType::A))
            .await
            .expect("resolves"),
    );
    assert_eq!(upstream.calls(), 1, "one question, not a loop");
    assert_eq!(answer.answer_addresses().len(), 1);
}

#[tokio::test]
async fn a_query_that_is_itself_a_response_is_rejected() {
    let resolver = resolver(BASE, FakeUpstream::answering(&[[1, 2, 3, 4]], 60));
    let mut response = query("example.com", RecordType::A);
    response.flags = Flags(0x8180);
    assert!(matches!(
        resolver.resolve_test(&response).await,
        Err(ResolverError::Unserviceable(ResponseCode::FORMERR))
    ));
}

#[tokio::test]
async fn the_opt_pseudo_record_ttl_is_never_rewritten() {
    // The OPT "TTL" field is an extended flags word; capping it corrupts EDNS.
    let mut message = query("example.com", RecordType::A);
    message.additionals.push(Record {
        name: Name::root(),
        rtype: RecordType::OPT,
        class: 4096,
        ttl: 0x0000_8000,
        rdata: Vec::new(),
    });
    cap_ttls(&mut message, 30);
    assert_eq!(message.additionals[0].ttl, 0x0000_8000);
}

#[test]
fn a_cache_can_be_swept_and_cleared_through_the_resolver() {
    let resolver = resolver(BASE, FakeUpstream::answering(&[[1, 2, 3, 4]], 60));
    assert_eq!(resolver.cache_len(), 0);
    // Nothing to sweep yet; the call must still be safe and report zero.
    assert_eq!(resolver.sweep(), 0);
    resolver.clear_cache();
    assert_eq!(resolver.cache_len(), 0);
}

#[test]
fn stats_describe_an_idle_resolver() {
    let resolver = resolver(BASE, FakeUpstream::answering(&[[1, 2, 3, 4]], 60));
    let stats = resolver.stats().snapshot();
    assert_eq!(stats, StatsSnapshot::default());
    assert!(
        stats.hit_ratio().is_none(),
        "no ratio before the first lookup"
    );
}
