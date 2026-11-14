use super::*;
use crate::wire::{Flags, Question, Record, ResponseCode};

fn name(text: &str) -> Name {
    Name::parse(text).expect("name")
}

fn key(text: &str, qtype: RecordType) -> Key {
    Key {
        name: name(text),
        qtype,
        qclass: Question::CLASS_IN,
    }
}

fn answer(text: &str, ttl: u32) -> Arc<Message> {
    Arc::new(Message {
        id: 1,
        flags: Flags(0x8180),
        questions: vec![Question::internet(name(text), RecordType::A)],
        answers: vec![Record {
            name: name(text),
            rtype: RecordType::A,
            class: Question::CLASS_IN,
            ttl,
            rdata: vec![93, 184, 216, 34],
        }],
        authorities: Vec::new(),
        additionals: Vec::new(),
    })
}

fn negative(text: &str, code: ResponseCode) -> Arc<Message> {
    Arc::new(Message {
        id: 1,
        flags: Flags::response_to(Flags(0x0100), code),
        questions: vec![Question::internet(name(text), RecordType::A)],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    })
}

#[test]
fn a_fresh_answer_ttl_counts_down() {
    let now = Instant::now();
    let mut cache = Cache::new(CacheConfig::default());
    cache
        .store(
            key("example.com", RecordType::A),
            answer("example.com", 300),
            now,
        )
        .expect("stores");

    let hit = cache
        .lookup(
            &key("example.com", RecordType::A),
            now + Duration::from_secs(100),
        )
        .expect("hit");
    assert!(!hit.needs_refresh());
    assert_eq!(hit.ttl(), 200, "the remaining ttl, not the original");
}

#[test]
fn an_expired_answer_is_served_stale_with_the_configured_ttl() {
    let now = Instant::now();
    let config = CacheConfig {
        optimistic: true,
        stale_ttl: 30,
        stale_reply_ttl: 7,
        ..CacheConfig::default()
    };
    let mut cache = Cache::new(config);
    cache
        .store(
            key("example.com", RecordType::A),
            answer("example.com", 10),
            now,
        )
        .expect("stores");

    let hit = cache
        .lookup(
            &key("example.com", RecordType::A),
            now + Duration::from_secs(20),
        )
        .expect("stale hit");
    assert!(hit.needs_refresh(), "a stale answer must ask for a refresh");
    assert_eq!(hit.ttl(), 7, "advertised ttl for stale data");
    assert_eq!(hit.expired_for(), Some(Duration::from_secs(10)));
}

#[test]
fn beyond_the_stale_window_the_entry_is_gone() {
    let now = Instant::now();
    let config = CacheConfig {
        optimistic: true,
        stale_ttl: 30,
        ..CacheConfig::default()
    };
    let mut cache = Cache::new(config);
    cache
        .store(
            key("example.com", RecordType::A),
            answer("example.com", 10),
            now,
        )
        .expect("stores");

    // TTL 10 + stale 30 = gone at 40s.
    assert!(
        cache
            .lookup(
                &key("example.com", RecordType::A),
                now + Duration::from_secs(39)
            )
            .is_some()
    );
    assert!(
        cache
            .lookup(
                &key("example.com", RecordType::A),
                now + Duration::from_secs(41)
            )
            .is_none()
    );
    assert!(cache.is_empty(), "an expired entry is removed on lookup");
}

#[test]
fn optimistic_off_drops_the_entry_instead_of_serving_it() {
    let now = Instant::now();
    let config = CacheConfig {
        optimistic: false,
        ..CacheConfig::default()
    };
    let mut cache = Cache::new(config);
    cache
        .store(
            key("example.com", RecordType::A),
            answer("example.com", 10),
            now,
        )
        .expect("stores");

    assert!(
        cache
            .lookup(
                &key("example.com", RecordType::A),
                now + Duration::from_secs(11)
            )
            .is_none()
    );
    assert!(cache.is_empty());
}

#[test]
fn a_stale_window_of_zero_never_expires() {
    let now = Instant::now();
    let config = CacheConfig {
        optimistic: true,
        stale_ttl: 0,
        ..CacheConfig::default()
    };
    let stale_reply_ttl = config.stale_reply_ttl;
    let mut cache = Cache::new(config);
    cache
        .store(
            key("example.com", RecordType::A),
            answer("example.com", 10),
            now,
        )
        .expect("stores");

    let far_future = now + Duration::from_secs(86_400);
    let hit = cache
        .lookup(&key("example.com", RecordType::A), far_future)
        .expect("hit");
    assert!(hit.needs_refresh());
    assert_eq!(hit.ttl(), stale_reply_ttl);
}

#[test]
fn the_minimum_record_ttl_wins() {
    // A cache may not outlive any record it serves: the A record says 300 but the
    // AAAA says 30, so the whole answer lives 30.
    let now = Instant::now();
    let mut cache = Cache::new(CacheConfig::default());
    let message = Arc::new(Message {
        id: 1,
        flags: Flags(0x8180),
        questions: vec![Question::internet(name("example.com"), RecordType::A)],
        answers: vec![
            Record {
                name: name("example.com"),
                rtype: RecordType::A,
                class: Question::CLASS_IN,
                ttl: 300,
                rdata: vec![1, 2, 3, 4],
            },
            Record {
                name: name("example.com"),
                rtype: RecordType::AAAA,
                class: Question::CLASS_IN,
                ttl: 30,
                rdata: vec![0; 16],
            },
        ],
        authorities: Vec::new(),
        additionals: Vec::new(),
    });

    assert_eq!(
        cache
            .store(key("example.com", RecordType::A), message, now)
            .expect("stores"),
        30
    );
}

#[test]
fn negative_answers_are_cached_and_servfail_is_not() {
    let now = Instant::now();
    let config = CacheConfig {
        stale_reply_ttl: 12,
        ..CacheConfig::default()
    };
    let mut cache = Cache::new(config);

    assert_eq!(
        cache
            .store(
                key("nx.example", RecordType::A),
                negative("nx.example", ResponseCode::NXDOMAIN),
                now
            )
            .expect("nxdomain is cacheable"),
        12,
        "a negative answer is worth caching"
    );
    assert_eq!(
        cache.store(
            key("fail.example", RecordType::A),
            negative("fail.example", ResponseCode::SERVFAIL),
            now
        ),
        Err(Skipped::ZeroTtl),
        "a SERVFAIL carries nothing to remember"
    );
}

#[test]
fn a_zero_ttl_answer_is_not_cached() {
    let now = Instant::now();
    let mut cache = Cache::new(CacheConfig::default());
    assert_eq!(
        cache.store(
            key("example.com", RecordType::A),
            answer("example.com", 0),
            now
        ),
        Err(Skipped::ZeroTtl)
    );
    assert!(cache.is_empty());
}

#[test]
fn a_fixed_ttl_override_wins_and_the_longest_suffix_applies() {
    let now = Instant::now();
    let config = CacheConfig {
        fixed_ttl: vec![(name("example.com"), 5), (name("a.example.com"), 99)],
        ..CacheConfig::default()
    };
    let mut cache = Cache::new(config);

    assert_eq!(
        cache
            .store(
                key("b.example.com", RecordType::A),
                answer("b.example.com", 300),
                now
            )
            .expect("stores"),
        5
    );
    assert_eq!(
        cache
            .store(
                key("a.example.com", RecordType::A),
                answer("a.example.com", 300),
                now
            )
            .expect("stores"),
        99,
        "the more specific override"
    );
}

#[test]
fn the_cache_is_bounded_and_evicts_expired_entries_first() {
    let now = Instant::now();
    let config = CacheConfig {
        max_entries: 2,
        optimistic: true,
        stale_ttl: 0,
        ..CacheConfig::default()
    };
    let mut cache = Cache::new(config);

    cache
        .store(
            key("a.example", RecordType::A),
            answer("a.example", 300),
            now,
        )
        .expect("stores");
    cache
        .store(key("b.example", RecordType::A), answer("b.example", 1), now)
        .expect("stores");
    assert_eq!(cache.len(), 2);

    // Adding a third must evict; the soonest-expiring entry goes first.
    cache
        .store(
            key("c.example", RecordType::A),
            answer("c.example", 300),
            now,
        )
        .expect("stores");
    assert_eq!(cache.len(), 2, "the cap holds");
    assert!(
        cache
            .lookup(
                &key("b.example", RecordType::A),
                now + Duration::from_secs(2)
            )
            .is_none(),
        "the soonest-expiring entry was evicted"
    );
}

#[test]
fn sweep_removes_only_what_left_its_window_and_reports_the_count() {
    let now = Instant::now();
    let config = CacheConfig {
        stale_ttl: 10,
        ..CacheConfig::default()
    };
    let mut cache = Cache::new(config);
    cache
        .store(
            key("short.example", RecordType::A),
            answer("short.example", 1),
            now,
        )
        .expect("stores");
    cache
        .store(
            key("long.example", RecordType::A),
            answer("long.example", 300),
            now,
        )
        .expect("stores");

    assert_eq!(cache.sweep(now + Duration::from_secs(5)), 0);
    assert_eq!(cache.len(), 2);
    // short: 1 + 10 = gone at 11s.
    assert_eq!(cache.sweep(now + Duration::from_secs(12)), 1);
    assert_eq!(cache.len(), 1);
}

#[test]
fn only_messages_with_one_question_have_a_key() {
    let mut message = (*answer("example.com", 60)).clone();
    message.questions.clear();
    assert!(Key::of(&message).is_none(), "no question, no key");

    message.questions = vec![
        Question::internet(name("a.example"), RecordType::A),
        Question::internet(name("b.example"), RecordType::A),
    ];
    assert!(Key::of(&message).is_none(), "two questions, no key");
}

#[test]
fn a_hit_can_be_routed_on_its_addresses() {
    let now = Instant::now();
    let mut cache = Cache::new(CacheConfig::default());
    cache
        .store(
            key("example.com", RecordType::A),
            answer("example.com", 60),
            now,
        )
        .expect("stores");
    let hit = cache
        .lookup(&key("example.com", RecordType::A), now)
        .expect("hit");
    assert_eq!(
        answer_addresses(&hit),
        vec!["93.184.216.34".parse::<IpAddr>().expect("ip")]
    );
}
