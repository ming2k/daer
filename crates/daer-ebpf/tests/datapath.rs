// SPDX-License-Identifier: AGPL-3.0-only

//! In-kernel datapath tests: the Rust harness for `ebpf/kern/tests/bpf_test.c`.
//!
//! ADR-0022. The test programs are self-checking BPF: for every case there is a
//! `pktgen_<case>` that builds a packet, a `setup_<case>` that primes the maps, and a
//! `check_<case>` whose return value is the assertion. This harness loads the compiled
//! test object, discovers those triples from the object itself, and drives each one
//! through `BPF_PROG_TEST_RUN` — the same syscall the previous Go harness used, through
//! `aya` instead of `cilium/ebpf`.
//!
//! # Why the triples are discovered
//!
//! The case list lives in `bpf_test.c`, not here. Enumerating it in Rust would be a
//! second source that goes stale the first time somebody adds a case, and a stale case
//! list is indistinguishable from a passing one. Discovering from the object means a new
//! case runs with no Rust change, and a half-added case (a `check_` with no `pktgen_`)
//! fails loudly.
//!
//! # Privileges
//!
//! `BPF_PROG_TEST_RUN` needs `CAP_BPF`/`CAP_NET_ADMIN`. Without them the harness skips
//! and says so; `scripts/kernel-check.sh` runs it with the capability and promotes the
//! skip to a failure, so a green unprivileged run never implies the kernel tests passed.

use std::collections::BTreeMap;

use aya::Ebpf;
use aya::programs::TestRun;
use aya::programs::tc::SchedClassifier;

use daer_ebpf::RuntimeParam;

/// The compiled test object, built by `cargo xtask ebpf --tests`.
fn object_path() -> Option<std::path::PathBuf> {
    if let Ok(path) = std::env::var("DAER_EBPF_TEST_OBJECT") {
        let path = std::path::PathBuf::from(path);
        return path.is_file().then_some(path);
    }
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/ebpf/datapath-test.o");
    path.is_file().then_some(path)
}

/// One `pktgen_` / `setup_` / `check_` triple.
struct Case {
    name: String,
}

/// Reads the case list out of the object's program names.
///
/// Returns the cases and, separately, any prefix that appears in only some of the three
/// roles — which is a broken case rather than a case to skip.
fn discover_cases(ebpf: &Ebpf) -> Result<Vec<Case>, String> {
    let mut roles: BTreeMap<String, [bool; 3]> = BTreeMap::new();
    for name in ebpf.programs().map(|(name, _)| name) {
        let Some((prefix, case)) = name.split_once('_') else {
            continue;
        };
        let slot = match prefix {
            "pktgen" => 0,
            "setup" => 1,
            "check" => 2,
            _ => continue,
        };
        roles.entry(case.to_owned()).or_default()[slot] = true;
    }

    let mut cases = Vec::new();
    let mut broken = Vec::new();
    for (case, present) in roles {
        if present == [true, true, true] {
            cases.push(Case { name: case });
        } else {
            let missing: Vec<&str> = ["pktgen", "setup", "check"]
                .into_iter()
                .zip(present)
                .filter(|(_, there)| !there)
                .map(|(role, _)| role)
                .collect();
            broken.push(format!("{case} (missing {})", missing.join(", ")));
        }
    }
    if !broken.is_empty() {
        return Err(format!(
            "half-defined datapath cases: {}. Every case needs a pktgen_/setup_/check_ \
             program; a case with only some of them would otherwise be skipped silently.",
            broken.join("; ")
        ));
    }
    Ok(cases)
}

/// `markAllOutboundsAlive`: an ARRAY map defaults to 0 ("not alive"), so a case that
/// routes to a user-defined outbound would get `TC_ACT_SHOT` before exercising anything.
fn mark_all_outbounds_alive(ebpf: &mut Ebpf) -> Result<(), String> {
    use aya::maps::Array;
    let map = ebpf
        .map_mut(daer_ebpf::names::map::OUTBOUND_CONNECTIVITY)
        .ok_or("missing outbound_connectivity_map")?;
    let mut array: Array<_, u32> = Array::try_from(map).map_err(|e| e.to_string())?;
    // The C indexes this map as `outbound * L4ProtoType_max + proto`; 256 outbounds and
    // 6 protocol slots is the bound the datapath itself uses.
    for key in 0..(256 * 6) {
        array.set(key, 1, 0).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// The number of `routing_map` slots a case may use.
///
/// The most rule-intensive case uses 5 slots. Iterating the full `MAX_MATCH_SET_LEN`
/// (1024) makes every zeroed slot look like a `MatchType_DomainSet` entry, and a case
/// whose fallback is not `must` then performs ~1022 extra domain lookups — minutes of
/// wall clock for no extra coverage.
const TEST_MAX_MATCH_SET_LEN: u32 = 5;

/// Clears the routing tables between cases, so a previous case's slots cannot make a
/// later one pass.
fn reset_routing(ebpf: &mut Ebpf) -> Result<(), String> {
    use aya::maps::{Array, HashMap};
    let meta = ebpf
        .map_mut(daer_ebpf::names::map::ROUTING_META)
        .ok_or("missing routing_meta_map")?;
    let mut meta: Array<_, u32> = Array::try_from(meta).map_err(|e| e.to_string())?;
    meta.set(0, TEST_MAX_MATCH_SET_LEN, 0)
        .map_err(|e| e.to_string())?;

    let routing = ebpf
        .map_mut(daer_ebpf::names::map::ROUTING)
        .ok_or("missing routing_map")?;
    // `MATCH_SET_SIZE` is a compile-time constant, so the value is a fixed-size array
    // rather than a `Vec`: aya's map values must be `Pod`.
    let mut routing: HashMap<_, u32, [u8; daer_ebpf::abi::MATCH_SET_SIZE]> =
        HashMap::try_from(routing).map_err(|e| e.to_string())?;
    for slot in 0..TEST_MAX_MATCH_SET_LEN {
        // `UpdateAny`-equivalent: insert or overwrite.
        routing
            .insert(slot, [0u8; daer_ebpf::abi::MATCH_SET_SIZE], 0)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Runs one program over `(data, ctx)` and returns its return code.
///
/// `data_out` is sized `data.len() + 256 + 2` because the kernel writes back the packet
/// plus headroom; `aya` requires the buffer to be at least that large.
fn run(ebpf: &mut Ebpf, name: &str, data: &[u8], ctx: &[u8]) -> Result<u32, String> {
    let program = ebpf
        .program_mut(name)
        .ok_or_else(|| format!("missing program {name}"))?;
    let classifier: &mut SchedClassifier = program
        .try_into()
        .map_err(|e: aya::programs::ProgramError| format!("{name} is not a tc classifier: {e}"))?;

    let mut data_out = vec![0u8; data.len() + 256 + 2];
    let mut ctx_out = vec![0u8; ctx.len()];
    let result = classifier
        .test_run(aya::programs::TestRunOptions {
            data_in: Some(data),
            data_out: Some(&mut data_out),
            ctx_in: Some(ctx),
            ctx_out: Some(&mut ctx_out),
            repeat: 1,
            ..Default::default()
        })
        .map_err(|e| format!("{name} failed to run: {e}"))?;
    Ok(result.return_value)
}

/// The packet buffer size the previous harness used: 4096 minus the skb headroom.
const DATA_LEN: usize = 4096 - 256 - 320;
const CTX_LEN: usize = 256;

fn run_case(ebpf: &mut Ebpf, case: &Case) -> Result<(), String> {
    reset_routing(ebpf)?;

    let data = vec![0u8; DATA_LEN];
    let ctx = vec![0u8; CTX_LEN];

    let status = run(ebpf, &format!("pktgen_{}", case.name), &data, &ctx)?;
    if status != 0 {
        return Err(format!(
            "pktgen_{} returned {status}, expected 0 (the packet could not be built)",
            case.name
        ));
    }

    let status = run(ebpf, &format!("setup_{}", case.name), &data, &ctx)?;
    let mut with_status = status.to_ne_bytes().to_vec();
    with_status.extend_from_slice(&data);

    let verdict = run(ebpf, &format!("check_{}", case.name), &with_status, &ctx)?;
    if verdict != 0 {
        return Err(format!(
            "check_{} returned {verdict}, expected 0 (the datapath verdict was wrong)",
            case.name
        ));
    }
    Ok(())
}

/// Why a load failed, as far as this harness cares.
enum LoadOutcome {
    Loaded(Ebpf),
    /// The kernel refused a map or program for want of a capability. Not a datapath
    /// bug, so the test skips and says which capability it needed.
    NoPrivilege(String),
}

/// Loads the test object through the same path production uses.
///
/// A privilege failure is separated from every other failure on purpose: on a machine
/// with `unprivileged_bpf_disabled=2` or without `CAP_BPF`, *every* map creation fails,
/// and reporting that as "the datapath is broken" is the kind of unfalsifiable red that
/// makes people stop reading the output. `scripts/kernel-check.sh` runs this privileged
/// and turns the skip into a failure, so the suite cannot pass without having run.
fn load_test_object(path: &std::path::Path) -> LoadOutcome {
    match daer_ebpf::load_path(path, &param()) {
        Ok(ebpf) => LoadOutcome::Loaded(ebpf),
        Err(error) => {
            // `MapError` does not implement `Error::source()`, so its `Display` drops the
            // `io::Error` that carries the errno; `Debug` keeps it. That is why this
            // matches on the debug rendering rather than on the message.
            let text = format!("{error:?}");
            if text.contains("PermissionDenied")
                || text.contains("Operation not permitted")
                || text.contains("EPERM")
            {
                LoadOutcome::NoPrivilege(text)
            } else {
                panic!("the test object must load: {error}")
            }
        }
    }
}

/// Prints the skip reason and returns, for the `LoadOutcome::NoPrivilege` case.
fn skip_without_privilege(reason: &str) {
    eprintln!(
        "skipping: the kernel refused the test object for want of a capability.\n  {reason}\n\
         Run it privileged: `sudo ./scripts/kernel-check.sh` (or `sudo cargo test -p \
         daer-ebpf --test datapath -- --include-ignored`)."
    );
}

fn param() -> RuntimeParam {
    RuntimeParam {
        tproxy_port: 12_345,
        control_plane_pid: std::process::id(),
        device_ifindex: 1,
        netns_id: 0,
        peer_mac: [0x02, 0, 0, 0, 0, 0x01],
        padding_after_mac: [0, 0],
        use_redirect_peer: false,
        has_bpf_get_current_task: true,
        datapath_generation: 41,
        socket_mark: 0x0200,
    }
}

#[test]
#[ignore = "needs CAP_BPF and CAP_NET_ADMIN; scripts/kernel-check.sh runs it privileged"]
fn every_datapath_case_passes() {
    let Some(path) = object_path() else {
        eprintln!(
            "skipped: target/ebpf/datapath-test.o is missing; run `cargo xtask ebpf --tests`"
        );
        return;
    };

    let mut ebpf = match load_test_object(&path) {
        LoadOutcome::Loaded(ebpf) => ebpf,
        LoadOutcome::NoPrivilege(reason) => return skip_without_privilege(&reason),
    };

    let cases = discover_cases(&ebpf).unwrap_or_else(|error| panic!("{error}"));
    assert!(
        !cases.is_empty(),
        "no pktgen_/setup_/check_ triples found in {}; the test object was built without \
         the case programs",
        path.display()
    );
    eprintln!("discovered {} datapath cases", cases.len());

    mark_all_outbounds_alive(&mut ebpf).unwrap_or_else(|error| panic!("{error}"));

    let mut failures = Vec::new();
    for case in &cases {
        if let Err(error) = run_case(&mut ebpf, case) {
            failures.push(error);
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} datapath cases failed:\n  {}",
        failures.len(),
        cases.len(),
        failures.join("\n  ")
    );
}

#[test]
#[ignore = "needs CAP_BPF and CAP_NET_ADMIN"]
fn every_case_is_complete() {
    let Some(path) = object_path() else {
        eprintln!("skipped: run `cargo xtask ebpf --tests` to build the test object");
        return;
    };
    let ebpf = match load_test_object(&path) {
        LoadOutcome::Loaded(ebpf) => ebpf,
        LoadOutcome::NoPrivilege(reason) => return skip_without_privilege(&reason),
    };
    if let Err(error) = discover_cases(&ebpf) {
        panic!("{error}");
    }
}
