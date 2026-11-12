// SPDX-License-Identifier: AGPL-3.0-only

//! Loads the datapath object and attaches it to a real interface.
//!
//! This is the only test that exercises the kernel: `daer-ebpf`'s object tests read the
//! ELF, and everything in `daer-control` is tested through traits. Loading and attaching is
//! where a verifier rejection, a missing map, or a wrong section name shows up, and none of
//! those are visible from the Rust side.
//!
//! Ignored by default: it needs `CAP_BPF` / `CAP_NET_ADMIN`, which a normal test run does
//! not have. Run it as root, or inside a user namespace with those capabilities:
//!
//! ```sh
//! sudo cargo test -p daer-ebpf --test kernel -- --include-ignored --nocapture
//! ```
//!
//! A rebuild of the object is needed first (`cargo xtask ebpf`).

use std::path::PathBuf;

use daer_ebpf::RuntimeParam;

fn object_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/ebpf/datapath.bpf.o")
}

fn param() -> RuntimeParam {
    RuntimeParam {
        control_plane_pid: std::process::id(),
        device_ifindex: 1,
        netns_id: 0,
        peer_mac: [0x02, 0, 0, 0, 0, 0x01],
        padding_after_mac: [0, 0],
        use_redirect_peer: false,
        has_bpf_get_current_task: true,
        datapath_generation: 1,
        socket_mark: 0x64616572,
    }
}

#[test]
#[ignore = "needs CAP_BPF and CAP_NET_ADMIN"]
fn the_object_loads_and_verifies() {
    let path = object_path();
    if !path.exists() {
        eprintln!(
            "skipped: {} is missing; run `cargo xtask ebpf`",
            path.display()
        );
        return;
    }
    // Loading is what runs the verifier. A failure here is a real kernel-side problem:
    // a map the verifier cannot prove, a helper the kernel does not have, or a global the
    // ABI does not match.
    let ebpf = daer_ebpf::load_path(&path, &param()).expect("the object must load");
    println!("loaded {} maps", daer_ebpf::loader::map_names(&ebpf).len());
    println!(
        "loaded {} programs",
        daer_ebpf::loader::program_names(&ebpf).len()
    );
}

#[test]
#[ignore = "needs CAP_BPF and CAP_NET_ADMIN"]
fn every_program_we_reference_is_in_the_object() {
    // The names table is asserted against the object by `tests/object.rs`, which parses the
    // ELF; this asserts the *loader* agrees, which is the path production takes.
    let path = object_path();
    if !path.exists() {
        eprintln!(
            "skipped: {} is missing; run `cargo xtask ebpf`",
            path.display()
        );
        return;
    }
    let ebpf = daer_ebpf::load_path(&path, &param()).expect("the object must load");
    let present = daer_ebpf::loader::program_names(&ebpf);
    for name in daer_ebpf::names::program::ALL {
        assert!(
            present.contains(&name),
            "the object is missing program {name}; present: {present:?}"
        );
    }
}

/// TCX is the only attachment mode. This proves it attaches on Linux 6.6+, not that
/// `bpf_sk_assign` delivers a flow: the real-daemon delivery check is
/// `scripts/ops/daer-delivery-check.sh`.
#[test]
#[ignore = "needs CAP_BPF and CAP_NET_ADMIN; TCX needs Linux 6.6+"]
fn a_tcx_program_attaches_to_loopback() {
    use aya::programs::tc::TcAttachType;

    daer_ebpf::require_tcx().expect("the kernel must support TCX");

    let path = object_path();
    if !path.exists() {
        eprintln!(
            "skipped: {} is missing; run `cargo xtask ebpf`",
            path.display()
        );
        return;
    }
    let mut ebpf = daer_ebpf::load_path(&path, &param()).expect("the object must load");
    let link = daer_ebpf::attach_tc(
        &mut ebpf,
        daer_ebpf::names::program::DEVICE_INGRESS,
        "lo",
        TcAttachType::Ingress,
    )
    .expect("TCX must attach on this kernel");
    println!("attached TCX as link id {link:?}");
}
