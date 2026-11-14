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

use std::os::fd::AsRawFd;
use std::path::PathBuf;

use daer_ebpf::RuntimeParam;

/// `struct pid_pname` from `ebpf/kern/src/state.h`.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
struct PidPname {
    last_seen_ns: u64,
    pid: u32,
    pname: [u8; 16],
    _padding: [u8; 4],
}

// SAFETY: the type is `repr(C)` and every field is plain old data; it is the
// exact value layout of the C `struct pid_pname` used by `cookie_pid_map`.
unsafe impl aya::Pod for PidPname {}

fn object_path() -> PathBuf {
    crate::common::workspace_path("target/ebpf/datapath.bpf.o")
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
    // The names table is asserted against the object by `tests/integration/ebpf_object.rs`, which parses the
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

/// The cgroup hooks are the producer of `cookie_pid_map`; without this attach,
/// `pname(...)` is accepted but can never match. Loading and attaching all six
/// here also runs their verifier paths.
#[test]
#[ignore = "needs CAP_BPF and CAP_NET_ADMIN, and a cgroup v2 mount"]
fn cgroup_hooks_attach_to_the_unified_hierarchy() {
    let path = object_path();
    if !path.exists() {
        eprintln!(
            "skipped: {} is missing; run `cargo xtask ebpf`",
            path.display()
        );
        return;
    }
    let cgroup = daer_ebpf::cgroup_v2_path().expect("cgroup v2 must be mounted");
    let mut ebpf = daer_ebpf::load_path(&path, &param()).expect("the object must load");
    daer_ebpf::attach_cgroup_hooks(&mut ebpf, &cgroup)
        .expect("the six pname cgroup hooks must attach");

    // The hooks must populate the map for a socket created after the attach.
    // This is the falsifier for "attached but no fact observed": the map lookup
    // uses the same SO_COOKIE value the cgroup `sock_create` program keys on.
    let socket = std::net::UdpSocket::bind(("127.0.0.1", 0)).expect("bind a test socket");
    let mut cookie: u64 = 0;
    let mut length = std::mem::size_of::<u64>() as libc::socklen_t;
    // SAFETY: `socket` is live and the output buffer is exactly `length` bytes.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_COOKIE,
            std::ptr::from_mut(&mut cookie).cast(),
            &mut length,
        )
    };
    assert_eq!(
        result,
        0,
        "SO_COOKIE must be readable: {}",
        std::io::Error::last_os_error()
    );

    let map = ebpf
        .map_mut(daer_ebpf::generated::map::COOKIE_PID)
        .expect("cookie_pid_map is in the object");
    let map: aya::maps::HashMap<_, u64, PidPname> =
        aya::maps::HashMap::try_from(map).expect("cookie_pid_map is a hash map");
    let observed = map
        .get(&cookie, 0)
        .expect("the cgroup sock_create hook must populate the cookie");
    assert_eq!(
        observed.pid,
        std::process::id(),
        "the observed pid must be the test's process"
    );
    let pname = String::from_utf8_lossy(&observed.pname)
        .trim_end_matches('\0')
        .to_owned();
    assert!(
        !pname.is_empty(),
        "the cgroup hook must record a process name"
    );
    println!(
        "cgroup hooks attached to {}; observed pname={pname}",
        cgroup.display()
    );
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
