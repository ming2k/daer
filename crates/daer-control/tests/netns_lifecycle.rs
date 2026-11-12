// SPDX-License-Identifier: AGPL-3.0-only

//! The private-ingress lifecycle, against the real kernel.
//!
//! This test creates and deletes `daer0ns` and `daer0`/`daer0peer`, so it is gated on
//! `DAER_NETNS_TEST=1` rather than running in the ordinary workspace suite. The privileged
//! e2e job sets it; a developer can run it inside a disposable user namespace:
//!
//! ```sh
//! unshare -Urnm sh -c 'mount -t tmpfs tmpfs /run/netns && \
//!   DAER_NETNS_TEST=1 cargo test -p daer-control --test netns_lifecycle'
//! ```
//!
//! The falsifiers are concrete: a namespace that is not created, a peer still visible in the
//! host, a policy rule keyed by mark instead of ingress, a missing return route, a namespace
//! that survives drop, a host veth end that is not freed with its peer, or a namespace mount
//! that is visible in the host's mount namespace instead of being private to the daemon.

use std::time::{Duration, Instant};

/// Sets the host-global prerequisites the daemon requires in this test's network namespace.
///
/// The test runs in a disposable netns, so this does not touch the host. It mirrors what an
/// operator installs in `/etc/sysctl.d/99-daer.conf`; the daemon checks these and refuses to
/// change them itself.
fn set_host_prerequisites() {
    for (path, value) in [
        ("ipv4/ip_forward", "1"),
        ("ipv4/conf/all/forwarding", "1"),
        ("ipv4/conf/all/rp_filter", "0"),
        ("ipv4/conf/all/arp_filter", "0"),
    ] {
        std::fs::write(format!("/proc/sys/net/{path}"), value)
            .unwrap_or_else(|error| panic!("set net/{path} = {value}: {error}"));
    }
    let ipv6 = "/proc/sys/net/ipv6/conf/all/forwarding";
    if std::path::Path::new(ipv6).exists() {
        std::fs::write(ipv6, "1").expect("set IPv6 forwarding");
    }
}

#[test]
fn prepare_and_drop_the_private_ingress() {
    if std::env::var_os("DAER_NETNS_TEST").is_none() {
        eprintln!(
            "skipping: set DAER_NETNS_TEST=1 in a disposable namespace; this test owns \
             daer0ns and daer0/daer0peer"
        );
        return;
    }
    set_host_prerequisites();

    // Started before `prepare` unshares the mount namespace, so this process stays in the
    // host mount namespace. `/proc/<pid>/root/run/netns` is therefore the host view: it must
    // never see the private mount, even while the ingress is alive.
    let mut host_view = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn the host-view process");
    let host_namespace = format!("/proc/{}/root/run/netns/daer0ns", host_view.id());

    let ingress = daer_control::PreparedIngress::prepare().expect("prepare the ingress");
    assert!(
        std::path::Path::new("/run/netns/daer0ns").exists(),
        "the named namespace mount must exist inside the daemon's mount namespace"
    );
    assert!(
        !std::path::Path::new(&host_namespace).exists(),
        "the namespace mount must be private to the daemon, but the host sees {host_namespace}"
    );
    let _ = host_view.kill();
    let _ = host_view.wait();
    assert!(
        !daer_control::datapath::interface_exists("daer0peer"),
        "the peer must have moved out of the host namespace"
    );
    let peer_link = std::process::Command::new("ip")
        .args(["-n", "daer0ns", "-o", "link", "show", "dev", "daer0peer"])
        .output()
        .expect("ip link show");
    let peer_link = String::from_utf8_lossy(&peer_link.stdout);
    let peer_mac = ingress
        .peer_mac
        .iter()
        .map(|octet| format!("{octet:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    assert!(
        peer_link.contains(&peer_mac),
        "the MAC captured for PARAM must be the peer's MAC in daer0ns: {peer_link}"
    );

    let host_rules = std::process::Command::new("ip")
        .args(["rule", "show"])
        .output()
        .expect("ip rule show");
    let host_rules = String::from_utf8_lossy(&host_rules.stdout);
    assert!(
        !host_rules.contains("table 2023"),
        "the host must not keep a table-2023 rule: {host_rules}"
    );

    let routes = daer_control::datapath::RouteTable::install(&ingress.namespace)
        .expect("install policy routing");
    let rules = std::process::Command::new("ip")
        .args(["-n", "daer0ns", "-4", "rule", "show"])
        .output()
        .expect("ip rule show");
    let rules = String::from_utf8_lossy(&rules.stdout);
    assert!(rules.contains("iif daer0peer"), "{rules}");
    assert!(
        !rules.contains("fwmark"),
        "a mark-keyed rule would capture marked listener replies: {rules}"
    );

    let route_output = std::process::Command::new("ip")
        .args(["-n", "daer0ns", "route", "show"])
        .output()
        .expect("ip route show");
    let route_text = String::from_utf8_lossy(&route_output.stdout);
    assert!(
        route_text.contains("default via 169.254.0.1"),
        "the peer needs a return route: {route_text}"
    );

    drop(routes);
    drop(ingress);

    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if !std::path::Path::new("/run/netns/daer0ns").exists()
            && !daer_control::datapath::interface_exists("daer0")
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !std::path::Path::new("/run/netns/daer0ns").exists(),
        "dropping the guard must remove the named namespace"
    );
    assert!(
        !daer_control::datapath::interface_exists("daer0"),
        "the host veth end must be freed with its peer"
    );
}

/// The listener is created by `Daemon::bind_in`, not by a host-side `bind`.
///
/// A direct loopback connection from inside `daer0ns` proves the socket is reachable there.
/// It does not prove `bpf_sk_assign` delivery; that needs the privileged datapath e2e.
#[tokio::test(flavor = "current_thread")]
async fn the_transparent_listener_binds_inside_the_namespace() {
    if std::env::var_os("DAER_NETNS_TEST").is_none() {
        eprintln!("skipping: set DAER_NETNS_TEST=1 in a disposable namespace");
        return;
    }
    set_host_prerequisites();

    let ingress = daer_control::PreparedIngress::prepare().expect("prepare the ingress");
    let config = daer_config::toml_config::load_str(
        "schema = 2\n\
         [global]\n\
         wan-interface = [\"lo\"]\n\
         lan-interface = [\"lo\"]\n\
         disable-waiting-network = true\n\
         [routing]\n\
         rules = []\n\
         fallback = \"direct\"\n",
    )
    .expect("minimal config");
    let options = daer_control::RouterOptions::for_config("netns_lifecycle.toml");
    let daemon = daer_control::Daemon::bind_in(&config, &options, Some(ingress))
        .expect("bind inside the namespace");
    let port = daemon.port;
    let ingress = daemon.ingress().expect("the daemon owns its ingress");

    let connected = ingress
        .namespace
        .with(|| std::net::TcpStream::connect(("127.0.0.1", port)))
        .expect("enter the namespace")
        .expect("connect to the listener from inside daer0ns");
    drop(connected);
    // The v6 listener is a separate fd, because a transparent v4 socket cannot serve a v6
    // flow. Reachability from inside the namespace proves it was bound there too, not in the
    // host namespace where `bpf_sk_assign` could not deliver to it.
    let connected6 = ingress
        .namespace
        .with(|| std::net::TcpStream::connect(("::1", port)))
        .expect("enter the namespace")
        .expect("connect to the IPv6 listener from inside daer0ns");
    drop(connected6);
    drop(daemon);
}
