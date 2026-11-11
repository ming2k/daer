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
//! that survives drop, or a host veth end that is not freed with its peer.

use std::time::{Duration, Instant};

#[test]
fn prepare_and_drop_the_private_ingress() {
    if std::env::var_os("DAER_NETNS_TEST").is_none() {
        eprintln!(
            "skipping: set DAER_NETNS_TEST=1 in a disposable namespace; this test owns \
             daer0ns and daer0/daer0peer"
        );
        return;
    }

    let ingress = daer_control::PreparedIngress::prepare().expect("prepare the ingress");
    assert!(
        std::path::Path::new("/run/netns/daer0ns").exists(),
        "the named namespace mount must exist"
    );
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

    let ingress = daer_control::PreparedIngress::prepare().expect("prepare the ingress");
    let port = 30_000 + (std::process::id() % 20_000) as u16;
    let config = daer_config::toml_config::load_str(&format!(
        "schema = 1\n\
         [global]\n\
         tproxy-port = {port}\n\
         wan-interface = [\"lo\"]\n\
         lan-interface = [\"lo\"]\n\
         disable-waiting-network = true\n\
         [routing]\n\
         rules = []\n\
         fallback = \"direct\"\n"
    ))
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
    drop(daemon);
}
