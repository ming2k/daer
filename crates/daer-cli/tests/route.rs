// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("daer-cli-route-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("creates temp dir");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn daer_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_daer"))
}

#[test]
fn route_cli_resolves_domain_and_ip() {
    let temp_dir = TempDir::new("route-test");
    let config_path = temp_dir.path().join("config.toml");

    let toml = r#"
[routing]
rules = [
    "domain(bilibili.com) -> direct",
    "ip(1.1.1.1) -> direct",
    "dport(443) -> block",
]
fallback = "direct"
"#;
    fs::write(&config_path, toml).expect("writes config.toml");

    // 1. Single domain argument: daer route bilibili.com
    let out = daer_cmd()
        .args(["route", "bilibili.com", "-c", config_path.to_str().unwrap()])
        .output()
        .expect("runs daer route domain");
    assert!(out.status.success(), "daer route bilibili.com must succeed");
    let out_str = String::from_utf8(out.stdout).unwrap();
    assert!(out_str.contains("decided by : domain(bilibili.com) -> direct"));
    assert!(out_str.contains("outbound   : direct"));

    // 2. Single IP argument: daer route 1.1.1.1
    let out_ip = daer_cmd()
        .args(["route", "1.1.1.1", "-c", config_path.to_str().unwrap()])
        .output()
        .expect("runs daer route IP");
    assert!(out_ip.status.success(), "daer route 1.1.1.1 must succeed");
    let ip_str = String::from_utf8(out_ip.stdout).unwrap();
    assert!(ip_str.contains("decided by : ip(1.1.1.1) -> direct"));

    // 3. Blocked route: daer route 8.8.8.8:443
    let out_block = daer_cmd()
        .args(["route", "8.8.8.8:443", "-c", config_path.to_str().unwrap()])
        .output()
        .expect("runs daer route blocked");
    assert!(
        !out_block.status.success(),
        "blocked route must exit non-zero"
    );

    // 4. Backward-compatible 4-tuple call: daer route 10.0.0.1:1234 1.1.1.1:80
    let out_four = daer_cmd()
        .args([
            "route",
            "10.0.0.1:1234",
            "1.1.1.1:80",
            "-c",
            config_path.to_str().unwrap(),
        ])
        .output()
        .expect("runs daer route 4-tuple");
    assert!(out_four.status.success());
    let four_str = String::from_utf8(out_four.stdout).unwrap();
    assert!(four_str.contains("10.0.0.1:1234 → 1.1.1.1:80"));

    // 5. Old `daer explain` verb fails cleanly with migration guide
    let out_explain = daer_cmd()
        .args(["explain", "bilibili.com"])
        .output()
        .expect("runs daer explain");
    assert!(
        !out_explain.status.success(),
        "`daer explain` must fail cleanly"
    );
    let err_str = String::from_utf8_lossy(&out_explain.stderr);
    assert!(err_str.contains("daer route <TARGET>"));

    // 6. `daer probe node` for direct node succeeds
    let out_probe_direct = daer_cmd()
        .args([
            "probe",
            "node",
            "direct",
            "-c",
            config_path.to_str().unwrap(),
        ])
        .output()
        .expect("runs daer probe node direct");
    assert!(
        out_probe_direct.status.success(),
        "probe node direct must succeed"
    );
    let probe_str = String::from_utf8(out_probe_direct.stdout).unwrap();
    assert!(probe_str.contains("probing node: direct"));
    assert!(probe_str.contains("verdict         : ok"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_url_resolves_and_probes_endpoint() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds mock listener");
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = [0u8; 512];
            let _ = socket.read(&mut buf).await;
            let _ = socket.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await;
        }
    });

    let out = daer_cmd()
        .args(["probe", "url", &format!("http://127.0.0.1:{port}/")])
        .output()
        .expect("runs daer probe url");
    assert!(out.status.success(), "daer probe url must succeed");
    let out_str = String::from_utf8(out.stdout).unwrap();
    assert!(out_str.contains("http probe     : ok"));
    assert!(out_str.contains("verdict        : reachable"));
}

#[test]
fn probe_node_supports_direct_link() {
    let out = daer_cmd()
        .args(["probe", "node", "direct://local#test-direct"])
        .output()
        .expect("runs daer probe node direct link");
    assert!(out.status.success(), "probe node direct link must succeed");
    let out_str = String::from_utf8(out.stdout).unwrap();
    assert!(out_str.contains("probing node: test-direct [direct]"));
    assert!(out_str.contains("verdict         : ok"));
}

#[test]
fn probe_supports_direct_command_link() {
    let out = daer_cmd()
        .args(["probe", "direct://local#test-direct"])
        .output()
        .expect("runs daer probe link");
    assert!(out.status.success(), "probe link must succeed");
    let out_str = String::from_utf8(out.stdout).unwrap();
    assert!(out_str.contains("probing node: test-direct [direct]"));
    assert!(out_str.contains("verdict         : ok"));
}

/// The LINK shortcut takes a link and nothing else. Given a flag it must name the verb that
/// does take flags rather than treat the flag as part of a node name.
#[test]
fn the_link_shortcut_refuses_flags_and_names_the_verb() {
    // Trailing flags reach the shortcut (clap hands everything after the external
    // subcommand's word through), which is exactly the case that could be misread as a
    // node named `vless://… -t 10`.
    let out = daer_cmd()
        .args(["probe", "direct://local#test-direct", "-t", "10"])
        .output()
        .expect("runs daer probe with a trailing flag");
    assert!(
        !out.status.success(),
        "a flag on the shortcut must fail: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("daer probe node <NODE>"),
        "the error must name the verb that takes flags, got: {err}"
    );
}

/// A subscription file is probed through the same decoder the daemon uses, so a file that
/// works here is the file the runtime would load. `direct://` proves the whole path without
/// needing the network: a node that requires no remote probe still reports its verdict.
#[test]
fn probe_file_probes_every_node_it_decodes() {
    let temp = TempDir::new("probe-file");
    let plain = temp.path().join("sub.txt");
    fs::write(
        &plain,
        "direct://local#first\n# a comment\ndirect://local#second\n",
    )
    .expect("writes the plain subscription");

    let out = daer_cmd()
        .args(["probe", "node", "--file", plain.to_str().unwrap()])
        .output()
        .expect("runs daer probe node --file");
    assert!(
        out.status.success(),
        "every node in the file is direct and must pass: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("2 node(s), format Plain"), "{stdout}");
    assert!(stdout.contains("probing node: first"), "{stdout}");
    assert!(stdout.contains("probing node: second"), "{stdout}");
    assert!(stdout.contains("2 of 2 node(s) operational"), "{stdout}");

    // The same list base64-wrapped: `daer` decodes subscriptions in both forms, so the probe
    // has to accept both or it disagrees with the loader (INV-LOADER-01).
    let wrapped = temp.path().join("sub.b64");
    let body = base64("direct://local#first\ndirect://local#second\n");
    fs::write(&wrapped, body).expect("writes the base64 subscription");
    let out = daer_cmd()
        .args(["probe", "node", "--file", wrapped.to_str().unwrap()])
        .output()
        .expect("runs daer probe node --file on base64");
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("2 node(s), format Base64"), "{stdout}");
}

/// A file whose nodes are all unreadable is a failure that says so, not an empty success.
#[test]
fn a_subscription_with_no_usable_node_fails_and_says_why() {
    let temp = TempDir::new("probe-file-empty");
    let path = temp.path().join("sub.txt");
    fs::write(&path, "vless://not-a-uuid@127.0.0.1:1#broken\n").expect("writes the file");

    let out = daer_cmd()
        .args(["probe", "node", "--file", path.to_str().unwrap()])
        .output()
        .expect("runs daer probe node --file");
    assert!(!out.status.success(), "an unusable list must exit non-zero");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("no usable node"), "got: {err}");
}

/// Naming two sources of nodes has three different readings, so it is refused rather than
/// guessed. Silently honouring one would make the other argument a no-op the operator
/// believed had taken effect.
#[test]
fn naming_two_sources_of_nodes_is_refused() {
    let temp = TempDir::new("probe-ambiguous");
    let config = temp.path().join("config.toml");
    fs::write(
        &config,
        "schema = 2\n\
         [[node]]\nname = \"n\"\ntype = \"direct\"\n\
         [[election]]\nname = \"g\"\nnode = \"n\"\ntype = \"manual\"\n\
         [routing]\nrules = []\nfallback = \"g\"\n",
    )
    .expect("writes config");
    let sub = temp.path().join("sub.txt");
    fs::write(&sub, "direct://local#x\n").expect("writes subscription");

    for args in [
        vec!["probe", "node", "n", "--all"],
        vec!["probe", "node", "n", "--file", sub.to_str().unwrap()],
        vec!["probe", "node", "--all", "--file", sub.to_str().unwrap()],
    ] {
        let out = daer_cmd()
            .args(&args)
            .arg("-c")
            .arg(&config)
            .output()
            .expect("runs daer probe with two sources");
        assert!(!out.status.success(), "{args:?} must be refused");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("name nodes at once"), "{args:?}: {err}");
        assert!(err.contains("Pick one"), "{args:?}: {err}");
    }
}

/// A node genuinely named `all` must still be probeable by name. Before the source was
/// tracked as a flag rather than inferred from the word, `probe node all` probed the whole
/// configuration and the node called `all` could never be reached.
#[test]
fn a_node_named_all_is_probeable_by_name() {
    let temp = TempDir::new("probe-named-all");
    let config = temp.path().join("config.toml");
    fs::write(
        &config,
        "schema = 2\n\
         [[node]]\nname = \"all\"\ntype = \"direct\"\n\
         [[node]]\nname = \"other\"\ntype = \"direct\"\n\
         [[election]]\nname = \"g\"\nnode = \"all\"\ntype = \"manual\"\n\
         [routing]\nrules = []\nfallback = \"g\"\n",
    )
    .expect("writes config");

    let out = daer_cmd()
        .args(["probe", "node", "all", "-c"])
        .arg(&config)
        .output()
        .expect("runs daer probe node all");
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        stdout.matches("probing node:").count(),
        1,
        "`all` is a node here, not a keyword: {stdout}"
    );
    assert!(stdout.contains("probing node: all [direct]"), "{stdout}");
}

/// A whole pool is probed concurrently, the way the daemon's health scheduler drives it, so
/// the cost is one probe timeout rather than one per node.
///
/// The falsifier is the elapsed time: five addresses in `192.0.2.0/24` (TEST-NET-1, which
/// never answers) at a one-second timeout must finish in about one second. A serial
/// implementation takes about five, so this test fails if the join is ever reverted.
#[test]
fn a_pool_is_probed_concurrently_not_one_after_another() {
    let temp = TempDir::new("probe-concurrency");
    let path = temp.path().join("sub.txt");
    let mut body = String::new();
    for index in 0..5 {
        body.push_str(&format!(
            "vless://2aec6a09-fb60-4461-9f28-ff6ccd184824@192.0.2.{}:443\
             ?security=reality&sni=example.com\
             &pbk=1qA2ff-bTrVm4R-UAkRa6GGI5Dd_OrNDAELO1pxXVjI&sid=d9#dead{index}\n",
            index + 1
        ));
    }
    fs::write(&path, body).expect("writes subscription");

    let started = std::time::Instant::now();
    let out = daer_cmd()
        .args(["probe", "node", "--file", path.to_str().unwrap(), "-t", "1"])
        .output()
        .expect("runs daer probe node --file");
    let elapsed = started.elapsed();

    assert!(!out.status.success(), "every node here is unreachable");
    assert!(
        elapsed < std::time::Duration::from_secs(3),
        "5 unreachable nodes at a 1s timeout took {elapsed:?}; a serial loop takes ~5s"
    );

    // The report still names every node, in configuration order, so concurrency did not cost
    // the operator the mapping from line to result.
    let stdout = String::from_utf8(out.stdout).unwrap();
    let order: Vec<&str> = stdout
        .lines()
        .filter(|line| line.starts_with("probing node:"))
        .collect();
    assert_eq!(order.len(), 5, "{stdout}");
    for (index, line) in order.iter().enumerate() {
        assert!(
            line.contains(&format!("dead{index}")),
            "report is out of order at {index}: {stdout}"
        );
    }
}

/// The link a diagnostic prints must not be a credential. `tuic://user:secret@host` carries
/// its password in the userinfo, and this build cannot parse it, so the raw link is the only
/// thing it knows about the node — and it must not be echoed.
#[test]
fn a_link_this_build_cannot_parse_is_redacted_before_it_is_printed() {
    let temp = TempDir::new("probe-redaction");
    let path = temp.path().join("sub.txt");
    fs::write(&path, "tuic://user:hunter2@192.0.2.1:443#t\n").expect("writes subscription");

    let out = daer_cmd()
        .args(["probe", "node", "--file", path.to_str().unwrap(), "-t", "1"])
        .output()
        .expect("runs daer probe node --file");

    let printed = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !printed.contains("hunter2"),
        "a password reached the output: {printed}"
    );
    assert!(printed.contains("tuic://<redacted>"), "{printed}");
}

/// Standard base64 with padding, which is what every subscription provider emits.
fn base64(text: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = text.as_bytes();
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(n >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

#[test]
fn route_supports_symbolic_exact_domain_match() {
    let temp_dir = TempDir::new("route-symbolic-test");
    let config_path = temp_dir.path().join("config.toml");

    let toml = r#"
[routing]
rules = [
    "domain(=auth.example.com) -> direct",
    "domain(example.com) -> block",
]
fallback = "direct"
"#;
    fs::write(&config_path, toml).expect("writes config.toml");

    let out_exact = daer_cmd()
        .args([
            "route",
            "auth.example.com",
            "-c",
            config_path.to_str().unwrap(),
        ])
        .output()
        .expect("runs daer route auth.example.com");
    assert!(out_exact.status.success());
    let str_exact = String::from_utf8(out_exact.stdout).unwrap();
    assert!(str_exact.contains("outbound   : direct"));

    // `=auth.example.com` must NOT match a subdomain; it falls through to `example.com`
    // suffix -> block, which is a non-actionable verdict (exit 1).
    let out_other = daer_cmd()
        .args([
            "route",
            "sub.auth.example.com",
            "-c",
            config_path.to_str().unwrap(),
        ])
        .output()
        .expect("runs daer route sub.auth.example.com");
    assert!(!out_other.status.success(), "blocked flows exit 1");
    let str_other = String::from_utf8(out_other.stdout).unwrap();
    assert!(str_other.contains("outbound   : block"));
}
