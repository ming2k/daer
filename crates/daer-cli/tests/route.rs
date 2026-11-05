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
    "domain(suffix: 'bilibili.com') -> direct",
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
    assert!(out_str.contains("decided by : domain(suffix: bilibili.com) -> direct"));
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
