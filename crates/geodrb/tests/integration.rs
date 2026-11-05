// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("geodrb-test-{name}-{}", std::process::id()));
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

fn geodrb_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_geodrb"))
}

#[test]
fn compile_inspect_and_test_workflow() {
    let temp_dir = TempDir::new("compile-test");
    let rules_path = temp_dir.path().join("test.rules");
    let drb_path = temp_dir.path().join("test.drb");

    let rule_content = r#"
name: my-test-rules

# CIDR intervals
ip: 192.168.1.0/24
ip: 10.0.0.0/8

# Domain patterns
full: login.example.com
suffix: example.com
keyword: internal
regex: ^.*\.corp\.local$
"#;

    fs::write(&rules_path, rule_content).expect("rules written");

    // 1. geodrb compile
    let compile_status = geodrb_cmd()
        .args([
            "compile",
            rules_path.to_str().unwrap(),
            "-o",
            drb_path.to_str().unwrap(),
        ])
        .status()
        .expect("runs geodrb compile");
    assert!(compile_status.success(), "compile must succeed");

    // 2. geodrb inspect
    let inspect_out = geodrb_cmd()
        .args(["inspect", drb_path.to_str().unwrap()])
        .output()
        .expect("runs geodrb inspect");
    assert!(inspect_out.status.success(), "inspect must succeed");
    let inspect_str = String::from_utf8(inspect_out.stdout).expect("utf8 inspect");
    assert!(inspect_str.contains("name:             my-test-rules"));
    assert!(inspect_str.contains("v4 intervals:     2"));
    assert!(inspect_str.contains("total domains:    4"));

    // 3. geodrb test - IP matches
    let test_ip = geodrb_cmd()
        .args(["test", drb_path.to_str().unwrap(), "192.168.1.100"])
        .output()
        .expect("runs test IP");
    assert!(test_ip.status.success(), "IP 192.168.1.100 should match");
    let test_ip_str = String::from_utf8(test_ip.stdout).expect("utf8 test output");
    assert!(test_ip_str.contains("matched: 192.168.1.100"));
    assert!(test_ip_str.contains("prefix 192.168.1.0/24"));

    // 4. geodrb test - IP does not match
    let test_ip_fail = geodrb_cmd()
        .args(["test", drb_path.to_str().unwrap(), "172.16.0.1"])
        .output()
        .expect("runs test IP fail");
    assert!(!test_ip_fail.status.success(), "IP 172.16.0.1 should fail");

    // 5. geodrb test - Domain full match
    let test_dom_full = geodrb_cmd()
        .args(["test", drb_path.to_str().unwrap(), "login.example.com"])
        .output()
        .expect("runs test domain full");
    assert!(test_dom_full.status.success());
    let full_str = String::from_utf8(test_dom_full.stdout).unwrap();
    assert!(full_str.contains("matched: login.example.com"));

    // 6. geodrb test - Domain suffix match
    let test_dom_suffix = geodrb_cmd()
        .args(["test", drb_path.to_str().unwrap(), "sub.example.com"])
        .output()
        .expect("runs test domain suffix");
    assert!(test_dom_suffix.status.success());

    // 7. geodrb test - Domain keyword match
    let test_dom_kw = geodrb_cmd()
        .args([
            "test",
            drb_path.to_str().unwrap(),
            "portal-internal-app.com",
        ])
        .output()
        .expect("runs test domain keyword");
    assert!(test_dom_kw.status.success());

    // 8. geodrb test - Domain regex match
    let test_dom_re = geodrb_cmd()
        .args(["test", drb_path.to_str().unwrap(), "srv01.corp.local"])
        .output()
        .expect("runs test domain regex");
    assert!(test_dom_re.status.success());

    // 9. geodrb test - Domain does not match
    let test_dom_fail = geodrb_cmd()
        .args(["test", drb_path.to_str().unwrap(), "google.com"])
        .output()
        .expect("runs test domain fail");
    assert!(
        !test_dom_fail.status.success(),
        "google.com should not match"
    );
}

fn length_delimited(number: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![(number << 3) | 2, payload.len() as u8];
    out.extend_from_slice(payload);
    out
}

#[test]
fn convert_mock_dat_files() {
    let temp_dir = TempDir::new("convert-test");

    // 1. Mock geoip.dat
    let mut geoip_entry = length_delimited(1, b"CN");
    let mut cidr_message = length_delimited(1, &[1, 2, 3, 0]);
    cidr_message.extend_from_slice(&[0x10, 24]); // prefix 24
    geoip_entry.extend_from_slice(&length_delimited(2, &cidr_message));

    let geoip_dat = length_delimited(1, &geoip_entry);
    let geoip_path = temp_dir.path().join("geoip.dat");
    fs::write(&geoip_path, &geoip_dat).expect("writes geoip.dat");

    let geoip_drb_path = temp_dir.path().join("geoip-cn.drb");
    let convert_ip = geodrb_cmd()
        .args([
            "convert",
            geoip_path.to_str().unwrap(),
            "--code",
            "cn",
            "-o",
            geoip_drb_path.to_str().unwrap(),
        ])
        .output()
        .expect("runs convert geoip");
    assert!(convert_ip.status.success(), "convert geoip must succeed");

    // Test the converted geoip drb
    let test_converted_ip = geodrb_cmd()
        .args(["test", geoip_drb_path.to_str().unwrap(), "1.2.3.4"])
        .output()
        .expect("runs test converted IP");
    assert!(test_converted_ip.status.success());
    let ip_out = String::from_utf8(test_converted_ip.stdout).unwrap();
    assert!(ip_out.contains("prefix 1.2.3.0/24"));

    // 2. Mock geosite.dat
    let mut geosite_entry = length_delimited(1, b"CN");
    // domain 1: type 2 (RootDomain), value: bilibili.com
    let mut domain_msg = vec![0x08, 2]; // type = 2
    domain_msg.extend_from_slice(&length_delimited(2, b"bilibili.com"));
    geosite_entry.extend_from_slice(&length_delimited(2, &domain_msg));

    let geosite_dat = length_delimited(1, &geosite_entry);
    let geosite_path = temp_dir.path().join("geosite.dat");
    fs::write(&geosite_path, &geosite_dat).expect("writes geosite.dat");

    let geosite_drb_path = temp_dir.path().join("geosite-cn.drb");
    let convert_site = geodrb_cmd()
        .args([
            "convert",
            geosite_path.to_str().unwrap(),
            "--code",
            "cn",
            "-o",
            geosite_drb_path.to_str().unwrap(),
        ])
        .output()
        .expect("runs convert geosite");
    assert!(
        convert_site.status.success(),
        "convert geosite must succeed"
    );

    // Test the converted geosite drb
    let test_converted_site = geodrb_cmd()
        .args([
            "test",
            geosite_drb_path.to_str().unwrap(),
            "www.bilibili.com",
        ])
        .output()
        .expect("runs test converted domain");
    assert!(test_converted_site.status.success());
    let site_out = String::from_utf8(test_converted_site.stdout).unwrap();
    assert!(site_out.contains("suffix 'bilibili.com'"));
}
