// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::Command;

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("daer-dat-test-{name}-{}", std::process::id()));
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

fn drb_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_daer-drb"))
}

fn write_varint(buf: &mut Vec<u8>, mut val: u64) {
    while val >= 0x80 {
        buf.push(((val & 0x7F) as u8) | 0x80);
        val >>= 7;
    }
    buf.push((val & 0x7F) as u8);
}

fn write_field_varint(buf: &mut Vec<u8>, field_num: u32, val: u64) {
    write_varint(buf, u64::from(field_num) << 3);
    write_varint(buf, val);
}

fn write_field_bytes(buf: &mut Vec<u8>, field_num: u32, val: &[u8]) {
    write_varint(buf, (u64::from(field_num) << 3) | 2);
    write_varint(buf, val.len() as u64);
    buf.extend_from_slice(val);
}

#[test]
fn test_dat_to_rules_and_compile_pipeline() {
    let temp = TempDir::new("dat-unpack");

    // 1. Build a synthetic geoip.dat protobuf binary
    // GeoIPList { repeated GeoIP entry = 1; }
    // GeoIP { string country_code = 1; repeated CIDR cidr = 2; }
    // CIDR { bytes ip = 1; uint32 prefix = 2; }
    let mut geoip_dat = Vec::new();

    // Entry 1: "CN"
    let mut cn_entry = Vec::new();
    write_field_bytes(&mut cn_entry, 1, b"CN");

    // CIDR 1: 198.51.100.0/24
    let mut cidr1 = Vec::new();
    let v4: Ipv4Addr = "198.51.100.0".parse().unwrap();
    write_field_bytes(&mut cidr1, 1, &v4.octets());
    write_field_varint(&mut cidr1, 2, 24);
    write_field_bytes(&mut cn_entry, 2, &cidr1);

    // CIDR 2: 2001:db8::/32
    let mut cidr2 = Vec::new();
    let v6: Ipv6Addr = "2001:db8::".parse().unwrap();
    write_field_bytes(&mut cidr2, 1, &v6.octets());
    write_field_varint(&mut cidr2, 2, 32);
    write_field_bytes(&mut cn_entry, 2, &cidr2);

    write_field_bytes(&mut geoip_dat, 1, &cn_entry);

    let geoip_path = temp.path().join("geoip.dat");
    fs::write(&geoip_path, &geoip_dat).expect("writes geoip.dat");

    // 2. Build a synthetic geosite.dat protobuf binary
    // GeoSiteList { repeated SiteGroup entry = 1; }
    // SiteGroup { string tag = 1; repeated Domain domain = 2; }
    // Domain { Type type = 1; string value = 2; repeated Attribute attribute = 3; }
    // Type: 0=Plain, 1=Regex, 2=RootDomain, 3=Full
    // Attribute { string key = 1; }
    let mut geosite_dat = Vec::new();

    let mut site_entry = Vec::new();
    write_field_bytes(&mut site_entry, 1, b"CN");

    // Domain 1: RootDomain (2) = "baidu.com" with attribute "cn"
    let mut d1 = Vec::new();
    write_field_varint(&mut d1, 1, 2); // RootDomain
    write_field_bytes(&mut d1, 2, b"baidu.com");
    let mut a1 = Vec::new();
    write_field_bytes(&mut a1, 1, b"cn");
    write_field_bytes(&mut d1, 3, &a1);
    write_field_bytes(&mut site_entry, 2, &d1);

    // Domain 2: Full (3) = "login.qq.com"
    let mut d2 = Vec::new();
    write_field_varint(&mut d2, 1, 3); // Full
    write_field_bytes(&mut d2, 2, b"login.qq.com");
    write_field_bytes(&mut site_entry, 2, &d2);

    // Domain 3: Plain (0) = "ads" (should be skipped with notice)
    let mut d3 = Vec::new();
    write_field_varint(&mut d3, 1, 0); // Plain
    write_field_bytes(&mut d3, 2, b"ads");
    write_field_bytes(&mut site_entry, 2, &d3);

    write_field_bytes(&mut geosite_dat, 1, &site_entry);

    let geosite_path = temp.path().join("geosite.dat");
    fs::write(&geosite_path, &geosite_dat).expect("writes geosite.dat");

    let script_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("scripts")
        .join("rules")
        .join("dat_to_rules.py");
    assert!(
        script_path.is_file(),
        "script must exist at {}",
        script_path.display()
    );

    // 3. Test unpacking geoip.dat
    let cn_ip_rules = temp.path().join("cn-ip.rules");
    let unpack_geoip_status = Command::new("python3")
        .args([
            script_path.to_str().unwrap(),
            "--kind",
            "geoip",
            "--dat",
            geoip_path.to_str().unwrap(),
            "--code",
            "cn",
            "-o",
            cn_ip_rules.to_str().unwrap(),
        ])
        .status()
        .expect("runs dat_to_rules for geoip");
    assert!(unpack_geoip_status.success());

    let rules_text = fs::read_to_string(&cn_ip_rules).unwrap();
    assert!(rules_text.contains("name: geoip-cn"));
    assert!(rules_text.contains("198.51.100.0/24"));
    assert!(rules_text.contains("2001:db8::/32"));
    assert!(!rules_text.contains("ip:"));

    // Compile unpacked geoip rules with daer-drb
    let cn_ip_drb = temp.path().join("cn-ip.drb");
    let compile_geoip = drb_cmd()
        .args([
            "compile",
            cn_ip_rules.to_str().unwrap(),
            "-o",
            cn_ip_drb.to_str().unwrap(),
        ])
        .status()
        .expect("compile geoip drb");
    assert!(compile_geoip.success());

    // Test IP lookups against compiled drb
    assert!(
        drb_cmd()
            .args(["test", cn_ip_drb.to_str().unwrap(), "198.51.100.50"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        drb_cmd()
            .args(["test", cn_ip_drb.to_str().unwrap(), "2001:db8::1"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        !drb_cmd()
            .args(["test", cn_ip_drb.to_str().unwrap(), "8.8.8.8"])
            .status()
            .unwrap()
            .success()
    );

    // 4. Test unpacking geosite.dat
    let cn_rules = temp.path().join("cn.rules");
    let unpack_geosite_status = Command::new("python3")
        .args([
            script_path.to_str().unwrap(),
            "--kind",
            "geosite",
            "--dat",
            geosite_path.to_str().unwrap(),
            "--code",
            "cn",
            "-o",
            cn_rules.to_str().unwrap(),
        ])
        .status()
        .expect("runs dat_to_rules for geosite");
    assert!(unpack_geosite_status.success());

    let site_text = fs::read_to_string(&cn_rules).unwrap();
    assert!(site_text.contains("name: geosite-cn"));
    assert!(site_text.contains("baidu.com"));
    assert!(!site_text.contains('@'));
    assert!(site_text.contains("=login.qq.com"));

    // Compile unpacked geosite rules with daer-drb
    let cn_drb = temp.path().join("geosite-cn.drb");
    let compile_geosite = drb_cmd()
        .args([
            "compile",
            cn_rules.to_str().unwrap(),
            "-o",
            cn_drb.to_str().unwrap(),
        ])
        .status()
        .expect("compile geosite drb");
    assert!(compile_geosite.success());

    // Test domain lookups against compiled drb
    assert!(
        drb_cmd()
            .args(["test", cn_drb.to_str().unwrap(), "news.baidu.com"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        drb_cmd()
            .args(["test", cn_drb.to_str().unwrap(), "login.qq.com"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        !drb_cmd()
            .args(["test", cn_drb.to_str().unwrap(), "qq.com"])
            .status()
            .unwrap()
            .success()
    );
}
