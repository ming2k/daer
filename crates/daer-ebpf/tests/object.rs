// SPDX-License-Identifier: AGPL-3.0-only

//! Checks the compiled datapath object against the names and ABI this crate
//! references.
//!
//! The object is built by `make ebpf` (see `scripts/build-ebpf.sh`). Without it
//! these tests skip rather than fail, so `cargo test` stays usable on a machine
//! that has no kernel headers.

use std::path::PathBuf;

use aya_obj::Object;

fn object_path() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("DAER_EBPF_OBJECT") {
        let path = PathBuf::from(path);
        return path.is_file().then_some(path);
    }
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/ebpf/datapath.o");
    path.is_file().then_some(path)
}

fn parsed_object() -> Option<Object> {
    let path = object_path()?;
    let bytes = std::fs::read(&path).expect("reads the compiled object");
    // The upstream object is built for `ebpf-go`; the loader normalizes section
    // names before handing it to `aya`, and so does this test.
    let bytes = daer_ebpf::normalize_section_names(&bytes).expect("normalizes the object");
    Some(Object::parse(&bytes).expect("the compiled object is a valid eBPF ELF"))
}

#[test]
fn object_contains_every_map_we_reference() {
    let Some(object) = parsed_object() else {
        eprintln!("skipping: run `make ebpf` to build target/ebpf/datapath.o");
        return;
    };
    for name in daer_ebpf::names::map::ALL {
        assert!(object.maps.contains_key(name), "missing map {name}");
    }
}

#[test]
fn object_contains_every_program_we_reference() {
    let Some(object) = parsed_object() else {
        eprintln!("skipping: run `make ebpf` to build target/ebpf/datapath.o");
        return;
    };
    for name in daer_ebpf::names::program::ALL {
        assert!(object.programs.contains_key(name), "missing program {name}");
    }
}

#[test]
fn object_is_licensed_for_the_kernel() {
    let Some(object) = parsed_object() else {
        eprintln!("skipping: run `make ebpf` to build target/ebpf/datapath.o");
        return;
    };
    // GPL-compatible helpers (bpf_loop, bpf_get_current_task) require this.
    let license = object.license.to_string_lossy();
    assert!(license.contains("GPL"), "unexpected license: {license}");
}

#[test]
fn param_layout_is_what_the_c_struct_expects() {
    // Kept next to the object checks: both guard the same boundary.
    assert_eq!(std::mem::size_of::<daer_ebpf::RuntimeParam>(), 32);
    let param = daer_ebpf::RuntimeParam::default();
    assert_eq!(param.as_bytes().len(), 32);
}
