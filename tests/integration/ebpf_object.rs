// SPDX-License-Identifier: AGPL-3.0-only

//! Checks the compiled datapath object against the names and ABI this crate
//! references.
//!
//! The object is built by `cargo xtask ebpf`. Without it
//! these tests skip rather than fail, so `cargo test` stays usable on a machine
//! that has no kernel headers.

use std::collections::HashSet;
use std::path::PathBuf;

use aya_obj::Object;

fn object_path() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("DAER_EBPF_OBJECT") {
        let path = PathBuf::from(path);
        return path.is_file().then_some(path);
    }
    let path = crate::common::workspace_path("target/ebpf/datapath.bpf.o");
    path.is_file().then_some(path)
}

fn parsed_object() -> Option<Object> {
    let path = object_path()?;
    let bytes = std::fs::read(&path).expect("reads the compiled object");
    // No rewriting step: the loader hands these bytes to `aya` unchanged (ADR-0020),
    // and so does this test.
    Some(Object::parse(&bytes).expect("the compiled object is a valid eBPF ELF"))
}

/// Every program's section is one `aya` parses natively, with no rewriting.
///
/// This is the ADR-0020 red line: the C source spells sections the way `aya` wants
/// (`classifier/<name>`, `cgroup/<hook>`), so the loader has nothing to normalize. If
/// this fails, someone reintroduced a spelling that needs repair — and the previous
/// repair step is what dropped every program's `func_info` and made the kernel reject
/// the load.
#[test]
fn every_program_section_is_one_aya_parses() {
    let Some(path) = object_path() else {
        eprintln!("skipping: run `cargo xtask ebpf` to build target/ebpf/datapath.bpf.o");
        return;
    };
    let bytes = std::fs::read(&path).expect("reads the compiled object");
    let object = Object::parse(&bytes).expect("the compiled object is a valid eBPF ELF");
    for name in daer_ebpf::names::program::ALL {
        let program = object
            .programs
            .get(name)
            .unwrap_or_else(|| panic!("missing program {name}"));
        // Parsing succeeded, which is the property under test: `ProgramSection::from_str`
        // rejects `tc/<name>` and unknown `sk_skb/` spellings outright.
        let _ = program.section;
    }
}

#[test]
fn object_contains_every_map_we_reference() {
    let Some(object) = parsed_object() else {
        eprintln!("skipping: run `cargo xtask ebpf` to build target/ebpf/datapath.bpf.o");
        return;
    };
    for name in daer_ebpf::names::map::ALL {
        assert!(object.maps.contains_key(name), "missing map {name}");
    }
}

#[test]
fn the_listener_map_is_a_sockmap_with_fd_sized_values() {
    let Some(object) = parsed_object() else {
        eprintln!("skipping: run `cargo xtask ebpf` to build target/ebpf/datapath.bpf.o");
        return;
    };
    let map = &object.maps[daer_ebpf::names::map::LISTEN_SOCKET];
    assert_eq!(
        map.map_type(),
        aya_obj::generated::bpf_map_type::BPF_MAP_TYPE_SOCKMAP as u32,
        "listen_socket_map must stay a SOCKMAP; bpf_sk_assign looks sockets up there"
    );
    assert_eq!(map.key_size(), 4, "SOCKMAP keys are family u32 values");
    assert_eq!(
        map.value_size(),
        4,
        "SOCKMAP values are socket fds (`int`), not u64; aya and the kernel both reject an 8-byte value"
    );
    assert_eq!(
        map.max_entries(),
        4,
        "listen_socket_map needs one slot per (protocol, family): tcp4, udp4, tcp6, udp6"
    );
}

#[test]
fn object_contains_every_program_we_reference() {
    let Some(object) = parsed_object() else {
        eprintln!("skipping: run `cargo xtask ebpf` to build target/ebpf/datapath.bpf.o");
        return;
    };
    for name in daer_ebpf::names::program::ALL {
        assert!(object.programs.contains_key(name), "missing program {name}");
        let prog = &object.programs[name];
        let func = &object.functions[&prog.function_key()];
        assert!(
            !func.func_info.func_info.is_empty(),
            "program {name} lost its BTF func_info"
        );
    }
}

/// The invariant the kernel enforces at `BPF_PROG_LOAD` time.
///
/// `check_btf_func()` in `kernel/bpf/check_btf.c` rejects a program whose first
/// `func_info` record is not at instruction offset 0:
///
/// ```text
/// nonzero insn_off 3 for the first func info record
/// ```
///
/// That is exactly the failure this test exists to catch, and it can only be
/// observed *after* aya links `.text` callees into the program: the linker appends
/// each callee's instructions (starting at instruction `N > 0`) and then appends
/// that callee's `func_info` rebased to `N`. If the program's own `func_info` was
/// dropped during parsing, the first surviving record is the callee's at `N`, and
/// the kernel refuses the load with `EINVAL`.
///
/// Dropping it is what happens when the ELF section names and the `.BTF` string
/// table disagree: aya keys `btf_ext.func_info` by the name it reads out of `.BTF`,
/// then looks it up by the *ELF* section name. Renaming only the ELF sections
/// leaves the lookup empty and silently loses the entry.
///
/// The check runs unprivileged because it stops just short of the syscall: it
/// reproduces aya's own relocation step (`relocate_calls`, fed the same
/// `text_sections` set that `aya::bpf` builds) and then asserts the invariant.
fn assert_programs_survive_call_relocation(object: &mut Object, source: &str) {
    // Mirrors aya::bpf: every section that holds a function is a "text" section.
    let text_sections: HashSet<usize> = object
        .functions
        .keys()
        .map(|(section_index, _)| *section_index)
        .collect();
    // Map relocations need real fds, so only the call relocation runs here; that is
    // the step that corrupts `func_info`.
    object
        .relocate_calls(&text_sections)
        .unwrap_or_else(|error| panic!("{source}: call relocation failed: {error}"));

    for name in daer_ebpf::names::program::ALL {
        let Some(program) = object.programs.get(name) else {
            panic!("{source}: missing program {name}");
        };
        let function = &object.functions[&program.function_key()];
        let records = &function.func_info.func_info;

        assert!(
            !records.is_empty(),
            "{source}: program {name} has no func_info, so the kernel will reject the load \
             with \"nonzero insn_off ... for the first func info record\""
        );
        assert_eq!(
            records[0].insn_off, 0,
            "{source}: program {name} has its first func_info at instruction {} instead of 0; \
             the kernel rejects this with EINVAL",
            records[0].insn_off
        );
    }
}

#[test]
fn every_program_keeps_a_verifier_legal_func_info_after_linking() {
    let Some(mut object) = parsed_object() else {
        eprintln!("skipping: run `cargo xtask ebpf` to build target/ebpf/datapath.bpf.o");
        return;
    };
    assert_programs_survive_call_relocation(&mut object, "compiled object");
}

#[test]
fn object_is_licensed_for_the_kernel() {
    let Some(object) = parsed_object() else {
        eprintln!("skipping: run `cargo xtask ebpf` to build target/ebpf/datapath.bpf.o");
        return;
    };
    // GPL-compatible helpers (bpf_loop, bpf_get_current_task) require this.
    let license = object.license.to_string_lossy();
    assert!(license.contains("GPL"), "unexpected license: {license}");
}

#[test]
fn param_layout_is_what_the_c_struct_expects() {
    // Kept next to the object checks: both guard the same boundary.
    assert_eq!(std::mem::size_of::<daer_ebpf::RuntimeParam>(), 28);
    let param = daer_ebpf::RuntimeParam::default();
    assert_eq!(param.as_bytes().len(), 28);
}
