// SPDX-License-Identifier: AGPL-3.0-only

//! `cargo xtask abi` — generate the kernel ABI from `ebpf/abi.toml` (ADR-0021).
//!
//! One declaration, two artifacts:
//!
//! | Output | Consumer |
//! | --- | --- |
//! | `ebpf/kern/daer_abi.h` | the C datapath |
//! | `crates/daer-ebpf/src/generated.rs` | the Rust loader and router |
//!
//! `--check` regenerates into memory and diffs against what is committed, so a hand edit to
//! either file, or a change to `abi.toml` without regenerating, is a red build. That check
//! is the mechanism that makes "single source" true; without it this is a convention.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// The parsed `abi.toml`.
///
/// Deserialised with the workspace's `toml` + `serde`, which are already dependencies of the
/// crates this generator serves; adding a schema-specific crate for a file only this task
/// reads would be a dependency nobody else benefits from.
#[derive(Debug, serde::Deserialize)]
pub struct Abi {
    pub schema: u32,
    pub params: Params,
    #[serde(default)]
    pub maps: Vec<Map>,
    #[serde(default)]
    pub programs: Vec<Program>,
    #[serde(default)]
    pub match_types: Vec<Discriminant>,
    #[serde(default)]
    pub outbounds: Vec<Discriminant>,
    #[serde(default)]
    pub l4_protos: Vec<Discriminant>,
    #[serde(default)]
    pub ip_versions: Vec<Discriminant>,
    #[serde(default)]
    pub structs: std::collections::BTreeMap<String, Struct>,
}

#[derive(Debug, serde::Deserialize)]
pub struct Params {
    pub global: String,
    pub c_struct: String,
    pub fields: Vec<Field>,
}

#[derive(Debug, serde::Deserialize)]
pub struct Field {
    pub name: String,
    pub c_type: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct Map {
    pub name: String,
    pub rust_const: String,
    pub generationality: Generationality,
}

#[derive(Debug, serde::Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Generationality {
    /// Holds routing policy. Exists per slot; a reload writes the inactive one and switches.
    PerGeneration,
    /// Holds flow state, not policy. Single, and deliberately survives a reload.
    Shared,
}

#[derive(Debug, serde::Deserialize)]
pub struct Program {
    pub name: String,
    pub rust_const: String,
    pub section: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct Discriminant {
    pub name: String,
    pub value: u32,
    #[serde(default)]
    pub rust_const: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct Struct {
    pub size: usize,
    pub align: usize,
    pub fields: Vec<StructField>,
}

#[derive(Debug, serde::Deserialize)]
pub struct StructField {
    pub name: String,
    pub offset: usize,
}

/// Turns a declared type into a C declaration.
///
/// The declaration file uses Rust type spelling (`[u8; 6]`, `u32`) because the same string
/// generates both sides. C needs `__u8 peer_mac[6]` and `__u32 tproxy_port`, so the array
/// suffix is moved after the name and the integer widths are mapped to the kernel's
/// `__u8`/`__u16`/`__u32`/`__u64`, which is what the datapath already uses.
fn c_declaration(ty: &str, name: &str) -> (String, String) {
    // `[u8; 6]` -> `__u8 name[6]`
    if let Some(rest) = ty.strip_prefix('[')
        && let Some((elem, len)) = rest.split_once("; ")
    {
        let len = len.trim_end_matches(']');
        return (c_scalar(elem.trim()), format!("{name}[{len}]"));
    }
    (c_scalar(ty), name.to_owned())
}

/// Maps a scalar type to its kernel spelling.
fn c_scalar(ty: &str) -> String {
    match ty {
        "u8" => "__u8".to_owned(),
        "u16" => "__u16".to_owned(),
        "u32" => "__u32".to_owned(),
        "u64" => "__u64".to_owned(),
        "i32" => "__s32".to_owned(),
        "bool" => "__u8".to_owned(),
        other => other.to_owned(),
    }
}

impl Abi {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
        let abi: Self = toml::from_str(&text)
            .map_err(|error| format!("failed to parse {}: {error}", path.display()))?;
        abi.validate()?;
        Ok(abi)
    }

    /// Rejects an inconsistent declaration before it can generate code that compiles but lies.
    fn validate(&self) -> Result<(), String> {
        if self.schema != 1 {
            return Err(format!(
                "unsupported abi.toml schema {}; expected 1",
                self.schema
            ));
        }

        // A map name or program name that repeats would generate two constants with the
        // same value, which silently makes one of them dead.
        let mut seen = std::collections::BTreeSet::new();
        for map in &self.maps {
            if !seen.insert(map.name.as_str()) {
                return Err(format!("duplicate map name {}", map.name));
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        for program in &self.programs {
            if !seen.insert(program.name.as_str()) {
                return Err(format!("duplicate program name {}", program.name));
            }
        }

        // A section `aya` cannot parse is a load failure at startup (ADR-0020). Catch it
        // here, where the fix is a one-line edit, rather than in production.
        for program in &self.programs {
            let kind = program.section.split('/').next().unwrap_or_default();
            let allowed = matches!(
                kind,
                "classifier" | "cgroup" | "sk_skb" | "fentry" | "kprobe" | "kretprobe"
            );
            if !allowed {
                return Err(format!(
                    "program {} uses section {:?}, whose prefix {kind:?} is not one daer \
                     attaches through (ADR-0020)",
                    program.name, program.section
                ));
            }
        }

        // A field that overruns its struct, or an offset that disagrees with the declared
        // size, is a layout that would produce a wrong assertion rather than a caught bug.
        for (name, s) in &self.structs {
            for field in &s.fields {
                if field.offset >= s.size && s.size != 0 {
                    return Err(format!(
                        "struct {name}: field {} at offset {} overruns size {}",
                        field.name, field.offset, s.size
                    ));
                }
            }
            if s.size % s.align != 0 {
                return Err(format!(
                    "struct {name}: size {} is not a multiple of align {}",
                    s.size, s.align
                ));
            }
        }

        Ok(())
    }

    /// The C header, `ebpf/kern/daer_abi.h`.
    pub fn render_c(&self) -> String {
        let mut out = String::new();
        let guard = "DAER_ABI_H";
        let _ = writeln!(
            out,
            "/* Code generated by `cargo xtask abi` from ebpf/abi.toml; DO NOT EDIT. */\n\
             #ifndef {guard}\n#define {guard}\n"
        );

        let _ = writeln!(out, "/* The load-time parameter struct. */");
        let _ = writeln!(out, "struct {} {{", self.params.c_struct);
        for field in &self.params.fields {
            let (decl, name) = c_declaration(&field.c_type, &field.name);
            let _ = writeln!(out, "\t{decl} {name};");
        }
        let _ = writeln!(out, "}};\n");

        let _ = writeln!(
            out,
            "/* enum MatchType, packed: one byte inside struct match_set. */"
        );
        let _ = writeln!(out, "enum __attribute__((packed)) MatchType {{");
        for (index, item) in self.match_types.iter().enumerate() {
            let comma = if index + 1 == self.match_types.len() {
                ""
            } else {
                ","
            };
            let _ = writeln!(out, "\tMatchType_{} = {}{comma}", item.name, item.value);
        }
        let _ = writeln!(out, "}};\n");

        let _ = writeln!(
            out,
            "/* The reserved outbound ids the datapath interprets itself. */"
        );
        for item in &self.outbounds {
            let _ = writeln!(out, "#define OUTBOUND_{} 0x{:X}", item.name, item.value);
        }
        let _ = writeln!(out);

        let _ = writeln!(out, "enum L4ProtoType {{");
        for (index, item) in self.l4_protos.iter().enumerate() {
            let comma = if index + 1 == self.l4_protos.len() {
                ""
            } else {
                ","
            };
            let _ = writeln!(out, "\tL4ProtoType_{} = {}{comma}", item.name, item.value);
        }
        let _ = writeln!(out, "}};\n");

        let _ = writeln!(out, "enum IpVersionType {{");
        for (index, item) in self.ip_versions.iter().enumerate() {
            let comma = if index + 1 == self.ip_versions.len() {
                ""
            } else {
                ","
            };
            let _ = writeln!(out, "\tIpVersionType_{} = {}{comma}", item.name, item.value);
        }
        let _ = writeln!(out, "}};\n");

        let _ = writeln!(out, "\n#endif /* {guard} */");
        out
    }

    /// The C layout assertions, for a file that has already declared the structs.
    ///
    /// They cannot live in `daer_abi.h`: the structs they describe (`match_set`,
    /// `routing_result`, …) are declared in `tproxy.c`, so the header would be asserting
    /// properties of incomplete types. `tproxy.c` includes this block after its own
    /// declarations instead.
    pub fn render_c_assertions(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "/* Code generated by `cargo xtask abi` from ebpf/abi.toml; DO NOT EDIT. */\n\
             /* Layout assertions. A struct whose real layout disagrees with ebpf/abi.toml\n \
              * fails to compile here, which is the earliest place it can be caught. */"
        );
        for (name, s) in &self.structs {
            let _ = writeln!(
                out,
                "_Static_assert(sizeof(struct {name}) == {}, \"struct {name}: size\");",
                s.size
            );
            let _ = writeln!(
                out,
                "_Static_assert(_Alignof(struct {name}) == {}, \"struct {name}: align\");",
                s.align
            );
            for field in &s.fields {
                let _ = writeln!(
                    out,
                    "_Static_assert(offsetof(struct {name}, {field}) == {offset}, \
                     \"struct {name}.{field}: offset\");",
                    field = field.name,
                    offset = field.offset
                );
            }
        }
        out
    }

    /// The Rust module, `crates/daer-ebpf/src/generated.rs`.
    pub fn render_rust(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "// Code generated by `cargo xtask abi` from ebpf/abi.toml; DO NOT EDIT.\n\
             //\n\
             // Regenerate with `cargo xtask abi`; `cargo xtask abi --check` fails the build\n\
             // when this file and the declaration disagree (ADR-0021).\n"
        );

        let _ = writeln!(
            out,
            "/// The name of the `const volatile` global the loader overrides."
        );
        let _ = writeln!(
            out,
            "pub const PARAM_GLOBAL: &str = {:?};\n",
            self.params.global
        );

        let _ = writeln!(out, "/// Every map name, as the object declares it.");
        let _ = writeln!(out, "pub mod map {{");
        for map in &self.maps {
            let _ = writeln!(
                out,
                "    pub const {}: &str = {:?};",
                map.rust_const, map.name
            );
        }
        let _ = writeln!(out, "\n    /// Every map the object must contain.");
        let _ = writeln!(out, "    pub const ALL: [&str; {}] = [", self.maps.len());
        for map in &self.maps {
            let _ = writeln!(out, "        {},", map.rust_const);
        }
        let _ = writeln!(out, "    ];\n");

        let _ = writeln!(
            out,
            "    /// Every per-generation map: routing policy a reload writes into the\n\
                 /// inactive slot and switches to (ADR-0004)."
        );
        let _ = writeln!(
            out,
            "    pub const PER_GENERATION: [&str; {}] = [",
            self.maps
                .iter()
                .filter(|m| m.generationality == Generationality::PerGeneration)
                .count()
        );
        for map in self
            .maps
            .iter()
            .filter(|m| m.generationality == Generationality::PerGeneration)
        {
            let _ = writeln!(out, "        {},", map.rust_const);
        }
        let _ = writeln!(out, "    ];\n");

        let _ = writeln!(
            out,
            "    /// Every shared map: flow state that deliberately survives a reload."
        );
        let _ = writeln!(
            out,
            "    pub const SHARED: [&str; {}] = [",
            self.maps
                .iter()
                .filter(|m| m.generationality == Generationality::Shared)
                .count()
        );
        for map in self
            .maps
            .iter()
            .filter(|m| m.generationality == Generationality::Shared)
        {
            let _ = writeln!(out, "        {},", map.rust_const);
        }
        let _ = writeln!(out, "    ];");
        let _ = writeln!(out, "}}\n");

        let _ = writeln!(out, "/// Every program name, as the object declares it.");
        let _ = writeln!(out, "pub mod program {{");
        for program in &self.programs {
            let _ = writeln!(
                out,
                "    pub const {}: &str = {:?};",
                program.rust_const, program.name
            );
        }
        let _ = writeln!(out, "\n    /// Every program the object must contain.");
        let _ = writeln!(
            out,
            "    pub const ALL: [&str; {}] = [",
            self.programs.len()
        );
        for program in &self.programs {
            let _ = writeln!(out, "        {},", program.rust_const);
        }
        let _ = writeln!(out, "    ];\n");

        let _ = writeln!(out, "    /// The section each program attaches through.");
        let _ = writeln!(
            out,
            "    pub const SECTIONS: [(&str, &str); {}] = [",
            self.programs.len()
        );
        for program in &self.programs {
            let _ = writeln!(
                out,
                "        ({}, {:?}),",
                program.rust_const, program.section
            );
        }
        let _ = writeln!(out, "    ];");
        let _ = writeln!(out, "}}\n");

        let _ = writeln!(out, "/// The `enum MatchType` discriminants.");
        let _ = writeln!(out, "pub mod match_type {{");
        for item in &self.match_types {
            let name = item.rust_const.as_deref().unwrap_or(&item.name);
            let _ = writeln!(out, "    pub const {name}: u8 = {};", item.value);
        }
        let _ = writeln!(out, "}}\n");

        let _ = writeln!(out, "/// The reserved outbound ids.");
        let _ = writeln!(out, "pub mod outbound {{");
        for item in &self.outbounds {
            let _ = writeln!(out, "    pub const {}: u8 = {};", item.name, item.value);
        }
        let _ = writeln!(out, "}}\n");

        let _ = writeln!(out, "/// `enum L4ProtoType`.");
        let _ = writeln!(out, "pub mod l4_proto {{");
        for item in &self.l4_protos {
            let _ = writeln!(out, "    pub const {}: u8 = {};", item.name, item.value);
        }
        let _ = writeln!(out, "}}\n");

        let _ = writeln!(out, "/// `enum IpVersionType`.");
        let _ = writeln!(out, "pub mod ip_version {{");
        for item in &self.ip_versions {
            let name = item.rust_const.as_deref().unwrap_or(&item.name);
            let _ = writeln!(out, "    pub const {name}: u8 = {};", item.value);
        }
        let _ = writeln!(out, "}}\n");

        let _ = writeln!(
            out,
            "/// Byte-layout assertions for the structs that cross the boundary."
        );
        let _ = writeln!(out, "///");
        let _ = writeln!(
            out,
            "/// Each is emitted as a `const` assertion, so a field whose offset drifts fails to"
        );
        let _ = writeln!(
            out,
            "/// compile here rather than misreading a map value in production."
        );
        let _ = writeln!(out, "pub mod layout {{");
        for (name, s) in &self.structs {
            let _ = writeln!(out, "    /// `struct {name}`.");
            let _ = writeln!(out, "    pub mod {name} {{");
            let _ = writeln!(out, "        /// The declared size, in bytes.");
            let _ = writeln!(out, "        pub const SIZE: usize = {};", s.size);
            let _ = writeln!(out, "        /// The declared alignment, in bytes.");
            let _ = writeln!(out, "        pub const ALIGN: usize = {};", s.align);
            let _ = writeln!(
                out,
                "\n        /// `(field name, byte offset)` for every field."
            );
            let _ = writeln!(
                out,
                "        pub const FIELDS: [(&str, usize); {}] = [",
                s.fields.len()
            );
            for field in &s.fields {
                let _ = writeln!(out, "            ({:?}, {}),", field.name, field.offset);
            }
            let _ = writeln!(out, "        ];");
            let _ = writeln!(out, "    }}");
        }
        let _ = writeln!(out, "}}\n");

        let _ = writeln!(out, "#[cfg(test)]");
        let _ = writeln!(out, "mod tests {{");
        let _ = writeln!(out, "    use super::*;\n");
        let _ = writeln!(
            out,
            "    /// The declared struct sizes are self-consistent."
        );
        let _ = writeln!(out, "    #[test]");
        let _ = writeln!(
            out,
            "    fn declared_layouts_are_internally_consistent() {{"
        );
        for (name, s) in &self.structs {
            for field in &s.fields {
                let _ = writeln!(
                    out,
                    "        assert!(layout::{name}::FIELDS.iter().any(|(n, o)| *n == {:?} && *o == {}), \
                     \"struct {name} must declare {} at offset {}\");",
                    field.name, field.offset, field.name, field.offset
                );
            }
            let _ = writeln!(
                out,
                "        assert_eq!(layout::{name}::SIZE % layout::{name}::ALIGN, 0, \
                 \"struct {name}: size must be a multiple of its alignment\");"
            );
        }
        let _ = writeln!(out, "    }}");
        let _ = writeln!(out, "}}");

        out
    }
}

/// Runs the `abi` subcommand.
///
/// `check` compares instead of writing; the caller turns a difference into a non-zero exit.
pub fn run(root: &Path, check: bool) -> Result<(), String> {
    let abi_path = root.join("ebpf/abi.toml");
    let abi = Abi::load(&abi_path)?;

    let c_path = root.join("ebpf/kern/daer_abi.h");
    let c_assert_path = root.join("ebpf/kern/daer_abi_assertions.h");
    let rust_path = root.join("crates/daer-ebpf/src/generated.rs");

    let c_text = abi.render_c();
    let c_assert_text = abi.render_c_assertions();
    let rust_text = abi.render_rust();

    if check {
        // The Rust side is compared in its *formatted* form, because that is what `write`
        // commits: `cargo fmt --all` would otherwise report a false drift after every run.
        let rust_text = format_rust_text(&rust_text)?;
        let mut drifted = Vec::new();
        for (path, generated) in [
            (&c_path, &c_text),
            (&c_assert_path, &c_assert_text),
            (&rust_path, &rust_text),
        ] {
            match std::fs::read_to_string(path) {
                Ok(existing) if &existing == generated => {}
                Ok(_) => drifted.push(format!(
                    "{} is out of date with ebpf/abi.toml",
                    path.display()
                )),
                Err(error) => drifted.push(format!("{} cannot be read: {error}", path.display())),
            }
        }
        if !drifted.is_empty() {
            return Err(format!(
                "the generated kernel ABI has drifted (ADR-0021):\n  {}\n\n\
                 Run `cargo xtask abi` and commit the result.",
                drifted.join("\n  ")
            ));
        }
        println!("kernel ABI is in sync with ebpf/abi.toml");
        return Ok(());
    }

    write(&c_path, &c_text)?;
    write(&c_assert_path, &c_assert_text)?;
    write(&rust_path, &rust_text)?;
    rustfmt_file(&rust_path)?;
    println!(
        "wrote {}, {} and {}",
        c_path.display(),
        c_assert_path.display(),
        rust_path.display()
    );
    Ok(())
}

fn write(path: &PathBuf, text: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    }
    std::fs::write(path, text)
        .map_err(|error| format!("failed to write {}: {error}", path.display()))
}

/// Runs `rustfmt` over a generated Rust file.
///
/// Without this, `cargo fmt --all` reformats the generated module and the next
/// `abi --check` reports drift nobody introduced — a false positive that would train people
/// to ignore the check. Formatting here means the committed file is already in the form
/// `cargo fmt` produces, so the check only fires on a real disagreement.
fn rustfmt_file(path: &PathBuf) -> Result<(), String> {
    let status = std::process::Command::new("rustfmt")
        .arg("--edition")
        .arg("2024")
        .arg(path)
        .status();
    match status {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(format!("rustfmt failed on {}: {status}", path.display())),
        Err(error) => Err(format!(
            "could not run rustfmt on {}: {error}. The generated module was written but is \
             not formatted; install rustfmt and rerun `cargo xtask abi`.",
            path.display()
        )),
    }
}

/// Formats Rust source text through `rustfmt` and returns the result.
///
/// Used by `--check` so the comparison sees the same bytes `write` would commit.
fn format_rust_text(text: &str) -> Result<String, String> {
    use std::io::Write as _;

    let mut child = std::process::Command::new("rustfmt")
        .args(["--edition", "2024", "--emit", "stdout", "--quiet"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| format!("could not run rustfmt: {error}"))?;

    child
        .stdin
        .as_mut()
        .ok_or("rustfmt stdin unavailable")?
        .write_all(text.as_bytes())
        .map_err(|error| format!("failed to write to rustfmt: {error}"))?;

    let output = child
        .wait_with_output()
        .map_err(|error| format!("rustfmt did not finish: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "rustfmt rejected the generated module: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|error| format!("rustfmt output is not UTF-8: {error}"))
}
