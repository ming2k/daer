// SPDX-License-Identifier: AGPL-3.0-only

//! Asserts that `daer.schema.json` at the workspace root is up to date with the
//! `Config` model.
//!
//! A failure means a field was added, removed, or changed in `daer-config`
//! without updating the published schema. Regenerate it with:
//!
//!     cargo run -p daer-cli -- schema > daer.schema.json

#[test]
fn schema_is_up_to_date() {
    let workspace_root = crate::common::workspace_root();
    let schema_file = workspace_root.join("daer.schema.json");
    let on_disk = std::fs::read_to_string(&schema_file)
        .expect("daer.schema.json should be present at workspace root");
    let generated = daer_config::schema::json_schema();

    if on_disk.trim() != generated.trim() {
        panic!(
            "\n[DRIFT DETECTED] daer.schema.json is out of date!\n\
             Run `cargo run -p daer-cli -- schema > daer.schema.json` to update it.\n"
        );
    }
}

/// Every TOML block in the reference documentation must actually load.
///
/// The reference is the only description of the configuration schema an operator reads, and it
/// drifted: it documented `[node.reality]` and a required `reality.fingerprint`, neither of
/// which the loader accepts (the table is `[node.security]` and the REALITY layer has no
/// fingerprint field at all). A schema test cannot catch that — the schema was right and the
/// prose was wrong — so the prose is compiled: every fenced ```toml block in
/// `docs/reference/configuration.md` is fed to the loader.
///
/// A block that is deliberately incomplete (a fragment showing one table, not a whole file)
/// is skipped by name rather than by guess: `schema = 5` and a `[[group]]` are what make a
/// snippet loadable, and a snippet without them is a fragment the prose is naming members of.
#[test]
fn every_toml_block_in_the_reference_documentation_loads() {
    let workspace_root = crate::common::workspace_root();
    let reference = workspace_root.join("docs/reference/configuration.md");
    let text = std::fs::read_to_string(&reference).expect("the reference must exist");

    let mut checked = 0usize;
    let mut block = String::new();
    let mut in_toml = false;
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            if in_toml {
                // A fragment: the prose is naming keys, not showing a file. A block that
                // declares a table is a real document and is loaded.
                let is_document = block.contains("schema =")
                    || block.contains("[[node]]")
                    || block.contains("[[subscription]]");
                if is_document {
                    let document = if block.contains("schema =") {
                        block.clone()
                    } else {
                        format!("schema = 5\n{block}")
                    };
                    daer_config::toml_config::load_str(&document).unwrap_or_else(|error| {
                        panic!(
                            "a ```toml block in docs/reference/configuration.md does not load:\n\
                             {block}\n--- error ---\n{error}\n"
                        )
                    });
                    checked += 1;
                }
                block.clear();
                in_toml = false;
            } else {
                in_toml = true;
            }
            continue;
        }
        if in_toml {
            block.push_str(line);
            block.push('\n');
        }
    }
    assert!(
        checked >= 3,
        "only {checked} TOML block(s) were checked; the extractor is not seeing the document"
    );
}
