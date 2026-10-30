// SPDX-License-Identifier: AGPL-3.0-only

//! Asserts that `daer.schema.json` at the workspace root is up to date with the
//! `Config` model.
//!
//! A failure means a field was added, removed, or changed in `daer-config`
//! without updating the published schema. Regenerate it with:
//!
//!     cargo run -p daer-cli -- config schema > daer.schema.json

#[test]
fn schema_is_up_to_date() {
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    let schema_file = workspace_root.join("daer.schema.json");
    let on_disk = std::fs::read_to_string(&schema_file)
        .expect("daer.schema.json should be present at workspace root");
    let generated = daer_config::schema::json_schema();

    if on_disk.trim() != generated.trim() {
        panic!(
            "\n[DRIFT DETECTED] daer.schema.json is out of date!\n\
             Run `cargo run -p daer-cli -- config schema > daer.schema.json` to update it.\n"
        );
    }
}
