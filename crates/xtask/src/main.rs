// SPDX-License-Identifier: AGPL-3.0-only

//! Dedicated project task runner for daer (the `cargo-xtask` pattern).
//!
//! Run with:
//!     cargo xtask <subcommand>
//!
//! Subcommands:
//!     ebpf    - Compiles the eBPF C datapath into target/ebpf/datapath.bpf.o
//!     schema  - Prints or writes (--write) the published JSON schema
//!     events  - Generates the diagnostic event catalog (ADR-0040)
//!     test    - Runs one test layer, audits the test architecture, or lists its inventory
//!     ci      - Runs the entire CI suite locally (fmt, clippy, tests)

mod abi;
mod events;
mod incident;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn detect_bpf_arch() -> &'static str {
    if let Ok(arch) = env::var("DAER_BPF_ARCH") {
        return match arch.as_str() {
            "x86" | "x86_64" => "x86",
            "arm64" | "aarch64" => "arm64",
            "riscv" | "riscv64" => "riscv",
            "powerpc" | "ppc64le" => "powerpc",
            "loongarch" | "loongarch64" => "loongarch",
            other => panic!("unsupported DAER_BPF_ARCH: {other}"),
        };
    }

    match env::consts::ARCH {
        "x86_64" => "x86",
        "aarch64" => "arm64",
        "riscv64" => "riscv",
        "powerpc64" => "powerpc",
        "loongarch64" => "loongarch",
        other => panic!("unsupported host architecture {other}; specify DAER_BPF_ARCH"),
    }
}

fn build_ebpf(build_tests: bool) {
    let root = workspace_root();

    // Regenerate the ABI before compiling (ADR-0021). This is not a convenience: `datapath.bpf.c`
    // includes the generated header, so a change to `ebpf/abi.toml` would otherwise compile
    // against a stale one without saying so — and a tree where the generated files were
    // removed or hand-edited could not build at all. They are tracked (ADR-0021, amended),
    // so this run is about freshness, not about creating them from nothing.
    if let Err(error) = abi::run(&root, false) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }

    let datapath_src = env::var("DAER_DATAPATH_SRC")
        .map(PathBuf::from)
        .unwrap_or_else(|_| root.join("ebpf/kern"));
    // The vendored BTF trees live beside the C source, not in a sibling `ebpf/headers`
    // directory: `ebpf/kern/headers/vmlinux.h` is what `#include "vmlinux.h"` resolves
    // against once the build directory symlinks `headers`. The default used to point at
    // the nonexistent sibling, so a clean checkout failed before clang ran.
    let headers = env::var("DAER_BPF_HEADERS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| datapath_src.join("headers"));
    let max_match_set_len = env::var("MAX_MATCH_SET_LEN").unwrap_or_else(|_| "1024".to_string());
    let clang = env::var("CLANG").unwrap_or_else(|_| "clang".to_string());
    let bpf_arch = detect_bpf_arch();

    if !datapath_src.is_dir() {
        eprintln!(
            "error: datapath source not found at {}",
            datapath_src.display()
        );
        std::process::exit(1);
    }

    let vmlinux = headers.join("vmlinux.h");
    if !vmlinux.is_file() {
        eprintln!("error: {} is missing", vmlinux.display());
        eprintln!("       point DAER_BPF_HEADERS at a vmlinux.h tree");
        std::process::exit(1);
    }

    let out_dir = root.join("target/ebpf");
    let build_dir = out_dir.join("build");
    let _ = fs::remove_dir_all(&build_dir);
    fs::create_dir_all(&build_dir).expect("failed to create build directory");

    // Copy the C source and header files into the build directory, preserving the
    // `src/` and `tests/` subdirectories: `datapath.bpf.c` includes `src/<module>.h`, and
    // `tests/bpf_test.c` includes `../datapath.bpf.c` (ADR-0028, ADR-0022).
    copy_c_and_h(&datapath_src, &build_dir);
    for sub in ["src", "tests"] {
        let from = datapath_src.join(sub);
        let to = build_dir.join(sub);
        if from.is_dir() {
            fs::create_dir_all(&to).expect("failed to create build subdirectory");
            copy_c_and_h(&from, &to);
        }
    }

    // Create symlinks for headers and include
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let _ = symlink(&headers, build_dir.join("headers"));
        let include_dir = datapath_src.join("include");
        if include_dir.is_dir() {
            let _ = symlink(&include_dir, build_dir.join("include"));
        }
    }

    let out_file = out_dir.join("datapath.bpf.o");
    compile(
        &clang,
        bpf_arch,
        &max_match_set_len,
        &build_dir,
        &build_dir.join("datapath.bpf.c"),
        &out_file,
    );

    println!("built {}", out_file.display());

    if build_tests {
        build_test_object(
            &clang,
            bpf_arch,
            &max_match_set_len,
            &datapath_src,
            &out_dir,
        );
    }
}

/// One clang invocation, shared by the production object and the test object so the two
/// cannot drift in flags (ADR-0022).
fn compile(
    clang: &str,
    bpf_arch: &str,
    max_match_set_len: &str,
    build_dir: &Path,
    source: &Path,
    out_file: &Path,
) {
    let mut cmd = Command::new(clang);
    cmd.args([
        "-O2",
        "-g",
        "-Wall",
        "-Werror",
        "-Wno-missing-declarations",
        "-target",
        "bpf",
        &format!("-D__TARGET_ARCH_{bpf_arch}"),
        &format!("-DMAX_MATCH_SET_LEN={max_match_set_len}"),
        "-I",
        build_dir.to_str().unwrap(),
        "-c",
        source.to_str().unwrap(),
        "-o",
        out_file.to_str().unwrap(),
    ]);

    let status = cmd.status().unwrap_or_else(|e| {
        eprintln!("failed to execute clang ({clang}): {e}");
        std::process::exit(1);
    });

    if !status.success() {
        eprintln!("clang compilation failed with status: {status}");
        std::process::exit(status.code().unwrap_or(1));
    }
}

/// Copies every `.c` and `.h` from `from` into `to`.
fn copy_c_and_h(from: &Path, to: &Path) {
    let Ok(entries) = fs::read_dir(from) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if let Some(ext) = path.extension().and_then(|s| s.to_str())
            && matches!(ext, "c" | "h")
        {
            let _ = fs::copy(&path, to.join(path.file_name().unwrap()));
        }
    }
}

/// Compiles `ebpf/kern/tests/bpf_test.c` into `target/ebpf/datapath_test.bpf.o`.
///
/// The test file `#include`s `../datapath.bpf.c`, so it is compiled against the production
/// datapath rather than a copy — that is the property that makes the cases worth running.
fn build_test_object(
    clang: &str,
    bpf_arch: &str,
    max_match_set_len: &str,
    datapath_src: &Path,
    out_dir: &Path,
) {
    let tests_src = datapath_src.join("tests");
    if !tests_src.is_dir() {
        eprintln!("error: datapath tests not found at {}", tests_src.display());
        std::process::exit(1);
    }

    // The test file includes `../datapath.bpf.c` and `./bpf_test.h`, so the build tree keeps
    // that shape: sources at the root, test sources in `tests/` beside them.
    let test_build = out_dir.join("test-build");
    let _ = fs::remove_dir_all(&test_build);
    fs::create_dir_all(test_build.join("tests")).expect("failed to create test build directory");
    copy_c_and_h(datapath_src, &test_build);
    copy_c_and_h(&tests_src, &test_build.join("tests"));
    // `datapath.bpf.c` includes `src/<module>.h` (ADR-0028), so the test build needs the
    // same subdirectory the production build gets.
    let src_dir = datapath_src.join("src");
    if src_dir.is_dir() {
        let to = test_build.join("src");
        fs::create_dir_all(&to).expect("failed to create src subdirectory");
        copy_c_and_h(&src_dir, &to);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let _ = symlink(datapath_src.join("headers"), test_build.join("headers"));
        let include_dir = datapath_src.join("include");
        if include_dir.is_dir() {
            let _ = symlink(&include_dir, test_build.join("include"));
        }
    }

    let out_file = out_dir.join("datapath_test.bpf.o");
    compile(
        clang,
        bpf_arch,
        max_match_set_len,
        &test_build,
        &test_build.join("tests").join("bpf_test.c"),
        &out_file,
    );
    println!("built {}", out_file.display());
}

fn generate_schema(write: bool) {
    let root = workspace_root();
    let output = Command::new("cargo")
        .args(["run", "-q", "-p", "daer-cli", "--", "schema"])
        .output()
        .expect("failed to run daer-cli schema");

    if !output.status.success() {
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
        std::process::exit(output.status.code().unwrap_or(1));
    }

    let schema_text = String::from_utf8(output.stdout).expect("valid utf-8 schema");
    if write {
        let dest = root.join("daer.schema.json");
        fs::write(&dest, &schema_text).expect("failed to write daer.schema.json");
        println!("wrote {}", dest.display());
    } else {
        print!("{schema_text}");
    }
}

/// Runs `daer check --object` over the built object and the example configuration.
///
/// This is the unprivileged gate from ADR-0029, exercised the way a packaging script would:
/// against the artifact on disk rather than against the test fixture in memory.
fn run_preflight(root: &Path) -> Result<(), String> {
    let object = root.join("target/ebpf/datapath.bpf.o");
    if !object.is_file() {
        return Err(format!(
            "{} is missing; run `cargo xtask ebpf` first (the CI suite builds it in the test              targets, not here)",
            object.display()
        ));
    }
    // A minimal, self-contained configuration. `daer.example.toml` fetches rule providers,
    // and a gate that needs the network is a gate that fails for reasons unrelated to the
    // object it is supposed to be validating.
    let config = root.join("target/ebpf/preflight.toml");
    if let Some(parent) = config.parent() {
        fs::create_dir_all(parent).expect("failed to create the preflight directory");
    }
    fs::write(&config, "schema = 5\n\nwan-interface = \"auto\"\n")
        .map_err(|error| format!("failed to write {}: {error}", config.display()))?;

    let status = Command::new("cargo")
        .current_dir(root)
        .args([
            "run",
            "--quiet",
            "--package",
            "daer-cli",
            "--",
            "check",
            "--config",
        ])
        .arg(&config)
        .arg("--object")
        .arg(&object)
        .status()
        .map_err(|error| format!("failed to run daer check: {error}"))?;
    if !status.success() {
        return Err("the unprivileged preflight rejected the built object".to_owned());
    }
    Ok(())
}

fn run_install(args: &[String]) {
    let root = workspace_root();
    let mut prefix = env::var("PREFIX").unwrap_or_else(|_| "/usr".to_string());
    let mut destdir = env::var("DESTDIR").unwrap_or_default();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--prefix" if i + 1 < args.len() => {
                prefix = args[i + 1].clone();
                i += 2;
            }
            "--destdir" if i + 1 < args.len() => {
                destdir = args[i + 1].clone();
                i += 2;
            }
            other if other.starts_with("--prefix=") => {
                prefix = other["--prefix=".len()..].to_string();
                i += 1;
            }
            other if other.starts_with("--destdir=") => {
                destdir = other["--destdir=".len()..].to_string();
                i += 1;
            }
            _ => i += 1,
        }
    }

    match install_layout(&root, &prefix, Path::new(&destdir)) {
        Ok(installed) => {
            for path in installed {
                println!("installed: {}", path.display());
            }
        }
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(1);
        }
    }
}

/// Resolves where `prefix` is installed under `destdir`.
///
/// An empty `DESTDIR` means the live filesystem. `Path::new("").join("usr")` is the relative
/// path `usr`, so treating the empty string as a base used to create `./usr` under the
/// caller's working directory instead of writing `/usr`. Normalising here keeps the default
/// install and the staged install on the same code path.
fn install_target_prefix(prefix: &str, destdir: &Path) -> PathBuf {
    let base = if destdir.as_os_str().is_empty() {
        Path::new("/")
    } else {
        destdir
    };
    base.join(prefix.strip_prefix('/').unwrap_or(prefix))
}

/// Copies every installed artifact into `destdir/prefix` and returns the paths written.
///
/// This function is the single definition of an install. `scripts/ops/daer-install-netns.sh`
/// copies the staged tree rather than listing binaries again, and `packaging/daer.plan.toml`
/// calls this task instead of restating the artifact list. The test below pins the exact file
/// set, so a binary that drops out of this list fails CI instead of failing on a host.
fn install_layout(root: &Path, prefix: &str, destdir: &Path) -> Result<Vec<PathBuf>, String> {
    let binaries = ["daer", "daer-drb"];

    // Validate every source before writing anything: a skipped build step must not leave a
    // half-installed tree whose unit names a binary or object that was never copied.
    for name in binaries {
        if !root.join("target/release").join(name).is_file() {
            return Err(format!(
                "target/release/{name} does not exist. Run `cargo build --release` first."
            ));
        }
    }
    let src_obj = root.join("target/ebpf/datapath.bpf.o");
    if !src_obj.is_file() {
        return Err(format!(
            "{} does not exist. Run `cargo xtask ebpf` first.",
            src_obj.display()
        ));
    }
    let src_service = root.join("install/daer.service");
    if !src_service.is_file() {
        return Err(format!("{} is missing", src_service.display()));
    }

    let target_prefix = install_target_prefix(prefix, destdir);
    let bin_dir = target_prefix.join("bin");
    let lib_dir = target_prefix.join("lib/daer");
    let unit_dir = target_prefix.join("lib/systemd/system");
    for directory in [&bin_dir, &lib_dir, &unit_dir] {
        fs::create_dir_all(directory)
            .map_err(|error| format!("cannot create {}: {error}", directory.display()))?;
    }

    // Pre-TCX releases installed a separate cleanup binary and a differently named
    // object. They are not part of the current set; remove them from a live `/usr`
    // or a reused staging tree so an upgrade cannot leave an orphan helper behind.
    for legacy in [bin_dir.join("daer-cleanup"), lib_dir.join("datapath.o")] {
        if let Err(error) = fs::remove_file(&legacy)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            return Err(format!(
                "cannot remove legacy {}: {error}",
                legacy.display()
            ));
        }
    }

    let mut installed = Vec::with_capacity(binaries.len() + 2);
    for name in binaries {
        // `daer-drb` is the rule-artifact producer operators need to compile `.rules`
        // (ADR-0031). The daemon itself must never link it; the surface test enforces that.
        installed.push(install_binary(root, &bin_dir, name)?);
    }

    let dest_obj = lib_dir.join("datapath.bpf.o");
    fs::copy(&src_obj, &dest_obj).map_err(|error| {
        format!(
            "cannot copy {} to {}: {error}",
            src_obj.display(),
            dest_obj.display()
        )
    })?;
    set_mode(&dest_obj, 0o644)?;
    installed.push(dest_obj);

    // The unit source names the canonical `/usr` install. Rewrite the two executable paths
    // when a different prefix was requested: copying it verbatim made `--prefix /usr/local`
    // install a binary that systemd could not find.
    let unit = fs::read_to_string(&src_service)
        .map_err(|error| format!("cannot read {}: {error}", src_service.display()))?;
    let unit = service_unit_for_prefix(&unit, prefix);
    let dest_service = unit_dir.join("daer.service");
    fs::write(&dest_service, unit)
        .map_err(|error| format!("cannot write {}: {error}", dest_service.display()))?;
    set_mode(&dest_service, 0o644)?;
    installed.push(dest_service);

    Ok(installed)
}

/// Rewrites the canonical `/usr` paths in the unit for the requested install prefix.
///
/// The repository keeps one complete unit (`install/daer.service`) for packages, which always
/// install under `/usr`. `cargo xtask install --prefix …` must not copy those paths verbatim:
/// systemd would exec a binary the install never wrote. The rewrite is deliberately limited to
/// the two paths the unit owns; the configuration path stays `/etc/daer/config.toml`.
fn service_unit_for_prefix(unit: &str, prefix: &str) -> String {
    let prefix_root = prefix.trim_end_matches('/');
    unit.replace("/usr/bin/daer", &format!("{prefix_root}/bin/daer"))
        .replace(
            "/usr/lib/daer/datapath.bpf.o",
            &format!("{prefix_root}/lib/daer/datapath.bpf.o"),
        )
}

/// Copies one built binary into `<prefix>/bin` with the executable bit set.
fn install_binary(root: &Path, bin_dir: &Path, name: &str) -> Result<PathBuf, String> {
    let src = root.join("target/release").join(name);
    if !src.is_file() {
        return Err(format!(
            "target/release/{name} does not exist. Run `cargo build --release` first."
        ));
    }
    let dest = bin_dir.join(name);
    fs::copy(&src, &dest).map_err(|error| {
        format!(
            "cannot copy {} to {}: {error}",
            src.display(),
            dest.display()
        )
    })?;
    set_mode(&dest, 0o755)?;
    Ok(dest)
}

/// Sets an exact mode on Unix.
///
/// The binary is Linux-only, but keeping the mode in one helper means the install test sees
/// the same permissions the caller gets instead of depending on the workspace's umask.
fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|error| format!("cannot set mode {mode:o} on {}: {error}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

fn main() {
    let mut args = env::args().skip(1);
    let subcommand = args.next();

    match subcommand.as_deref() {
        Some("ebpf") => {
            let build_tests = args.any(|a| a == "--tests");
            build_ebpf(build_tests);
        }
        Some("schema") => {
            let write = args.any(|a| a == "--write" || a == "-w");
            generate_schema(write);
        }
        Some("abi") => {
            let check = args.any(|a| a == "--check");
            let root = workspace_root();
            if let Err(error) = abi::run(&root, check) {
                eprintln!("error: {error}");
                std::process::exit(1);
            }
        }
        Some("events") => {
            let check = args.any(|a| a == "--check");
            let root = workspace_root();
            if let Err(error) = events::run(&root, check) {
                eprintln!("error: {error}");
                std::process::exit(1);
            }
        }
        Some("incident") => {
            let root = workspace_root();
            if let Err(error) = incident::run(&root) {
                eprintln!("error: {error}");
                std::process::exit(1);
            }
        }
        Some("preflight") => {
            let root = workspace_root();
            if let Err(error) = run_preflight(&root) {
                eprintln!("error: {error}");
                std::process::exit(1);
            }
        }
        Some("install") => run_install(&args.collect::<Vec<_>>()),
        Some("help") | None => {
            println!("daer workspace task runner (cargo-xtask)\n");
            println!("Usage:");
            println!(
                "    cargo xtask abi [--check]      Generate the kernel ABI from ebpf/abi.toml"
            );
            println!("    cargo xtask events [--check]   Generate the diagnostic event catalog");
            println!("    cargo xtask incident           Validate the post-bug incident records");
            println!(
                "    cargo xtask ebpf [--tests]     Compile eBPF C datapath (and the test object)"
            );
            println!("    cargo xtask schema [--write]   Print or update daer.schema.json");
            println!(
                "    cargo xtask preflight          Validate the built object and example config (no capability)"
            );
            println!(
                "    cargo xtask install            Install binaries, datapath, and unit (--prefix/--destdir)"
            );
        }
        Some(other) => {
            eprintln!("unknown subcommand: {other}");
            eprintln!("run `cargo xtask help` for usage");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn the_installed_unit_follows_the_requested_prefix() {
        let unit = "[Service]\n\
                    ExecStart=/usr/bin/daer run --object /usr/lib/daer/datapath.bpf.o\n";
        let custom = service_unit_for_prefix(unit, "/usr/local/");
        assert!(custom.contains("ExecStart=/usr/local/bin/daer run"));
        assert!(custom.contains("--object /usr/local/lib/daer/datapath.bpf.o"));
        assert!(!custom.contains("/usr/bin/daer"));
        assert!(!custom.contains("/usr/lib/daer/datapath.bpf.o"));

        // The package build installs under `/usr`; its unit must stay byte-identical.
        assert_eq!(service_unit_for_prefix(unit, "/usr"), unit);
    }

    /// Creates a fake workspace with every source artifact `install_layout` expects.
    fn temporary_root() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};

        static NEXT: AtomicU64 = AtomicU64::new(0);

        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after the epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "daer-xtask-install-{}-{stamp}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        for directory in ["target/release", "target/ebpf", "install"] {
            fs::create_dir_all(root.join(directory)).expect("create fake workspace directory");
        }
        for name in ["daer", "daer-drb"] {
            fs::write(root.join("target/release").join(name), b"fake binary")
                .expect("write fake binary");
        }
        fs::write(root.join("target/ebpf/datapath.bpf.o"), b"fake object")
            .expect("write fake object");
        fs::write(
            root.join("install/daer.service"),
            "[Service]\n\
             UMask=0077\n\
             ExecStart=/usr/bin/daer run --object /usr/lib/daer/datapath.bpf.o\n",
        )
        .expect("write fake unit");
        root
    }

    #[test]
    fn the_staged_tree_is_exactly_the_documented_file_set() {
        let root = temporary_root();
        let destdir = root.join("stage");
        let installed = install_layout(&root, "/usr", &destdir).expect("install layout");

        let relative: BTreeSet<String> = installed
            .iter()
            .map(|path| {
                path.strip_prefix(&destdir)
                    .expect("installed path is under destdir")
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        assert_eq!(
            relative,
            BTreeSet::from([
                "usr/bin/daer".to_owned(),
                "usr/bin/daer-drb".to_owned(),
                "usr/lib/daer/datapath.bpf.o".to_owned(),
                "usr/lib/systemd/system/daer.service".to_owned(),
            ])
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            for (relative, mode) in [
                ("usr/bin/daer", 0o755),
                ("usr/bin/daer-drb", 0o755),
                ("usr/lib/daer/datapath.bpf.o", 0o644),
                ("usr/lib/systemd/system/daer.service", 0o644),
            ] {
                let actual = fs::metadata(destdir.join(relative))
                    .expect("staged file exists")
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(actual, mode, "{relative}");
            }
        }

        let unit = fs::read_to_string(destdir.join("usr/lib/systemd/system/daer.service"))
            .expect("read staged unit");
        assert!(!unit.contains("ExecStopPost"), "{unit}");
        assert!(!unit.contains("daer-cleanup"), "{unit}");
        assert!(unit.contains("UMask=0077"), "{unit}");

        fs::remove_dir_all(&root).expect("remove fake workspace");
    }

    #[test]
    fn a_reused_staging_tree_does_not_keep_pre_tcx_artifacts() {
        let root = temporary_root();
        let destdir = root.join("stage");
        let legacy_bin = destdir.join("usr/bin/daer-cleanup");
        let legacy_object = destdir.join("usr/lib/daer/datapath.o");
        fs::create_dir_all(legacy_bin.parent().expect("bin parent")).expect("create bin dir");
        fs::create_dir_all(legacy_object.parent().expect("object parent"))
            .expect("create object dir");
        fs::write(&legacy_bin, b"old cleanup").expect("write legacy cleanup");
        fs::write(&legacy_object, b"old object").expect("write legacy object");

        install_layout(&root, "/usr", &destdir).expect("install layout");

        assert!(!legacy_bin.exists(), "legacy cleanup must be removed");
        assert!(!legacy_object.exists(), "legacy object must be removed");
        fs::remove_dir_all(&root).expect("remove fake workspace");
    }

    #[test]
    fn the_package_plan_uses_the_install_task_instead_of_a_second_artifact_list() {
        let plan = fs::read_to_string(workspace_root().join("packaging/daer.plan.toml"))
            .expect("read the package plan");
        assert!(
            plan.contains("cargo run --package xtask -- install"),
            "the package staging step must call the install task"
        );
        for direct in [
            "install -Dm755 target/release/daer ",
            "install -Dm755 target/release/daer-drb ",
            "install -Dm644 target/ebpf/datapath.bpf.o ",
            "install -Dm644 install/daer.service ",
        ] {
            assert!(
                !plan.contains(direct),
                "the package plan still duplicates the install set: {direct}"
            );
        }
    }

    #[test]
    fn a_missing_producer_binary_fails_the_install() {
        // The falsifier for a partial install: dropping a shipped binary must fail before
        // writing a tree whose unit or documented workflow names a file that is not there.
        let root = temporary_root();
        fs::remove_file(root.join("target/release/daer-drb")).expect("remove producer");

        let error = install_layout(&root, "/usr", &root.join("stage")).expect_err("must fail");
        assert!(error.contains("daer-drb"), "{error}");

        fs::remove_dir_all(&root).expect("remove fake workspace");
    }

    #[test]
    fn a_missing_datapath_object_fails_the_install() {
        // The unit's ExecStart names this object. Installing the unit without it used to
        // succeed silently; the service then failed only after systemd started it.
        let root = temporary_root();
        fs::remove_file(root.join("target/ebpf/datapath.bpf.o")).expect("remove datapath object");

        let error = install_layout(&root, "/usr", &root.join("stage")).expect_err("must fail");
        assert!(error.contains("cargo xtask ebpf"), "{error}");

        fs::remove_dir_all(&root).expect("remove fake workspace");
    }

    #[test]
    fn the_install_target_defaults_to_the_live_root() {
        assert_eq!(
            install_target_prefix("/usr", Path::new("")),
            PathBuf::from("/usr")
        );
        assert_eq!(
            install_target_prefix("/usr", Path::new("/tmp/pkg")),
            PathBuf::from("/tmp/pkg/usr")
        );
        assert_eq!(
            install_target_prefix("/usr/local", Path::new("/tmp/pkg")),
            PathBuf::from("/tmp/pkg/usr/local")
        );
    }
}
