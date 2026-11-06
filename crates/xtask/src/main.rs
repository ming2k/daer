// SPDX-License-Identifier: AGPL-3.0-only

//! Dedicated project task runner for daer (the `cargo-xtask` pattern).
//!
//! Run with:
//!     cargo xtask <subcommand>
//!
//! Subcommands:
//!     ebpf    - Compiles the eBPF C datapath into target/ebpf/datapath.o
//!     schema  - Prints or writes (--write) the published JSON schema
//!     ci      - Runs the entire CI suite locally (fmt, clippy, tests)

mod abi;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

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

    // Regenerate the ABI before compiling (ADR-0021). This is not a convenience: `tproxy.c`
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
    // `src/` and `tests/` subdirectories: `tproxy.c` includes `src/<module>.h`, and
    // `tests/bpf_test.c` includes `../tproxy.c` (ADR-0028, ADR-0022).
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

    let out_file = out_dir.join("datapath.o");
    compile(
        &clang,
        bpf_arch,
        &max_match_set_len,
        &build_dir,
        &build_dir.join("tproxy.c"),
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

/// Compiles `ebpf/kern/tests/bpf_test.c` into `target/ebpf/datapath-test.o`.
///
/// The test file `#include`s `../tproxy.c`, so it is compiled against the production
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

    // The test file includes `../tproxy.c` and `./bpf_test.h`, so the build tree keeps
    // that shape: sources at the root, test sources in `tests/` beside them.
    let test_build = out_dir.join("test-build");
    let _ = fs::remove_dir_all(&test_build);
    fs::create_dir_all(test_build.join("tests")).expect("failed to create test build directory");
    copy_c_and_h(datapath_src, &test_build);
    copy_c_and_h(&tests_src, &test_build.join("tests"));
    // `tproxy.c` includes `src/<module>.h` (ADR-0028), so the test build needs the
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

    let out_file = out_dir.join("datapath-test.o");
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

fn run_command(cmd: &str, args: &[&str]) -> ExitStatus {
    println!("> {cmd} {}", args.join(" "));
    let status = Command::new(cmd)
        .args(args)
        .status()
        .unwrap_or_else(|e| panic!("failed to execute {cmd}: {e}"));
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    status
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

fn run_ci() {
    println!("=== Running CI Suite ===");
    let jobs = format!("-j{}", ci_jobs());

    // The kernel ABI is generated (ADR-0021). Checking it first means a drifted
    // declaration fails before the compile that would hide it, and the message names the
    // file and the command that fixes it.
    println!("> cargo xtask abi --check");
    let root = workspace_root();
    if let Err(error) = abi::run(&root, true) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }

    run_command("cargo", &["fmt", "--all", "--", "--check"]);
    run_command(
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--locked",
            &jobs,
            "--",
            "-D",
            "warnings",
        ],
    );
    run_command("cargo", &["test", "--workspace", "--locked", &jobs]);

    // The unprivileged preflight (ADR-0029): the object the repository just built has to be
    // one `daer check` accepts, which is the same gate a packaging script runs against an
    // installed artifact. It needs no capability, so it belongs in this suite.
    println!("> cargo xtask preflight");
    if let Err(error) = run_preflight(&root) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }

    println!("\n✅ All checks and tests passed cleanly!");
}

/// Runs `daer check --object` over the built object and the example configuration.
///
/// This is the unprivileged gate from ADR-0029, exercised the way a packaging script would:
/// against the artifact on disk rather than against the test fixture in memory.
fn run_preflight(root: &Path) -> Result<(), String> {
    let object = root.join("target/ebpf/datapath.o");
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
    fs::write(
        &config,
        "schema = 1\n\n[global]\nwan-interface = [\"auto\"]\n",
    )
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

/// How many codegen units to run in parallel during CI.
///
/// Cargo's default is one job per core, and this workspace has 23 test targets that each link
/// the entire dependency graph. On a 16-core box that is 23 concurrent `rust-lld` processes,
/// and the wall-clock cost is dominated by their *contention* rather than their work: measured
/// on the dev machine, an uncontended no-op `cargo test --no-run --workspace` takes 169 ms
/// while the same command after touching one library took 666 s, every one of those seconds
/// inside the linker.
///
/// Half the cores is the point where the linkers stop competing for the same page cache and
/// the same disk queue while still using the machine. `DAER_CI_JOBS` overrides it for a
/// machine where that trade is different — a CI runner with a fast NVMe wants more, a laptop
/// on a battery wants fewer.
fn ci_jobs() -> usize {
    if let Some(jobs) = std::env::var("DAER_CI_JOBS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|jobs| *jobs > 0)
    {
        return jobs;
    }
    std::thread::available_parallelism()
        .map(|cores| (cores.get() / 2).max(1))
        .unwrap_or(1)
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

    let base = Path::new(&destdir);
    let clean_prefix = prefix.strip_prefix('/').unwrap_or(&prefix);
    let target_prefix = base.join(clean_prefix);

    let bin_dir = target_prefix.join("bin");
    let lib_dir = target_prefix.join("lib/daer");
    let unit_dir = target_prefix.join("lib/systemd/system");

    fs::create_dir_all(&bin_dir).expect("failed to create bin directory");
    fs::create_dir_all(&lib_dir).expect("failed to create lib/daer directory");
    fs::create_dir_all(&unit_dir).expect("failed to create systemd unit directory");

    let src_bin = root.join("target/release/daer");
    if !src_bin.exists() {
        eprintln!("target/release/daer does not exist. Run `cargo build --release` first.");
        std::process::exit(1);
    }
    let dest_bin = bin_dir.join("daer");
    fs::copy(&src_bin, &dest_bin).expect("failed to copy binary");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dest_bin, fs::Permissions::from_mode(0o755));
    }
    println!("installed: {}", dest_bin.display());

    let src_obj = root.join("target/ebpf/datapath.o");
    if src_obj.exists() {
        let dest_obj = lib_dir.join("datapath.o");
        fs::copy(&src_obj, &dest_obj).expect("failed to copy datapath object");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&dest_obj, fs::Permissions::from_mode(0o644));
        }
        println!("installed: {}", dest_obj.display());
    }

    let src_service = root.join("install/daer.service");
    if src_service.exists() {
        let dest_service = unit_dir.join("daer.service");
        fs::copy(&src_service, &dest_service).expect("failed to copy systemd service unit");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&dest_service, fs::Permissions::from_mode(0o644));
        }
        println!("installed: {}", dest_service.display());
    }
}

/// Runs one of the privileged verification scripts under `scripts/`.
///
/// The two scripts answer different questions and have different dependency closures, so
/// neither is a superset of the other: `kernel-check.sh` asks whether the eBPF object loads
/// and behaves, and `e2e-check.sh` asks whether a real redirected flow reaches the daemon
/// and comes back. Running the wrong one for a change is how a gate silently stops covering
/// what it claims, so both are named explicitly rather than folded into one entry point.
fn run_privileged_script(name: &str, args: Vec<String>) {
    let root = workspace_root();
    let script = root.join("scripts").join(name);
    if !script.is_file() {
        eprintln!("error: scripts/{name} not found");
        std::process::exit(1);
    }
    let status = Command::new(&script)
        .args(&args)
        .status()
        .unwrap_or_else(|e| panic!("failed to run {}: {e}", script.display()));
    std::process::exit(status.code().unwrap_or(1));
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
        Some("preflight") => {
            let root = workspace_root();
            if let Err(error) = run_preflight(&root) {
                eprintln!("error: {error}");
                std::process::exit(1);
            }
        }
        Some("ci") => run_ci(),
        Some("install") => run_install(&args.collect::<Vec<_>>()),
        Some("kernel-check") => run_privileged_script("kernel-check.sh", args.collect()),
        Some("e2e-check") => run_privileged_script("e2e-check.sh", args.collect()),
        Some("help") | None => {
            println!("daer workspace task runner (cargo-xtask)\n");
            println!("Usage:");
            println!(
                "    cargo xtask abi [--check]      Generate the kernel ABI from ebpf/abi.toml"
            );
            println!(
                "    cargo xtask ebpf [--tests]     Compile eBPF C datapath (and the test object)"
            );
            println!("    cargo xtask schema [--write]   Print or update daer.schema.json");
            println!(
                "    cargo xtask preflight          Validate the built object and example config (no capability)"
            );
            println!("    cargo xtask ci                 Run full CI suite (fmt, clippy, test)");
            println!(
                "    cargo xtask install            Install binary, datapath, and systemd unit"
            );
            println!("    cargo xtask kernel-check       Run privileged kernel datapath tests");
            println!("    cargo xtask e2e-check          Run privileged end-to-end ingress tests");
        }
        Some(other) => {
            eprintln!("unknown subcommand: {other}");
            eprintln!("run `cargo xtask help` for usage");
            std::process::exit(1);
        }
    }
}
