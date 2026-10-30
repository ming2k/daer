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

fn build_ebpf() {
    let root = workspace_root();
    let datapath_src = env::var("DAER_DATAPATH_SRC")
        .map(PathBuf::from)
        .unwrap_or_else(|_| root.join("ebpf/kern"));
    let headers = env::var("DAER_BPF_HEADERS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| root.join("ebpf/headers"));
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

    // Copy C source and header files into build directory
    if let Ok(entries) = fs::read_dir(&datapath_src) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(ext) = path.extension().and_then(|s| s.to_str())
                && (ext == "c" || ext == "h")
            {
                let dest = build_dir.join(path.file_name().unwrap());
                fs::copy(&path, &dest).expect("failed to copy C source file");
            }
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
    let mut cmd = Command::new(&clang);
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
        build_dir.join("tproxy.c").to_str().unwrap(),
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
        .args(["run", "-q", "-p", "daer-cli", "--", "config", "schema"])
        .output()
        .expect("failed to run daer-cli config schema");

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
    run_command("cargo", &["fmt", "--all", "--", "--check"]);
    run_command(
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
    );
    run_command("cargo", &["test", "--workspace", "--locked"]);
    println!("\n✅ All checks and tests passed cleanly!");
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

fn run_kernel_check(args: Vec<String>) {
    let root = workspace_root();
    let script = root.join("scripts/kernel-check.sh");
    if !script.is_file() {
        eprintln!("error: scripts/kernel-check.sh not found");
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
        Some("ebpf") => build_ebpf(),
        Some("schema") => {
            let write = args.any(|a| a == "--write" || a == "-w");
            generate_schema(write);
        }
        Some("ci") => run_ci(),
        Some("install") => run_install(&args.collect::<Vec<_>>()),
        Some("kernel-check") => run_kernel_check(args.collect()),
        Some("help") | None => {
            println!("daer workspace task runner (cargo-xtask)\n");
            println!("Usage:");
            println!("    cargo xtask ebpf               Compile eBPF C datapath");
            println!("    cargo xtask schema [--write]   Print or update daer.schema.json");
            println!("    cargo xtask ci                 Run full CI suite (fmt, clippy, test)");
            println!(
                "    cargo xtask install            Install binary, datapath, and systemd unit"
            );
            println!("    cargo xtask kernel-check       Run privileged kernel datapath tests");
        }
        Some(other) => {
            eprintln!("unknown subcommand: {other}");
            eprintln!("run `cargo xtask help` for usage");
            std::process::exit(1);
        }
    }
}
