// SPDX-License-Identifier: AGPL-3.0-only

//! `daer-drb`: The DRB (daer Rule Binary) compiler, decompiler, inspector, and tester.
//!
//! Under ADR-0015 and ADR-0031, `daer-drb` is a standalone producer toolchain. It links no
//! Protobuf reader and performs no format conversion: input is strictly Canonical Rule Source
//! (`.rules`), and output is strictly DRB v2 (`.drb`).

use std::fs;
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use daer_routing::{DrbSet, DrbSummary};
use daer_rule_ast::RuleSet;

#[derive(Debug, Parser)]
#[command(
    name = "daer-drb",
    version,
    about = "DRB (daer Rule Binary) toolchain: compile, decompile, inspect, and test rules",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Compiles a Canonical Rule Source (.rules) file into a .drb binary artifact.
    Compile {
        /// Input rule text file (`.rules`), or `-` for standard input.
        #[arg(value_name = "INPUT")]
        input: PathBuf,
        /// Output path for the compiled `.drb` binary.
        #[arg(short, long, value_name = "OUTPUT")]
        output: PathBuf,
        /// Rule set name. Defaults to file stem or name specified inside the rule file.
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
    },
    /// Decompiles an existing .drb binary artifact back into Canonical Rule Source (.rules) text.
    Decompile {
        /// Path to the `.drb` binary file.
        #[arg(value_name = "INPUT")]
        input: PathBuf,
        /// Output path for the decompiled `.rules` text, or `-` for standard output.
        #[arg(short, long, value_name = "OUTPUT")]
        output: PathBuf,
    },
    /// Inspects an existing .drb binary artifact and displays its metadata.
    Inspect {
        /// Path to the `.drb` binary file.
        #[arg(value_name = "INPUT")]
        input: PathBuf,
    },
    /// Tests whether an IP address or domain matches any rule in a .drb binary artifact.
    #[command(alias = "match")]
    Test {
        /// Path to the `.drb` binary file.
        #[arg(value_name = "INPUT")]
        input: PathBuf,
        /// The IP address or domain name to test.
        #[arg(value_name = "TARGET")]
        target: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: Command) -> anyhow::Result<()> {
    match command {
        Command::Compile {
            input,
            output,
            name,
        } => compile(&input, &output, name.as_deref()),
        Command::Decompile { input, output } => decompile(&input, &output),
        Command::Inspect { input } => inspect(&input),
        Command::Test { input, target } => test(&input, &target),
    }
}

fn read_input_text(path: &Path) -> anyhow::Result<(String, String)> {
    if path.as_os_str() == "-" {
        let mut buffer = String::new();
        io::stdin()
            .read_to_string(&mut buffer)
            .context("cannot read from standard input")?;
        Ok(("rules".to_owned(), buffer))
    } else {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("rules")
            .to_owned();
        let content = fs::read_to_string(path)
            .with_context(|| format!("cannot read input file {}", path.display()))?;
        Ok((stem, content))
    }
}

fn compile(input: &Path, output: &Path, explicit_name: Option<&str>) -> anyhow::Result<()> {
    let (stem, text) = read_input_text(input)?;
    let mut rules = RuleSet::parse(&text)
        .with_context(|| format!("cannot parse rules from {}", input.display()))?;

    if let Some(name) = explicit_name {
        rules.set_name(name);
    } else if rules.name().is_empty() {
        rules.set_name(stem);
    }

    let set = DrbSet::from_rule_set(&rules);
    let bytes = set.encode();
    fs::write(output, &bytes)
        .with_context(|| format!("cannot write output to {}", output.display()))?;

    let summary = DrbSet::inspect_bytes(&bytes)
        .with_context(|| format!("failed to inspect compiled binary at {}", output.display()))?;

    print_summary(output, &summary);
    Ok(())
}

fn decompile(input: &Path, output: &Path) -> anyhow::Result<()> {
    let bytes =
        fs::read(input).with_context(|| format!("cannot read DRB file {}", input.display()))?;
    let set = DrbSet::decode(&bytes)
        .map_err(|err| anyhow::anyhow!("invalid DRB file {}: {err}", input.display()))?;
    let rules = set.to_rule_set();
    let text = rules.render();

    if output.as_os_str() == "-" {
        let mut stdout = io::stdout().lock();
        stdout
            .write_all(text.as_bytes())
            .context("cannot write to standard output")?;
    } else {
        fs::write(output, text.as_bytes())
            .with_context(|| format!("cannot write to {}", output.display()))?;
        let count = rules.v4_intervals().len() + rules.v6_intervals().len() + rules.domains().len();
        eprintln!("wrote {} ({} directives)", output.display(), count);
    }
    Ok(())
}

fn inspect(input: &Path) -> anyhow::Result<()> {
    let bytes =
        fs::read(input).with_context(|| format!("cannot read DRB file {}", input.display()))?;
    let summary = DrbSet::inspect_bytes(&bytes)
        .map_err(|err| anyhow::anyhow!("invalid DRB file {}: {err}", input.display()))?;

    print_summary(input, &summary);
    Ok(())
}

fn print_summary(path: &Path, summary: &DrbSummary) {
    println!("{}: ok", path.display());
    println!("  name:             {}", summary.name);
    println!("  version:          {}", summary.version);
    println!("  v4 intervals:     {}", summary.v4_intervals);
    println!("  v6 intervals:     {}", summary.v6_intervals);
    println!("  domain patterns:  {}", summary.domain_patterns);
    println!("  binary size:      {} bytes", summary.file_size);
    println!("  sha256:           {}", summary.checksum);
}

fn test(input: &Path, target: &str) -> anyhow::Result<()> {
    let bytes =
        fs::read(input).with_context(|| format!("cannot read DRB file {}", input.display()))?;
    let set = DrbSet::decode(&bytes)
        .map_err(|err| anyhow::anyhow!("invalid DRB file {}: {err}", input.display()))?;

    let trimmed = target.trim();
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        let matched = set.contains_ip(ip);
        if matched {
            println!("matched: {trimmed}");
            println!("  rule set : {}", set.name);
            println!("  kind     : IP");
            Ok(())
        } else {
            println!("not matched: {trimmed} not in rule set '{}'", set.name);
            bail!("target did not match any rule in {}", input.display());
        }
    } else {
        let matched = set.matches_domain(trimmed);
        if matched {
            println!("matched: {trimmed}");
            println!("  rule set : {}", set.name);
            println!("  kind     : Domain");
            Ok(())
        } else {
            println!("not matched: {trimmed} not in rule set '{}'", set.name);
            bail!("target did not match any rule in {}", input.display());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_inspect_and_test_flow() {
        let dir = std::env::temp_dir().join(format!("daer-drb-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let rules_file = dir.join("test.rules");
        fs::write(
            &rules_file,
            "---\nname: my-rules\n---\n192.168.1.0/24\nexample.com\n=auth.corp.internal\n",
        )
        .unwrap();

        let drb_file = dir.join("test.drb");
        compile(&rules_file, &drb_file, None).unwrap();

        let summary = DrbSet::inspect_bytes(&fs::read(&drb_file).unwrap()).unwrap();
        assert_eq!(summary.name, "my-rules");
        assert_eq!(summary.v4_intervals, 1);
        // Two patterns: `example.com` and `=auth.corp.internal`.
        assert_eq!(summary.domain_patterns, 2);

        test(&drb_file, "192.168.1.100").unwrap();
        test(&drb_file, "api.example.com").unwrap();
        test(&drb_file, "auth.corp.internal").unwrap();

        assert!(test(&drb_file, "10.0.0.1").is_err());
        assert!(test(&drb_file, "corp.internal").is_err());

        let _ = fs::remove_dir_all(&dir);
    }
}
