// SPDX-License-Identifier: AGPL-3.0-only

//! `geodrb`: The DRB (daer Rule Binary) compiler, converter, inspector, and tester.
//!
//! As established in ADR-0014 and ADR-0015, rule producers and format converters
//! live in `geodrb` rather than inside the `daer` runtime daemon.

use std::fs;
use std::io::{self, Read};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand, ValueEnum};
use daer_geodata::{DomainType, unmarshal_geoip, unmarshal_geosite};
use daer_routing::{DrbSet, DrbSummary, SuffixScope};
use ipnet::IpNet;

#[derive(Debug, Parser)]
#[command(
    name = "geodrb",
    version,
    about = "DRB (daer Rule Binary) compiler, converter, inspector, and tester",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Compiles plain-text rules into a .drb binary artifact.
    Compile {
        /// Input rule text file (`.rules` or `.txt`), or `-` for standard input.
        #[arg(value_name = "INPUT")]
        input: PathBuf,
        /// Output path for the compiled `.drb` binary.
        #[arg(short, long, value_name = "OUTPUT")]
        output: PathBuf,
        /// Rule set name. Defaults to file stem or name specified inside the rule file.
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
    },
    /// Inspects an existing .drb binary artifact and displays its metadata.
    Inspect {
        /// Path to the `.drb` binary file.
        #[arg(value_name = "INPUT")]
        input: PathBuf,
    },
    /// Converts legacy geoip.dat or geosite.dat into a .drb binary artifact.
    Convert {
        /// Path to the `.dat` file (e.g. `geoip.dat` or `geosite.dat`).
        #[arg(value_name = "INPUT")]
        input: PathBuf,
        /// Country or category code to extract (e.g. `cn`, `google`, `apple`).
        #[arg(short, long, value_name = "CODE")]
        code: String,
        /// Output path for the converted `.drb` binary.
        #[arg(short, long, value_name = "OUTPUT")]
        output: PathBuf,
        /// Format type of the .dat file (`geosite` or `geoip`). Auto-detected if omitted.
        #[arg(short, long, value_name = "TYPE")]
        r#type: Option<DatType>,
        /// Rule set name. Defaults to code or `<type>-<code>`.
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum DatType {
    Geosite,
    Geoip,
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
        } => compile_rules(&input, &output, name.as_deref()),
        Command::Inspect { input } => inspect_drb(&input),
        Command::Convert {
            input,
            code,
            output,
            r#type,
            name,
        } => convert_dat(&input, &code, &output, r#type, name.as_deref()),
        Command::Test { input, target } => test_drb(&input, &target),
    }
}

fn read_input_text(path: &Path) -> anyhow::Result<(String, String)> {
    if path.as_os_str() == "-" {
        let mut buffer = String::new();
        io::stdin()
            .read_to_string(&mut buffer)
            .context("failed to read from standard input")?;
        Ok(("rules".to_string(), buffer))
    } else {
        let default_name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("rules")
            .to_string();
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        Ok((default_name, content))
    }
}

fn compile_rules(input: &Path, output: &Path, explicit_name: Option<&str>) -> anyhow::Result<()> {
    let (default_name, text) = read_input_text(input)?;
    let set_name = explicit_name.unwrap_or(&default_name);
    let set = DrbSet::from_text(set_name, &text)
        .map_err(|e| anyhow::anyhow!("failed to parse rules: {e}"))?;

    let bytes = set.encode();
    fs::write(output, &bytes)
        .with_context(|| format!("failed to write output to {}", output.display()))?;

    let summary = DrbSet::inspect_bytes(&bytes)
        .map_err(|e| anyhow::anyhow!("failed to inspect generated binary: {e}"))?;

    print_summary(output, &summary);
    Ok(())
}

fn inspect_drb(input: &Path) -> anyhow::Result<()> {
    let bytes = fs::read(input).with_context(|| format!("failed to read {}", input.display()))?;
    let summary = DrbSet::inspect_bytes(&bytes)
        .map_err(|e| anyhow::anyhow!("invalid DRB file {}: {e}", input.display()))?;

    print_summary(input, &summary);
    Ok(())
}

fn print_summary(path: &Path, summary: &DrbSummary) {
    println!("{}: ok", path.display());
    println!("  name:             {}", summary.name);
    println!("  version:          {}", summary.version);
    println!("  v4 intervals:     {}", summary.v4_intervals);
    println!("  v6 intervals:     {}", summary.v6_intervals);
    println!("  ip prefixes:      {}", summary.prefixes);
    println!("  domain suffix:    {}", summary.domain_suffix);
    println!("  domain full:      {}", summary.domain_full);
    println!("  domain keyword:   {}", summary.domain_keyword);
    println!("  domain regex:     {}", summary.domain_regex);
    println!("  total domains:    {}", summary.total_domains);
    println!("  binary size:      {} bytes", summary.file_size);
    println!("  sha256:           {}", summary.checksum);
}

fn detect_dat_type(path: &Path, explicit: Option<DatType>) -> DatType {
    if let Some(t) = explicit {
        return t;
    }
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();

    if file_name.contains("geoip") {
        DatType::Geoip
    } else {
        DatType::Geosite
    }
}

fn convert_dat(
    input: &Path,
    code: &str,
    output: &Path,
    explicit_type: Option<DatType>,
    explicit_name: Option<&str>,
) -> anyhow::Result<()> {
    let dat_type = detect_dat_type(input, explicit_type);
    let default_name = code.to_string();
    let name = explicit_name.unwrap_or(&default_name);

    let set = match dat_type {
        DatType::Geoip => {
            let geoip = unmarshal_geoip(input, code).with_context(|| {
                format!(
                    "failed to read geoip code '{code}' from {}",
                    input.display()
                )
            })?;

            let mut prefixes = Vec::with_capacity(geoip.cidrs.len());
            for cidr in geoip.cidrs {
                let ip_addr =
                    match cidr.ip.len() {
                        4 => {
                            let octets: [u8; 4] = cidr.ip.as_slice().try_into().map_err(|_| {
                                anyhow::anyhow!("invalid IPv4 length in geoip CIDR")
                            })?;
                            IpAddr::from(octets)
                        }
                        16 => {
                            let octets: [u8; 16] = cidr.ip.as_slice().try_into().map_err(|_| {
                                anyhow::anyhow!("invalid IPv6 length in geoip CIDR")
                            })?;
                            IpAddr::from(octets)
                        }
                        len => bail!("unsupported IP length {len} in geoip entry"),
                    };
                let prefix_len = u8::try_from(cidr.prefix)
                    .map_err(|_| anyhow::anyhow!("invalid prefix length: {}", cidr.prefix))?;
                let net = IpNet::new(ip_addr, prefix_len)
                    .map_err(|e| anyhow::anyhow!("invalid CIDR {ip_addr}/{prefix_len}: {e}"))?;
                prefixes.push(net);
            }
            DrbSet::from_prefixes(name, &prefixes)
        }
        DatType::Geosite => {
            let geosite = unmarshal_geosite(input, code).with_context(|| {
                format!(
                    "failed to read geosite code '{code}' from {}",
                    input.display()
                )
            })?;

            let mut full = Vec::new();
            let mut suffix = Vec::new();
            let mut keyword = Vec::new();
            let mut regex = Vec::new();

            for domain in geosite.domains {
                match domain.domain_type {
                    DomainType::Full => full.push(domain.value),
                    DomainType::RootDomain => {
                        suffix.push((domain.value, SuffixScope::SelfAndSubdomains));
                    }
                    DomainType::Plain => keyword.push(domain.value),
                    DomainType::Regex => regex.push(domain.value),
                    DomainType::Unknown(_) => {}
                }
            }
            DrbSet::from_patterns(name, full, suffix, keyword, regex)
        }
    };

    let bytes = set.encode();
    fs::write(output, &bytes)
        .with_context(|| format!("failed to write output to {}", output.display()))?;

    let summary = DrbSet::inspect_bytes(&bytes)
        .map_err(|e| anyhow::anyhow!("failed to inspect generated binary: {e}"))?;

    print_summary(output, &summary);
    Ok(())
}

fn test_drb(input: &Path, target: &str) -> anyhow::Result<()> {
    let bytes = fs::read(input).with_context(|| format!("failed to read {}", input.display()))?;
    let set = DrbSet::decode(&bytes)
        .map_err(|e| anyhow::anyhow!("invalid DRB file {}: {e}", input.display()))?;

    let target_trimmed = target.trim();
    if let Ok(ip) = target_trimmed.parse::<IpAddr>() {
        let ip_index = set.to_ip_index();
        let matched = ip_index.as_ref().is_some_and(|idx| idx.contains(ip));

        if matched {
            println!("matched: {target_trimmed}");
            println!("  rule set : {}", set.name);
            println!("  kind     : IP");
            if let Some(prefix) = set.prefixes.iter().find(|p| p.contains(&ip)) {
                println!("  matched  : prefix {prefix}");
            } else {
                println!("  matched  : IP interval");
            }
            Ok(())
        } else {
            println!(
                "not matched: {target_trimmed} not in rule set '{}'",
                set.name
            );
            bail!("target did not match any rule in {}", input.display());
        }
    } else {
        // Domain match
        let domain_index = set.to_domain_index();
        let matched = domain_index
            .as_ref()
            .is_some_and(|idx| idx.matches(target_trimmed));

        if matched {
            println!("matched: {target_trimmed}");
            println!("  rule set : {}", set.name);
            println!("  kind     : Domain");

            // Pinpoint the matched pattern for enhanced diagnostics
            let target_lower = target_trimmed.to_ascii_lowercase();
            if let Some(f) = set
                .domain_full
                .iter()
                .find(|item| item.eq_ignore_ascii_case(&target_lower))
            {
                println!("  matched  : full '{f}'");
            } else if let Some((s, scope)) = set.domain_suffix.iter().find(|(s, scope)| match scope
            {
                SuffixScope::SelfAndSubdomains => {
                    target_lower == *s || target_lower.ends_with(&format!(".{s}"))
                }
                SuffixScope::SubdomainsOnly => {
                    target_lower.ends_with(&format!(".{s}")) && target_lower != *s
                }
            }) {
                println!("  matched  : suffix '{s}' ({scope:?})");
            } else if let Some(k) = set
                .domain_keyword
                .iter()
                .find(|item| target_lower.contains(item.as_str()))
            {
                println!("  matched  : keyword '{k}'");
            } else if let Some(r) = set
                .domain_regex
                .iter()
                .find(|r| regex::Regex::new(r).is_ok_and(|re| re.is_match(target_trimmed)))
            {
                println!("  matched  : regex '{r}'");
            }

            Ok(())
        } else {
            println!(
                "not matched: {target_trimmed} not in rule set '{}'",
                set.name
            );
            bail!("target did not match any rule in {}", input.display());
        }
    }
}
