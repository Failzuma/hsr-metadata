use anyhow::{bail, Context};
use clap::{Args as ClapArgs, Parser};
use star_rail_metadata_reconstructor::discovery::discover_from_paths;
use star_rail_metadata_reconstructor::{BuildProfile, ProfileOverrides, Reconstructor};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "StarRailMetadataReconstructor")]
#[command(version = "1.0")]
#[command(about = "High-performance Star Rail Il2Cpp metadata reconstructor")]
struct Args {
    #[arg(help = "Path to global-metadata.dat")]
    metadata: PathBuf,
    #[arg(help = "Path to GameAssembly.dll")]
    dll: PathBuf,
    #[arg(help = "Path to startup-metadata.dat (optional, default: same directory as metadata)")]
    startup: Option<PathBuf>,
    #[arg(short, long, help = "Output directory (default: current directory)")]
    output_dir: Option<PathBuf>,
    #[arg(long, help = "Load a build profile from JSON")]
    profile: Option<PathBuf>,
    #[arg(long, help = "Write the resolved build profile to JSON")]
    write_profile: Option<PathBuf>,
    #[arg(long, help = "Write automatic discovery evidence to JSON")]
    discovery_report: Option<PathBuf>,
    #[arg(long, help = "Write the discovered Il2Cpp runtime profile to JSON")]
    write_runtime_profile: Option<PathBuf>,
    #[command(flatten)]
    overrides: ProfileArgs,
}

#[derive(ClapArgs, Default)]
struct ProfileArgs {
    #[arg(long, value_parser = parse_usize)]
    metadata_prefix_size: Option<usize>,
    #[arg(long, value_parser = parse_usize)]
    type_definition_count: Option<usize>,
    #[arg(long, value_parser = parse_usize)]
    type_definition_offset: Option<usize>,
    #[arg(long, value_parser = parse_usize)]
    generic_parameter_count: Option<usize>,
    #[arg(long, value_parser = parse_usize)]
    generic_container_count: Option<usize>,
    #[arg(long, value_parser = parse_usize)]
    interface_count: Option<usize>,
    #[arg(long, value_parser = parse_usize)]
    interface_offset: Option<usize>,
    #[arg(long, value_parser = parse_usize)]
    string_literal_count: Option<usize>,
    #[arg(long, value_parser = parse_usize)]
    primary_method_pointer_file_offset: Option<usize>,
    #[arg(long, value_parser = parse_usize)]
    fallback_method_pointer_file_offset: Option<usize>,
    #[arg(long, value_parser = parse_u64)]
    minimum_method_pointer_va: Option<u64>,
    #[arg(long, value_parser = parse_u64)]
    maximum_method_pointer_va: Option<u64>,
}

impl From<ProfileArgs> for ProfileOverrides {
    fn from(value: ProfileArgs) -> Self {
        Self {
            metadata_prefix_size: value.metadata_prefix_size,
            type_definition_count: value.type_definition_count,
            type_definition_offset: value.type_definition_offset,
            generic_parameter_count: value.generic_parameter_count,
            generic_container_count: value.generic_container_count,
            interface_count: value.interface_count,
            interface_offset: value.interface_offset,
            string_literal_count: value.string_literal_count,
            primary_method_pointer_file_offset: value.primary_method_pointer_file_offset,
            fallback_method_pointer_file_offset: value.fallback_method_pointer_file_offset,
            minimum_method_pointer_va: value.minimum_method_pointer_va,
            maximum_method_pointer_va: value.maximum_method_pointer_va,
        }
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let startup_path = args.startup.unwrap_or_else(|| {
        args.metadata
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("startup-metadata.dat")
    });
    let output_dir = args.output_dir.unwrap_or_else(|| PathBuf::from("."));
    let (mut profile, mut discovered) = if let Some(path) = args.profile {
        (BuildProfile::load(&path)?, None)
    } else {
        let discovered = discover_from_paths(&args.metadata, &args.dll, &startup_path)?;
        println!(
            "[*] Auto profile: MHY at {:#x}, metadata prefix {}, {} images",
            discovered.evidence.mhy_file_offset,
            discovered.evidence.metadata_prefix_size,
            discovered.evidence.image_count
        );
        if let Some(path) = args.discovery_report {
            write_json(&path, &discovered.evidence)?;
        }
        if let Some(path) = args.write_runtime_profile {
            let runtime = discovered
                .evidence
                .runtime
                .as_ref()
                .context("runtime profile discovery was ambiguous or incomplete")?;
            write_json(&path, runtime)?;
        }
        (discovered.profile.clone(), Some(discovered))
    };
    profile.apply(&args.overrides.into());
    validate_profile(&profile)?;
    if let Some(path) = args.write_profile {
        profile.save(&path)?;
    }
    let reconstructor = if let Some(mut resolved) = discovered.take() {
        resolved.profile = profile;
        Reconstructor::with_discovered(&args.metadata, &args.dll, &startup_path, resolved)?
    } else {
        Reconstructor::with_profile(&args.metadata, &args.dll, &startup_path, profile)?
    };
    reconstructor.run(&output_dir)
}

fn validate_profile(profile: &BuildProfile) -> anyhow::Result<()> {
    if profile.type_definition_count == 0 {
        bail!("type definition count must not be zero");
    }
    if profile.minimum_method_pointer_va >= profile.maximum_method_pointer_va {
        bail!("method pointer VA range is empty");
    }
    Ok(())
}

fn write_json(path: &Path, value: &impl serde::Serialize) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(value)?)
        .with_context(|| format!("failed to write {}", path.display()))
}

fn parse_usize(value: &str) -> Result<usize, String> {
    parse_u64(value).and_then(|value| usize::try_from(value).map_err(|error| error.to_string()))
}

fn parse_u64(value: &str) -> Result<u64, String> {
    let value = value.replace('_', "");
    if let Some(value) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(value, 16).map_err(|error| error.to_string())
    } else {
        value.parse::<u64>().map_err(|error| error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_u64, parse_usize};

    #[test]
    fn profile_numbers_accept_decimal_hex_and_separators() {
        assert_eq!(parse_usize("76_920").unwrap(), 76_920);
        assert_eq!(parse_usize("0x12C78").unwrap(), 76_920);
        assert_eq!(parse_u64("0x180001000").unwrap(), 0x180001000);
    }
}
