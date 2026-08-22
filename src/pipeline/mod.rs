use crate::discovery::discover_from_paths;
use crate::discovery::profile::BuildProfile;
use crate::output::metadata::{build, write};
use crate::reconstruction::decode;
use crate::reconstruction::input::ReconstructionInputs;
use anyhow::{bail, Result};
use std::path::Path;

mod validation;

use validation::validate;

pub struct Reconstructor {
    inputs: ReconstructionInputs,
    profile: BuildProfile,
}

impl Reconstructor {
    pub fn new(
        global_metadata_path: &Path,
        dll_path: &Path,
        startup_metadata_path: &Path,
    ) -> Result<Self> {
        let discovered =
            discover_from_paths(global_metadata_path, dll_path, startup_metadata_path)?;
        Self::with_profile(
            global_metadata_path,
            dll_path,
            startup_metadata_path,
            discovered.profile,
        )
    }

    pub fn with_profile(
        global_metadata_path: &Path,
        dll_path: &Path,
        startup_metadata_path: &Path,
        profile: BuildProfile,
    ) -> Result<Self> {
        let inputs = ReconstructionInputs::load(
            global_metadata_path,
            dll_path,
            startup_metadata_path,
            &profile,
        )?;
        Ok(Self { inputs, profile })
    }

    pub fn run(&self, output_dir: &Path) -> Result<()> {
        println!("[*] Decoding metadata tables...");
        let metadata = decode(&self.inputs, &self.profile);
        let validation = validate(&metadata, &self.profile);
        if !validation.is_valid() {
            let messages = validation
                .errors
                .iter()
                .map(|issue| issue.message.as_str())
                .collect::<Vec<_>>()
                .join("; ");
            bail!("decoded metadata failed validation: {messages}");
        }
        println!(
            "[*] Decoded {} images, {} types, {} fields, {} properties, {} events, {} methods, {} parameters",
            metadata.images.len(),
            metadata.types.len(),
            metadata.fields.len(),
            metadata.properties.len(),
            metadata.events.len(),
            metadata.methods.len(),
            metadata.parameters.len()
        );
        println!(
            "[*] Decoded {} interfaces, {} vtable methods, {} interface offsets",
            metadata.interfaces.len(),
            metadata.vtable_methods.len(),
            metadata.interface_offsets.len()
        );
        println!(
            "[*] Decoded {} generic parameters, {} type containers, {} method containers",
            metadata.generics.gp_names.len(),
            metadata
                .types
                .iter()
                .filter(|value| value.generic_container_index >= 0)
                .count(),
            metadata
                .methods
                .iter()
                .filter(|value| value.generic_container_index >= 0)
                .count()
        );
        let artifacts = build(&metadata);
        let paths = write(output_dir, &artifacts)?;
        println!(
            "[+] Generated {} ({} bytes)",
            paths.rebuilt_metadata.display(),
            artifacts.rebuilt_metadata.len()
        );
        println!(
            "[+] Generated {} ({} entries)",
            paths.field_offsets.display(),
            metadata.field_offsets.len()
        );
        println!(
            "[+] Generated {} ({} entries)",
            paths.method_mappings.display(),
            metadata.method_mappings.len()
        );
        println!(
            "[+] Generated {} ({} entries)",
            paths.generic_classes.display(),
            metadata.generic_classes.len()
        );
        Ok(())
    }
}
