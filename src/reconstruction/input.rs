use crate::discovery::mhy::MhyHeader;
use crate::discovery::profile::BuildProfile;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

pub struct ReconstructionInputs {
    pub global_body: Vec<u8>,
    pub dll: Vec<u8>,
    pub startup_metadata: Vec<u8>,
    pub mhy: MhyHeader,
}

impl ReconstructionInputs {
    pub fn load(
        global_metadata_path: &Path,
        dll_path: &Path,
        startup_metadata_path: &Path,
        profile: &BuildProfile,
    ) -> Result<Self> {
        let dll =
            fs::read(dll_path).with_context(|| format!("Failed to read {}", dll_path.display()))?;
        let metadata = fs::read(global_metadata_path)
            .with_context(|| format!("Failed to read {}", global_metadata_path.display()))?;
        let global_body = if metadata.len() > profile.metadata_prefix_size {
            metadata[profile.metadata_prefix_size..].to_vec()
        } else {
            metadata
        };
        let startup_metadata = fs::read(startup_metadata_path)
            .with_context(|| format!("Failed to read {}", startup_metadata_path.display()))?;
        let mut matching_headers = MhyHeader::candidates(&dll).into_iter().filter(|header| {
            (header.values[33] ^ 0x6853_1d3f) as usize == profile.type_definition_offset
                && header.image_count() > 0
                && header
                    .image_count()
                    .checked_mul(40)
                    .and_then(|size| size.checked_add(header.image_off()))
                    .is_some_and(|end| end <= startup_metadata.len())
        });
        let mhy = matching_headers
            .next()
            .or_else(|| MhyHeader::parse(&dll).ok())
            .ok_or_else(|| anyhow::anyhow!("no MHY header matches the resolved build profile"))?;
        Ok(Self {
            global_body,
            dll,
            startup_metadata,
            mhy,
        })
    }
}
