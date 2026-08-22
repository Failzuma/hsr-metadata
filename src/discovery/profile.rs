use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildProfile {
    pub metadata_prefix_size: usize,
    pub type_definition_count: usize,
    pub type_definition_offset: usize,
    pub generic_parameter_count: usize,
    pub generic_container_count: usize,
    pub interface_count: usize,
    pub interface_offset: usize,
    pub string_literal_count: usize,
    pub primary_method_pointer_file_offset: usize,
    pub fallback_method_pointer_file_offset: usize,
    pub minimum_method_pointer_va: u64,
    pub maximum_method_pointer_va: u64,
}

impl BuildProfile {
    pub fn load(path: &Path) -> Result<Self> {
        let data = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        serde_json::from_slice(&data)
            .with_context(|| format!("failed to parse profile {}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_vec_pretty(self)?;
        fs::write(path, data).with_context(|| format!("failed to write {}", path.display()))
    }

    pub fn apply(&mut self, overrides: &ProfileOverrides) {
        macro_rules! assign {
            ($field:ident) => {
                if let Some(value) = overrides.$field {
                    self.$field = value;
                }
            };
        }
        assign!(metadata_prefix_size);
        assign!(type_definition_count);
        assign!(type_definition_offset);
        assign!(generic_parameter_count);
        assign!(generic_container_count);
        assign!(interface_count);
        assign!(interface_offset);
        assign!(string_literal_count);
        assign!(primary_method_pointer_file_offset);
        assign!(fallback_method_pointer_file_offset);
        assign!(minimum_method_pointer_va);
        assign!(maximum_method_pointer_va);
    }
}

#[derive(Clone, Debug, Default)]
pub struct ProfileOverrides {
    pub metadata_prefix_size: Option<usize>,
    pub type_definition_count: Option<usize>,
    pub type_definition_offset: Option<usize>,
    pub generic_parameter_count: Option<usize>,
    pub generic_container_count: Option<usize>,
    pub interface_count: Option<usize>,
    pub interface_offset: Option<usize>,
    pub string_literal_count: Option<usize>,
    pub primary_method_pointer_file_offset: Option<usize>,
    pub fallback_method_pointer_file_offset: Option<usize>,
    pub minimum_method_pointer_va: Option<u64>,
    pub maximum_method_pointer_va: Option<u64>,
}
