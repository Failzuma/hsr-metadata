use super::methods::MethodDef;
use super::types::TypeDef;
use crate::discovery::mhy::MhyHeader;
use crate::discovery::profile::BuildProfile;
use byteorder::{ByteOrder, LittleEndian};
use std::collections::HashMap;

pub struct MethodMappingEntry {
    pub method_idx: u32,
    pub pointer: u64,
}

pub fn extract_method_mappings(
    global_body: &[u8],
    dll: &[u8],
    mhy: &MhyHeader,
    types: &[TypeDef],
    methods: &[MethodDef],
    profile: &BuildProfile,
) -> Vec<MethodMappingEntry> {
    let t42_base = mhy.table42_base();
    let t42_count = mhy.table42_count();
    let mut t42_map = HashMap::with_capacity(t42_count);

    for i in 0..t42_count {
        let off = t42_base + i * 6;
        if off + 6 <= global_body.len() {
            let midx = LittleEndian::read_i32(&global_body[off..]) as usize;
            let pidx = LittleEndian::read_u16(&global_body[off + 4..]) as usize;
            t42_map.insert(midx, pidx);
        }
    }

    let p58_off = profile.primary_method_pointer_file_offset;
    let p17_off = profile.fallback_method_pointer_file_offset;

    let mut unavailable = vec![false; methods.len()];
    for type_definition in types {
        if type_definition.generic_container_index < 0 {
            continue;
        }
        let start = type_definition.m_start as usize;
        let end = start
            .saturating_add(type_definition.m_count as usize)
            .min(unavailable.len());
        if start < end {
            unavailable[start..end].fill(true);
        }
    }
    for (index, method) in methods.iter().enumerate() {
        if method.generic_container_index >= 0 || method.flags & 0x0400 != 0 {
            unavailable[index] = true;
        }
    }

    let mut mappings = Vec::with_capacity(methods.len() / 2);

    for (m_idx, is_unavailable) in unavailable.into_iter().enumerate() {
        if is_unavailable {
            continue;
        }
        let mut ptr = 0u64;

        if let Some(&pidx) = t42_map.get(&m_idx) {
            let off = p58_off + pidx * 8;
            if off + 8 <= dll.len() {
                ptr = LittleEndian::read_u64(&dll[off..]);
            }
        }

        if ptr == 0 {
            let off = p17_off + m_idx * 8;
            if off + 8 <= dll.len() {
                ptr = LittleEndian::read_u64(&dll[off..]);
            }
        }

        if (profile.minimum_method_pointer_va..profile.maximum_method_pointer_va).contains(&ptr) {
            mappings.push(MethodMappingEntry {
                method_idx: m_idx as u32,
                pointer: ptr,
            });
        }
    }

    mappings
}
