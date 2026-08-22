pub(crate) mod mhy;
pub(crate) mod pe;
pub mod profile;

use crate::reconstruction::images::decrypt_images;
use crate::reconstruction::literals::discover_count as discover_string_literal_count;
use crate::reconstruction::strings::StringDecryptor;
use crate::reconstruction::types::decode_interface_ranges;
use anyhow::{bail, Context, Result};
use byteorder::{ByteOrder, LittleEndian};
use iced_x86::{Decoder, DecoderOptions, Mnemonic};
use mhy::MhyHeader;
use pe::PeImage;
use profile::BuildProfile;
use serde::Serialize;
use std::fs;
use std::path::Path;

#[derive(Clone, Debug, Serialize)]
pub struct DiscoveryEvidence {
    pub mhy_file_offset: usize,
    pub metadata_prefix_size: usize,
    pub image_count: usize,
    pub interface_range_upper_bound: usize,
    pub executable_va_minimum: u64,
    pub executable_va_maximum: u64,
    pub code_registration_file_offset: Option<usize>,
    pub runtime: Option<RuntimeProfile>,
    pub discovered_fields: Vec<String>,
    pub legacy_fallback_fields: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct DiscoveredProfile {
    pub profile: BuildProfile,
    pub evidence: DiscoveryEvidence,
}

#[derive(Clone, Debug, Serialize)]
pub struct RuntimeProfile {
    pub code_registration_va: u64,
    pub metadata_registration_va: u64,
    pub method_pointers_va: u64,
    pub method_pointers_count: usize,
    pub types_va: u64,
    pub types_count: usize,
    pub generic_insts_va: u64,
    pub generic_insts_count: usize,
    pub generic_insts_are_inline: bool,
    pub types_are_inline: bool,
    pub generic_class_source_offset: usize,
    pub generic_class_count: usize,
}

pub fn discover_from_paths(
    metadata: &Path,
    dll: &Path,
    startup: &Path,
) -> Result<DiscoveredProfile> {
    let metadata =
        fs::read(metadata).with_context(|| format!("failed to read {}", metadata.display()))?;
    let dll = fs::read(dll).with_context(|| format!("failed to read {}", dll.display()))?;
    let startup =
        fs::read(startup).with_context(|| format!("failed to read {}", startup.display()))?;
    discover(&metadata, &dll, &startup)
}

pub fn discover(metadata: &[u8], dll: &[u8], startup: &[u8]) -> Result<DiscoveredProfile> {
    let pe = PeImage::parse(dll)?;
    let (minimum_method_pointer_va, maximum_method_pointer_va) = pe.executable_va_range()?;
    let candidates = MhyHeader::candidates(dll);
    if candidates.is_empty() {
        bail!("MHY header signature not found in GameAssembly.dll");
    }
    let mut matches = Vec::new();
    for mhy in candidates {
        if let Some((prefix, score)) = discover_prefix(metadata, startup, &mhy) {
            matches.push((score, prefix, mhy));
        }
    }
    matches.sort_by_key(|entry| std::cmp::Reverse(entry.0));
    if matches.len() > 1 && matches[0].0 == matches[1].0 {
        bail!(
            "automatic profile discovery is ambiguous between MHY headers at {:#x} and {:#x}",
            matches[0].2.file_offset,
            matches[1].2.file_offset
        );
    }
    let Some((score, metadata_prefix_size, mhy)) = matches.into_iter().next() else {
        bail!("no MHY candidate produced valid metadata tables");
    };
    if score < 8 {
        bail!("MHY discovery confidence is too low ({score})");
    }
    let global_body = &metadata[metadata_prefix_size..];
    let decryptor = StringDecryptor::new(global_body, mhy.string_table_off());
    let images = decrypt_images(startup, &mhy, &decryptor);
    let type_definition_count = images
        .iter()
        .try_fold(0usize, |total, image| {
            total.checked_add(image.type_count as usize)
        })
        .context("image type count overflow")?;
    if type_definition_count == 0 || type_definition_count > 10_000_000 {
        bail!("discovered implausible type count {type_definition_count}");
    }
    let type_definition_offset = (mhy.values[33] ^ 0x6853_1d3f) as usize;
    let type_bytes = type_definition_count
        .checked_mul(70)
        .and_then(|size| type_definition_offset.checked_add(size))
        .context("type table size overflow")?;
    if type_bytes > global_body.len() {
        bail!("discovered type table exceeds global metadata");
    }
    let interface_range_upper_bound =
        interface_range_upper_bound(global_body, type_definition_offset, type_definition_count);
    let interface_offset = mhy.interface_table_base();
    let interface_end = interface_range_upper_bound
        .checked_mul(4)
        .and_then(|size| interface_offset.checked_add(size))
        .context("interface table size overflow")?;
    if interface_end > global_body.len() {
        bail!("discovered interface table exceeds global metadata");
    }
    let method_pointer_tables = discover_method_pointer_tables(global_body, dll, &mhy, &pe);
    let mut profile = BuildProfile::legacy_current();
    profile.metadata_prefix_size = metadata_prefix_size;
    profile.type_definition_count = type_definition_count;
    profile.type_definition_offset = type_definition_offset;
    profile.interface_count = interface_range_upper_bound;
    profile.interface_offset = interface_offset;
    profile.string_literal_count = discover_string_literal_count(global_body, &mhy)
        .context("failed to discover managed string literal count")?;
    profile.minimum_method_pointer_va = minimum_method_pointer_va;
    profile.maximum_method_pointer_va = maximum_method_pointer_va;
    let code_registration_file_offset = method_pointer_tables.as_ref().map(|tables| {
        profile.primary_method_pointer_file_offset = tables.primary;
        profile.fallback_method_pointer_file_offset = tables.fallback;
        tables.registration
    });
    let runtime = method_pointer_tables.as_ref().and_then(|tables| {
        discover_runtime_profile(
            global_body,
            startup,
            dll,
            &mhy,
            &pe,
            tables,
            type_definition_count,
        )
    });
    let generic_counts = runtime
        .as_ref()
        .and_then(|runtime| discover_generic_metadata_counts(global_body, &mhy, dll, &pe, runtime));
    if let Some((parameter_count, container_count)) = generic_counts {
        profile.generic_parameter_count = parameter_count;
        profile.generic_container_count = container_count;
    }
    let mut discovered_fields = vec![
        "metadata_prefix_size".into(),
        "type_definition_count".into(),
        "type_definition_offset".into(),
        "interface_count".into(),
        "interface_offset".into(),
        "string_literal_count".into(),
        "minimum_method_pointer_va".into(),
        "maximum_method_pointer_va".into(),
    ];
    let mut legacy_fallback_fields = Vec::new();
    if generic_counts.is_some() {
        discovered_fields.push("generic_parameter_count".into());
        discovered_fields.push("generic_container_count".into());
    } else {
        legacy_fallback_fields.push("generic_parameter_count".into());
        legacy_fallback_fields.push("generic_container_count".into());
    }
    if method_pointer_tables.is_some() {
        discovered_fields.push("primary_method_pointer_file_offset".into());
        discovered_fields.push("fallback_method_pointer_file_offset".into());
    } else {
        legacy_fallback_fields.push("primary_method_pointer_file_offset".into());
        legacy_fallback_fields.push("fallback_method_pointer_file_offset".into());
    }
    let evidence = DiscoveryEvidence {
        mhy_file_offset: mhy.file_offset,
        metadata_prefix_size,
        image_count: images.len(),
        interface_range_upper_bound,
        executable_va_minimum: minimum_method_pointer_va,
        executable_va_maximum: maximum_method_pointer_va,
        code_registration_file_offset,
        runtime,
        discovered_fields,
        legacy_fallback_fields,
    };
    Ok(DiscoveredProfile { profile, evidence })
}

fn discover_generic_metadata_counts(
    global_body: &[u8],
    mhy: &MhyHeader,
    dll: &[u8],
    pe: &PeImage,
    runtime: &RuntimeProfile,
) -> Option<(usize, usize)> {
    let types_offset = pe.va_to_file_offset(runtime.types_va)?;
    let mut maximum_parameter = None;
    for index in 0..runtime.types_count {
        let offset = types_offset.checked_add(index.checked_mul(16)?)?;
        let record = dll.get(offset..offset + 16)?;
        let type_kind = (LittleEndian::read_u32(&record[8..]) >> 16) as u8;
        if type_kind != 0x13 && type_kind != 0x1e {
            continue;
        }
        let parameter = usize::try_from(LittleEndian::read_u64(record)).ok()?;
        maximum_parameter =
            Some(maximum_parameter.map_or(parameter, |value: usize| value.max(parameter)));
    }
    let parameter_count = maximum_parameter?.checked_add(1)?;
    let parameter_base = mhy.gp_table_base();
    let parameter_end = parameter_base.checked_add(parameter_count.checked_mul(14)?)?;
    if parameter_end > global_body.len() {
        return None;
    }
    let mut maximum_container = None;
    for index in 0..parameter_count {
        let offset = parameter_base + index * 14;
        let index64 = index as u64;
        let term = (0x617f_e3cc_452cu64
            .wrapping_mul(index64)
            .wrapping_add(0x09dc_5db7_1f0e_b440)
            >> 9)
            .wrapping_add(718_849_585)
            ^ 0x5278_374d;
        let key = ((1_252_900_171u64.wrapping_mul(term)) >> 15) as u32;
        let encoded = LittleEndian::read_u16(&global_body[offset + 8..]);
        let container = (encoded ^ 0x7526).wrapping_sub(key as u16) as i16;
        if container < 0 {
            return None;
        }
        let container = container as usize;
        maximum_container =
            Some(maximum_container.map_or(container, |value: usize| value.max(container)));
    }
    let container_count = maximum_container?.checked_add(1)?;
    let container_end = mhy
        .gc_table_base()
        .checked_add(container_count.checked_mul(16)?)?;
    (container_end <= global_body.len()).then_some((parameter_count, container_count))
}

struct MethodPointerTables {
    primary: usize,
    fallback: usize,
    registration: usize,
}

fn discover_method_pointer_tables(
    global_body: &[u8],
    dll: &[u8],
    mhy: &MhyHeader,
    pe: &PeImage,
) -> Option<MethodPointerTables> {
    let table_offset = mhy.table42_base();
    let table_count = mhy.table42_count();
    let table_end = table_offset.checked_add(table_count.checked_mul(6)?)?;
    if table_count == 0 || table_end > global_body.len() {
        return None;
    }
    let required_pointers = (0..table_count)
        .map(|index| LittleEndian::read_u16(&global_body[table_offset + index * 6 + 4..]) as usize)
        .max()?
        .checked_add(1)?;
    let mut primary_candidates = Vec::new();
    for (range_start, range_end) in pe.readable_file_ranges() {
        let end = range_end.min(dll.len());
        let mut run_start = None;
        let mut offset = (range_start + 7) & !7;
        while offset + 8 <= end {
            let pointer = LittleEndian::read_u64(&dll[offset..]);
            if pe.is_executable_va(pointer) {
                run_start.get_or_insert(offset);
            } else if let Some(start) = run_start.take() {
                if (offset - start) / 8 == required_pointers {
                    primary_candidates.push(start);
                }
            }
            offset += 8;
        }
        if let Some(start) = run_start {
            if (offset - start) / 8 == required_pointers {
                primary_candidates.push(start);
            }
        }
    }
    let mut results = Vec::new();
    for primary in primary_candidates {
        let primary_va = pe.file_offset_to_va(primary)?;
        for reference in find_qword(dll, primary_va) {
            let Some(registration) = reference.checked_sub(0x58) else {
                continue;
            };
            let fallback_pointer_offset = registration.checked_add(0x88)?;
            let Some(bytes) = dll.get(fallback_pointer_offset..fallback_pointer_offset + 8) else {
                continue;
            };
            let fallback_va = LittleEndian::read_u64(bytes);
            let Some(fallback) = pe.va_to_file_offset(fallback_va) else {
                continue;
            };
            if validate_pointer_table(dll, fallback, required_pointers.min(4096), pe) {
                results.push(MethodPointerTables {
                    primary,
                    fallback,
                    registration,
                });
            }
        }
    }
    (results.len() == 1).then(|| results.remove(0))
}

fn find_qword(data: &[u8], value: u64) -> Vec<usize> {
    let bytes = value.to_le_bytes();
    data.windows(8)
        .enumerate()
        .filter_map(|(offset, candidate)| (candidate == bytes).then_some(offset))
        .collect()
}

fn validate_pointer_table(data: &[u8], offset: usize, count: usize, pe: &PeImage) -> bool {
    let Some(end) = offset.checked_add(count.saturating_mul(8)) else {
        return false;
    };
    let Some(table) = data.get(offset..end) else {
        return false;
    };
    table.chunks_exact(8).all(|bytes| {
        let value = LittleEndian::read_u64(bytes);
        value == 0 || pe.is_executable_va(value)
    })
}

fn discover_runtime_profile(
    global_body: &[u8],
    startup: &[u8],
    dll: &[u8],
    mhy: &MhyHeader,
    pe: &PeImage,
    tables: &MethodPointerTables,
    type_definition_count: usize,
) -> Option<RuntimeProfile> {
    let code_registration_va = pe.file_offset_to_va(tables.registration)?;
    let metadata_registration_va = find_metadata_registration(dll, pe, code_registration_va)?;
    let metadata_registration = pe.va_to_file_offset(metadata_registration_va)?;
    let generic_insts_va = read_u64_at(dll, metadata_registration.checked_add(0x20)?)?;
    let generic_insts_are_inline = discover_generic_inst_layout(dll, pe, generic_insts_va)?;
    let types_va = read_u64_at(dll, metadata_registration.checked_add(0x68)?)?;
    let types_offset = pe.va_to_file_offset(types_va)?;
    let types_are_inline = discover_type_layout(dll, pe, types_va)?;
    if !types_are_inline {
        return None;
    }
    let types_count = discover_types_count(dll, types_offset);
    if types_count == 0 {
        return None;
    }
    let method_pointers_va = read_u64_at(dll, tables.registration.checked_add(8)?)?;
    pe.va_to_file_offset(method_pointers_va)?;
    let method_pointers_count = discover_method_count(global_body, mhy, type_definition_count);
    let generic_class_count = ((mhy.values[47] >> 3) ^ 0x079f_c2ec) as usize;
    let generic_class_source_offset = (mhy.values[89] ^ 0x7f5c_5934) as usize;
    let source_end =
        generic_class_source_offset.checked_add(generic_class_count.checked_mul(8)?)?;
    let source = startup.get(generic_class_source_offset..source_end)?;
    let generic_insts_count = source
        .chunks_exact(8)
        .filter_map(|record| {
            let value = LittleEndian::read_i32(&record[4..]);
            (value >= 0).then_some(value as usize)
        })
        .max()?
        .checked_add(1)?;
    Some(RuntimeProfile {
        code_registration_va,
        metadata_registration_va,
        method_pointers_va,
        method_pointers_count,
        types_va,
        types_count,
        generic_insts_va,
        generic_insts_count,
        generic_insts_are_inline,
        types_are_inline,
        generic_class_source_offset,
        generic_class_count,
    })
}

fn discover_generic_inst_layout(dll: &[u8], pe: &PeImage, table_va: u64) -> Option<bool> {
    let table_offset = pe.va_to_file_offset(table_va)?;
    if valid_generic_inst_record(dll, pe, table_offset) {
        return Some(true);
    }
    let first_pointer = read_u64_at(dll, table_offset)?;
    let first_offset = pe.va_to_file_offset(first_pointer)?;
    valid_generic_inst_record(dll, pe, first_offset).then_some(false)
}

fn valid_generic_inst_record(dll: &[u8], pe: &PeImage, offset: usize) -> bool {
    let Some(record) = dll.get(offset..offset + 16) else {
        return false;
    };
    let count = LittleEndian::read_u64(record);
    let arguments = LittleEndian::read_u64(&record[8..]);
    count <= 1024 && (count == 0 || pe.va_to_file_offset(arguments).is_some())
}

fn discover_type_layout(dll: &[u8], pe: &PeImage, table_va: u64) -> Option<bool> {
    let table_offset = pe.va_to_file_offset(table_va)?;
    if valid_type_record(dll, table_offset) {
        return Some(true);
    }
    let first_pointer = read_u64_at(dll, table_offset)?;
    let first_offset = pe.va_to_file_offset(first_pointer)?;
    valid_type_record(dll, first_offset).then_some(false)
}

fn valid_type_record(dll: &[u8], offset: usize) -> bool {
    let Some(record) = dll.get(offset..offset + 16) else {
        return false;
    };
    let kind = (LittleEndian::read_u32(&record[8..]) >> 16) as u8;
    matches!(kind, 0x01..=0x21 | 0x40 | 0x41 | 0x45 | 0x55)
}

fn find_metadata_registration(dll: &[u8], pe: &PeImage, code_registration_va: u64) -> Option<u64> {
    let mut matches = Vec::new();
    for (start, section_end, section_va) in pe.executable_mapped_ranges() {
        let end = section_end.min(dll.len());
        let bytes = dll.get(start..end)?;
        for (index, window) in bytes.windows(7).enumerate() {
            if window[0] & 0xf0 != 0x40 || window[1] != 0x8d || window[2] & 0xc7 != 0x05 {
                continue;
            }
            let displacement = LittleEndian::read_i32(&window[3..]) as i64;
            let next_ip = section_va.checked_add(index as u64)?.checked_add(7)?;
            if next_ip.wrapping_add_signed(displacement) != code_registration_va {
                continue;
            }
            let code = &bytes[index..bytes.len().min(index + 64)];
            let mut decoder =
                Decoder::with_ip(64, code, section_va + index as u64, DecoderOptions::NONE);
            let _ = decoder.decode();
            for _ in 0..4 {
                if !decoder.can_decode() {
                    break;
                }
                let instruction = decoder.decode();
                if instruction.mnemonic() != Mnemonic::Lea
                    || !instruction.is_ip_rel_memory_operand()
                {
                    continue;
                }
                let candidate = instruction.ip_rel_memory_address();
                if validate_metadata_registration(dll, pe, candidate) {
                    matches.push(candidate);
                }
                break;
            }
        }
    }
    matches.sort_unstable();
    matches.dedup();
    (matches.len() == 1).then_some(matches[0])
}

fn validate_metadata_registration(dll: &[u8], pe: &PeImage, address: u64) -> bool {
    let Some(offset) = pe.va_to_file_offset(address) else {
        return false;
    };
    let Some(generic_insts) = offset
        .checked_add(0x20)
        .and_then(|value| read_u64_at(dll, value))
    else {
        return false;
    };
    let Some(types) = offset
        .checked_add(0x68)
        .and_then(|value| read_u64_at(dll, value))
    else {
        return false;
    };
    pe.va_to_file_offset(generic_insts).is_some() && pe.va_to_file_offset(types).is_some()
}

fn discover_types_count(dll: &[u8], offset: usize) -> usize {
    let valid_types = [
        0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x18, 0x19, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        0x21, 0x40, 0x41, 0x45, 0x55,
    ];
    let mut count = 0usize;
    while let Some(record) = offset
        .checked_add(count.saturating_mul(16))
        .and_then(|start| dll.get(start..start + 16))
    {
        let bits = LittleEndian::read_u32(&record[8..]);
        let kind = ((bits >> 16) & 0xff) as u8;
        if LittleEndian::read_u32(&record[12..]) != 0 || !valid_types.contains(&kind) {
            break;
        }
        count += 1;
    }
    count
}

fn discover_method_count(
    global_body: &[u8],
    mhy: &MhyHeader,
    type_definition_count: usize,
) -> usize {
    let type_offset = (mhy.values[33] ^ 0x6853_1d3f) as usize;
    let mut maximum = 0usize;
    let available = global_body.len().saturating_sub(type_offset) / 70;
    for index in 0..available.min(type_definition_count) {
        let offset = type_offset + index * 70;
        let start = LittleEndian::read_u32(&global_body[offset + 8..]) ^ 0x1a7a_f5fe;
        let count = LittleEndian::read_u16(&global_body[offset + 52..]).wrapping_add(24_467);
        if start < 10_000_000 {
            maximum = maximum.max(start as usize + count as usize);
        }
    }
    maximum
}

fn read_u64_at(data: &[u8], offset: usize) -> Option<u64> {
    data.get(offset..offset + 8).map(LittleEndian::read_u64)
}

fn discover_prefix(metadata: &[u8], startup: &[u8], mhy: &MhyHeader) -> Option<(usize, usize)> {
    let image_count = mhy.image_count();
    let image_offset = mhy.image_off();
    let image_end = image_count.checked_mul(40)?.checked_add(image_offset)?;
    if image_count == 0 || image_count > 10_000 || image_end > startup.len() {
        return None;
    }
    let string_offset = mhy.string_table_off();
    let maximum_prefix = metadata.len().min(4096);
    let mut best = None;
    let mut tied = false;
    for prefix in (0..=maximum_prefix).step_by(4) {
        let body = &metadata[prefix..];
        if string_offset >= body.len() {
            continue;
        }
        let decryptor = StringDecryptor::new(body, string_offset);
        let images = decrypt_images(startup, mhy, &decryptor);
        let mut score = 0usize;
        for image in images.iter().take(16) {
            if image.name.ends_with(".dll") {
                score += 3;
            }
            if !image.name.starts_with("Image_")
                && image.name.bytes().all(|value| value.is_ascii_graphic())
            {
                score += 1;
            }
            if image.type_count < 1_000_000 {
                score += 1;
            }
        }
        if best
            .as_ref()
            .is_none_or(|(_, best_score)| score > *best_score)
        {
            best = Some((prefix, score));
            tied = false;
        } else if best
            .as_ref()
            .is_some_and(|(_, best_score)| score == *best_score)
        {
            tied = true;
        }
    }
    (!tied).then_some(best).flatten()
}

fn interface_range_upper_bound(body: &[u8], type_offset: usize, type_count: usize) -> usize {
    decode_interface_ranges(body, type_offset, type_count)
        .into_iter()
        .filter(|range| range.count != 0)
        .map(|range| range.start + range.count)
        .max()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{discover_types_count, interface_range_upper_bound};

    #[test]
    fn interface_range_bound_uses_direct_interface_counts() {
        let mut body = vec![0u8; 280];
        body[68] = 0xc7;
        body[54..56].copy_from_slice(&(0xc28cu16 ^ 0xffff).to_le_bytes());
        body[138] = 0xc5;
        body[124..126].copy_from_slice(&(0xc28cu16 ^ 7).to_le_bytes());
        body[208] = 0xc6;
        body[194..196].copy_from_slice(&(0xc28cu16 ^ 2).to_le_bytes());
        body[278] = 0xcf;
        body[264..266].copy_from_slice(&(0xc28cu16 ^ 20).to_le_bytes());
        assert_eq!(interface_range_upper_bound(&body, 0, 4), 28);
    }

    #[test]
    fn type_table_scan_stops_at_invalid_record() {
        let mut data = vec![0u8; 48];
        data[10] = 0x15;
        data[26] = 0x1d;
        data[42] = 0x4c;
        assert_eq!(discover_types_count(&data, 0), 2);
    }
}
