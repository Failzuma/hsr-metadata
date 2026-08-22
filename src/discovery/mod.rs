pub(crate) mod mhy;
pub(crate) mod native;
pub(crate) mod pe;
pub mod profile;

use crate::reconstruction::images::decrypt_images;
use crate::reconstruction::literals::{
    decrypt as decrypt_string_literals, discover_count as discover_string_literal_count,
};
use crate::reconstruction::methods::calc_term;
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
}

#[derive(Clone, Debug)]
pub struct DiscoveredProfile {
    pub profile: BuildProfile,
    pub evidence: DiscoveryEvidence,
    pub(crate) mhy: MhyHeader,
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
    let candidates = MhyHeader::candidates(dll, &pe);
    if candidates.is_empty() {
        MhyHeader::parse(dll)?;
        bail!("MHY header signature not found in GameAssembly.dll");
    }
    let mut matches = Vec::new();
    for mhy in candidates {
        if let Some((prefix, score, mhy)) = discover_phase_a(metadata, startup, mhy) {
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
    let string_literal_count = discover_string_literal_count(global_body, &mhy)
        .with_context(|| {
            format!(
                "phase A selected an invalid string-literal layout at prefix {metadata_prefix_size}, table {:#x}, data {:#x}",
                mhy.string_literal_offsets_base(),
                mhy.string_literal_data_base()
            )
        })?;
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
    let method_count = discover_method_count(global_body, &mhy, type_definition_count);
    let parameter_count =
        discover_parameter_count(global_body, mhy.method_table_base(), method_count)
            .context("failed to derive parameter count from the semantic method table")?;
    let field_count = discover_field_count(
        global_body,
        mhy.type_definition_offset(),
        type_definition_count,
    )
    .context("failed to derive field count from the semantic type table")?;
    let mhy = discover_phase_b(
        global_body,
        startup,
        mhy,
        &decryptor,
        PrimaryCounts {
            types: type_definition_count,
            methods: method_count,
            parameters: parameter_count,
            fields: field_count,
        },
    )
    .context("failed to classify secondary metadata tables")?;
    let type_definition_offset = mhy.type_definition_offset();
    let type_bytes = type_definition_count
        .checked_mul(70)
        .and_then(|size| type_definition_offset.checked_add(size))
        .context("type table size overflow")?;
    if type_bytes > global_body.len() {
        bail!("discovered type table exceeds global metadata");
    }
    let interface_range_upper_bound =
        interface_range_upper_bound(global_body, type_definition_offset, type_definition_count);
    let method_pointer_tables = discover_method_pointer_tables(global_body, dll, &mhy, &pe)
        .context("failed to discover method-pointer tables")?;
    let runtime = discover_runtime_profile(
        global_body,
        startup,
        dll,
        &mhy,
        &pe,
        &method_pointer_tables,
        type_definition_count,
    )
    .context("failed to discover IL2CPP runtime tables")?;
    let (mhy, generic_parameter_count, generic_container_count) = discover_generic_metadata_layout(
        global_body,
        mhy,
        dll,
        &pe,
        &runtime,
        &decryptor,
        interface_range_upper_bound,
    )
    .context("failed to classify generic metadata tables")?;
    let interface_offset = mhy.interface_table_base();
    let interface_end = interface_range_upper_bound
        .checked_mul(4)
        .and_then(|size| interface_offset.checked_add(size))
        .context("interface table size overflow")?;
    if interface_end > global_body.len() {
        bail!("discovered interface table exceeds global metadata");
    }
    let profile = BuildProfile {
        metadata_prefix_size,
        type_definition_count,
        type_definition_offset,
        generic_parameter_count,
        generic_container_count,
        interface_count: interface_range_upper_bound,
        interface_offset,
        string_literal_count,
        primary_method_pointer_file_offset: method_pointer_tables.primary,
        fallback_method_pointer_file_offset: method_pointer_tables.fallback,
        minimum_method_pointer_va,
        maximum_method_pointer_va,
    };
    let discovered_fields = vec![
        "metadata_prefix_size".into(),
        "type_definition_count".into(),
        "type_definition_offset".into(),
        "generic_parameter_count".into(),
        "generic_container_count".into(),
        "interface_count".into(),
        "interface_offset".into(),
        "string_literal_count".into(),
        "primary_method_pointer_file_offset".into(),
        "fallback_method_pointer_file_offset".into(),
        "minimum_method_pointer_va".into(),
        "maximum_method_pointer_va".into(),
    ];
    let evidence = DiscoveryEvidence {
        mhy_file_offset: mhy.file_offset,
        metadata_prefix_size,
        image_count: images.len(),
        interface_range_upper_bound,
        executable_va_minimum: minimum_method_pointer_va,
        executable_va_maximum: maximum_method_pointer_va,
        code_registration_file_offset: Some(method_pointer_tables.registration),
        runtime: Some(runtime),
        discovered_fields,
    };
    Ok(DiscoveredProfile {
        profile,
        evidence,
        mhy,
    })
}

fn discover_generic_metadata_layout(
    global_body: &[u8],
    mut mhy: MhyHeader,
    dll: &[u8],
    pe: &PeImage,
    runtime: &RuntimeProfile,
    decryptor: &StringDecryptor,
    interface_count: usize,
) -> Option<(MhyHeader, usize, usize)> {
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
    let additive = unique_values(&mhy.candidates.additive);
    let xor = unique_values(&mhy.candidates.xor);
    let parameter_size = parameter_count.checked_mul(14)?;
    let parameter_base =
        select_table_offset(&additive, global_body.len(), parameter_size, |base| {
            score_generic_parameter_table(global_body, decryptor, base, parameter_count)
        })?;
    let mut maximum_container = None;
    let mut constraint_count = 0usize;
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
        let constraint_start = (LittleEndian::read_u16(&global_body[offset + 4..]) ^ 0x69b4)
            .wrapping_sub(key as u16) as i16;
        let constraint_length = (LittleEndian::read_u16(&global_body[offset + 6..]) ^ 0x0fd1)
            .wrapping_sub(key as u16) as i16;
        if let (Ok(start), Ok(length)) = (
            usize::try_from(constraint_start),
            usize::try_from(constraint_length),
        ) {
            constraint_count = constraint_count.max(start.checked_add(length)?);
        }
    }
    let container_count = maximum_container?.checked_add(1)?;
    let container_base = select_table_offset(
        &additive,
        global_body.len(),
        container_count.checked_mul(16)?,
        |base| score_generic_container_table(global_body, base, container_count, parameter_count),
    )?;
    let constraint_layouts = additive
        .iter()
        .copied()
        .map(|value| value as usize)
        .filter_map(|constraint_base| {
            let interface_base = constraint_base.checked_sub(interface_count.checked_mul(4)?)?;
            let score = score_generic_constraint_table(
                global_body,
                constraint_base,
                constraint_count,
                runtime.types_count,
            );
            (xor.iter().any(|value| *value as usize == interface_base)
                && score_interface_table(global_body, interface_base, interface_count)
                    == interface_count)
                .then_some((score, (constraint_base, interface_base)))
        })
        .collect::<Vec<_>>();
    let (_, (constraint_base, interface_base)) = unique_best(constraint_layouts, |value| *value)?;
    mhy.layout.generic_parameter_table = parameter_base;
    mhy.layout.generic_container_table = container_base;
    mhy.layout.generic_constraint_table = constraint_base;
    mhy.layout.interface_table = interface_base;
    Some((mhy, parameter_count, container_count))
}

fn generic_parameter_key(index: usize) -> u64 {
    let term = (0x617f_e3cc_452cu64
        .wrapping_mul(index as u64)
        .wrapping_add(0x09dc_5db7_1f0e_b440)
        >> 9)
        .wrapping_add(718_849_585)
        ^ 0x5278_374d;
    (1_252_900_171u64.wrapping_mul(term)) >> 15
}

fn score_generic_parameter_table(
    body: &[u8],
    decryptor: &StringDecryptor,
    base: usize,
    count: usize,
) -> usize {
    sample_indices(count, 4096)
        .into_iter()
        .filter_map(|index| {
            let record = body.get(base + index * 14..base + index * 14 + 14)?;
            let key = generic_parameter_key(index);
            let name_key = key as u32;
            let name_index = LittleEndian::read_u32(record)
                .wrapping_sub(name_key)
                .wrapping_sub(1_149_796_643);
            let container =
                (LittleEndian::read_u16(&record[8..]) ^ 0x7526).wrapping_sub(key as u16) as i16;
            let number = (LittleEndian::read_u16(&record[10..]) ^ 0xbd3b).wrapping_sub(key as u16);
            let flags = (LittleEndian::read_u16(&record[12..]) ^ 0x7af7).wrapping_sub(key as u16);
            Some(
                usize::from(!decryptor.decrypt_string(name_index).is_empty()) * 4
                    + usize::from(container >= 0)
                    + usize::from(number < 1024)
                    + usize::from(flags < 0x100),
            )
        })
        .sum()
}

fn score_generic_container_table(
    body: &[u8],
    base: usize,
    count: usize,
    parameter_count: usize,
) -> usize {
    sample_indices(count, 4096)
        .into_iter()
        .filter(|index| {
            let Some(record) = body.get(base + index * 16..base + index * 16 + 16) else {
                return false;
            };
            let step1 = (0x3d69_13e0_af40u64
                .wrapping_mul(*index as u64)
                .wrapping_add(0x0a64_cad6_0fa0_52c0))
                >> 23;
            let step2 = 1_997_422_568u64.wrapping_mul(step1) >> 11;
            let key = (748_293_795u64.wrapping_mul(step2) >> 23) as u32;
            let length = (LittleEndian::read_u32(record).wrapping_sub(214_875_017) ^ key) as usize;
            let start =
                (LittleEndian::read_u32(&record[12..]).wrapping_sub(248_843_855) ^ key) as usize;
            length > 0
                && length < 1024
                && start
                    .checked_add(length)
                    .is_some_and(|end| end <= parameter_count)
        })
        .count()
}

fn score_generic_constraint_table(
    body: &[u8],
    base: usize,
    count: usize,
    type_count: usize,
) -> usize {
    (0..count)
        .filter_map(|index| body.get(base + index * 4..base + index * 4 + 4))
        .filter(|record| (0..type_count as i32).contains(&LittleEndian::read_i32(record)))
        .count()
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
    let generic_class_count = mhy.generic_class_count();
    let generic_class_source_offset = mhy.generic_class_source_offset();
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
    let type_offset = mhy.type_definition_offset();
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

fn discover_phase_a(
    metadata: &[u8],
    startup: &[u8],
    mut mhy: MhyHeader,
) -> Option<(usize, usize, MhyHeader)> {
    let additive = unique_values(&mhy.candidates.additive);
    let xor = unique_values(&mhy.candidates.xor);
    let image_counts = xor
        .iter()
        .copied()
        .filter(|value| value % 40 == 0)
        .map(|value| value as usize / 40)
        .filter(|count| (1..=10_000).contains(count))
        .collect::<Vec<_>>();
    let image_offsets = additive
        .iter()
        .copied()
        .map(|value| value as usize)
        .filter(|offset| *offset < startup.len())
        .collect::<Vec<_>>();
    let string_offsets = additive
        .iter()
        .copied()
        .map(|value| value as usize)
        .collect::<Vec<_>>();
    let mut layouts = Vec::new();
    for prefix in (0..=metadata.len().min(4096)).step_by(4) {
        let body = &metadata[prefix..];
        for &string_offset in string_offsets.iter().filter(|offset| **offset < body.len()) {
            let decryptor = StringDecryptor::new(body, string_offset);
            for &image_offset in &image_offsets {
                for &image_count in &image_counts {
                    let Some(end) = image_count
                        .checked_mul(40)
                        .and_then(|size| image_offset.checked_add(size))
                    else {
                        continue;
                    };
                    if end > startup.len() {
                        continue;
                    }
                    let mut candidate = mhy.clone();
                    candidate.layout.string_table_offset = string_offset;
                    candidate.layout.image_offset = image_offset;
                    candidate.layout.image_count = image_count.min(16);
                    let score = score_images(startup, &candidate, &decryptor);
                    if score >= 32 {
                        layouts.push((score, (prefix, string_offset, image_offset, image_count)));
                    }
                }
            }
        }
    }
    let (score, (prefix, string_offset, image_offset, image_count)) =
        unique_best(layouts, |value| *value)?;
    mhy.layout.string_table_offset = string_offset;
    mhy.layout.image_offset = image_offset;
    mhy.layout.image_count = image_count;
    let body = &metadata[prefix..];
    let decryptor = StringDecryptor::new(body, string_offset);
    let images = decrypt_images(startup, &mhy, &decryptor);
    let type_count = images.iter().try_fold(0usize, |total, image| {
        total.checked_add(image.type_count as usize)
    })?;
    if type_count == 0 || type_count > 10_000_000 {
        return None;
    }
    let type_candidates = xor
        .iter()
        .copied()
        .map(|value| value as usize)
        .filter(|offset| {
            offset
                .checked_add(type_count.saturating_mul(70))
                .is_some_and(|end| end <= body.len())
        })
        .map(|offset| {
            (
                score_type_table(body, &decryptor, offset, type_count),
                offset,
            )
        })
        .filter(|(candidate_score, _)| *candidate_score > 0)
        .collect::<Vec<_>>();
    let (_, type_offset) = unique_best(type_candidates, |value| *value)?;
    mhy.layout.type_definition_offset = type_offset;

    let method_count = discover_method_count(body, &mhy, type_count);
    let field_count = discover_field_count(body, type_offset, type_count)?;
    let method_candidates = additive
        .iter()
        .copied()
        .map(|value| value as usize)
        .filter(|offset| {
            offset
                .checked_add(method_count.saturating_mul(26))
                .is_some_and(|end| end <= body.len())
        })
        .map(|offset| {
            (
                score_method_table(body, &decryptor, offset, method_count),
                offset,
            )
        })
        .filter(|(candidate_score, _)| *candidate_score > 0)
        .collect::<Vec<_>>();
    let (_, method_offset) = unique_best(method_candidates, |value| *value)?;
    mhy.layout.method_table = method_offset;
    let parameter_count = discover_parameter_count(body, method_offset, method_count)?;

    let field_candidates = additive
        .iter()
        .copied()
        .map(|value| value as usize)
        .filter(|offset| {
            offset
                .checked_add(field_count.saturating_mul(8))
                .is_some_and(|end| end <= body.len())
        })
        .map(|offset| {
            (
                score_field_table(body, &decryptor, type_offset, type_count, offset),
                offset,
            )
        })
        .filter(|(candidate_score, _)| *candidate_score > 0)
        .collect::<Vec<_>>();
    let (_, field_offset) = unique_best(field_candidates, |value| *value)?;
    mhy.layout.field_table = field_offset;

    let parameter_candidates = additive
        .iter()
        .copied()
        .map(|value| value as usize)
        .filter(|offset| {
            offset
                .checked_add(parameter_count.saturating_mul(8))
                .is_some_and(|end| end <= body.len())
        })
        .map(|offset| (score_parameter_table(body, offset, parameter_count), offset))
        .filter(|(candidate_score, _)| *candidate_score > 0)
        .collect::<Vec<_>>();
    let (_, parameter_offset) = unique_best(parameter_candidates, |value| *value)?;
    mhy.layout.parameter_table = parameter_offset;

    let mut literal_candidates = Vec::new();
    for table in xor
        .iter()
        .copied()
        .map(|value| value as usize)
        .filter(|offset| *offset < body.len())
    {
        for data in additive.iter().copied() {
            let mut candidate = mhy.clone();
            candidate.layout.string_literal_offsets = table;
            candidate.layout.string_literal_data = data;
            if let Some(count) = discover_string_literal_count(body, &candidate) {
                if (1..10_000_000).contains(&count) {
                    let payload_score = decrypt_string_literals(body, &candidate, count.min(256))
                        .iter()
                        .map(|literal| match std::str::from_utf8(&literal.data) {
                            Ok(value)
                                if value.chars().all(|character| {
                                    !character.is_control() || character.is_whitespace()
                                }) =>
                            {
                                4
                            }
                            Ok(_) => 1,
                            Err(_) => 0,
                        })
                        .sum::<usize>();
                    literal_candidates.push((
                        count.saturating_mul(2048).saturating_add(payload_score),
                        (table, data),
                    ));
                }
            }
        }
    }
    let (_, (literal_table, literal_data)) = unique_best(literal_candidates, |value| *value)?;
    mhy.layout.string_literal_offsets = literal_table;
    mhy.layout.string_literal_data = literal_data;
    Some((prefix, score, mhy))
}

#[derive(Clone, Copy)]
struct SecondaryCounts {
    properties: usize,
    events: usize,
    interfaces: usize,
    vtables: usize,
    interface_offsets: usize,
}

#[derive(Clone, Copy)]
struct PrimaryCounts {
    types: usize,
    methods: usize,
    parameters: usize,
    fields: usize,
}

fn discover_phase_b(
    body: &[u8],
    startup: &[u8],
    mut mhy: MhyHeader,
    decryptor: &StringDecryptor,
    primary: PrimaryCounts,
) -> Option<MhyHeader> {
    let PrimaryCounts {
        types: type_count,
        methods: method_count,
        parameters: parameter_count,
        fields: field_count,
    } = primary;
    let additive = unique_values(&mhy.candidates.additive);
    let xor = unique_values(&mhy.candidates.xor);
    let shifted = unique_values(&mhy.candidates.shift_xor);
    let counts = secondary_counts(body, mhy.type_definition_offset(), type_count)?;

    mhy.layout.property_table = select_table_offset(
        &xor,
        body.len(),
        counts.properties.checked_mul(10)?,
        |base| score_property_table(body, decryptor, base, counts.properties, method_count),
    )?;
    mhy.layout.event_table =
        select_table_offset(&xor, body.len(), counts.events.checked_mul(14)?, |base| {
            score_event_table(body, decryptor, base, counts.events, method_count)
        })?;
    let interface_size = counts.interfaces.checked_mul(4)?;
    mhy.layout.interface_table = select_table_offset(&xor, body.len(), interface_size, |base| {
        score_interface_table(body, base, counts.interfaces)
    })?;
    let vtable_size = counts.vtables.checked_mul(4)?;
    mhy.layout.vtable_method_table = additive
        .iter()
        .copied()
        .map(|value| value as usize)
        .find(|base| base.checked_add(vtable_size) == Some(mhy.layout.event_table))
        .or_else(|| {
            select_table_offset(&additive, body.len(), vtable_size, |base| {
                vtable_score(body, base, counts.vtables)
            })
        })?;
    mhy.layout.interface_offset_table = select_table_offset(
        &xor,
        body.len(),
        counts.interface_offsets.checked_mul(6)?,
        |base| score_interface_offset_table(body, base, counts.interface_offsets),
    )?;

    let mut field_layouts = Vec::new();
    for &field_type_map in &additive {
        let field_type_map = field_type_map as usize;
        let Some(map_count) = maximum_field_map_index(body, field_type_map, type_count)
            .and_then(|value| value.checked_add(1))
        else {
            continue;
        };
        if map_count > type_count.checked_mul(4)? {
            continue;
        }
        for &field_default_table in &xor {
            let field_default_table = field_default_table as usize;
            for &field_offset_map in &additive {
                let field_offset_map = field_offset_map as usize;
                if field_offset_map <= field_default_table
                    || (field_offset_map - field_default_table) % 12 != 0
                {
                    continue;
                }
                let field_default_count = (field_offset_map - field_default_table) / 12;
                if field_default_count > field_count
                    || !valid_default_records(
                        body,
                        field_default_table,
                        field_default_count,
                        field_count,
                        true,
                    )
                {
                    continue;
                }
                let map_score =
                    score_field_offset_map(body, field_offset_map, map_count, field_count);
                if map_score == sample_indices(map_count, 4096).len() {
                    field_layouts.push((
                        field_default_count,
                        (
                            field_type_map,
                            field_default_table,
                            field_default_count,
                            field_offset_map,
                        ),
                    ));
                }
            }
        }
    }
    let (_, (field_type_map, field_default_table, field_default_count, field_offset_map)) =
        unique_best(field_layouts, |value| *value)?;
    let parameter_layouts = additive
        .iter()
        .copied()
        .map(|value| value as usize)
        .filter_map(|base| {
            let size = mhy.layout.field_table.checked_sub(base)?;
            (size > 0 && size % 12 == 0).then_some((base, size / 12))
        })
        .filter(|(_, count)| *count <= parameter_count)
        .filter(|(base, count)| valid_default_records(body, *base, *count, parameter_count, false))
        .collect::<Vec<_>>();
    let maximum_parameter_defaults = parameter_layouts.iter().map(|(_, count)| *count).max()?;
    let parameter_layouts = parameter_layouts
        .into_iter()
        .filter(|(_, count)| *count == maximum_parameter_defaults)
        .collect::<Vec<_>>();
    let [parameter_layout] = parameter_layouts.as_slice() else {
        return None;
    };
    let (parameter_default_table, parameter_default_count) = *parameter_layout;
    mhy.layout.field_default_table = field_default_table;
    mhy.layout.field_default_count = field_default_count;
    mhy.layout.parameter_default_table = parameter_default_table;
    mhy.layout.parameter_default_count = parameter_default_count;

    let maximum_default_data = maximum_default_data_index(
        body,
        field_default_table,
        field_default_count,
        parameter_default_table,
        parameter_default_count,
    );
    mhy.layout.default_value_data = additive
        .iter()
        .copied()
        .map(|value| value as usize)
        .filter(|base| {
            *base < mhy.type_definition_offset()
                && base
                    .checked_add(maximum_default_data)
                    .is_some_and(|end| end < mhy.type_definition_offset())
        })
        .max()?;

    let offset_count = maximum_field_offset_index(
        body,
        mhy.type_definition_offset(),
        type_count,
        field_type_map,
        field_offset_map,
    )?;
    let offset_table =
        select_table_offset(&xor, body.len(), offset_count.checked_mul(4)?, |base| {
            score_field_offset_table(
                body,
                base,
                mhy.type_definition_offset(),
                type_count,
                field_type_map,
                field_offset_map,
            )
        })?;
    mhy.layout.field_type_map = field_type_map;
    mhy.layout.field_offset_map = field_offset_map;
    mhy.layout.field_offset_table = offset_table;

    let generic_class = select_generic_class_table(startup, &xor, &shifted, type_count)?;
    mhy.layout.generic_class_source = generic_class.0;
    mhy.layout.generic_class_count = generic_class.1;

    let method_map = select_method_map(body, &xor, method_count)?;
    mhy.layout.method_pointer_map = method_map.0;
    mhy.layout.method_pointer_map_count = method_map.1;
    Some(mhy)
}

fn secondary_counts(body: &[u8], type_base: usize, type_count: usize) -> Option<SecondaryCounts> {
    let mut counts = SecondaryCounts {
        properties: 0,
        events: 0,
        interfaces: 0,
        vtables: 0,
        interface_offsets: 0,
    };
    let interface_ranges = decode_interface_ranges(body, type_base, type_count);
    for index in 0..type_count {
        let record = body.get(type_base + index * 70..type_base + index * 70 + 70)?;
        let property_count = record[65].wrapping_add(31) as usize;
        if property_count != 0 {
            let start = LittleEndian::read_u32(&record[28..]).wrapping_sub(970_393_327) as usize;
            counts.properties = counts.properties.max(start.checked_add(property_count)?);
        }
        let event_count = (record[64] ^ 0x73) as usize;
        if event_count != 0 {
            let start = (LittleEndian::read_u16(&record[48..]) ^ 0x6ecd) as usize;
            counts.events = counts.events.max(start.checked_add(event_count)?);
        }
        let vtable_count = (record[66] ^ 8) as usize;
        if vtable_count != 0 {
            let start = (LittleEndian::read_u32(&record[24..]) ^ 0x4b4c_5f23) as usize;
            counts.vtables = counts.vtables.max(start.checked_add(vtable_count)?);
        }
        let interface_offset_count = record[69].wrapping_sub(1) as usize;
        if interface_offset_count != 0 {
            let start = (LittleEndian::read_u16(&record[62..]) ^ 0x3e74) as usize;
            counts.interface_offsets = counts
                .interface_offsets
                .max(start.checked_add(interface_offset_count)?);
        }
        let range = interface_ranges.get(index)?;
        counts.interfaces = counts.interfaces.max(range.start.checked_add(range.count)?);
    }
    Some(counts)
}

fn select_table_offset(
    candidates: &[u32],
    body_len: usize,
    size: usize,
    score: impl Fn(usize) -> usize,
) -> Option<usize> {
    let scored = candidates
        .iter()
        .copied()
        .map(|value| value as usize)
        .filter(|base| base.checked_add(size).is_some_and(|end| end <= body_len))
        .map(|base| (score(base), base))
        .filter(|(value, _)| *value != 0)
        .collect::<Vec<_>>();
    unique_best(scored, |base| *base).map(|(_, base)| base)
}

fn score_property_table(
    body: &[u8],
    decryptor: &StringDecryptor,
    base: usize,
    count: usize,
    method_count: usize,
) -> usize {
    sample_indices(count, 1024)
        .into_iter()
        .filter_map(|index| {
            body.get(base + index * 10..base + index * 10 + 10)
                .map(|r| (index, r))
        })
        .map(|(index, record)| {
            let key = property_key(index);
            let name_index =
                (LittleEndian::read_u32(record) ^ 0x6199_063c).wrapping_sub(key as u32);
            let name = decryptor.decrypt_string(name_index);
            let set = decode_member_accessor(LittleEndian::read_u16(&record[4..]) ^ 0x4b8f, key);
            let get = decode_member_accessor(LittleEndian::read_u16(&record[6..]) ^ 0xfa36, key);
            usize::from(!name.is_empty()) * 4
                + usize::from(set < 0 || set as usize <= method_count)
                + usize::from(get < 0 || get as usize <= method_count)
        })
        .sum()
}

fn score_event_table(
    body: &[u8],
    decryptor: &StringDecryptor,
    base: usize,
    count: usize,
    method_count: usize,
) -> usize {
    sample_indices(count, 1024)
        .into_iter()
        .filter_map(|index| {
            body.get(base + index * 14..base + index * 14 + 14)
                .map(|r| (index, r))
        })
        .map(|(index, record)| {
            let key = event_key(index);
            let name_index =
                (LittleEndian::read_u32(record) ^ 0x0789_81cb).wrapping_sub(key as u32);
            let name = decryptor.decrypt_string(name_index);
            let accessors = [8usize, 10, 12]
                .into_iter()
                .map(|offset| {
                    decode_member_accessor(
                        LittleEndian::read_u16(&record[offset..])
                            ^ [0x8450, 0xe8cb, 0x3ce2][(offset - 8) / 2],
                        key,
                    )
                })
                .filter(|value| *value < 0 || *value as usize <= method_count)
                .count();
            usize::from(!name.is_empty()) * 4 + accessors
        })
        .sum()
}

fn property_key(index: usize) -> u64 {
    let value = 6035u64.wrapping_mul(index as u64) ^ 0x280e_7a20;
    let value = 1_831_379_439u64.wrapping_mul(value) >> 17;
    ((value ^ 0x727e_ff5b).wrapping_add(1_664_893_910)) ^ 0x4adb_d505
}

fn event_key(index: usize) -> u64 {
    let value = 15_580u64.wrapping_mul(index as u64) ^ 0x550d_63ba;
    let value = 1_057_473_644u64.wrapping_mul(value) >> 19;
    1_598_447_864u64
        .wrapping_mul(value)
        .wrapping_add(0x2682_4684_ca69_ca48)
        >> 15
}

fn decode_member_accessor(value: u16, key: u64) -> i32 {
    let value = value.wrapping_sub(key as u16);
    if value == u16::MAX {
        -1
    } else {
        value as i32
    }
}

fn score_interface_table(body: &[u8], base: usize, count: usize) -> usize {
    (0..count)
        .filter_map(|index| body.get(base + index * 4..base + index * 4 + 4))
        .filter(|record| (0..10_000_000).contains(&LittleEndian::read_i32(record)))
        .count()
}

fn vtable_score(body: &[u8], base: usize, count: usize) -> usize {
    (0..count)
        .filter_map(|index| body.get(base + index * 4..base + index * 4 + 4))
        .filter(|record| {
            let encoded = LittleEndian::read_u32(record);
            let usage = encoded >> 29;
            let method = encoded & 0x1fff_ffff;
            matches!(usage, 0 | 3 | 6) && (usage == 6 || method < 10_000_000)
        })
        .count()
}

fn score_interface_offset_table(body: &[u8], base: usize, count: usize) -> usize {
    (0..count)
        .filter_map(|index| body.get(base + index * 6..base + index * 6 + 6))
        .filter(|record| {
            (0..10_000_000).contains(&LittleEndian::read_i32(record))
                && LittleEndian::read_i16(&record[4..]) >= 0
        })
        .count()
}

fn valid_default_records(
    body: &[u8],
    base: usize,
    count: usize,
    owner_count: usize,
    field: bool,
) -> bool {
    (0..count).all(|index| {
        let Some(record) = body.get(base + index * 12..base + index * 12 + 12) else {
            return false;
        };
        let owner_offset = if field { 8 } else { 4 };
        let data_offset = if field { 4 } else { 8 };
        LittleEndian::read_i32(record) >= 0
            && (0..owner_count as i32).contains(&LittleEndian::read_i32(&record[owner_offset..]))
            && LittleEndian::read_i32(&record[data_offset..]) >= -1
    })
}

fn maximum_default_data_index(
    body: &[u8],
    field_base: usize,
    field_count: usize,
    parameter_base: usize,
    parameter_count: usize,
) -> usize {
    let fields = (0..field_count).filter_map(|index| {
        body.get(field_base + index * 12 + 4..field_base + index * 12 + 8)
            .map(LittleEndian::read_i32)
    });
    let parameters = (0..parameter_count).filter_map(|index| {
        body.get(parameter_base + index * 12 + 8..parameter_base + index * 12 + 12)
            .map(LittleEndian::read_i32)
    });
    fields
        .chain(parameters)
        .filter_map(|value| usize::try_from(value).ok())
        .max()
        .unwrap_or_default()
}

fn maximum_field_map_index(body: &[u8], base: usize, count: usize) -> Option<usize> {
    (0..count).try_fold(0usize, |maximum, index| {
        let value = usize::try_from(LittleEndian::read_i32(
            body.get(base + index * 4..base + index * 4 + 4)?,
        ))
        .ok()?;
        Some(maximum.max(value))
    })
}

fn score_field_offset_map(body: &[u8], base: usize, count: usize, field_count: usize) -> usize {
    sample_indices(count, 4096)
        .into_iter()
        .filter_map(|index| body.get(base + index * 12..base + index * 12 + 12))
        .filter(|record| {
            let value = LittleEndian::read_i32(&record[8..]);
            value >= 0 && value as usize <= field_count
        })
        .count()
}

fn maximum_field_offset_index(
    body: &[u8],
    type_base: usize,
    type_count: usize,
    field_type_map: usize,
    field_offset_map: usize,
) -> Option<usize> {
    let mut maximum = 0usize;
    for index in 0..type_count {
        let type_record = body.get(type_base + index * 70..type_base + index * 70 + 70)?;
        let field_count = LittleEndian::read_u16(&type_record[50..]).wrapping_add(17_485) as usize;
        let map_index = usize::try_from(LittleEndian::read_i32(
            body.get(field_type_map + index * 4..field_type_map + index * 4 + 4)?,
        ))
        .ok()?;
        let base = usize::try_from(LittleEndian::read_i32(body.get(
            field_offset_map + map_index * 12 + 8..field_offset_map + map_index * 12 + 12,
        )?))
        .ok()?;
        maximum = maximum.max(base.checked_add(field_count)?);
    }
    Some(maximum)
}

fn score_field_offset_table(
    body: &[u8],
    base: usize,
    type_base: usize,
    type_count: usize,
    field_type_map: usize,
    field_offset_map: usize,
) -> usize {
    sample_indices(type_count, 4096)
        .into_iter()
        .filter_map(|type_index| {
            let type_record =
                body.get(type_base + type_index * 70..type_base + type_index * 70 + 70)?;
            let field_count =
                LittleEndian::read_u16(&type_record[50..]).wrapping_add(17_485) as usize;
            let map_index = usize::try_from(LittleEndian::read_i32(
                body.get(field_type_map + type_index * 4..field_type_map + type_index * 4 + 4)?,
            ))
            .ok()?;
            let offset_index = usize::try_from(LittleEndian::read_i32(body.get(
                field_offset_map + map_index * 12 + 8..field_offset_map + map_index * 12 + 12,
            )?))
            .ok()?;
            Some((offset_index, field_count))
        })
        .map(|(offset_index, field_count)| {
            let mut previous = 0;
            (0..field_count.min(64))
                .filter_map(|index| {
                    let record = body.get(
                        base + (offset_index + index) * 4..base + (offset_index + index + 1) * 4,
                    )?;
                    let offset = LittleEndian::read_u32(record) & 0x00ff_ffff;
                    let valid = offset == 0x00ff_ffff || offset < 0x0010_0000;
                    let ordered = offset == 0x00ff_ffff || offset >= previous;
                    if offset != 0x00ff_ffff {
                        previous = offset;
                    }
                    Some(usize::from(valid) + usize::from(ordered))
                })
                .sum::<usize>()
        })
        .sum()
}

fn select_generic_class_table(
    startup: &[u8],
    bases: &[u32],
    counts: &[u32],
    type_count: usize,
) -> Option<(usize, usize)> {
    let mut scored = Vec::new();
    for &base in bases {
        let base = base as usize;
        for &count in counts {
            let count = count as usize;
            if count == 0
                || count > 10_000_000
                || base
                    .checked_add(count.saturating_mul(8))
                    .is_none_or(|end| end > startup.len())
            {
                continue;
            }
            let score = sample_indices(count, 4096)
                .into_iter()
                .filter_map(|index| startup.get(base + index * 8..base + index * 8 + 8))
                .filter(|record| {
                    let type_index = LittleEndian::read_i32(record);
                    let inst_index = LittleEndian::read_i32(&record[4..]);
                    (0..type_count as i32).contains(&type_index) && inst_index >= 0
                })
                .count();
            if score != 0 {
                scored.push((score, (base, count)));
            }
        }
    }
    unique_best(scored, |value| *value).map(|(_, value)| value)
}

fn select_method_map(body: &[u8], bases: &[u32], method_count: usize) -> Option<(usize, usize)> {
    let mut scored = Vec::new();
    for &base in bases {
        let base = base as usize;
        let mut count = 0usize;
        let mut previous_method = -1i32;
        let mut previous_pointer = None;
        while count < method_count {
            let Some(record) = body.get(base + count * 6..base + count * 6 + 6) else {
                break;
            };
            let method = LittleEndian::read_i32(record);
            let pointer = LittleEndian::read_u16(&record[4..]) as usize;
            if !(0..method_count as i32).contains(&method)
                || method <= previous_method
                || previous_pointer.is_some_and(|previous| pointer <= previous)
            {
                break;
            }
            previous_method = method;
            previous_pointer = Some(pointer);
            count += 1;
        }
        if count > 0 {
            scored.push((count, (base, count)));
        }
    }
    unique_best(scored, |value| *value).map(|(_, value)| value)
}

fn score_images(startup: &[u8], mhy: &MhyHeader, decryptor: &StringDecryptor) -> usize {
    decrypt_images(startup, mhy, decryptor)
        .iter()
        .map(|image| {
            let mut score = usize::from(image.type_count < 1_000_000);
            if !image.name.starts_with("Image_") {
                score += 2;
            }
            if image.name.ends_with(".dll") {
                score += 3;
            }
            if !image.name.is_empty() && image.name.bytes().all(|value| value.is_ascii_graphic()) {
                score += 1;
            }
            score
        })
        .sum()
}

fn score_type_table(body: &[u8], decryptor: &StringDecryptor, base: usize, count: usize) -> usize {
    sample_indices(count, 512)
        .into_iter()
        .filter_map(|index| body.get(base + index * 70..base + index * 70 + 70))
        .map(|record| {
            let name_index = LittleEndian::read_u32(&record[40..]).wrapping_sub(369_268_488);
            let namespace_index = LittleEndian::read_u32(&record[36..]).wrapping_add(0xf1d3_2d89);
            let name = decryptor.decrypt_string(name_index);
            let namespace = decryptor.decrypt_string(namespace_index);
            let mut score = 0;
            if !name.is_empty() && name.bytes().all(|value| !value.is_ascii_control()) {
                score += 4;
            }
            if namespace.bytes().all(|value| !value.is_ascii_control()) {
                score += 1;
            }
            let method_count = LittleEndian::read_u16(&record[52..]).wrapping_add(24_467);
            let field_count = LittleEndian::read_u16(&record[50..]).wrapping_add(17_485);
            if method_count < 4096 && field_count < 4096 {
                score += 2;
            }
            score
        })
        .sum()
}

fn discover_field_count(body: &[u8], base: usize, count: usize) -> Option<usize> {
    (0..count).try_fold(0usize, |total, index| {
        let offset = base.checked_add(index.checked_mul(70)?)?;
        let record = body.get(offset..offset + 70)?;
        total.checked_add(LittleEndian::read_u16(&record[50..]).wrapping_add(17_485) as usize)
    })
}

fn score_method_table(
    body: &[u8],
    decryptor: &StringDecryptor,
    base: usize,
    count: usize,
) -> usize {
    sample_indices(count, 1024)
        .into_iter()
        .filter_map(|index| {
            body.get(base + index * 26..base + index * 26 + 26)
                .map(|r| (index, r))
        })
        .map(|(index, record)| {
            let term = calc_term(index);
            let name_index = LittleEndian::read_u32(record) ^ term ^ 0x0e71_4bc1;
            let name = decryptor.decrypt_string(name_index);
            let parameter_count = record[24] ^ term as u8 ^ 0xa8;
            usize::from(!name.is_empty() && name.bytes().all(|value| !value.is_ascii_control())) * 4
                + usize::from(parameter_count < 64)
        })
        .sum()
}

fn discover_parameter_count(body: &[u8], base: usize, method_count: usize) -> Option<usize> {
    let mut maximum = 0usize;
    for index in 0..method_count {
        let offset = base.checked_add(index.checked_mul(26)?)?;
        let record = body.get(offset..offset + 26)?;
        let term = calc_term(index);
        let count = (record[24] ^ term as u8 ^ 0xa8) as usize;
        let start = LittleEndian::read_u32(&record[4..]) ^ term ^ 0x0098_89b8;
        if count == 0 || start == u32::MAX {
            continue;
        }
        maximum = maximum.max(start as usize + count);
    }
    Some(maximum)
}

fn score_field_table(
    body: &[u8],
    decryptor: &StringDecryptor,
    type_base: usize,
    type_count: usize,
    field_base: usize,
) -> usize {
    let mut score = 0usize;
    let mut sampled = 0usize;
    for type_index in sample_indices(type_count, 1024) {
        let Some(record) = body.get(type_base + type_index * 70..type_base + type_index * 70 + 70)
        else {
            continue;
        };
        let raw_start = LittleEndian::read_i32(&record[32..]);
        let start = (raw_start as u32).wrapping_sub(1_954_887_780) as usize;
        let count = LittleEndian::read_u16(&record[50..]).wrapping_add(17_485) as usize;
        let mut key =
            (-1_388_221_511i32).wrapping_sub(744_344_320i32.wrapping_mul(raw_start)) as u32;
        for field in 0..count.min(8) {
            let Some(offset) = start
                .checked_add(field)
                .and_then(|index| index.checked_mul(8))
                .and_then(|offset| field_base.checked_add(offset))
            else {
                continue;
            };
            let Some(field_record) = body.get(offset..offset + 8) else {
                continue;
            };
            let name_index = key
                .wrapping_add(LittleEndian::read_u32(field_record))
                .wrapping_add(716_162_949);
            let type_index = key.wrapping_add(LittleEndian::read_u32(&field_record[4..])) as i32;
            let name = decryptor.decrypt_string(name_index);
            if !name.is_empty() && name.bytes().all(|value| !value.is_ascii_control()) {
                score += 4;
            }
            if (0..10_000_000).contains(&type_index) {
                score += 1;
            }
            sampled += 1;
            key = key.wrapping_sub(744_344_320);
        }
    }
    score + usize::from(sampled > 0)
}

fn score_parameter_table(body: &[u8], base: usize, count: usize) -> usize {
    sample_indices(count, 2048)
        .into_iter()
        .filter_map(|index| {
            body.get(base + index * 8..base + index * 8 + 8)
                .map(|r| (index, r))
        })
        .map(|(index, record)| {
            let term = parameter_term(index);
            let name = (LittleEndian::read_u32(&record[4..]) ^ 0x7103_092e).wrapping_sub(term);
            let type_index =
                (LittleEndian::read_u32(record) ^ 0x67e9_0dc5).wrapping_sub(term) as i32;
            usize::from(name == u32::MAX) * 4 + usize::from((0..10_000_000).contains(&type_index))
        })
        .sum()
}

fn parameter_term(index: usize) -> u32 {
    (1_488_482_466u64.wrapping_mul(
        (0x072e_1d74_b12b_u64
            .wrapping_mul(index as u64)
            .wrapping_add(0x0191_1d05_aff5))
            >> 11,
    ) as u32)
        .wrapping_sub(2_083_554_492)
}

fn sample_indices(count: usize, maximum: usize) -> Vec<usize> {
    if count <= maximum {
        return (0..count).collect();
    }
    (0..maximum)
        .map(|index| index.saturating_mul(count - 1) / (maximum - 1))
        .collect()
}

fn unique_values(values: &[u32]) -> Vec<u32> {
    values
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn unique_best<T, K>(values: Vec<(usize, T)>, key: impl Fn(&T) -> K) -> Option<(usize, T)>
where
    T: Clone,
    K: Clone + Eq,
{
    let maximum = values.iter().map(|(score, _)| *score).max()?;
    let mut best = values.into_iter().filter(|(score, _)| *score == maximum);
    let first = best.next()?;
    let first_key = key(&first.1);
    best.all(|(_, value)| key(&value) == first_key)
        .then_some(first)
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
