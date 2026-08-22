pub(crate) mod defaults;
pub(crate) mod generics;
pub(crate) mod images;
pub(crate) mod input;
pub(crate) mod literals;
pub(crate) mod mappings;
pub(crate) mod members;
pub(crate) mod methods;
pub(crate) mod model;
pub(crate) mod strings;
pub(crate) mod types;

use crate::discovery::mhy::MhyHeader;
use crate::discovery::profile::BuildProfile;
use byteorder::{ByteOrder, LittleEndian};
use defaults::decode as decode_default_values;
use generics::decrypt_generics;
use images::decrypt_images;
use input::ReconstructionInputs;
use literals::decrypt as decrypt_string_literals;
use mappings::extract_method_mappings;
use members::{decode_events, decode_properties};
use methods::{decrypt_methods, decrypt_parameters};
use model::{DecodedMetadata, GenericClassEntry, InterfaceOffsetEntry};
use strings::{StringDecryptor, StringPool};
use types::{build_nested_type_indices, decode_type_generic_containers, decrypt_types_and_fields};

pub(crate) fn decode(inputs: &ReconstructionInputs, profile: &BuildProfile) -> DecodedMetadata {
    let decryptor = StringDecryptor::new(&inputs.global_body, inputs.mhy.string_table_off());
    let mut images = decrypt_images(&inputs.startup_metadata, &inputs.mhy, &decryptor);
    let type_generic_containers = decode_type_generic_containers(
        &inputs.global_body,
        profile.type_definition_offset,
        profile.type_definition_count,
    );
    let mut generics = decrypt_generics(
        &inputs.global_body,
        &inputs.mhy,
        &decryptor,
        profile,
        &type_generic_containers,
    );
    let (mut types, mut fields, field_offsets) = decrypt_types_and_fields(
        &inputs.global_body,
        &inputs.mhy,
        &decryptor,
        &type_generic_containers,
        profile,
    );
    let nested_types = build_nested_type_indices(&mut types);
    let mut properties = decode_properties(&inputs.global_body, &inputs.mhy, &decryptor, &types);
    let mut events = decode_events(&inputs.global_body, &inputs.mhy, &decryptor, &types);
    let parameter_capacity = inputs
        .global_body
        .len()
        .saturating_sub(inputs.mhy.param_table_base())
        / 8;
    let method_count = types
        .iter()
        .filter(|value| value.m_count > 0)
        .map(|value| value.m_start as usize + value.m_count as usize)
        .max()
        .unwrap_or(0);
    let mut methods = decrypt_methods(
        &inputs.global_body,
        &inputs.mhy,
        &decryptor,
        method_count,
        parameter_capacity,
        &generics.method_to_container,
    );
    let parameter_count = methods
        .iter()
        .filter(|value| value.parameter_start >= 0)
        .map(|value| value.parameter_start as usize + value.parameter_count as usize)
        .max()
        .unwrap_or(0);
    let mut parameters = decrypt_parameters(
        &inputs.global_body,
        &inputs.mhy,
        &decryptor,
        parameter_count,
    );
    let mut strings = StringPool::new();
    for value in &mut types {
        value.name_off = strings.add_string(&value.name);
        value.ns_off = strings.add_string(&value.ns);
    }
    for value in &mut methods {
        value.name_off = strings.add_string(&value.name);
    }
    for value in &mut parameters {
        value.name_off = strings.add_string(&value.name);
    }
    for value in &mut fields {
        value.name_off = strings.add_string(&value.name);
    }
    for value in &mut properties {
        value.name_off = strings.add_string(&value.name);
    }
    for value in &mut events {
        value.name_off = strings.add_string(&value.name);
    }
    for value in &mut images {
        value.name_off = strings.add_string(&value.name);
    }
    generics.gp_name_offs = generics
        .gp_names
        .iter()
        .map(|name| strings.add_string(name))
        .collect();
    let interfaces = decode_interfaces(&inputs.global_body, &inputs.mhy, &types);
    let vtable_methods = decode_vtable_methods(&inputs.global_body, &inputs.mhy, &types);
    let interface_offsets = decode_interface_offsets(&inputs.global_body, &inputs.mhy, &types);
    let method_mappings = extract_method_mappings(
        &inputs.global_body,
        &inputs.dll,
        &inputs.mhy,
        &types,
        &methods,
        profile,
    );
    let generic_classes = decode_generic_classes(&inputs.startup_metadata, &inputs.mhy);
    let string_literals = decrypt_string_literals(
        &inputs.global_body,
        &inputs.mhy,
        profile.string_literal_count,
    );
    let default_values = decode_default_values(&inputs.global_body, &inputs.mhy, profile);
    DecodedMetadata {
        images,
        generics,
        types,
        fields,
        field_offsets,
        parameters,
        methods,
        interfaces,
        vtable_methods,
        interface_offsets,
        method_mappings,
        generic_classes,
        string_literals,
        nested_types,
        properties,
        events,
        field_defaults: default_values.fields,
        parameter_defaults: default_values.parameters,
        default_value_data: default_values.data,
        expected_field_default_count: default_values.expected_field_count,
        expected_parameter_default_count: default_values.expected_parameter_count,
        strings,
    }
}

fn decode_generic_classes(startup_metadata: &[u8], mhy: &MhyHeader) -> Vec<GenericClassEntry> {
    let count = mhy.generic_class_count();
    let base = mhy.generic_class_source_offset();
    (0..count)
        .filter_map(|index| {
            let offset = base.checked_add(index.checked_mul(8)?)?;
            let record = startup_metadata.get(offset..offset + 8)?;
            Some(GenericClassEntry {
                type_definition_index: LittleEndian::read_i32(record),
                generic_inst_index: LittleEndian::read_i32(&record[4..]),
            })
        })
        .collect()
}

fn decode_interfaces(global_body: &[u8], mhy: &MhyHeader, types: &[types::TypeDef]) -> Vec<i32> {
    let count = types
        .iter()
        .filter(|value| value.if_count > 0)
        .filter_map(|value| {
            usize::try_from(value.if_start)
                .ok()?
                .checked_add(value.if_count as usize)
        })
        .max()
        .unwrap_or(0);
    (0..count)
        .filter_map(|index| {
            let offset = mhy
                .interface_table_base()
                .checked_add(index.checked_mul(4)?)?;
            let record = global_body.get(offset..offset + 4)?;
            Some(LittleEndian::read_i32(record))
        })
        .collect()
}

fn decode_vtable_methods(
    global_body: &[u8],
    mhy: &MhyHeader,
    types: &[types::TypeDef],
) -> Vec<u32> {
    let count = types
        .iter()
        .filter(|value| value.vtable_count > 0)
        .filter_map(|value| {
            usize::try_from(value.vtable_start)
                .ok()?
                .checked_add(value.vtable_count as usize)
        })
        .max()
        .unwrap_or(0);
    (0..count)
        .filter_map(|index| {
            let offset = mhy
                .vtable_method_table_base()
                .checked_add(index.checked_mul(4)?)?;
            global_body
                .get(offset..offset + 4)
                .map(LittleEndian::read_u32)
        })
        .collect()
}

fn decode_interface_offsets(
    global_body: &[u8],
    mhy: &MhyHeader,
    types: &[types::TypeDef],
) -> Vec<InterfaceOffsetEntry> {
    let count = types
        .iter()
        .filter(|value| value.interface_offset_count > 0)
        .filter_map(|value| {
            usize::try_from(value.interface_offset_start)
                .ok()?
                .checked_add(value.interface_offset_count as usize)
        })
        .max()
        .unwrap_or(0);
    (0..count)
        .filter_map(|index| {
            let offset = mhy
                .interface_offset_table_base()
                .checked_add(index.checked_mul(6)?)?;
            let record = global_body.get(offset..offset + 6)?;
            Some(InterfaceOffsetEntry {
                type_index: LittleEndian::read_i32(record),
                offset: LittleEndian::read_i16(&record[4..]) as i32,
            })
        })
        .collect()
}
