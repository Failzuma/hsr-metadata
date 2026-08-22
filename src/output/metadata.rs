use crate::reconstruction::model::{DecodedMetadata, OutputArtifacts};
use anyhow::Result;
use byteorder::{ByteOrder, LittleEndian};
use std::fs;
use std::path::{Path, PathBuf};

pub struct ArtifactPaths {
    pub rebuilt_metadata: PathBuf,
    pub field_offsets: PathBuf,
    pub method_mappings: PathBuf,
    pub generic_classes: PathBuf,
}

pub fn build(metadata: &DecodedMetadata) -> OutputArtifacts {
    let (string_literals, string_literal_data) = build_string_literals(metadata);
    let generic_parameters = build_generic_parameters(metadata);
    let generic_containers = build_generic_containers(metadata);
    let generic_constraints = build_generic_constraints(metadata);
    let parameter_defaults = build_parameter_defaults(metadata);
    let field_defaults = build_field_defaults(metadata);
    let interfaces = build_interfaces(metadata);
    let vtable_methods = build_vtable_methods(metadata);
    let interface_offsets = build_interface_offsets(metadata);
    let nested_types = build_nested_types(metadata);
    let properties = build_properties(metadata);
    let events = build_events(metadata);
    let types = build_types(metadata);
    let parameters = build_parameters(metadata);
    let methods = build_methods(metadata);
    let fields = build_fields(metadata);
    let images = build_images(metadata);
    let assemblies = build_assemblies(metadata);
    let sections = MetadataSections {
        string_literals: &string_literals,
        string_literal_data: &string_literal_data,
        strings: &metadata.strings.pool,
        events: &events,
        properties: &properties,
        methods: &methods,
        parameter_defaults: &parameter_defaults,
        field_defaults: &field_defaults,
        default_value_data: &metadata.default_value_data,
        parameters: &parameters,
        fields: &fields,
        generic_parameters: &generic_parameters,
        generic_constraints: &generic_constraints,
        generic_containers: &generic_containers,
        nested_types: &nested_types,
        interfaces: &interfaces,
        vtable_methods: &vtable_methods,
        interface_offsets: &interface_offsets,
        types: &types,
        images: &images,
        assemblies: &assemblies,
    };
    let rebuilt_metadata = assemble_metadata(&sections);
    OutputArtifacts {
        rebuilt_metadata,
        field_offsets: build_field_offsets(metadata),
        method_mappings: build_method_mappings(metadata),
        generic_classes: build_generic_classes(metadata),
    }
}

pub fn write(output_dir: &Path, artifacts: &OutputArtifacts) -> Result<ArtifactPaths> {
    fs::create_dir_all(output_dir)?;
    let paths = ArtifactPaths {
        rebuilt_metadata: output_dir.join("rebuilt_metadata.dat"),
        field_offsets: output_dir.join("field_offsets.bin"),
        method_mappings: output_dir.join("method_mappings.bin"),
        generic_classes: output_dir.join("generic_classes.bin"),
    };
    fs::write(&paths.rebuilt_metadata, &artifacts.rebuilt_metadata)?;
    fs::write(&paths.field_offsets, &artifacts.field_offsets)?;
    fs::write(&paths.method_mappings, &artifacts.method_mappings)?;
    fs::write(&paths.generic_classes, &artifacts.generic_classes)?;
    Ok(paths)
}

fn build_string_literals(metadata: &DecodedMetadata) -> (Vec<u8>, Vec<u8>) {
    let mut definitions = Vec::new();
    let mut data = Vec::new();
    for value in &metadata.string_literals {
        let bytes = &value.data;
        let offset = data.len() as u32;
        data.extend_from_slice(bytes);
        push_u32(&mut definitions, bytes.len() as u32);
        push_u32(&mut definitions, offset);
    }
    (definitions, data)
}

fn build_nested_types(metadata: &DecodedMetadata) -> Vec<u8> {
    let mut output = Vec::with_capacity(metadata.nested_types.len() * 4);
    for &index in &metadata.nested_types {
        push_i32(&mut output, index);
    }
    output
}

fn build_properties(metadata: &DecodedMetadata) -> Vec<u8> {
    let mut output = Vec::with_capacity(metadata.properties.len() * 20);
    for value in &metadata.properties {
        push_u32(&mut output, value.name_off);
        push_i32(&mut output, value.get);
        push_i32(&mut output, value.set);
        push_u32(&mut output, value.attrs);
        push_u32(&mut output, value.token);
    }
    output
}

fn build_events(metadata: &DecodedMetadata) -> Vec<u8> {
    let mut output = Vec::with_capacity(metadata.events.len() * 24);
    for value in &metadata.events {
        push_u32(&mut output, value.name_off);
        push_i32(&mut output, value.type_index);
        push_i32(&mut output, value.add);
        push_i32(&mut output, value.remove);
        push_i32(&mut output, value.raise);
        push_u32(&mut output, value.token);
    }
    output
}

fn build_generic_parameters(metadata: &DecodedMetadata) -> Vec<u8> {
    let mut output = Vec::with_capacity(metadata.generics.gp_names.len() * 16);
    for index in 0..metadata.generics.gp_names.len() {
        push_i32(&mut output, metadata.generics.gp_containers[index] as i32);
        push_u32(&mut output, metadata.generics.gp_name_offs[index]);
        push_i16(&mut output, metadata.generics.gp_constraint_starts[index]);
        push_i16(&mut output, metadata.generics.gp_constraint_counts[index]);
        push_u16(&mut output, metadata.generics.gp_nums[index]);
        push_u16(&mut output, metadata.generics.gp_flags[index]);
    }
    output
}

fn build_generic_constraints(metadata: &DecodedMetadata) -> Vec<u8> {
    let mut output = Vec::with_capacity(metadata.generics.constraints.len() * 4);
    for &index in &metadata.generics.constraints {
        push_i32(&mut output, index);
    }
    output
}

fn build_parameter_defaults(metadata: &DecodedMetadata) -> Vec<u8> {
    let mut output = Vec::with_capacity(metadata.parameter_defaults.len() * 12);
    for value in &metadata.parameter_defaults {
        push_i32(&mut output, value.parameter_index);
        push_i32(&mut output, value.type_index);
        push_i32(&mut output, value.data_index);
    }
    output
}

fn build_field_defaults(metadata: &DecodedMetadata) -> Vec<u8> {
    let mut output = Vec::with_capacity(metadata.field_defaults.len() * 12);
    for value in &metadata.field_defaults {
        push_i32(&mut output, value.field_index);
        push_i32(&mut output, value.type_index);
        push_i32(&mut output, value.data_index);
    }
    output
}

fn build_generic_containers(metadata: &DecodedMetadata) -> Vec<u8> {
    let mut output = Vec::with_capacity(metadata.generics.containers.len() * 16);
    for &(owner, parameter_count, is_method, parameter_start) in &metadata.generics.containers {
        push_i32(&mut output, owner);
        push_i32(&mut output, parameter_count);
        push_i32(&mut output, is_method);
        push_i32(&mut output, parameter_start);
    }
    output
}

fn build_interfaces(metadata: &DecodedMetadata) -> Vec<u8> {
    let mut output = Vec::with_capacity(metadata.interfaces.len() * 4);
    for &type_index in &metadata.interfaces {
        push_i32(&mut output, type_index);
    }
    output
}

fn build_vtable_methods(metadata: &DecodedMetadata) -> Vec<u8> {
    let mut output = Vec::with_capacity(metadata.vtable_methods.len() * 4);
    for &method in &metadata.vtable_methods {
        push_u32(&mut output, method);
    }
    output
}

fn build_interface_offsets(metadata: &DecodedMetadata) -> Vec<u8> {
    let mut output = Vec::with_capacity(metadata.interface_offsets.len() * 8);
    for value in &metadata.interface_offsets {
        push_i32(&mut output, value.type_index);
        push_i32(&mut output, value.offset);
    }
    output
}

fn build_types(metadata: &DecodedMetadata) -> Vec<u8> {
    let mut output = Vec::with_capacity(metadata.types.len() * 92);
    for (index, value) in metadata.types.iter().enumerate() {
        push_u32(&mut output, value.name_off);
        push_u32(&mut output, value.ns_off);
        push_i32(&mut output, value.byval_type_index);
        push_i32(&mut output, value.type_index);
        push_i32(&mut output, value.declaring_type_index);
        push_i32(&mut output, value.parent_index);
        push_i32(&mut output, -1);
        push_i32(&mut output, value.generic_container_index);
        push_u32(&mut output, value.flags);
        push_i32(&mut output, value.f_start);
        push_i32(&mut output, value.m_start as i32);
        push_i32(&mut output, value.event_start);
        push_i32(&mut output, value.property_start);
        push_i32(&mut output, value.nested_start);
        push_i32(&mut output, value.if_start);
        push_i32(&mut output, value.vtable_start);
        push_i32(&mut output, value.interface_offset_start);
        push_u16(&mut output, value.m_count);
        push_u16(&mut output, value.property_count);
        push_u16(&mut output, value.f_count);
        push_u16(&mut output, value.event_count);
        push_u16(&mut output, value.nested_count);
        push_u16(&mut output, value.vtable_count);
        push_u16(&mut output, value.if_count);
        push_u16(&mut output, value.interface_offset_count);
        push_u32(&mut output, value.bitfield);
        push_u32(&mut output, 0x02000000 | (index as u32 + 1));
    }
    output
}

fn build_parameters(metadata: &DecodedMetadata) -> Vec<u8> {
    let mut output = Vec::with_capacity(metadata.parameters.len() * 12);
    for value in &metadata.parameters {
        push_u32(&mut output, value.name_off);
        push_u32(&mut output, value.token);
        push_i32(&mut output, value.type_index);
    }
    output
}

fn build_methods(metadata: &DecodedMetadata) -> Vec<u8> {
    let mut output = Vec::with_capacity(metadata.methods.len() * 32);
    for value in &metadata.methods {
        push_u32(&mut output, value.name_off);
        push_i32(&mut output, -1);
        push_i32(&mut output, value.return_type);
        push_i32(&mut output, value.parameter_start);
        push_i32(&mut output, value.generic_container_index);
        push_u32(&mut output, value.token);
        push_u16(&mut output, value.flags);
        push_u16(&mut output, 0);
        push_u16(&mut output, value.slot);
        push_u16(&mut output, value.parameter_count);
    }
    output
}

fn build_fields(metadata: &DecodedMetadata) -> Vec<u8> {
    let mut output = Vec::with_capacity(metadata.fields.len() * 12);
    for value in &metadata.fields {
        push_u32(&mut output, value.name_off);
        push_i32(&mut output, value.type_index);
        push_u32(&mut output, value.token);
    }
    output
}

fn build_images(metadata: &DecodedMetadata) -> Vec<u8> {
    let mut output = Vec::with_capacity(metadata.images.len() * 40);
    let mut type_start = 0u32;
    for (index, value) in metadata.images.iter().enumerate() {
        push_i32(&mut output, value.name_off as i32);
        push_i32(&mut output, index as i32);
        push_i32(&mut output, type_start as i32);
        push_i32(&mut output, value.type_count as i32);
        output.resize(output.len() + 24, 0);
        type_start += value.type_count;
    }
    output
}

fn build_assemblies(metadata: &DecodedMetadata) -> Vec<u8> {
    let mut output = Vec::with_capacity(metadata.images.len() * 68);
    for (index, value) in metadata.images.iter().enumerate() {
        let start = output.len();
        output.resize(start + 68, 0);
        LittleEndian::write_i32(&mut output[start..start + 4], index as i32);
        LittleEndian::write_i32(&mut output[start + 16..start + 20], value.name_off as i32);
    }
    output
}

struct MetadataSections<'a> {
    string_literals: &'a [u8],
    string_literal_data: &'a [u8],
    strings: &'a [u8],
    events: &'a [u8],
    properties: &'a [u8],
    methods: &'a [u8],
    parameter_defaults: &'a [u8],
    field_defaults: &'a [u8],
    default_value_data: &'a [u8],
    parameters: &'a [u8],
    fields: &'a [u8],
    generic_parameters: &'a [u8],
    generic_constraints: &'a [u8],
    generic_containers: &'a [u8],
    nested_types: &'a [u8],
    interfaces: &'a [u8],
    vtable_methods: &'a [u8],
    interface_offsets: &'a [u8],
    types: &'a [u8],
    images: &'a [u8],
    assemblies: &'a [u8],
}

fn assemble_metadata(sections: &MetadataSections<'_>) -> Vec<u8> {
    let mut header = [0u32; 66];
    header[0] = 0xFAB11BAF;
    header[1] = 24;
    let mut offset = header.len() * 4;
    set_section(&mut header, 2, &mut offset, sections.string_literals);
    set_section(&mut header, 4, &mut offset, sections.string_literal_data);
    set_section(&mut header, 6, &mut offset, sections.strings);
    set_section(&mut header, 8, &mut offset, sections.events);
    set_section(&mut header, 10, &mut offset, sections.properties);
    set_section(&mut header, 12, &mut offset, sections.methods);
    set_section(&mut header, 14, &mut offset, sections.parameter_defaults);
    set_section(&mut header, 16, &mut offset, sections.field_defaults);
    set_section(&mut header, 18, &mut offset, sections.default_value_data);
    set_section(&mut header, 22, &mut offset, sections.parameters);
    set_section(&mut header, 24, &mut offset, sections.fields);
    set_section(&mut header, 26, &mut offset, sections.generic_parameters);
    set_section(&mut header, 28, &mut offset, sections.generic_constraints);
    set_section(&mut header, 30, &mut offset, sections.generic_containers);
    set_section(&mut header, 32, &mut offset, sections.nested_types);
    set_section(&mut header, 34, &mut offset, sections.interfaces);
    set_section(&mut header, 36, &mut offset, sections.vtable_methods);
    set_section(&mut header, 38, &mut offset, sections.interface_offsets);
    set_section(&mut header, 40, &mut offset, sections.types);
    set_section(&mut header, 42, &mut offset, sections.images);
    set_section(&mut header, 44, &mut offset, sections.assemblies);
    let capacity = offset;
    let mut output = Vec::with_capacity(capacity);
    for value in header {
        push_u32(&mut output, value);
    }
    for section in [
        sections.string_literals,
        sections.string_literal_data,
        sections.strings,
        sections.events,
        sections.properties,
        sections.methods,
        sections.parameter_defaults,
        sections.field_defaults,
        sections.default_value_data,
        sections.parameters,
        sections.fields,
        sections.generic_parameters,
        sections.generic_constraints,
        sections.generic_containers,
        sections.nested_types,
        sections.interfaces,
        sections.vtable_methods,
        sections.interface_offsets,
        sections.types,
        sections.images,
        sections.assemblies,
    ] {
        output.extend_from_slice(section);
    }
    output
}

fn build_field_offsets(metadata: &DecodedMetadata) -> Vec<u8> {
    let mut output = Vec::with_capacity(metadata.field_offsets.len() * 12);
    for value in &metadata.field_offsets {
        push_u32(&mut output, value.type_idx);
        push_u32(&mut output, value.field_idx_in_type);
        push_u32(&mut output, value.offset);
    }
    output
}

fn build_method_mappings(metadata: &DecodedMetadata) -> Vec<u8> {
    let mut output = Vec::with_capacity(metadata.method_mappings.len() * 12);
    for value in &metadata.method_mappings {
        push_u32(&mut output, value.method_idx);
        push_u64(&mut output, value.pointer);
    }
    output
}

fn build_generic_classes(metadata: &DecodedMetadata) -> Vec<u8> {
    let mut output = Vec::with_capacity(metadata.generic_classes.len() * 8);
    for value in &metadata.generic_classes {
        push_i32(&mut output, value.type_definition_index);
        push_i32(&mut output, value.generic_inst_index);
    }
    output
}

fn set_section(header: &mut [u32], index: usize, offset: &mut usize, section: &[u8]) {
    header[index] = *offset as u32;
    header[index + 1] = section.len() as u32;
    *offset += section.len();
}

fn push_i16(output: &mut Vec<u8>, value: i16) {
    let mut bytes = [0u8; 2];
    LittleEndian::write_i16(&mut bytes, value);
    output.extend_from_slice(&bytes);
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    let mut bytes = [0u8; 2];
    LittleEndian::write_u16(&mut bytes, value);
    output.extend_from_slice(&bytes);
}

fn push_i32(output: &mut Vec<u8>, value: i32) {
    let mut bytes = [0u8; 4];
    LittleEndian::write_i32(&mut bytes, value);
    output.extend_from_slice(&bytes);
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    let mut bytes = [0u8; 4];
    LittleEndian::write_u32(&mut bytes, value);
    output.extend_from_slice(&bytes);
}

fn push_u64(output: &mut Vec<u8>, value: u64) {
    let mut bytes = [0u8; 8];
    LittleEndian::write_u64(&mut bytes, value);
    output.extend_from_slice(&bytes);
}
