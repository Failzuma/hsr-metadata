use super::defaults::{FieldDefaultValue, ParameterDefaultValue};
use super::generics::GenericsData;
use super::images::ImageDef;
use super::literals::StringLiteral;
use super::mappings::MethodMappingEntry;
use super::members::{EventDef, PropertyDef};
use super::methods::{MethodDef, ParamDef};
use super::strings::StringPool;
use super::types::{FieldDef, FieldOffsetEntry, TypeDef};

pub struct InterfaceOffsetEntry {
    pub type_index: i32,
    pub offset: i32,
}

pub struct GenericClassEntry {
    pub type_definition_index: i32,
    pub generic_inst_index: i32,
}

pub struct DecodedMetadata {
    pub images: Vec<ImageDef>,
    pub generics: GenericsData,
    pub types: Vec<TypeDef>,
    pub fields: Vec<FieldDef>,
    pub field_offsets: Vec<FieldOffsetEntry>,
    pub parameters: Vec<ParamDef>,
    pub methods: Vec<MethodDef>,
    pub interfaces: Vec<i32>,
    pub vtable_methods: Vec<u32>,
    pub interface_offsets: Vec<InterfaceOffsetEntry>,
    pub method_mappings: Vec<MethodMappingEntry>,
    pub generic_classes: Vec<GenericClassEntry>,
    pub string_literals: Vec<StringLiteral>,
    pub nested_types: Vec<i32>,
    pub properties: Vec<PropertyDef>,
    pub events: Vec<EventDef>,
    pub field_defaults: Vec<FieldDefaultValue>,
    pub parameter_defaults: Vec<ParameterDefaultValue>,
    pub default_value_data: Vec<u8>,
    pub expected_field_default_count: usize,
    pub expected_parameter_default_count: usize,
    pub strings: StringPool,
}

pub struct OutputArtifacts {
    pub rebuilt_metadata: Vec<u8>,
    pub field_offsets: Vec<u8>,
    pub method_mappings: Vec<u8>,
    pub generic_classes: Vec<u8>,
}
