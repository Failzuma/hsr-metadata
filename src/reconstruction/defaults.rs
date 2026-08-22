use crate::discovery::mhy::MhyHeader;
use crate::discovery::profile::BuildProfile;
use byteorder::{ByteOrder, LittleEndian};

pub struct FieldDefaultValue {
    pub field_index: i32,
    pub type_index: i32,
    pub data_index: i32,
}

pub struct ParameterDefaultValue {
    pub parameter_index: i32,
    pub type_index: i32,
    pub data_index: i32,
}

pub struct DefaultValues {
    pub fields: Vec<FieldDefaultValue>,
    pub parameters: Vec<ParameterDefaultValue>,
    pub data: Vec<u8>,
    pub expected_field_count: usize,
    pub expected_parameter_count: usize,
}

pub fn decode(global_body: &[u8], mhy: &MhyHeader, profile: &BuildProfile) -> DefaultValues {
    let fields = decode_fields(global_body, mhy);
    let parameters = decode_parameters(global_body, mhy);
    let data_start = mhy.default_value_data_base();
    let data_end = profile.type_definition_offset.min(global_body.len());
    let data = global_body
        .get(data_start..data_end)
        .unwrap_or_default()
        .to_vec();
    DefaultValues {
        fields,
        parameters,
        data,
        expected_field_count: mhy.field_default_count(),
        expected_parameter_count: mhy.parameter_default_count(),
    }
}

fn decode_fields(global_body: &[u8], mhy: &MhyHeader) -> Vec<FieldDefaultValue> {
    decode_records(
        global_body,
        mhy.field_default_table_base(),
        mhy.field_default_count(),
    )
    .into_iter()
    .map(|[type_index, data_index, field_index]| FieldDefaultValue {
        field_index,
        type_index,
        data_index,
    })
    .collect()
}

fn decode_parameters(global_body: &[u8], mhy: &MhyHeader) -> Vec<ParameterDefaultValue> {
    decode_records(
        global_body,
        mhy.parameter_default_table_base(),
        mhy.parameter_default_count(),
    )
    .into_iter()
    .map(
        |[type_index, parameter_index, data_index]| ParameterDefaultValue {
            parameter_index,
            type_index,
            data_index,
        },
    )
    .collect()
}

fn decode_records(global_body: &[u8], base: usize, count: usize) -> Vec<[i32; 3]> {
    (0..count)
        .filter_map(|index| {
            let offset = base.checked_add(index.checked_mul(12)?)?;
            let record = global_body.get(offset..offset + 12)?;
            Some([
                LittleEndian::read_i32(record),
                LittleEndian::read_i32(&record[4..]),
                LittleEndian::read_i32(&record[8..]),
            ])
        })
        .collect()
}
