use super::strings::StringDecryptor;
use crate::discovery::mhy::MhyHeader;
use crate::discovery::profile::BuildProfile;
use byteorder::{ByteOrder, LittleEndian};
use std::collections::HashMap;

pub struct TypeDef {
    pub name: String,
    pub ns: String,
    pub name_off: u32,
    pub ns_off: u32,
    pub byval_type_index: i32,
    pub type_index: i32,
    pub declaring_type_index: i32,
    pub parent_index: i32,
    pub generic_container_index: i32,
    pub flags: u32,
    pub bitfield: u32,
    pub f_start: i32,
    pub f_count: u16,
    pub m_start: u32,
    pub m_count: u16,
    pub if_start: i32,
    pub if_count: u16,
    pub nested_start: i32,
    pub nested_count: u16,
    pub property_start: i32,
    pub property_count: u16,
    pub event_start: i32,
    pub event_count: u16,
    pub vtable_start: i32,
    pub vtable_count: u16,
    pub interface_offset_start: i32,
    pub interface_offset_count: u16,
}

pub fn build_nested_type_indices(types: &mut [TypeDef]) -> Vec<i32> {
    let byval_to_definition = types
        .iter()
        .enumerate()
        .map(|(index, value)| (value.byval_type_index, index))
        .collect::<HashMap<_, _>>();
    let mut children = vec![Vec::new(); types.len()];
    for (child, value) in types.iter().enumerate() {
        if let Some(&parent) = byval_to_definition.get(&value.declaring_type_index) {
            children[parent].push(child as i32);
        }
    }
    let mut nested_types = Vec::new();
    for (value, child_indices) in types.iter_mut().zip(children) {
        if child_indices.is_empty() {
            value.nested_start = -1;
            value.nested_count = 0;
            continue;
        }
        value.nested_start = nested_types.len() as i32;
        value.nested_count = child_indices.len() as u16;
        nested_types.extend(child_indices);
    }
    nested_types
}

pub struct FieldDef {
    pub name: String,
    pub name_off: u32,
    pub type_index: i32,
    pub token: u32,
}

pub struct FieldOffsetEntry {
    pub type_idx: u32,
    pub field_idx_in_type: u32,
    pub offset: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct InterfaceRange {
    pub start: usize,
    pub count: usize,
}

pub(crate) fn decode_interface_ranges(
    global_body: &[u8],
    type_definition_offset: usize,
    type_definition_count: usize,
) -> Vec<InterfaceRange> {
    let count_bias = global_body
        .get(type_definition_offset + 68)
        .copied()
        .unwrap_or(0);
    (0..type_definition_count)
        .map(|index| {
            let offset = type_definition_offset + index * 70;
            let start = global_body
                .get(offset + 54..offset + 56)
                .map(|value| (LittleEndian::read_u16(value) ^ 0xc28c) as usize)
                .unwrap_or(0xffff);
            let count = global_body
                .get(offset + 68)
                .map(|value| count_bias ^ value)
                .unwrap_or(0) as usize;
            InterfaceRange { start, count }
        })
        .collect()
}

pub(crate) fn decode_type_generic_containers(
    global_body: &[u8],
    type_definition_offset: usize,
    type_definition_count: usize,
) -> Vec<i32> {
    (0..type_definition_count)
        .map(|index| {
            let offset = type_definition_offset + index * 70 + 60;
            global_body
                .get(offset..offset + 2)
                .map(|value| LittleEndian::read_u16(value).wrapping_add(21_508) as i16 as i32)
                .unwrap_or(-1)
        })
        .collect()
}

fn find_core_type_indices(
    global_body: &[u8],
    decryptor: &StringDecryptor,
    type_definition_offset: usize,
    type_definition_count: usize,
) -> (i32, i32) {
    let mut enum_index = -1;
    let mut value_type_index = -1;
    for index in 0..type_definition_count {
        let offset = type_definition_offset + index * 70;
        let Some(record) = global_body.get(offset..offset + 70) else {
            break;
        };
        let name = decryptor.decrypt_string(
            (LittleEndian::read_i32(&record[40..]) as u32).wrapping_sub(369_268_488),
        );
        if name != "Enum" && name != "ValueType" {
            continue;
        }
        let namespace = decryptor.decrypt_string(
            (LittleEndian::read_i32(&record[36..]) as u32).wrapping_add(0xF1D3_2D89),
        );
        if namespace != "System" {
            continue;
        }
        let byval_type_index = (LittleEndian::read_u32(&record[16..]) ^ 0x39F5_4DE4) as i32;
        if name == "Enum" {
            enum_index = byval_type_index;
        } else {
            value_type_index = byval_type_index;
        }
        if enum_index >= 0 && value_type_index >= 0 {
            break;
        }
    }
    (enum_index, value_type_index)
}

pub fn decrypt_types_and_fields(
    global_body: &[u8],
    mhy: &MhyHeader,
    decryptor: &StringDecryptor,
    type_generic_containers: &[i32],
    profile: &BuildProfile,
) -> (Vec<TypeDef>, Vec<FieldDef>, Vec<FieldOffsetEntry>) {
    let total_types = profile.type_definition_count;
    let type_def_off = profile.type_definition_offset;
    let mhy96_off = mhy.mhy96().wrapping_sub(455350429) as usize;
    let mhy39_off = mhy.mhy39().wrapping_sub(1132541481) as usize;
    let field_base = mhy.field_table_base();
    let offset_base = mhy.offset_table_base();
    let interface_ranges = decode_interface_ranges(global_body, type_def_off, total_types);
    let (enum_type_index, value_type_index) =
        find_core_type_indices(global_body, decryptor, type_def_off, total_types);

    let mut types = Vec::with_capacity(total_types);
    let mut fields = Vec::new();
    let mut field_offsets = Vec::new();
    let mut curr_field_start = 0i32;

    for i in 0..total_types {
        let t_off = type_def_off + i * 70;
        if t_off + 70 > global_body.len() {
            break;
        }

        let raw_i32_9 = LittleEndian::read_i32(&global_body[t_off + 36..]);
        let raw_i32_10 = LittleEndian::read_i32(&global_body[t_off + 40..]);
        let raw_i32_1 = LittleEndian::read_i32(&global_body[t_off + 4..]);
        let raw_i32_3 = LittleEndian::read_i32(&global_body[t_off + 12..]);
        let raw_i32_4 = LittleEndian::read_u32(&global_body[t_off + 16..]);
        let raw_i32_11 = LittleEndian::read_i32(&global_body[t_off + 44..]);
        let raw_i32_2 = LittleEndian::read_u32(&global_body[t_off + 8..]);
        let raw_u16_26 = LittleEndian::read_u16(&global_body[t_off + 52..]);
        let raw_i32_8 = LittleEndian::read_i32(&global_body[t_off + 32..]);
        let raw_u16_25 = LittleEndian::read_u16(&global_body[t_off + 50..]);
        let raw_i32_5 = LittleEndian::read_u32(&global_body[t_off + 20..]);
        let property_count = global_body[t_off + 65].wrapping_add(31) as u16;
        let property_start = if property_count > 0 {
            LittleEndian::read_u32(&global_body[t_off + 28..]).wrapping_sub(970_393_327) as i32
        } else {
            -1
        };
        let event_count = (global_body[t_off + 64] ^ 0x73) as u16;
        let event_start = if event_count > 0 {
            (LittleEndian::read_u16(&global_body[t_off + 48..]) ^ 0x6ECD) as i32
        } else {
            -1
        };
        let vtable_count = (global_body[t_off + 66] ^ 8) as u16;
        let vtable_start = if vtable_count > 0 {
            (LittleEndian::read_u32(&global_body[t_off + 24..]) ^ 0x4B4C_5F23) as i32
        } else {
            -1
        };
        let interface_offset_count = global_body[t_off + 69].wrapping_sub(1) as u16;
        let interface_offset_start = if interface_offset_count > 0 {
            (LittleEndian::read_u16(&global_body[t_off + 62..]) ^ 0x3E74) as i32
        } else {
            -1
        };

        let name_idx = (raw_i32_10 as u32).wrapping_sub(369268488);
        let ns_idx = (raw_i32_9 as u32).wrapping_add(0xF1D32D89);

        let mut name = decryptor.decrypt_string(name_idx);
        if name.is_empty() {
            name = format!("Type_{}", i);
        }
        let ns = decryptor.decrypt_string(ns_idx);

        let decl_idx = if raw_i32_3 != 472568491 {
            raw_i32_3.wrapping_sub(472568492)
        } else {
            -1
        };
        let is_nested = decl_idx != -1;

        let mut parent_idx = if raw_i32_1 != 1224299846 {
            raw_i32_1.wrapping_sub(1224299847)
        } else {
            -1
        };
        let byval_idx = (raw_i32_4 ^ 0x39F54DE4) as i32;

        let is_interface = parent_idx == -1
            && (((raw_i32_5 >> 4) & 0xF) == 3
                || (raw_i32_5 & 0xFF) == 0x32
                || (raw_i32_5 & 0xFF) == 0x31)
            && name != "Object"
            && name != "<Module>";

        let is_enum = parent_idx == enum_type_index;
        let is_struct = !is_enum
            && !is_interface
            && parent_idx == value_type_index
            && byval_idx != enum_type_index;
        let is_static = !is_enum && !is_struct && !is_interface && (((raw_i32_5 >> 8) & 0xF) == 5);
        let is_abstract = !is_enum
            && !is_struct
            && !is_interface
            && !is_static
            && (((raw_i32_5 >> 4) & 0xF) == 1);
        let is_sealed = !is_enum
            && !is_struct
            && !is_interface
            && !is_static
            && (((raw_i32_5 >> 8) & 0xF) == 4);

        let visibility = if is_nested {
            if name.starts_with("<>") || name.starts_with("<Private") {
                0x00000003
            } else {
                0x00000002
            }
        } else {
            0x00000001
        };

        let flags = if is_interface {
            visibility | 0x00000020 | 0x00000080
        } else if is_enum {
            visibility | 0x00000100 | 0x00100000
        } else if is_struct {
            visibility | 0x00000008 | 0x00000100 | 0x00100000
        } else if is_static {
            visibility | 0x00000080 | 0x00000100 | 0x00100000
        } else if is_abstract {
            visibility | 0x00000080 | 0x00100000
        } else if is_sealed {
            visibility | 0x00000100 | 0x00100000
        } else {
            visibility | 0x00100000
        };

        let bitfield = if is_enum {
            2
        } else if is_struct {
            1
        } else {
            0
        };

        if is_interface {
            parent_idx = -1;
        }

        let type_idx = raw_i32_11.wrapping_sub(1576109422);

        let m_start = raw_i32_2 ^ 0x1A7AF5FE;
        let m_count = raw_u16_26.wrapping_add(24467);

        let f_start_raw = (raw_i32_8 as u32).wrapping_sub(1954887780) as usize;
        let f_count = raw_u16_25.wrapping_add(17485);
        let f_start = curr_field_start;
        curr_field_start += f_count as i32;

        let interface_range = interface_ranges[i];
        let if_count = interface_range.count as u16;
        let if_start = if if_count > 0 {
            interface_range.start as i32
        } else {
            -1
        };

        let mut v55_rec_2 = 0i32;
        if mhy96_off + 4 * i + 4 <= global_body.len() {
            let t_idx_in_96 = LittleEndian::read_i32(&global_body[mhy96_off + 4 * i..]);
            let v55_off = mhy39_off + 12 * (t_idx_in_96 as usize);
            if v55_off + 12 <= global_body.len() {
                v55_rec_2 = LittleEndian::read_i32(&global_body[v55_off + 8..]);
            }
        }

        let mut v38_key =
            (-1388221511i32).wrapping_sub(744344320i32.wrapping_mul(raw_i32_8)) as u32;

        for v40 in 0..(f_count as usize) {
            let v43 = f_start_raw + v40;
            let f_off = field_base + 8 * v43;
            let (fname, ftype_idx) = if f_off + 8 <= global_body.len() {
                let raw_0 = LittleEndian::read_u32(&global_body[f_off..]);
                let raw_1 = LittleEndian::read_u32(&global_body[f_off + 4..]);
                let fname_idx = v38_key.wrapping_add(raw_0).wrapping_add(716162949);
                let ftype = v38_key.wrapping_add(raw_1) as i32;
                let mut fnm = decryptor.decrypt_string(fname_idx);
                if fnm.is_empty() {
                    fnm = format!("field_{}", v40);
                }
                (fnm, ftype)
            } else {
                (format!("field_{}", v40), -1i32)
            };

            let off_idx = (v40 as i32 + v55_rec_2) as usize;
            let foff = if offset_base + 4 * off_idx + 4 <= global_body.len() {
                LittleEndian::read_u32(&global_body[offset_base + 4 * off_idx..]) & 0xFFFFFF
            } else {
                0
            };

            field_offsets.push(FieldOffsetEntry {
                type_idx: i as u32,
                field_idx_in_type: v40 as u32,
                offset: foff,
            });

            fields.push(FieldDef {
                name: fname,
                name_off: 0,
                type_index: ftype_idx,
                token: 0x04000000 | (fields.len() as u32 + 1),
            });

            v38_key = v38_key.wrapping_sub(744344320);
        }

        let gc_idx = type_generic_containers.get(i).copied().unwrap_or(-1);

        types.push(TypeDef {
            name,
            ns,
            name_off: 0,
            ns_off: 0,
            byval_type_index: byval_idx,
            type_index: type_idx,
            declaring_type_index: decl_idx,
            parent_index: parent_idx,
            generic_container_index: gc_idx,
            flags,
            bitfield,
            f_start,
            f_count,
            m_start,
            m_count,
            if_start,
            if_count,
            nested_start: -1,
            nested_count: 0,
            property_start,
            property_count,
            event_start,
            event_count,
            vtable_start,
            vtable_count,
            interface_offset_start,
            interface_offset_count,
        });
    }

    (types, fields, field_offsets)
}

#[cfg(test)]
mod tests {
    use super::decode_type_generic_containers;

    #[test]
    fn generic_container_indices_decode_sentinel_and_valid_values() {
        let mut body = vec![0u8; 140];
        body[60..62].copy_from_slice(&0xabfbu16.to_le_bytes());
        body[130..132].copy_from_slice(&0xabfcu16.to_le_bytes());
        assert_eq!(decode_type_generic_containers(&body, 0, 2), [-1, 0]);
    }
}
