use super::strings::StringDecryptor;
use super::types::TypeDef;
use crate::discovery::mhy::MhyHeader;
use byteorder::{ByteOrder, LittleEndian};

pub struct PropertyDef {
    pub name: String,
    pub name_off: u32,
    pub get: i32,
    pub set: i32,
    pub attrs: u32,
    pub token: u32,
}

pub struct EventDef {
    pub name: String,
    pub name_off: u32,
    pub type_index: i32,
    pub add: i32,
    pub remove: i32,
    pub raise: i32,
    pub token: u32,
}

pub fn decode_properties(
    global_body: &[u8],
    mhy: &MhyHeader,
    decryptor: &StringDecryptor,
    types: &[TypeDef],
) -> Vec<PropertyDef> {
    let count = types
        .iter()
        .filter(|value| value.property_count > 0)
        .filter_map(|value| {
            usize::try_from(value.property_start)
                .ok()?
                .checked_add(value.property_count as usize)
        })
        .max()
        .unwrap_or(0);
    let base = mhy.property_table_base();
    (0..count)
        .filter_map(|index| {
            let offset = base.checked_add(index.checked_mul(10)?)?;
            let record = global_body.get(offset..offset + 10)?;
            let key = property_key(index);
            let name_index =
                (LittleEndian::read_u32(record) ^ 0x6199_063C).wrapping_sub(key as u32);
            let set = decode_accessor(LittleEndian::read_u16(&record[4..]) ^ 0x4B8F, key as u16);
            let get = decode_accessor(LittleEndian::read_u16(&record[6..]) ^ 0xFA36, key as u16);
            let attrs =
                (LittleEndian::read_u16(&record[8..]) ^ 0x5E8B).wrapping_sub(key as u16) as u32;
            Some(PropertyDef {
                name: decryptor.decrypt_string(name_index),
                name_off: 0,
                get,
                set,
                attrs,
                token: 0x1700_0000 | (index as u32 + 1),
            })
        })
        .collect()
}

pub fn decode_events(
    global_body: &[u8],
    mhy: &MhyHeader,
    decryptor: &StringDecryptor,
    types: &[TypeDef],
) -> Vec<EventDef> {
    let count = types
        .iter()
        .filter(|value| value.event_count > 0)
        .filter_map(|value| {
            usize::try_from(value.event_start)
                .ok()?
                .checked_add(value.event_count as usize)
        })
        .max()
        .unwrap_or(0);
    let base = mhy.event_table_base();
    (0..count)
        .filter_map(|index| {
            let offset = base.checked_add(index.checked_mul(14)?)?;
            let record = global_body.get(offset..offset + 14)?;
            let key = event_key(index);
            let name_index =
                (LittleEndian::read_u32(record) ^ 0x0789_81CB).wrapping_sub(key as u32);
            let type_index = (LittleEndian::read_u32(&record[4..]) ^ 0x5324_3DF3)
                .wrapping_sub(key as u32) as i32;
            let raise = decode_accessor(LittleEndian::read_u16(&record[8..]) ^ 0x8450, key as u16);
            let add = decode_accessor(LittleEndian::read_u16(&record[10..]) ^ 0xE8CB, key as u16);
            let remove =
                decode_accessor(LittleEndian::read_u16(&record[12..]) ^ 0x3CE2, key as u16);
            Some(EventDef {
                name: decryptor.decrypt_string(name_index),
                name_off: 0,
                type_index,
                add,
                remove,
                raise,
                token: 0x1400_0000 | (index as u32 + 1),
            })
        })
        .collect()
}

fn decode_accessor(value: u16, key: u16) -> i32 {
    let value = value.wrapping_sub(key);
    if value == u16::MAX {
        -1
    } else {
        value as i32
    }
}

fn property_key(index: usize) -> u64 {
    let value = 6035u64.wrapping_mul(index as u64) ^ 0x280E_7A20;
    let value = 1_831_379_439u64.wrapping_mul(value) >> 17;
    ((value ^ 0x727E_FF5B).wrapping_add(1_664_893_910)) ^ 0x4ADB_D505
}

fn event_key(index: usize) -> u64 {
    let value = 15_580u64.wrapping_mul(index as u64) ^ 0x550D_63BA;
    let value = 1_057_473_644u64.wrapping_mul(value) >> 19;
    1_598_447_864u64
        .wrapping_mul(value)
        .wrapping_add(0x2682_4684_CA69_CA48)
        >> 15
}
