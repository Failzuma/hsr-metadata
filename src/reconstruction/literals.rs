use crate::discovery::mhy::MhyHeader;
use byteorder::{ByteOrder, LittleEndian};

pub struct StringLiteral {
    pub data: Vec<u8>,
}

pub fn discover_count(global_body: &[u8], mhy: &MhyHeader) -> Option<usize> {
    let table = mhy.string_literal_offsets_base();
    let limit = table.min(global_body.len());
    let maximum = global_body.len().checked_sub(table)?.checked_div(4)?;
    let mut previous = data_position(global_body, mhy, 0)?;
    if previous >= limit {
        return None;
    }
    for index in 1..maximum {
        let current = data_position(global_body, mhy, index)?;
        if current < previous || current > limit {
            return (index > 1).then_some(index - 1);
        }
        previous = current;
    }
    None
}

pub fn decrypt(global_body: &[u8], mhy: &MhyHeader, count: usize) -> Vec<StringLiteral> {
    (0..count)
        .filter_map(|index| {
            let start = data_position(global_body, mhy, index)?;
            let end = data_position(global_body, mhy, index + 1)?;
            let length = end.checked_sub(start)?;
            let padded_length = length.checked_add(7)? & !7;
            let encrypted = global_body.get(start..start.checked_add(padded_length)?)?;
            let mut key = (0xde8c_09c8_3613_3dbdu64.wrapping_mul(index as u64)
                ^ 0x18d0_25c9_6ee7_4e86)
                .wrapping_add(0x2c68_33cc_6f0a_9c48);
            let mut data = Vec::with_capacity(padded_length);
            for chunk in encrypted.chunks_exact(8) {
                data.extend_from_slice(&(LittleEndian::read_u64(chunk) ^ key).to_le_bytes());
                key = key.wrapping_add(0x464c_4654_0f73_0312);
            }
            data.truncate(length);
            Some(StringLiteral { data })
        })
        .collect()
}

fn data_position(global_body: &[u8], mhy: &MhyHeader, index: usize) -> Option<usize> {
    let offset = mhy
        .string_literal_offsets_base()
        .checked_add(index.checked_mul(4)?)?;
    let encoded = LittleEndian::read_u32(global_body.get(offset..offset + 4)?);
    let index64 = index as u64;
    let scaled = 0x32c1_cf25_bb14u64.wrapping_mul(index64);
    let mixed = scaled.wrapping_add(0x001f_0fe2_59cf_0538) >> 14;
    let mask = 604_527_770u64.wrapping_mul(mixed) >> 8;
    let relative = encoded.wrapping_sub(mask as u32);
    Some(mhy.string_literal_data_base().wrapping_add(relative) as usize)
}

#[cfg(test)]
mod tests {
    use super::data_position;
    use crate::discovery::mhy::{MhyHeader, MhyLayout};

    #[test]
    fn literal_position_uses_wrapping_runtime_arithmetic() {
        let mut body = vec![0u8; 16];
        let mixed = 0x001f_0fe2_59cf_0538_u64 >> 14;
        let mask = 604_527_770u64.wrapping_mul(mixed) >> 8;
        let data_base = 0xc3e2_b83d_u32.wrapping_add(854_233_332);
        let encoded = (mask as u32).wrapping_sub(data_base);
        body[..4].copy_from_slice(&encoded.to_le_bytes());
        let header = MhyHeader {
            file_offset: 0,
            layout: MhyLayout {
                string_literal_offsets: 0,
                string_literal_data: data_base,
                ..MhyLayout::default()
            },
            candidates: Default::default(),
        };
        assert_eq!(data_position(&body, &header, 0), Some(0));
    }
}
