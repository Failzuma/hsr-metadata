use super::strings::StringDecryptor;
use crate::discovery::mhy::MhyHeader;
use byteorder::{ByteOrder, LittleEndian};
use rayon::prelude::*;
use std::collections::HashMap;

pub struct ParamDef {
    pub name: String,
    pub name_off: u32,
    pub type_index: i32,
    pub token: u32,
}

pub struct MethodDef {
    pub name: String,
    pub name_off: u32,
    pub token: u32,
    pub return_type: i32,
    pub parameter_start: i32,
    pub parameter_count: u16,
    pub flags: u16,
    pub slot: u16,
    pub generic_container_index: i32,
}

pub fn calc_term(m: usize) -> u32 {
    let r8 = m as u128;
    let step1 = (12769u128 * r8) ^ 0x33914937u128;
    let step2 = (738455933u128 * step1) >> 23;
    let step3 = (1410124276u128 * step2) >> 21;
    ((step3 + 1908176993) & 0xFFFFFFFF) as u32
}

pub fn decrypt_parameters(
    global_body: &[u8],
    mhy: &MhyHeader,
    decryptor: &StringDecryptor,
    total_params: usize,
) -> Vec<ParamDef> {
    let param_base = mhy.param_table_base();

    (0..total_params)
        .into_par_iter()
        .map(|v28| {
            let v30 = (1488482466u64.wrapping_mul(
                (0x72E1D74B12Bu64
                    .wrapping_mul(v28 as u64)
                    .wrapping_add(0x1911D05AFF5))
                    >> 11,
            ) as u32)
                .wrapping_sub(2083554492);

            let off = param_base + 8 * v28;
            let raw_0 = LittleEndian::read_u32(&global_body[off..]);
            let raw_1 = LittleEndian::read_u32(&global_body[off + 4..]);

            let pname_idx = (raw_1 ^ 0x7103092E).wrapping_sub(v30);
            let ptype_idx = ((raw_0 ^ 0x67E90DC5).wrapping_sub(v30)) as i32;

            let pname = decryptor.decrypt_string(pname_idx);
            let token = 0x08000000 | (v28 as u32 + 1);

            ParamDef {
                name: pname,
                name_off: 0,
                type_index: ptype_idx,
                token,
            }
        })
        .collect()
}

pub fn decrypt_methods(
    global_body: &[u8],
    mhy: &MhyHeader,
    decryptor: &StringDecryptor,
    total_methods: usize,
    total_params: usize,
    method_to_container: &HashMap<usize, usize>,
) -> Vec<MethodDef> {
    let method_base = mhy.method_table_base();
    (0..total_methods)
        .into_par_iter()
        .map(|m| {
            let m_off = method_base + m * 26;
            let raw_0 = LittleEndian::read_u32(&global_body[m_off..]);
            let raw_1 = LittleEndian::read_u32(&global_body[m_off + 4..]);
            let raw_dword_8 = LittleEndian::read_i32(&global_body[m_off + 8..]);
            let raw_u16_7 = LittleEndian::read_u16(&global_body[m_off + 14..]);
            let raw_u16_20 = LittleEndian::read_u16(&global_body[m_off + 20..]);
            let raw_24 = global_body[m_off + 24];

            let term = calc_term(m);
            let term_w = (term & 0xFFFF) as u16;

            let name_idx = raw_0 ^ term ^ 0x0E714BC1;
            let mut name = decryptor.decrypt_string(name_idx);
            if name.is_empty() {
                name = format!("Method_{}", m);
            }

            let p_cnt = (raw_24 ^ (term as u8) ^ 0xA8) as u16;
            let p_start_raw = raw_1 ^ term ^ 0x9889B8;
            let (p_start, p_count) =
                if p_cnt > 0 && p_start_raw != u32::MAX && (p_start_raw as usize) < total_params {
                    (p_start_raw as i32, p_cnt)
                } else {
                    (-1, 0)
                };

            let ret_type_idx = (((raw_dword_8 as u32).wrapping_sub(1698564893)) ^ term) as i32;
            let flags = raw_u16_7 ^ term_w ^ 0x3733;
            let slot = (raw_u16_20.wrapping_sub(30979)) ^ term_w;
            let token = 0x06000000 | (m as u32 + 1);
            let gc_idx = method_to_container
                .get(&m)
                .copied()
                .map(|c| c as i32)
                .unwrap_or(-1);

            MethodDef {
                name,
                name_off: 0,
                token,
                return_type: ret_type_idx,
                parameter_start: p_start,
                parameter_count: p_count,
                flags,
                slot,
                generic_container_index: gc_idx,
            }
        })
        .collect()
}
