use super::strings::StringDecryptor;
use crate::discovery::mhy::MhyHeader;
use crate::discovery::profile::BuildProfile;
use byteorder::{ByteOrder, LittleEndian};
use std::collections::HashMap;

pub struct GenericsData {
    pub gp_names: Vec<String>,
    pub gp_containers: Vec<u32>,
    pub gp_name_offs: Vec<u32>,
    pub gp_constraint_starts: Vec<i16>,
    pub gp_constraint_counts: Vec<i16>,
    pub gp_nums: Vec<u16>,
    pub gp_flags: Vec<u16>,
    pub constraints: Vec<i32>,
    pub containers: Vec<(i32, i32, i32, i32)>,
    pub method_to_container: HashMap<usize, usize>,
}

pub fn decrypt_generics(
    global_body: &[u8],
    mhy: &MhyHeader,
    decryptor: &StringDecryptor,
    profile: &BuildProfile,
    type_generic_containers: &[i32],
) -> GenericsData {
    let total_gp = profile.generic_parameter_count;
    let mut gp_names = Vec::with_capacity(total_gp);
    let mut gp_constraint_starts = Vec::with_capacity(total_gp);
    let mut gp_constraint_counts = Vec::with_capacity(total_gp);
    let mut gp_nums = Vec::with_capacity(total_gp);
    let mut gp_flags = Vec::with_capacity(total_gp);
    let mut gp_containers = Vec::with_capacity(total_gp);

    let gp_base = mhy.gp_table_base();

    for p in 0..total_gp {
        let off = gp_base + p * 14;
        if off + 14 > global_body.len() {
            break;
        }

        let p_u64 = p as u64;
        let term1 = (0x617FE3CC452Cu64
            .wrapping_mul(p_u64)
            .wrapping_add(0x9DC5DB71F0EB440)
            >> 9)
            .wrapping_add(718849585)
            ^ 0x5278374D;
        let v15_qword = (1252900171u64.wrapping_mul(term1)) >> 15;
        let v15_dword = v15_qword as u32;
        let key = v15_qword as u16;

        let name_dword = LittleEndian::read_i32(&global_body[off..]) as u32;
        let name_idx = name_dword.wrapping_sub(v15_dword).wrapping_sub(1149796643);

        let mut pname = decryptor.decrypt_string(name_idx);
        if pname.is_empty() {
            pname = "T".to_string();
        }

        gp_names.push(pname);
        gp_constraint_starts.push(
            (LittleEndian::read_u16(&global_body[off + 4..]) ^ 0x69B4).wrapping_sub(key) as i16,
        );
        gp_constraint_counts.push(
            (LittleEndian::read_u16(&global_body[off + 6..]) ^ 0x0FD1).wrapping_sub(key) as i16,
        );
        gp_containers.push(
            (LittleEndian::read_u16(&global_body[off + 8..]) ^ 0x7526).wrapping_sub(key) as u32,
        );
        gp_nums.push((LittleEndian::read_u16(&global_body[off + 10..]) ^ 0xBD3B).wrapping_sub(key));
        gp_flags
            .push((LittleEndian::read_u16(&global_body[off + 12..]) ^ 0x7AF7).wrapping_sub(key));
    }

    let constraint_count = gp_constraint_starts
        .iter()
        .zip(&gp_constraint_counts)
        .filter_map(|(&start, &count)| {
            let start = usize::try_from(start).ok()?;
            let count = usize::try_from(count).ok()?;
            start.checked_add(count)
        })
        .max()
        .unwrap_or(0);
    let constraint_base = mhy.generic_constraint_table_base();
    let constraints = (0..constraint_count)
        .filter_map(|index| {
            let offset = constraint_base.checked_add(index.checked_mul(4)?)?;
            global_body
                .get(offset..offset + 4)
                .map(LittleEndian::read_i32)
        })
        .collect();

    let total_containers = profile.generic_container_count;
    let method_count = global_body.len().saturating_sub(mhy.method_table_base()) / 26;
    let mut containers = Vec::with_capacity(total_containers);
    let mut method_to_container = HashMap::new();
    let container_to_type = type_generic_containers
        .iter()
        .enumerate()
        .filter_map(|(type_index, &container_index)| {
            usize::try_from(container_index)
                .ok()
                .map(|container_index| (container_index, type_index))
        })
        .collect::<HashMap<_, _>>();
    let gc_base = mhy.gc_table_base();

    for c in 0..total_containers {
        let off = gc_base + c * 16;
        let mut p_start = -1i32;
        let mut p_cnt = 0i32;
        let mut is_method = 0i32;
        let mut owner_idx = -1i32;

        if off + 16 <= global_body.len() {
            let d0 = LittleEndian::read_u32(&global_body[off..]);
            let d2 = LittleEndian::read_u32(&global_body[off + 8..]);
            let d3 = LittleEndian::read_u32(&global_body[off + 12..]);

            let v21 = c as u64;
            let step1 = (0x3D6913E0AF40u64
                .wrapping_mul(v21)
                .wrapping_add(0xA64CAD60FA052C0))
                >> 23;
            let step2 = 1_997_422_568u64.wrapping_mul(step1) >> 11;
            let v22 = (748_293_795u64.wrapping_mul(step2) >> 23) as u32;

            p_cnt = (d0.wrapping_sub(214_875_017) ^ v22) as i32;
            p_start = (d3.wrapping_sub(248_843_855) ^ v22) as i32;
            let v25 = d2;

            if let Some(&owner) = container_to_type.get(&c) {
                owner_idx = owner as i32;
                is_method = 0;
            } else {
                let owner = (v22 ^ v25 ^ 0x687A16BA) as usize;
                owner_idx = owner as i32;
                is_method = 1;
                if owner < method_count {
                    method_to_container.insert(owner, c);
                }
            }
        }

        containers.push((owner_idx, p_cnt, is_method, p_start));
    }

    GenericsData {
        gp_names,
        gp_containers,
        gp_name_offs: Vec::new(),
        gp_constraint_starts,
        gp_constraint_counts,
        gp_nums,
        gp_flags,
        constraints,
        containers,
        method_to_container,
    }
}
