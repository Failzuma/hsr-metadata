use super::strings::StringDecryptor;
use crate::discovery::mhy::MhyHeader;
use byteorder::{ByteOrder, LittleEndian};

#[derive(Clone)]
pub struct ImageDef {
    pub name: String,
    pub type_count: u32,
    pub name_off: u32,
}

pub fn decrypt_images(
    startup_meta: &[u8],
    mhy: &MhyHeader,
    decryptor: &StringDecryptor,
) -> Vec<ImageDef> {
    let count = mhy.image_count();
    let base_off = mhy.image_off();
    let mut images = Vec::with_capacity(count);

    for i in 0..count {
        let v157 = (302843651u32.wrapping_mul((57468u32.wrapping_mul(i as u32)) ^ 0x7538159E)
            ^ 0x6032C9D3)
            .wrapping_add(784007301);

        let off = base_off + i * 40;
        if off + 40 > startup_meta.len() {
            break;
        }

        let raw_1 = LittleEndian::read_u32(&startup_meta[off + 4..]);
        let raw_3 = LittleEndian::read_u32(&startup_meta[off + 12..]);

        let name_idx = v157 ^ raw_3 ^ 0x4D648371;
        let t_cnt = v157 ^ raw_1 ^ 0x7FDC8C8F ^ 0x1324FE97;

        let mut img_name = decryptor.decrypt_string(name_idx);
        if img_name.is_empty() {
            img_name = format!("Image_{}.dll", i);
        }

        images.push(ImageDef {
            name: img_name,
            type_count: t_cnt,
            name_off: 0,
        });
    }

    images
}
