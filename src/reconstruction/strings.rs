use byteorder::{ByteOrder, LittleEndian};
use std::collections::HashMap;

pub struct StringDecryptor<'a> {
    global_body: &'a [u8],
    string_table_off: usize,
}

impl<'a> StringDecryptor<'a> {
    pub fn new(global_body: &'a [u8], string_table_off: usize) -> Self {
        Self {
            global_body,
            string_table_off,
        }
    }

    pub fn decrypt_string(&self, index: u32) -> String {
        if index == 0 || index == u32::MAX {
            return String::new();
        }

        let is_neg = (index as i32) < 0;
        let (length, offset) = if is_neg {
            (((index >> 23) & 0xFF) as usize, (index & 0x7FFFFF) as usize)
        } else {
            (
                ((index >> 25) & 0x3F) as usize,
                (index & 0x1FFFFFF) as usize,
            )
        };

        if length == 0 {
            return String::new();
        }

        let str_off = self.string_table_off + offset;
        let pad_len = length.div_ceil(8) * 8;
        if str_off + pad_len > self.global_body.len() {
            return String::new();
        }

        let raw = &self.global_body[str_off..str_off + pad_len];
        let mut key = (offset as u64)
            .wrapping_mul(0x907C49622D94D21A)
            .wrapping_add(0x75B679DAF67C3F24);
        let step = 0x3E693CD23A41FDEF;

        let mut dec = Vec::with_capacity(pad_len);
        for c in (0..pad_len).step_by(8) {
            let chunk = LittleEndian::read_u64(&raw[c..]);
            let dec_val = chunk ^ key;
            let mut buf = [0u8; 8];
            LittleEndian::write_u64(&mut buf, dec_val);
            dec.extend_from_slice(&buf);
            key = key.wrapping_add(step);
        }

        dec.truncate(length);
        String::from_utf8_lossy(&dec).into_owned()
    }
}

pub struct StringPool {
    pub pool: Vec<u8>,
    pub map: HashMap<String, u32>,
    pub list: Vec<String>,
}

impl StringPool {
    pub fn new() -> Self {
        let mut map = HashMap::new();
        map.insert(String::new(), 0);
        Self {
            pool: vec![0],
            map,
            list: Vec::new(),
        }
    }

    pub fn add_string(&mut self, s: &str) -> u32 {
        if s.is_empty() {
            return 0;
        }
        if let Some(&off) = self.map.get(s) {
            return off;
        }
        let off = self.pool.len() as u32;
        self.pool.extend_from_slice(s.as_bytes());
        self.pool.push(0);
        self.map.insert(s.to_string(), off);
        self.list.push(s.to_string());
        off
    }
}
