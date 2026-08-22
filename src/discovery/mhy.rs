use anyhow::{bail, Result};
use byteorder::{ByteOrder, LittleEndian};

#[derive(Clone, Debug)]
pub struct MhyHeader {
    pub values: [u32; 150],
    pub file_offset: usize,
}

impl MhyHeader {
    pub fn parse(dll: &[u8]) -> Result<Self> {
        let needle = b"MHY\0";
        let offset = dll
            .windows(needle.len())
            .position(|w| w == needle)
            .ok_or_else(|| anyhow::anyhow!("MHY header signature not found in GameAssembly.dll"))?;

        Self::parse_at(dll, offset)
    }

    pub fn candidates(dll: &[u8]) -> Vec<Self> {
        dll.windows(4)
            .enumerate()
            .filter(|(_, value)| *value == b"MHY\0")
            .filter_map(|(offset, _)| Self::parse_at(dll, offset).ok())
            .collect()
    }

    fn parse_at(dll: &[u8], offset: usize) -> Result<Self> {
        if offset + 150 * 4 > dll.len() {
            bail!("GameAssembly.dll too small for MHY header");
        }

        let mut values = [0u32; 150];
        for i in 0..150 {
            values[i] = LittleEndian::read_u32(&dll[offset + i * 4..]);
        }

        Ok(Self {
            values,
            file_offset: offset,
        })
    }

    pub fn string_table_off(&self) -> usize {
        self.values[109].wrapping_sub(1924946706) as usize
    }

    pub fn string_literal_offsets_base(&self) -> usize {
        (self.values[124] ^ 0x56c7_d20d) as usize
    }

    pub fn string_literal_data_base(&self) -> u32 {
        self.values[2].wrapping_add(854_233_332)
    }

    pub fn image_off(&self) -> usize {
        self.values[84].wrapping_add(0xD882615E) as usize
    }

    pub fn image_count(&self) -> usize {
        ((self.values[77] ^ 0x10210728) / 0x28) as usize
    }

    pub fn method_table_base(&self) -> usize {
        self.values[83].wrapping_sub(207601004) as usize
    }

    pub fn param_table_base(&self) -> usize {
        self.values[12].wrapping_sub(587858498) as usize
    }

    pub fn field_table_base(&self) -> usize {
        self.values[8].wrapping_sub(1292050039) as usize
    }

    pub fn offset_table_base(&self) -> usize {
        (self.values[82] ^ 0x329E1172) as usize
    }

    pub fn interface_table_base(&self) -> usize {
        (self.values[114] ^ 0x042F_9275) as usize
    }

    pub fn gc_table_base(&self) -> usize {
        self.values[60].wrapping_sub(1656188401) as usize
    }

    pub fn gp_table_base(&self) -> usize {
        self.values[80].wrapping_sub(626232567) as usize
    }

    pub fn generic_constraint_table_base(&self) -> usize {
        self.values[76].wrapping_sub(22_792_381) as usize
    }

    pub fn parameter_default_table_base(&self) -> usize {
        self.values[19].wrapping_sub(399_745_016) as usize
    }

    pub fn parameter_default_count(&self) -> usize {
        ((self.values[24] ^ 0x2F5D_2DD0) / 12) as usize
    }

    pub fn field_default_table_base(&self) -> usize {
        (self.values[127] ^ 0x6238_CDB0) as usize
    }

    pub fn field_default_count(&self) -> usize {
        ((self.values[119] ^ 0x3E0C_72F0) / 12) as usize
    }

    pub fn default_value_data_base(&self) -> usize {
        self.values[15].wrapping_sub(1_752_438_875) as usize
    }

    pub fn property_table_base(&self) -> usize {
        (self.values[16] ^ 0x3C68_5CDB) as usize
    }

    pub fn event_table_base(&self) -> usize {
        (self.values[107] ^ 0x3708_0D6E) as usize
    }

    pub fn vtable_method_table_base(&self) -> usize {
        self.values[88].wrapping_sub(949_367_470) as usize
    }

    pub fn interface_offset_table_base(&self) -> usize {
        (self.values[69] ^ 0x3EAB_B25A) as usize
    }

    pub fn mhy39(&self) -> u32 {
        self.values[39]
    }

    pub fn mhy96(&self) -> u32 {
        self.values[96]
    }

    pub fn table42_base(&self) -> usize {
        (self.values[42] ^ 0x2CE30270) as usize
    }

    pub fn table42_count(&self) -> usize {
        (self.values[17].wrapping_sub(533897168) / 6) as usize
    }
}
