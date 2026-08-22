use anyhow::{bail, Result};
use byteorder::{ByteOrder, LittleEndian};

#[derive(Clone, Debug)]
pub struct PeSection {
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

#[derive(Clone, Debug)]
pub struct PeImage {
    pub image_base: u64,
    pub sections: Vec<PeSection>,
}

impl PeImage {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 0x40 || &data[..2] != b"MZ" {
            bail!("GameAssembly.dll is not a PE image");
        }
        let pe_offset = read_u32(data, 0x3c)? as usize;
        if data.get(pe_offset..pe_offset + 4) != Some(b"PE\0\0") {
            bail!("invalid PE signature");
        }
        let section_count = read_u16(data, pe_offset + 6)? as usize;
        let optional_size = read_u16(data, pe_offset + 20)? as usize;
        let optional = pe_offset + 24;
        if read_u16(data, optional)? != 0x20b {
            bail!("GameAssembly.dll is not PE32+");
        }
        let image_base = read_u64(data, optional + 24)?;
        let section_table = optional + optional_size;
        let mut sections = Vec::with_capacity(section_count);
        for index in 0..section_count {
            let offset = section_table + index * 40;
            sections.push(PeSection {
                virtual_size: read_u32(data, offset + 8)?,
                virtual_address: read_u32(data, offset + 12)?,
                raw_size: read_u32(data, offset + 16)?,
                raw_offset: read_u32(data, offset + 20)?,
                characteristics: read_u32(data, offset + 36)?,
            });
        }
        Ok(Self {
            image_base,
            sections,
        })
    }

    pub fn executable_va_range(&self) -> Result<(u64, u64)> {
        let mut ranges = self
            .sections
            .iter()
            .filter(|section| section.characteristics & 0x2000_0000 != 0)
            .map(|section| {
                let start = self.image_base + section.virtual_address as u64;
                let size = section.virtual_size.max(section.raw_size) as u64;
                (start, start + size)
            });
        let Some((mut minimum, mut maximum)) = ranges.next() else {
            bail!("PE image has no executable sections");
        };
        for (start, end) in ranges {
            minimum = minimum.min(start);
            maximum = maximum.max(end);
        }
        Ok((minimum, maximum))
    }

    pub fn is_executable_va(&self, address: u64) -> bool {
        self.sections.iter().any(|section| {
            if section.characteristics & 0x2000_0000 == 0 {
                return false;
            }
            let start = self.image_base + section.virtual_address as u64;
            let end = start + section.virtual_size.max(section.raw_size) as u64;
            (start..end).contains(&address)
        })
    }

    pub fn file_offset_to_va(&self, offset: usize) -> Option<u64> {
        self.sections.iter().find_map(|section| {
            let start = section.raw_offset as usize;
            let end = start.checked_add(section.raw_size as usize)?;
            (start..end)
                .contains(&offset)
                .then(|| self.image_base + section.virtual_address as u64 + (offset - start) as u64)
        })
    }

    pub fn va_to_file_offset(&self, address: u64) -> Option<usize> {
        let rva = address.checked_sub(self.image_base)?;
        self.sections.iter().find_map(|section| {
            let start = section.virtual_address as u64;
            let end = start.checked_add(section.raw_size as u64)?;
            (start..end)
                .contains(&rva)
                .then(|| section.raw_offset as usize + (rva - start) as usize)
        })
    }

    pub fn readable_file_ranges(&self) -> impl Iterator<Item = (usize, usize)> + '_ {
        self.sections
            .iter()
            .filter(|section| section.characteristics & 0x4000_0000 != 0)
            .filter_map(|section| {
                let start = section.raw_offset as usize;
                let end = start.checked_add(section.raw_size as usize)?;
                Some((start, end))
            })
    }

    pub fn executable_mapped_ranges(&self) -> impl Iterator<Item = (usize, usize, u64)> + '_ {
        self.sections
            .iter()
            .filter(|section| section.characteristics & 0x2000_0000 != 0)
            .filter_map(|section| {
                let start = section.raw_offset as usize;
                let end = start.checked_add(section.raw_size as usize)?;
                let va = self.image_base + section.virtual_address as u64;
                Some((start, end, va))
            })
    }
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
    data.get(offset..offset + 2)
        .map(LittleEndian::read_u16)
        .ok_or_else(|| anyhow::anyhow!("truncated PE structure at {offset:#x}"))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    data.get(offset..offset + 4)
        .map(LittleEndian::read_u32)
        .ok_or_else(|| anyhow::anyhow!("truncated PE structure at {offset:#x}"))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64> {
    data.get(offset..offset + 8)
        .map(LittleEndian::read_u64)
        .ok_or_else(|| anyhow::anyhow!("truncated PE structure at {offset:#x}"))
}
