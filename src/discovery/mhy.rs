use anyhow::{bail, Result};
use byteorder::{ByteOrder, LittleEndian};
use std::collections::{HashMap, HashSet};

use super::native::{
    extract_header_expressions, find_header_candidates, HeaderExpression, TransformOp,
};
use super::pe::PeImage;

#[derive(Clone, Debug, Default)]
pub(crate) struct MhyCandidateCatalog {
    pub additive: Vec<u32>,
    pub xor: Vec<u32>,
    pub shift_xor: Vec<u32>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct MhyLayout {
    pub string_table_offset: usize,
    pub string_literal_offsets: usize,
    pub string_literal_data: u32,
    pub image_offset: usize,
    pub image_count: usize,
    pub type_definition_offset: usize,
    pub method_table: usize,
    pub parameter_table: usize,
    pub field_table: usize,
    pub field_offset_table: usize,
    pub interface_table: usize,
    pub generic_container_table: usize,
    pub generic_parameter_table: usize,
    pub generic_constraint_table: usize,
    pub parameter_default_table: usize,
    pub parameter_default_count: usize,
    pub field_default_table: usize,
    pub field_default_count: usize,
    pub default_value_data: usize,
    pub property_table: usize,
    pub event_table: usize,
    pub vtable_method_table: usize,
    pub interface_offset_table: usize,
    pub field_type_map: usize,
    pub field_offset_map: usize,
    pub method_pointer_map: usize,
    pub method_pointer_map_count: usize,
    pub generic_class_source: usize,
    pub generic_class_count: usize,
}

#[derive(Clone, Debug)]
pub struct MhyHeader {
    pub file_offset: usize,
    pub(crate) layout: MhyLayout,
    pub(crate) candidates: MhyCandidateCatalog,
}

impl MhyHeader {
    pub fn parse(dll: &[u8]) -> Result<Self> {
        let needle = b"MHY\0";
        let offset = dll
            .windows(needle.len())
            .position(|w| w == needle)
            .ok_or_else(|| anyhow::anyhow!("MHY header signature not found in GameAssembly.dll"))?;

        let pe = PeImage::parse(dll)?;
        Self::parse_at(dll, offset, &pe)
    }

    pub fn candidates(dll: &[u8], pe: &PeImage) -> Vec<Self> {
        let signed = dll
            .windows(4)
            .enumerate()
            .filter(|(_, value)| *value == b"MHY\0")
            .filter_map(|(offset, _)| Self::parse_at(dll, offset, pe).ok())
            .collect::<Vec<_>>();
        if !signed.is_empty() {
            return signed;
        }
        find_header_candidates(dll, pe)
            .into_iter()
            .filter_map(|(offset, expressions)| {
                Self::parse_with_expressions(dll, offset, expressions).ok()
            })
            .collect()
    }

    fn parse_at(dll: &[u8], offset: usize, pe: &PeImage) -> Result<Self> {
        let expressions = extract_header_expressions(dll, pe, offset)?;
        let values = read_values(dll, offset, &expressions)?;
        Self::from_values(offset, values, expressions)
    }

    fn parse_with_expressions(
        dll: &[u8],
        offset: usize,
        expressions: Vec<HeaderExpression>,
    ) -> Result<Self> {
        let values = read_values(dll, offset, &expressions)?;
        Self::from_values(offset, values, expressions)
    }

    fn from_values(
        offset: usize,
        values: Vec<u32>,
        expressions: Vec<HeaderExpression>,
    ) -> Result<Self> {
        let candidates = MhyCandidateCatalog::resolve(&values, &expressions);
        if candidates.additive.is_empty() || candidates.xor.is_empty() {
            bail!("native MHY transforms did not produce a usable candidate catalog");
        }
        Ok(Self {
            file_offset: offset,
            layout: MhyLayout::default(),
            candidates,
        })
    }

    pub fn string_table_off(&self) -> usize {
        self.layout.string_table_offset
    }

    pub fn string_literal_offsets_base(&self) -> usize {
        self.layout.string_literal_offsets
    }

    pub fn string_literal_data_base(&self) -> u32 {
        self.layout.string_literal_data
    }

    pub fn image_off(&self) -> usize {
        self.layout.image_offset
    }

    pub fn image_count(&self) -> usize {
        self.layout.image_count
    }

    pub fn method_table_base(&self) -> usize {
        self.layout.method_table
    }

    pub fn param_table_base(&self) -> usize {
        self.layout.parameter_table
    }

    pub fn field_table_base(&self) -> usize {
        self.layout.field_table
    }

    pub fn offset_table_base(&self) -> usize {
        self.layout.field_offset_table
    }

    pub fn interface_table_base(&self) -> usize {
        self.layout.interface_table
    }

    pub fn gc_table_base(&self) -> usize {
        self.layout.generic_container_table
    }

    pub fn gp_table_base(&self) -> usize {
        self.layout.generic_parameter_table
    }

    pub fn generic_constraint_table_base(&self) -> usize {
        self.layout.generic_constraint_table
    }

    pub fn parameter_default_table_base(&self) -> usize {
        self.layout.parameter_default_table
    }

    pub fn parameter_default_count(&self) -> usize {
        self.layout.parameter_default_count
    }

    pub fn field_default_table_base(&self) -> usize {
        self.layout.field_default_table
    }

    pub fn field_default_count(&self) -> usize {
        self.layout.field_default_count
    }

    pub fn default_value_data_base(&self) -> usize {
        self.layout.default_value_data
    }

    pub fn property_table_base(&self) -> usize {
        self.layout.property_table
    }

    pub fn event_table_base(&self) -> usize {
        self.layout.event_table
    }

    pub fn vtable_method_table_base(&self) -> usize {
        self.layout.vtable_method_table
    }

    pub fn interface_offset_table_base(&self) -> usize {
        self.layout.interface_offset_table
    }

    pub fn field_type_map_base(&self) -> usize {
        self.layout.field_type_map
    }

    pub fn field_offset_map_base(&self) -> usize {
        self.layout.field_offset_map
    }

    pub fn table42_base(&self) -> usize {
        self.layout.method_pointer_map
    }

    pub fn table42_count(&self) -> usize {
        self.layout.method_pointer_map_count
    }

    pub fn type_definition_offset(&self) -> usize {
        self.layout.type_definition_offset
    }

    pub fn generic_class_source_offset(&self) -> usize {
        self.layout.generic_class_source
    }

    pub fn generic_class_count(&self) -> usize {
        self.layout.generic_class_count
    }
}

fn read_values(dll: &[u8], offset: usize, expressions: &[HeaderExpression]) -> Result<Vec<u32>> {
    let count = expressions
        .iter()
        .map(|expression| expression.index)
        .max()
        .and_then(|index| index.checked_add(1))
        .ok_or_else(|| anyhow::anyhow!("native MHY code does not access any header fields"))?;
    if count > 4096 {
        bail!("native MHY header span is implausibly large ({count} fields)");
    }
    let end = offset
        .checked_add(
            count
                .checked_mul(4)
                .ok_or_else(|| anyhow::anyhow!("MHY header size overflow"))?,
        )
        .ok_or_else(|| anyhow::anyhow!("MHY header range overflow"))?;
    let bytes = dll.get(offset..end).ok_or_else(|| {
        anyhow::anyhow!("GameAssembly.dll is too small for the native MHY field span")
    })?;
    Ok(bytes.chunks_exact(4).map(LittleEndian::read_u32).collect())
}

impl MhyCandidateCatalog {
    fn resolve(values: &[u32], expressions: &[HeaderExpression]) -> Self {
        Self {
            additive: candidate_values_any(values, expressions, Shape::Additive),
            xor: candidate_values_any(values, expressions, Shape::Xor),
            shift_xor: candidate_values_any(values, expressions, Shape::ShiftRightXor),
        }
    }
}

#[derive(Clone, Copy)]
enum Shape {
    Additive,
    Xor,
    ShiftRightXor,
}

fn candidate_values(
    values: &[u32],
    expressions: &[HeaderExpression],
    index: usize,
    shape: Shape,
) -> Vec<u32> {
    let matches_shape = |operations: &[TransformOp]| match shape {
        Shape::Additive => {
            !operations.is_empty()
                && operations
                    .iter()
                    .all(|operation| matches!(operation, TransformOp::Add(_) | TransformOp::Sub(_)))
        }
        Shape::Xor => matches!(operations, [TransformOp::Xor(_)]),
        Shape::ShiftRightXor => matches!(
            operations,
            [
                TransformOp::ShiftRight(_) | TransformOp::ShiftRightArithmetic(_),
                TransformOp::Xor(_)
            ]
        ),
    };
    let transform_score = |expression: &HeaderExpression| {
        expression
            .operations
            .iter()
            .map(|operation| match operation {
                TransformOp::Add(value) | TransformOp::Sub(value) | TransformOp::Xor(value) => {
                    (*value as i32).unsigned_abs() as u64
                }
                _ => 0,
            })
            .sum::<u64>()
    };
    let mut candidates = expressions
        .iter()
        .filter(|expression| expression.index == index && matches_shape(&expression.operations))
        .filter_map(|expression| {
            expression
                .evaluate(values)
                .map(|value| (value, transform_score(expression)))
        })
        .fold(HashMap::new(), |mut candidates, (value, score)| {
            candidates
                .entry(value)
                .and_modify(|current: &mut u64| *current = (*current).max(score))
                .or_insert(score);
            candidates
        })
        .into_iter()
        .collect::<Vec<_>>();
    candidates.sort_unstable_by_key(|(value, score)| (std::cmp::Reverse(*score), *value));
    candidates.into_iter().map(|(value, _)| value).collect()
}

fn candidate_values_any(
    values: &[u32],
    expressions: &[HeaderExpression],
    shape: Shape,
) -> Vec<u32> {
    let indices = expressions
        .iter()
        .map(|expression| expression.index)
        .collect::<HashSet<_>>();
    let mut candidates = indices
        .into_iter()
        .flat_map(|index| candidate_values(values, expressions, index, shape))
        .collect::<Vec<_>>();
    candidates.sort_unstable();
    candidates.dedup();
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_catalog_is_invariant_under_field_permutation() {
        let mut values = vec![0u32; 150];
        for (index, value) in values.iter_mut().enumerate() {
            *value = (index as u32).wrapping_mul(0x1020_3041).wrapping_add(7);
        }
        let expressions = (0..150)
            .flat_map(|index| {
                [
                    HeaderExpression {
                        index,
                        operations: vec![TransformOp::Add(0x1234_5678)],
                    },
                    HeaderExpression {
                        index,
                        operations: vec![TransformOp::Xor(0xa5a5_5a5a)],
                    },
                    HeaderExpression {
                        index,
                        operations: vec![TransformOp::ShiftRight(3), TransformOp::Xor(0x1357_9bdf)],
                    },
                ]
            })
            .collect::<Vec<_>>();
        let expected = MhyCandidateCatalog::resolve(&values, &expressions);

        let mut permuted_values = vec![0u32; 150];
        for (old_index, value) in values.iter().copied().enumerate() {
            let new_index = (old_index * 47 + 13) % 150;
            permuted_values[new_index] = value;
        }
        let permuted_expressions = expressions
            .iter()
            .cloned()
            .map(|mut expression| {
                expression.index = (expression.index * 47 + 13) % 150;
                expression
            })
            .collect::<Vec<_>>();
        let actual = MhyCandidateCatalog::resolve(&permuted_values, &permuted_expressions);
        assert_eq!(actual.additive, expected.additive);
        assert_eq!(actual.xor, expected.xor);
        assert_eq!(actual.shift_xor, expected.shift_xor);
    }
}
