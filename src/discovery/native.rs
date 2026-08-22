use super::pe::PeImage;
use anyhow::{bail, Context, Result};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};
use std::collections::{HashMap, HashSet};

const MAX_HEADER_FIELDS: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TransformOp {
    Add(u32),
    Sub(u32),
    Xor(u32),
    ShiftRight(u32),
    ShiftRightArithmetic(u32),
    ShiftLeft(u32),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HeaderExpression {
    pub index: usize,
    pub operations: Vec<TransformOp>,
}

impl HeaderExpression {
    pub fn evaluate(&self, values: &[u32]) -> Option<u32> {
        let mut value = *values.get(self.index)?;
        for operation in &self.operations {
            value = match *operation {
                TransformOp::Add(operand) => value.wrapping_add(operand),
                TransformOp::Sub(operand) => value.wrapping_sub(operand),
                TransformOp::Xor(operand) => value ^ operand,
                TransformOp::ShiftRight(operand) => value.wrapping_shr(operand),
                TransformOp::ShiftRightArithmetic(operand) => ((value as i32) >> operand) as u32,
                TransformOp::ShiftLeft(operand) => value.wrapping_shl(operand),
            };
        }
        Some(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum SymbolicValue {
    HeaderPointer,
    Header(HeaderExpression),
    Constant(u32),
    Offset(u32),
}

pub fn extract_header_expressions(
    dll: &[u8],
    pe: &PeImage,
    header_file_offset: usize,
) -> Result<Vec<HeaderExpression>> {
    let header_va = pe
        .file_offset_to_va(header_file_offset)
        .context("MHY header is not mapped by the PE image")?;
    let header_global = find_header_global(dll, pe, header_va)?;
    let mut expressions = HashSet::new();
    let mut seeds = Vec::new();

    for (start, end, section_va) in pe.executable_mapped_ranges() {
        let Some(bytes) = dll.get(start..end.min(dll.len())) else {
            continue;
        };
        let mut decoder = Decoder::with_ip(64, bytes, section_va, DecoderOptions::NONE);
        while decoder.can_decode() {
            let instruction = decoder.decode();
            if instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Memory
                && instruction.is_ip_rel_memory_operand()
                && instruction.ip_rel_memory_address() == header_global
            {
                seeds.push((instruction.next_ip(), normalize(instruction.op0_register())));
            }
        }
    }

    for (ip, register) in seeds {
        scan_header_window(dll, pe, ip, register, header_global, &mut expressions);
    }

    if expressions.is_empty() {
        bail!("no MHY decoding expressions were recovered from GameAssembly.dll");
    }
    let mut expressions = expressions.into_iter().collect::<Vec<_>>();
    expressions.sort_by_key(|expression| (expression.index, expression.operations.len()));
    Ok(expressions)
}

pub fn find_header_candidates(dll: &[u8], pe: &PeImage) -> Vec<(usize, Vec<HeaderExpression>)> {
    let mut stores = HashSet::new();
    let mut load_counts = HashMap::<u64, usize>::new();
    for (start, end, section_va) in pe.executable_mapped_ranges() {
        let Some(bytes) = dll.get(start..end.min(dll.len())) else {
            continue;
        };
        let mut decoder = Decoder::with_ip(64, bytes, section_va, DecoderOptions::NONE);
        let mut addresses = HashMap::<Register, u64>::new();
        while decoder.can_decode() {
            let instruction = decoder.decode();
            if instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Memory
                && instruction.is_ip_rel_memory_operand()
            {
                *load_counts
                    .entry(instruction.ip_rel_memory_address())
                    .or_default() += 1;
            }
            if instruction.mnemonic() == Mnemonic::Lea
                && instruction.op0_kind() == OpKind::Register
                && instruction.is_ip_rel_memory_operand()
            {
                addresses.insert(
                    normalize(instruction.op0_register()),
                    instruction.ip_rel_memory_address(),
                );
                continue;
            }
            if instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_kind() == OpKind::Memory
                && instruction.op1_kind() == OpKind::Register
                && instruction.is_ip_rel_memory_operand()
            {
                if let Some(&target) = addresses.get(&normalize(instruction.op1_register())) {
                    stores.insert((target, instruction.ip_rel_memory_address()));
                }
            }
            if instruction.op0_kind() == OpKind::Register {
                addresses.remove(&normalize(instruction.op0_register()));
            }
            if instruction.flow_control() == FlowControl::Return {
                addresses.clear();
            }
        }
    }

    let mut candidates = Vec::new();
    for (target, global) in stores {
        if load_counts.get(&global).copied().unwrap_or_default() < 2 {
            continue;
        }
        let Some(offset) = pe.va_to_file_offset(target) else {
            continue;
        };
        if offset >= dll.len() {
            continue;
        }
        let mut expressions = HashSet::new();
        for (start, end, section_va) in pe.executable_mapped_ranges() {
            let Some(bytes) = dll.get(start..end.min(dll.len())) else {
                continue;
            };
            let mut decoder = Decoder::with_ip(64, bytes, section_va, DecoderOptions::NONE);
            while decoder.can_decode() {
                let instruction = decoder.decode();
                if instruction.mnemonic() == Mnemonic::Mov
                    && instruction.op0_kind() == OpKind::Register
                    && instruction.op1_kind() == OpKind::Memory
                    && instruction.is_ip_rel_memory_operand()
                    && instruction.ip_rel_memory_address() == global
                {
                    scan_header_window(
                        dll,
                        pe,
                        instruction.next_ip(),
                        normalize(instruction.op0_register()),
                        global,
                        &mut expressions,
                    );
                }
            }
        }
        if expressions.len() < 8 {
            continue;
        }
        let mut expressions = expressions.into_iter().collect::<Vec<_>>();
        expressions.sort_by_key(|expression| (expression.index, expression.operations.len()));
        candidates.push((offset, expressions));
    }
    candidates.sort_by_key(|(offset, _)| *offset);
    candidates.dedup_by_key(|(offset, _)| *offset);
    candidates
}

fn scan_header_window(
    dll: &[u8],
    pe: &PeImage,
    start_ip: u64,
    header_register: Register,
    header_global: u64,
    expressions: &mut HashSet<HeaderExpression>,
) {
    let Some(offset) = pe.va_to_file_offset(start_ip) else {
        return;
    };
    let end = offset.saturating_add(0x400).min(dll.len());
    let mut decoder = Decoder::with_ip(64, &dll[offset..end], start_ip, DecoderOptions::NONE);
    let mut registers = HashMap::new();
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if normalize(instruction.memory_base()) == header_register
            && instruction.memory_index() == Register::None
            && instruction.memory_displacement64() < (MAX_HEADER_FIELDS * 4) as u64
        {
            registers.insert(header_register, SymbolicValue::HeaderPointer);
        }
        process_instruction(&instruction, header_global, &mut registers, expressions);
    }
}

fn find_header_global(dll: &[u8], pe: &PeImage, header_va: u64) -> Result<u64> {
    let mut matches = HashSet::new();
    for (start, end, section_va) in pe.executable_mapped_ranges() {
        let Some(bytes) = dll.get(start..end.min(dll.len())) else {
            continue;
        };
        let mut decoder = Decoder::with_ip(64, bytes, section_va, DecoderOptions::NONE);
        let mut address_registers = HashSet::new();
        while decoder.can_decode() {
            let instruction = decoder.decode();
            if instruction.mnemonic() == Mnemonic::Lea
                && instruction.op0_kind() == OpKind::Register
                && instruction.is_ip_rel_memory_operand()
                && instruction.ip_rel_memory_address() == header_va
            {
                address_registers.insert(normalize(instruction.op0_register()));
                continue;
            }
            if instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_kind() == OpKind::Memory
                && instruction.op1_kind() == OpKind::Register
                && instruction.is_ip_rel_memory_operand()
                && address_registers.contains(&normalize(instruction.op1_register()))
            {
                matches.insert(instruction.ip_rel_memory_address());
            }
            if instruction.op0_kind() == OpKind::Register {
                address_registers.remove(&normalize(instruction.op0_register()));
            }
            if instruction.flow_control() == FlowControl::Return {
                address_registers.clear();
            }
        }
    }
    if matches.len() != 1 {
        bail!(
            "expected one native MHY header pointer, recovered {}",
            matches.len()
        );
    }
    Ok(matches.into_iter().next().unwrap())
}

fn process_instruction(
    instruction: &Instruction,
    header_global: u64,
    registers: &mut HashMap<Register, SymbolicValue>,
    expressions: &mut HashSet<HeaderExpression>,
) {
    let mnemonic = instruction.mnemonic();
    if mnemonic == Mnemonic::Lea
        && instruction.op0_kind() == OpKind::Register
        && instruction.op1_kind() == OpKind::Memory
        && !instruction.is_ip_rel_memory_operand()
    {
        let destination = normalize(instruction.op0_register());
        let displacement = instruction.memory_displacement64() as u32;
        let base_offset = match registers.get(&normalize(instruction.memory_base())) {
            Some(SymbolicValue::Constant(value)) | Some(SymbolicValue::Offset(value)) => *value,
            _ => 0,
        };
        registers.insert(
            destination,
            SymbolicValue::Offset(base_offset.wrapping_add(displacement)),
        );
        return;
    }
    if matches!(mnemonic, Mnemonic::Mov | Mnemonic::Movsxd | Mnemonic::Movzx)
        && instruction.op0_kind() == OpKind::Register
    {
        let destination = normalize(instruction.op0_register());
        let source = symbolic_source(instruction, 1, header_global, registers);
        if let Some(source) = source {
            registers.insert(destination, source);
        } else {
            registers.remove(&destination);
        }
        return;
    }

    if !matches!(
        mnemonic,
        Mnemonic::Add
            | Mnemonic::Sub
            | Mnemonic::Xor
            | Mnemonic::Shr
            | Mnemonic::Sar
            | Mnemonic::Shl
    ) || instruction.op0_kind() != OpKind::Register
    {
        return;
    }

    let destination = normalize(instruction.op0_register());
    let destination_value = registers.get(&destination).cloned();
    let source_value = symbolic_source(instruction, 1, header_global, registers);
    let (mut expression, operand) = match (destination_value, source_value) {
        (Some(SymbolicValue::Header(expression)), Some(SymbolicValue::Constant(operand))) => {
            (expression, operand)
        }
        (Some(SymbolicValue::Header(expression)), Some(SymbolicValue::Offset(operand)))
            if matches!(mnemonic, Mnemonic::Add | Mnemonic::Sub) =>
        {
            (expression, operand)
        }
        (Some(SymbolicValue::Header(expression)), None)
            if matches!(mnemonic, Mnemonic::Add | Mnemonic::Sub) =>
        {
            registers.insert(destination, SymbolicValue::Header(expression));
            return;
        }
        (Some(SymbolicValue::Constant(operand)), Some(SymbolicValue::Header(expression)))
            if matches!(mnemonic, Mnemonic::Add | Mnemonic::Xor) =>
        {
            (expression, operand)
        }
        _ => {
            registers.remove(&destination);
            return;
        }
    };
    let operation = match mnemonic {
        Mnemonic::Add => TransformOp::Add(operand),
        Mnemonic::Sub => TransformOp::Sub(operand),
        Mnemonic::Xor => TransformOp::Xor(operand),
        Mnemonic::Shr => TransformOp::ShiftRight(operand),
        Mnemonic::Sar => TransformOp::ShiftRightArithmetic(operand),
        Mnemonic::Shl => TransformOp::ShiftLeft(operand),
        _ => return,
    };
    expression.operations.push(operation);
    expressions.insert(expression.clone());
    registers.insert(destination, SymbolicValue::Header(expression));
}

fn symbolic_source(
    instruction: &Instruction,
    operand: u32,
    header_global: u64,
    registers: &HashMap<Register, SymbolicValue>,
) -> Option<SymbolicValue> {
    match instruction.op_kind(operand) {
        OpKind::Register => registers
            .get(&normalize(instruction.op_register(operand)))
            .cloned(),
        kind if is_immediate(kind) => Some(SymbolicValue::Constant(
            instruction.immediate(operand) as u32
        )),
        OpKind::Memory => {
            if instruction.is_ip_rel_memory_operand()
                && instruction.ip_rel_memory_address() == header_global
            {
                return Some(SymbolicValue::HeaderPointer);
            }
            let base = normalize(instruction.memory_base());
            if !matches!(registers.get(&base), Some(SymbolicValue::HeaderPointer))
                || instruction.memory_index() != Register::None
            {
                return None;
            }
            let displacement = instruction.memory_displacement64() as usize;
            if displacement % 4 != 0 || displacement / 4 >= MAX_HEADER_FIELDS {
                return None;
            }
            Some(SymbolicValue::Header(HeaderExpression {
                index: displacement / 4,
                operations: Vec::new(),
            }))
        }
        _ => None,
    }
}

fn is_immediate(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::Immediate8
            | OpKind::Immediate8_2nd
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    )
}

fn normalize(register: Register) -> Register {
    register.full_register()
}
