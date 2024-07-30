use crate::lc3::hardware::ARCH_SZ;

pub const NULL: u16 = 0x0;
pub const TEXT_BASE: u16 = 0x3000;
pub const INSTR_OFFSET: u16 = 12;

pub enum ConditionFlags {
    MaskPositive = 1<<0,
    MaskZero = 1<<1,
    MaskNegative = 1<<2
}

// impl ConditionFlags {}

pub struct Instruction {
    v: u16
}

impl Instruction {
    pub fn get_v(&self) -> u16 {
        self.v
    }
    
    pub fn from_mem(v: u16) -> Self {
        Instruction{
            v
        }
    }

    // nth_bit - bits counting from zero
    pub fn nth_bit(&self, n: u16) -> bool {
        if self.range_bits(n, 1) == 0b1 {
            true
        } else {
            false
        }
    }

    // range_bits - reading n bits starting from s
    pub fn range_bits(&self, s: u16, n: u16) -> u16 {
        (self.v >> s) & ((1<<n) - 1)
    }

    pub fn opcode(&self) -> Opcode {
        let raw_opcode = self.range_bits(INSTR_OFFSET, ARCH_SZ-INSTR_OFFSET);

        match raw_opcode {
            0x0 => Opcode::Branch,
            0x1 => Opcode::Add,
            0x2 => Opcode::Load,
            0x3 => Opcode::Store,
            0x4 => Opcode::JumpReg,
            0x5 => Opcode::And,
            0x6 => Opcode::LoadReg,
            0x7 => Opcode::StoreReg,
            0x8 => Opcode::Reserved1,
            0x9 => Opcode::BitwiseNot,
            0xa => Opcode::LoadIndirect,
            0xb => Opcode::StoreIndirect,
            0xc => Opcode::Jump,
            0xd => Opcode::Reserve2,
            0xe => Opcode::LoadEffectiveAddress,
            0xf => Opcode::Trap,
            _ => Opcode::UD2,
        }
    }
}

#[derive(Debug)]
pub enum Opcode {
    Branch,
    Add,
    Load,
    Store,
    JumpReg,
    And,
    LoadReg,
    StoreReg,
    Reserved1,
    BitwiseNot,
    LoadIndirect,
    StoreIndirect,
    Jump,
    Reserve2,
    LoadEffectiveAddress,
    Trap,
    UD2
}