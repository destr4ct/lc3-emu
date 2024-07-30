use crate::lc3::trap::TrapCall;
use crate::lc3::util::{extend_sign, get_file, read_short_at, u16_to_char};

use super::program::{NULL, Opcode, TEXT_BASE};
use super::program::ConditionFlags;

pub const ARCH_SZ: u16 = 0x10;

const MEM_BLOCKS: usize = 1 << 16;
const REG_COUNT: usize = 10;

const REG_RCO: u16 =  Register::RCO as u16;
const REG_RPC: u16 =  Register::RPC as u16;
const REG_LR: u16 = Register::R7 as u16;

const MR_KBSR: usize = 0xFE00; /* keyboard status */
const MR_KBDR: usize = 0xFE02;  /* keyboard data */

pub enum Register {
    // Generic registers
    R0 = 0,
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,

    // program counter
    RPC,

    // conditions register
    RCO,

    RBAD
}

pub struct Machine {
    is_running: bool,

    // mem - 128KB of machine memory
    mem: [u16; MEM_BLOCKS],

    // 10 system registers
    regs: [u16; REG_COUNT]
}

pub struct Fault {
    pub reason: String,
    pub regs_dump: [u16; REG_COUNT]
}

impl Fault {
    fn construct<T>(reason: &str, regs_dump: [u16; REG_COUNT]) -> Result<T, Self> {
        Err(Fault{
            reason: reason.to_string(),
            regs_dump,
        })
    }

    pub fn construct_default<T>(reason: &str) -> Result<T, Self> {
        Self::construct(reason, [0; REG_COUNT])
    }
}

pub type LC3Result<T> = Result<T, Fault>;

impl Machine {
    fn update_register<T>(&mut self, reg: T, v: T) where T: Into<u16> {
        self.regs[reg.into() as usize] = v.into();
    }

    fn inc_reg<T>(&mut self, reg: T, to_add: T)
    where
        T: Into<u16> + From<u16> + Copy
    {
        let res = to_add.into().wrapping_add(self.get_register(reg.into()));

        self.update_register(
            reg, T::from(res)
        );
    }


    fn get_register<T>(&self, reg: T) -> u16 where T: Into<usize> {
        return self.regs[reg.into()]
    }

    fn update_flags<T>(&mut self, reg: T) where T: Into<usize> {
        let reg_v = self.regs[reg.into()];

        self.regs[Register::RCO as usize] = if reg_v == 0 {
            ConditionFlags::MaskZero
        } else if ((reg_v >> 15) & 0b1) == 1 {
            ConditionFlags::MaskNegative
        } else {
            ConditionFlags::MaskPositive
        } as u16;
    }

    pub fn new() -> Self {
        // Fill the mem and regs with NULL values
        Machine{
            is_running: false,
            mem: [0x0; MEM_BLOCKS],
            regs: [NULL; REG_COUNT],
        }
    }

    pub fn setup(&mut self) -> &mut Self {
        // Setup flag register
        self.regs[Register::RCO as usize] = ConditionFlags::MaskZero as u16;

        // Setup program counter with defined constant
        self.regs[Register::RPC as usize] = TEXT_BASE;

        // Before starting loop is_running should be toggled
        self.is_running = true;
        self
    }

    pub fn load_mem_from_reg<T>(&mut self, reg: T) -> u16 where T: Into<usize> {
        let reg_v = self.regs[reg.into()];
        self.get_mem_by_addr(reg_v)
    }

    pub fn set_mem_by_addr<T>(&mut self, idx: T, v: u16)
    where
        T: Into<usize>
    {
        let idx = idx.into();
        self.mem[idx] = v;
    }

    pub fn get_mem_by_addr<T>(&mut self, idx: T) -> u16
    where
        T: Into<usize>
    {
        let idx = idx.into();

        if idx == MR_KBSR {
            self.mem[MR_KBSR] = 1 << 15;
            self.mem[MR_KBDR] = 0x41;
            panic!("todo")
        }

        self.mem[idx]
    }


    // load the executable to machine memory
    pub fn load(&mut self, path: &str) -> LC3Result<&mut Self> {
        let mut binary = get_file(path)?;

        // Load the origin
        let origin = read_short_at(&mut binary, 0)?;

        // Calculating indices
        let mut read_offset: usize = 1;

        while let Ok(v) = read_short_at(&mut binary, 2*read_offset as u64) {
            self.mem[(origin as usize) + read_offset - 1] = v;
            read_offset += 1;
        }

        Ok(self)
    }

    pub fn execute(&mut self) -> LC3Result<()> {
        use super::program::Instruction;

        while self.is_running {
            // Get instruction
            let instr = Instruction::from_mem(
                self.load_mem_from_reg(REG_RPC)
            );

            // println!("{:?} raw=0x{:x} at RIP=0x{:04x}", instr.opcode(), instr.get_v(), self.get_register(REG_RPC));

            self.inc_reg(REG_RPC, 1);

            match instr.opcode() {
                // also RET
                Opcode::Jump => {
                    let jr = instr.range_bits(6, 3);

                    self.update_register(
                        REG_RPC, self.get_register(jr)
                    )
                }

                Opcode::Branch => {
                    let pc_offset = extend_sign(instr.range_bits(0, 9), 9);
                    let addr = self.get_register(REG_RPC).wrapping_add(pc_offset);
                    let co = instr.range_bits(9, 3);

                    if (co & self.get_register(REG_RCO)) > 0 {
                        self.update_register(
                            REG_RPC, addr
                        )
                    }
                }

                Opcode::Add => {
                    let dr = instr.range_bits(9, 3);
                    let sr1 = instr.range_bits(6, 3);


                    if instr.nth_bit(5) {
                        let imm = instr.range_bits(0, 5);
                        self.update_register(
                            dr, self.get_register(sr1).wrapping_add(extend_sign(imm, 5)),
                        );

                    } else {
                        let sr2 = instr.range_bits(0, 3);
                        self.update_register(
                            dr, self.get_register(sr1).wrapping_add(self.get_register(sr2)),
                        );
                    }

                    self.update_flags(dr)
                }
                Opcode::Load => {
                    let dr = instr.range_bits(9, 3);

                    let pc_offset = extend_sign(instr.range_bits(0, 9), 9);
                    let ptr = self.get_register(REG_RPC).wrapping_add(pc_offset);
                    let v = self.get_mem_by_addr(ptr);

                    self.update_register(dr, v);
                    self.update_flags(dr);
                }
                Opcode::Store => {
                    let sr = instr.range_bits(9, 3);
                    let pc_offset = extend_sign(instr.range_bits(0, 9), 9);
                    let ptr = self.get_register(REG_RPC).wrapping_add(pc_offset);

                    self.set_mem_by_addr(ptr, self.get_register(sr));
                }
                Opcode::JumpReg => {
                    // Set next instruction address to LR
                    self.update_register(REG_LR, self.get_register(REG_RPC));

                    if instr.nth_bit(11) {
                        let pc_offset = extend_sign(instr.range_bits(0, 11), 11);
                        let ptr_subroutine = self.get_register(REG_RPC).wrapping_add(pc_offset);

                        self.update_register(REG_RPC, ptr_subroutine)

                    } else {
                        let reg = instr.range_bits(6, 3);
                        let ptr_reg = self.get_register(reg);

                        self.update_register(REG_RPC, ptr_reg);
                    }
                }
                Opcode::And => {
                    let dr = instr.range_bits(9, 3);
                    let sr1 = instr.range_bits(6, 3);

                    if instr.nth_bit(5) {
                        let sr2 = instr.range_bits(0, 3);

                        self.update_register(
                            dr, self.get_register(sr1) & self.get_register(sr2)
                        )

                    } else {
                        let imm = extend_sign(instr.range_bits(0, 5), 5);

                        self.update_register(
                            dr, self.get_register(sr1) & imm
                        )
                    }

                    self.update_flags(dr);
                }
                Opcode::LoadReg => {
                    let dr = instr.range_bits(9, 3);
                    let br = instr.range_bits(6, 3);
                    let offset = extend_sign(instr.range_bits(0, 6), 6);

                    let addr = self.get_register(br).wrapping_add(offset);
                    let mem = self.get_mem_by_addr(addr);

                    self.update_register(
                        dr, mem
                    );

                    self.update_flags(dr);

                }
                Opcode::StoreReg => {
                    let sr = instr.range_bits(9, 3);
                    let br = instr.range_bits(6, 3);
                    let offset = extend_sign(instr.range_bits(0, 6), 6);

                    let addr = self.get_register(br).wrapping_add(offset);

                    self.set_mem_by_addr(addr, self.get_register(sr))
                }
                Opcode::Reserved1 => {
                    return Fault::construct(
                        "res1 call",
                        self.regs,
                    )
                }
                Opcode::BitwiseNot => {
                    let dr = instr.range_bits(9, 3);
                    let sr = instr.range_bits(6, 3);

                    self.update_register(dr, !self.get_register(sr));
                    self.update_flags(dr);
                }

                Opcode::LoadIndirect => {
                    let dr = instr.range_bits(9, 3);
                    let pc_offset = extend_sign(instr.range_bits(0, 9), 9);

                    let v_addr = self.get_mem_by_addr( self.get_register(REG_RPC).wrapping_add(pc_offset));
                    let v = self.get_mem_by_addr(v_addr);

                    self.update_register(dr, v);
                    self.update_flags(dr);
                }
                Opcode::StoreIndirect => {
                    let sr = instr.range_bits(9, 3);
                    let pc_offset = extend_sign(instr.range_bits(0, 9), 9);
                    let ptr = self.get_mem_by_addr(self.get_register(REG_RPC).wrapping_add(pc_offset));

                    self.set_mem_by_addr(ptr, self.get_register(sr));
                }
                Opcode::Reserve2 => {
                    return Fault::construct(
                        "res2 call",
                        self.regs,
                    )
                }
                Opcode::LoadEffectiveAddress => {
                    let dr = instr.range_bits(9, 3);
                    let pc_offset = extend_sign(instr.range_bits(0, 9), 9);
                    let addr = self.get_register(REG_RPC).wrapping_add(pc_offset);

                    self.update_register(dr, addr);
                    self.update_flags(dr);
                }

                Opcode::Trap => {
                    let trap_vec = instr.range_bits(0, 8);

                    match TrapCall::classify_trap(trap_vec) {
                        TrapCall::TrapGetc => {
                            return Fault::construct(
                                "trap not impl",
                                self.regs,
                            )
                        },

                        TrapCall::TrapOut => {
                            let co = u16_to_char(self.get_register(Register::R0 as u16));
                            print!("{co}")
                        },

                        TrapCall::TrapPuts => {
                            let mut shift = 0u16;
                            let addr = self.get_register(Register::R0 as u16);

                            loop {
                                let c = self.get_mem_by_addr(addr + shift);
                                if c == 0x0 {
                                    break;
                                }

                                print!("{}", u16_to_char(c));
                                shift += 1;
                            }
                        },

                        TrapCall::TrapIn => {
                            return Fault::construct(
                                "trap not impl",
                                self.regs,
                            )
                        },

                        TrapCall::TrapPutsp => {
                            return Fault::construct(
                                "trap not impl",
                                self.regs,
                            )
                        },

                        TrapCall::TrapHalt => {
                            return Ok(println!("\nMachine halted..."))
                        }

                        _ => {
                          return Fault::construct(
                              "bad trap_vec specified",
                              self.regs,
                          )
                        }

                    }
                }

                _ => {
                    return Fault::construct(
                        "Bad instruction called",
                        self.regs,
                    )
                }
            }
        }

        Ok(())
    }
}