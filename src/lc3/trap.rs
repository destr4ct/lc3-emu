pub enum TrapCall {
    TrapGetc,
    TrapOut,
    TrapPuts,
    TrapIn,
    TrapPutsp,
    TrapHalt,

    TrapFault = 0xff
}

impl TrapCall {
    pub fn classify_trap(trap: u16) -> Self {
        match trap {
            0x20 => TrapCall::TrapGetc,
            0x21 => TrapCall::TrapOut,
            0x22 => TrapCall::TrapPuts,
            0x23 => TrapCall::TrapIn,
            0x24 => TrapCall::TrapPutsp,
            0x25 => TrapCall::TrapHalt,

            _ => TrapCall::TrapFault
        }
    }
}