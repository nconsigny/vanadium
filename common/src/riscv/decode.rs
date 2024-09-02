use super::op::Op;

#[inline]
fn rd(inst: u32) -> u8 {
    ((inst >> 7) & 0b11111) as u8
}

#[inline]
fn rs1(inst: u32) -> u8 {
    ((inst >> 15) & 0b11111) as u8
}

#[inline]
fn rs2(inst: u32) -> u8 {
    ((inst >> 20) & 0b11111) as u8
}

#[inline]
fn b_imm(inst: u32) -> i32 {
    ((inst & 0b10000000_00000000_00000000_00000000) as i32) >> 19
        | ((inst & 0b00000000_00000000_00000000_10000000) as i32) << 4
        | ((inst & 0b01111110_00000000_00000000_00000000) as i32) >> 20
        | ((inst & 0b00000000_00000000_00001111_00000000) as i32) >> 7
}

#[inline]
fn i_imm(inst: u32) -> i32 {
    (inst as i32) >> 20
}

#[inline]
fn j_imm(inst: u32) -> i32 {
    ((inst & 0b10000000_00000000_00000000_00000000) as i32) >> 11
        | ((inst & 0b00000000_00001111_11110000_00000000) as i32) >> 0
        | ((inst & 0b00000000_00010000_00000000_00000000) as i32) >> 9
        | ((inst & 0b01111111_11100000_00000000_00000000) as i32) >> 20
}

#[inline]
fn s_imm(inst: u32) -> i32 {
    ((inst & 0b11111110_00000000_00000000_00000000) as i32) >> 20
        | ((inst & 0b00000000_00000000_00001111_10000000) as i32) >> 7
}

#[inline]
fn u_imm(inst: u32) -> i32 {
    (inst & 0xfffff000) as i32
}

#[rustfmt::skip]
pub fn decode(inst: u32) -> Op {
    match inst & 0x0000007f {
        0x00000037 => Op::Lui { rd: rd(inst), imm: u_imm(inst) },
        0x00000017 => Op::Auipc { rd: rd(inst), imm: u_imm(inst) },
        0x0000006f => Op::Jal { rd: rd(inst), imm: j_imm(inst) },
        0x00000067 => match inst & 0x0000707f {
            0x00000067 => Op::Jalr { rd: rd(inst), rs1: rs1(inst), imm: i_imm(inst) },
            _ => Op::Unknown,
        },
        0x00000063 => match inst & 0x0000707f {
            0x00000063 => Op::Beq { rs1: rs1(inst), rs2: rs2(inst), imm: b_imm(inst) },
            0x00001063 => Op::Bne { rs1: rs1(inst), rs2: rs2(inst), imm: b_imm(inst) },
            0x00004063 => Op::Blt { rs1: rs1(inst), rs2: rs2(inst), imm: b_imm(inst) },
            0x00005063 => Op::Bge { rs1: rs1(inst), rs2: rs2(inst), imm: b_imm(inst) },
            0x00006063 => Op::Bltu { rs1: rs1(inst), rs2: rs2(inst), imm: b_imm(inst) },
            0x00007063 => Op::Bgeu { rs1: rs1(inst), rs2: rs2(inst), imm: b_imm(inst) },
            _ => Op::Unknown,
        },
        0x00000003 => match inst & 0x0000707f {
            0x00000003 => Op::Lb { rd: rd(inst), rs1: rs1(inst), imm: i_imm(inst) },
            0x00001003 => Op::Lh { rd: rd(inst), rs1: rs1(inst), imm: i_imm(inst) },
            0x00002003 => Op::Lw { rd: rd(inst), rs1: rs1(inst), imm: i_imm(inst) },
            0x00004003 => Op::Lbu { rd: rd(inst), rs1: rs1(inst), imm: i_imm(inst) },
            0x00005003 => Op::Lhu { rd: rd(inst), rs1: rs1(inst), imm: i_imm(inst) },
            _ => Op::Unknown,
        },
        0x00000023 => match inst & 0x0000707f {
            0x00000023 => Op::Sb { rs1: rs1(inst), rs2: rs2(inst), imm: s_imm(inst) },
            0x00001023 => Op::Sh { rs1: rs1(inst), rs2: rs2(inst), imm: s_imm(inst) },
            0x00002023 => Op::Sw { rs1: rs1(inst), rs2: rs2(inst), imm: s_imm(inst) },
            _ => Op::Unknown,
        },
        0x00000013 => match inst & 0x0000707f {
            0x00000013 => Op::Addi { rd: rd(inst), rs1: rs1(inst), imm: i_imm(inst) },
            0x00002013 => Op::Slti { rd: rd(inst), rs1: rs1(inst), imm: i_imm(inst) },
            0x00003013 => Op::Sltiu { rd: rd(inst), rs1: rs1(inst), imm: i_imm(inst) },
            0x00004013 => Op::Xori { rd: rd(inst), rs1: rs1(inst), imm: i_imm(inst) },
            0x00006013 => Op::Ori { rd: rd(inst), rs1: rs1(inst), imm: i_imm(inst) },
            0x00007013 => Op::Andi { rd: rd(inst), rs1: rs1(inst), imm: i_imm(inst) },
            0x00001013 => match inst & 0xfe00707f {
                0x00001013 => Op::Slli { rd: rd(inst), rs1: rs1(inst), imm: i_imm(inst) },
                _ => Op::Unknown,
            },
            0x00005013 => match inst & 0xfe00707f {
                0x00005013 => Op::Srli { rd: rd(inst), rs1: rs1(inst), imm: i_imm(inst) },
                0x40005013 => Op::Srai { rd: rd(inst), rs1: rs1(inst), imm: i_imm(inst) },
                _ => Op::Unknown,
            },
            _ => Op::Unknown,
        },
        0x00000033 => match inst & 0xfe00707f {
            0x00000033 => Op::Add { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
            0x40000033 => Op::Sub { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
            0x00001033 => Op::Sll { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
            0x00002033 => Op::Slt { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
            0x00003033 => Op::Sltu { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
            0x00004033 => Op::Xor { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
            0x00005033 => Op::Srl { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
            0x40005033 => Op::Sra { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
            0x00006033 => Op::Or { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
            0x00007033 => Op::And { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
            // 0x02000033 => Op::RV_OP_MUL,
            // 0x02001033 => Op::RV_OP_MULH,
            // 0x02002033 => Op::RV_OP_MULHSU,
            // 0x02003033 => Op::RV_OP_MULHU,
            // 0x02004033 => Op::RV_OP_DIV,
            // 0x02005033 => Op::RV_OP_DIVU,
            // 0x02006033 => Op::RV_OP_REM,
            // 0x02007033 => Op::RV_OP_REMU,
            _ => Op::Unknown,
        },
        // 0x0000000f => match inst & 0x0000707f {
        //     0x0000000f => match inst & 0xffffffff {
        //         0x8330000f => Op::RV_OP_FENCE_TSO,
        //         0x0100000f => Op::RV_OP_PAUSE,
        //         _ => Op::RV_OP_FENCE,
        //     },
        //     _ => Op::Unknown,
        // },
        0x00000073 => match inst & 0xffffffff {
            0x00000073 => Op::Ecall,
            0x00100073 => Op::Break,
            _ => Op::Unknown,
        },
        _ => Op::Unknown,
    }
}
