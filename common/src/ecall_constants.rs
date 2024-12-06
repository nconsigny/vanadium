pub const ECALL_FATAL: u32 = 1;
pub const ECALL_XSEND: u32 = 2;
pub const ECALL_XRECV: u32 = 3;
pub const ECALL_EXIT: u32 = 4;
pub const ECALL_UX_IDLE: u32 = 12;

// Big numbers
pub const ECALL_MODM: u32 = 110;
pub const ECALL_ADDM: u32 = 111;
pub const ECALL_SUBM: u32 = 112;
pub const ECALL_MULTM: u32 = 113;
pub const ECALL_POWM: u32 = 114;

pub const MAX_BIGNUMBER_SIZE: usize = 64;

// HD derivations
pub enum CurveKind {
    Secp256k1 = 0x21,
}

pub const ECALL_DERIVE_HD_NODE: u32 = 130;
pub const ECALL_GET_MASTER_FINGERPRINT: u32 = 131;

// Hash functions
pub const ECALL_HASH_INIT: u32 = 150;
pub const ECALL_HASH_UPDATE: u32 = 151;
pub const ECALL_HASH_DIGEST: u32 = 152;
