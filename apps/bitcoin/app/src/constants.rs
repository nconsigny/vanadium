pub const BIP44_COIN_TYPE: u32 = 1; // testnet

pub const MAX_BIP44_ACCOUNT_RECOMMENDED: u32 = 100;

pub const COIN_TICKER: &'static str = "TEST";

// For amount (in sats) not smaller than THRESHOLD_WARN_HIGH_FEES_AMOUNT, we show a warning
// if the amount spend in fees divided by the total amount of all inputs) is greater than
// or equal THRESHOLD_WARN_HIGH_FEES_FRACTION.
pub const THRESHOLD_WARN_HIGH_FEES_FRACTION: f64 = 0.1;
pub const THRESHOLD_WARN_HIGH_FEES_AMOUNT: u64 = 100_000;
