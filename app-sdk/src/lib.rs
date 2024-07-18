#![cfg_attr(target_arch = "riscv32", no_main, no_std)]

pub fn fatal(msg: &str) {
    // TODO: placeholder
    let _ = msg;
}

#[cfg(test)]
mod tests {
    
}
