use std::io;
use std::io::Write;

pub fn ecall_ux_idle() {}

pub fn ecall_exit(status: i32) -> ! {
    std::process::exit(status);
}

pub fn ecall_fatal(msg: *const u8, size: usize) -> ! {
    // print the message as a panic
    let slice = unsafe { std::slice::from_raw_parts(msg, size) };
    let msg = std::str::from_utf8(slice).unwrap();
    panic!("{}", msg);
}

pub fn ecall_xsend(buffer: *const u8, size: usize) {
    let slice = unsafe { std::slice::from_raw_parts(buffer, size) };
    for byte in slice {
        print!("{:02x}", byte);
    }
    print!("\n");
    io::stdout().flush().expect("Failed to flush stdout");
}

pub fn ecall_xrecv(buffer: *mut u8, max_size: usize) -> usize {
    // Request a hex string from the user; repeat until the input is valid
    // and at most max_size bytes long
    let (n_bytes_to_copy, bytes) = loop {
        let mut input = String::new();
        io::stdout().flush().expect("Failed to flush stdout");
        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read line");

        let input = input.trim();

        let Ok(bytes) = hex::decode(input) else {
            println!(
                "Input too large, max size is {} bytes, please try again.",
                max_size
            );
            continue;
        };
        if bytes.len() <= max_size {
            break (bytes.len(), bytes);
        }
        println!("Input too large, please try again.");
    };

    // copy to the destination buffer
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, n_bytes_to_copy);
    }

    return n_bytes_to_copy;
}
