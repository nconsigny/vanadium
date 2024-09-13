use core::{cell::RefCell, cmp::min};

use alloc::{rc::Rc, vec};
use common::{
    client_commands::{Message, ReceiveBufferMessage, ReceiveBufferResponse, SendBufferMessage},
    ecall_constants::*,
    vm::{Cpu, EcallHandler},
};

use crate::{AppSW, Instruction};

use super::outsourced_mem::OutsourcedMemory;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
enum Register {
    Zero, // x0, constant zero
    Ra,   // x1, return address
    Sp,   // x2, stack pointer
    Gp,   // x3, global pointer
    Tp,   // x4, thread pointer
    T0,   // x5, temporary register
    T1,   // x6, temporary register
    T2,   // x7, temporary register
    S0,   // x8, saved register (frame pointer)
    S1,   // x9, saved register
    A0,   // x10, function argument/return value
    A1,   // x11, function argument/return value
    A2,   // x12, function argument
    A3,   // x13, function argument
    A4,   // x14, function argument
    A5,   // x15, function argument
    A6,   // x16, function argument
    A7,   // x17, function argument
    S2,   // x18, saved register
    S3,   // x19, saved register
    S4,   // x20, saved register
    S5,   // x21, saved register
    S6,   // x22, saved register
    S7,   // x23, saved register
    S8,   // x24, saved register
    S9,   // x25, saved register
    S10,  // x26, saved register
    S11,  // x27, saved register
    T3,   // x28, temporary register
    T4,   // x29, temporary register
    T5,   // x30, temporary register
    T6,   // x31, temporary register
}

impl Register {
    // To get the register's index as a number (x0 to x31)
    pub fn as_index(&self) -> u8 {
        match self {
            Register::Zero => 0,
            Register::Ra => 1,
            Register::Sp => 2,
            Register::Gp => 3,
            Register::Tp => 4,
            Register::T0 => 5,
            Register::T1 => 6,
            Register::T2 => 7,
            Register::S0 => 8,
            Register::S1 => 9,
            Register::A0 => 10,
            Register::A1 => 11,
            Register::A2 => 12,
            Register::A3 => 13,
            Register::A4 => 14,
            Register::A5 => 15,
            Register::A6 => 16,
            Register::A7 => 17,
            Register::S2 => 18,
            Register::S3 => 19,
            Register::S4 => 20,
            Register::S5 => 21,
            Register::S6 => 22,
            Register::S7 => 23,
            Register::S8 => 24,
            Register::S9 => 25,
            Register::S10 => 26,
            Register::S11 => 27,
            Register::T3 => 28,
            Register::T4 => 29,
            Register::T5 => 30,
            Register::T6 => 31,
        }
    }
}

// A pointer in the V-app's address space
#[derive(Debug, Clone, Copy)]
struct GuestPointer(pub u32);

pub struct CommEcallHandler<'a> {
    comm: Rc<RefCell<&'a mut ledger_device_sdk::io::Comm>>,
}

impl<'a> CommEcallHandler<'a> {
    pub fn new(comm: Rc<RefCell<&'a mut ledger_device_sdk::io::Comm>>) -> Self {
        Self { comm }
    }

    // Sends exactly size bytes from the buffer in the V-app memory to the host
    // TODO: we might want to revise the protocol, not as optimized as it could be
    fn handle_xsend(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_>>,
        buffer: GuestPointer,
        mut size: usize,
    ) -> Result<(), &'static str> {
        if size == 0 {
            // We must not read the pointer for an empty buffer; Rust always uses address 0x01 for
            // an empty buffer

            let mut comm = self.comm.borrow_mut();
            SendBufferMessage::new(size as u32, vec![]).serialize_to_comm(&mut comm);
            comm.reply(AppSW::InterruptedExecution);

            let Instruction::Continue(p1, p2) = comm.next_command() else {
                return Err("INS not supported"); // expected "Continue"
            };

            if (p1, p2) != (0, 0) {
                return Err("Wrong P1/P2");
            }
            return Ok(());
        }

        if buffer.0.checked_add(size as u32).is_none() {
            return Err("Buffer overflow");
        }

        let mut g_ptr = buffer.0;

        let segment = cpu.get_segment(g_ptr)?;

        // loop while size > 0
        while size > 0 {
            let copy_size = min(size, 255 - 4); // send maximum 251 bytes per message

            let mut buffer = vec![0; copy_size];
            segment.read_buffer(g_ptr, &mut buffer)?;

            let mut comm = self.comm.borrow_mut();
            SendBufferMessage::new(size as u32, buffer).serialize_to_comm(&mut comm);
            comm.reply(AppSW::InterruptedExecution);

            let Instruction::Continue(p1, p2) = comm.next_command() else {
                return Err("INS not supported"); // expected "Continue"
            };

            if (p1, p2) != (0, 0) {
                return Err("Wrong P1/P2");
            }

            size -= copy_size;
            g_ptr += copy_size as u32;
        }

        Ok(())
    }

    // Receives up to max_size bytes from the host into the buffer in the V-app memory
    // Returns the catual of bytes received.
    fn handle_xrecv(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_>>,
        buffer: GuestPointer,
        max_size: usize,
    ) -> Result<usize, &'static str> {
        let mut g_ptr = buffer.0;

        let segment = cpu.get_segment(g_ptr)?;

        let mut remaining_length = None;
        let mut total_received: usize = 0;
        while remaining_length != Some(0) {
            let mut comm = self.comm.borrow_mut();
            ReceiveBufferMessage::new().serialize_to_comm(&mut comm);
            comm.reply(AppSW::InterruptedExecution);

            let Instruction::Continue(p1, p2) = comm.next_command() else {
                return Err("INS not supported"); // expected "Data"
            };

            if (p1, p2) != (0, 0) {
                return Err("Wrong P1/P2");
            }

            let raw_data = comm.get_data().map_err(|_| "Invalid response from host")?;
            let response = ReceiveBufferResponse::deserialize(raw_data)?;

            drop(comm); // TODO: figure out how to avoid having to deal with this drop explicitly

            match remaining_length {
                None => {
                    // first chunk, check if the total length is acceptable
                    if response.remaining_length > max_size as u32 {
                        return Err("Received data is too large");
                    }
                    remaining_length = Some(response.remaining_length);
                }
                Some(remaining) => {
                    if remaining != response.remaining_length {
                        return Err("Mismatching remaining length");
                    }
                }
            }

            segment.write_buffer(g_ptr, &response.content)?;

            remaining_length = Some(remaining_length.unwrap() - response.content.len() as u32);
            g_ptr += response.content.len() as u32;
            total_received += response.content.len();
        }
        Ok(total_received)
    }
}

impl<'a> EcallHandler for CommEcallHandler<'a> {
    type Memory = OutsourcedMemory<'a>;
    type Error = &'static str;

    fn handle_ecall(&mut self, cpu: &mut Cpu<OutsourcedMemory<'a>>) -> Result<(), &'static str> {
        macro_rules! reg {
            ($reg:ident) => {
                cpu.regs[Register::$reg.as_index() as usize]
            };
        }

        macro_rules! GPreg {
            ($reg:ident) => {
                GuestPointer(cpu.regs[Register::$reg.as_index() as usize] as u32)
            };
        }

        let ecall_code = reg!(T0);
        crate::println!("ecall_code: {:?}", ecall_code);
        match ecall_code {
            ECALL_XSEND => {
                crate::println!("Executing xsend()");
                self.handle_xsend(cpu, GPreg!(A0), reg!(A1) as usize)?
            }
            ECALL_XRECV => {
                crate::println!("Executing xrecv()");
                let ret = self.handle_xrecv(cpu, GPreg!(A0), reg!(A1) as usize)?;
                reg!(A0) = ret as u32;
            }
            ECALL_UX_IDLE => {
                crate::println!("Executing ux_idle()");

                ledger_device_sdk::ui::gadgets::clear_screen();
                // TODO: we would like to show the application name and icon, and allow for a more customizable menu
                let page = ledger_device_sdk::ui::gadgets::Page::from((
                    ["Application", "is ready"],
                    false,
                ));
                page.place();
            }
            _ => {
                return Err("Unhandled ECALL");
            }
        }

        crate::println!("Done with: {:?}", ecall_code);
        Ok(())
    }
}
