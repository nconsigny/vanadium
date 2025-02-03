use crate::ecalls::{self, Ecall, EcallsInterface};

use common::ecall_constants;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Event {
    Ticker,
    Unknown([u8; 16]),
}

/// Blocks until an event is received, then returns it.
pub fn get_event() -> Event {
    loop {
        let mut event_data = ecalls::EventData::default();
        let event_code = ecall_constants::EventCode::from(Ecall::get_event(&mut event_data));
        match event_code {
            ecall_constants::EventCode::Ticker => {
                return Event::Ticker;
            }
            ecall_constants::EventCode::Unknown => {
                let data = unsafe { event_data.raw };
                return Event::Unknown(data);
            }
        }
    }
}

pub fn ux_idle() {
    Ecall::ux_idle()
}
