use alloc::vec::Vec;

pub type Handler = fn(&mut App, &[u8]) -> Vec<u8>;

pub struct App {
    handler: Handler,
}

impl App {
    pub fn new(handler: Handler) -> Self {
        App { handler }
    }

    pub fn run(&mut self) {
        crate::ux::ux_idle();
        loop {
            // TODO: can we handle the error any better?
            //       Aborting in Vanadium might be necessary anyway, if communication breaks.
            let req_msg = crate::comm::receive_message().expect("Communication error");
            let resp_msg = (self.handler)(self, &req_msg);
            crate::comm::send_message(&resp_msg);
        }
    }

    pub fn singleton() -> Self {
        App::new(|_app, _msg| Vec::new())
    }
}
