use alloc::vec::Vec;

/// A Handler is a function that is called when a message is received from the host, and
/// returns the app's response.
pub type Handler = fn(&mut App, &[u8]) -> Vec<u8>;

/// The App struct represents the context of the application.
pub struct App {
    handler: Handler,
}

impl App {
    /// Creates a new App instance with the given handler.
    pub fn new(handler: Handler) -> Self {
        App { handler }
    }

    /// This function shows the dashboard, then enters the core loop of the app.
    /// It never returns, as it keeps the app running until sdk::exit() is called,
    /// or a fatal error occurs.
    pub fn run(&mut self) -> ! {
        crate::ux::ux_idle();
        loop {
            // TODO: can we handle the error any better?
            //       Aborting in Vanadium might be necessary anyway, if communication breaks.
            let req_msg = crate::comm::receive_message().expect("Communication error");
            let resp_msg = (self.handler)(self, &req_msg);
            crate::comm::send_message(&resp_msg);
        }
    }

    /// This is only useful to produce a valid app instance in tests.
    pub fn singleton() -> Self {
        App::new(|_app, _msg| Vec::new())
    }
}
