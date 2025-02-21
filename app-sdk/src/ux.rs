use crate::{
    ecalls::{Ecall, EcallsInterface},
    ux_generated::{
        make_review_pairs_content, make_review_pairs_final_confirmationbutton,
        make_review_pairs_final_longpress, make_review_pairs_intro,
    },
};
use alloc::vec::Vec;

pub use common::ux::{
    Action, Event, EventCode, EventData, Icon, NavInfo, NavigationInfo, Page, PageContent,
    PageContentInfo, Serializable, TagValue,
};

use crate::ux_generated;

#[inline(always)]
fn show_page_raw(page: &[u8]) {
    Ecall::show_page(page.as_ptr(), page.len());
}

/// Blocks until an event is received, then returns it.
pub fn get_event() -> Event {
    loop {
        let mut event_data = EventData::default();
        let event_code = EventCode::from(Ecall::get_event(&mut event_data));
        match event_code {
            EventCode::Ticker => {
                return Event::Ticker;
            }
            EventCode::Action => {
                let action = unsafe { event_data.action };
                // TODO: sanitize?
                return Event::Action(action);
            }
            EventCode::Unknown => {
                let data = unsafe { event_data.raw };
                return Event::Unknown(data);
            }
        }
    }
}

// waits for a number of ticker events
pub fn wait(n: u32) {
    let mut n_tickers = 0u32;
    loop {
        let mut event_data = EventData::default();
        let event_code = EventCode::from(Ecall::get_event(&mut event_data));
        match event_code {
            EventCode::Ticker => {
                n_tickers += 1;
                if n_tickers >= n {
                    return;
                }
            }
            _ => {}
        }
    }
}

// Like get_event, but it ignores any event that is not an Action
pub fn get_action() -> Action {
    loop {
        if let Event::Action(action) = get_event() {
            return action;
        }
    }
}

// Temporary function; similar to nbgl_useCaseReview
pub fn review_pairs(
    intro_text: &str,
    intro_subtext: &str,
    pairs: &[TagValue],
    final_text: &str,
    final_button_text: &str,
    long_press: bool,
) -> bool {
    let n_pair_pages = ((pairs.len() + 1) / 2) as u32;
    let n_pages = 1 + n_pair_pages + 1; // intro page + pair pages + final page

    let mut serialized_pages = Vec::with_capacity(n_pages as usize);

    // create intro page
    serialized_pages.push(make_review_pairs_intro(
        0,
        n_pages,
        intro_text,
        intro_subtext,
    ));

    // create a page for each pair of tag-value; the last page might possible have a single tag-value
    for (i, pair_chunk) in pairs.chunks(2).enumerate() {
        serialized_pages.push(make_review_pairs_content(1 + i as u32, n_pages, pair_chunk));
    }

    // create final page

    if long_press {
        serialized_pages.push(make_review_pairs_final_longpress(
            n_pages - 1,
            n_pages,
            final_text,
            final_button_text,
        ));
    } else {
        serialized_pages.push(make_review_pairs_final_confirmationbutton(
            n_pages - 1,
            n_pages,
            final_text,
            final_button_text,
        ));
    }

    let mut active_page = 0;
    loop {
        show_page_raw(&serialized_pages[active_page]);
        active_page = loop {
            match get_event() {
                Event::Action(Action::PreviousPage) => {
                    break active_page - 1;
                }
                Event::Action(Action::NextPage) => {
                    break active_page + 1;
                }
                Event::Action(Action::Quit) => {
                    return false;
                }
                Event::Action(Action::Confirm) => {
                    return true;
                }
                _ => {} // ignore other events for now
            }
        }
    }
}

pub fn show_spinner(text: &str) {
    ux_generated::show_spinner(text);
}

pub fn show_info(icon: Icon, text: &str) {
    ux_generated::show_info(icon, text);
}

#[inline(always)]
pub fn show_confirm_reject(title: &str, text: &str, confirm: &str, reject: &str) -> bool {
    ux_generated::show_confirm_reject(title, text, confirm, reject);

    // wait until a button is pressed
    loop {
        match get_event() {
            Event::Action(action) => {
                if action == Action::Reject {
                    return false;
                } else if action == Action::Confirm {
                    return true;
                }
            }
            _ => {}
        }
    }
}

#[inline(always)]
pub fn ux_idle() {
    show_page_raw(&ux_generated::RAW_PAGE_APP_DASHBOARD);
}
