use alloc::{vec, vec::Vec};

pub fn handle_show_ux_screen(data: &[u8]) -> Vec<u8> {
    if data.len() != 1 {
        return vec![];
    }

    let screen_id = data[0];
    match screen_id {
        0 => {
            sdk::ux::show_info(sdk::ux::Icon::Success, "Oh yeah!");
            sdk::ux::wait(10);
        }
        1 => {
            sdk::ux::show_info(sdk::ux::Icon::Failure, "Oh no!");
            sdk::ux::wait(10);
        }
        2 => {
            sdk::ux::show_spinner("Loading...");
            sdk::ux::wait(10);
        }
        3 => {
            sdk::ux::show_confirm_reject("Confirm", "Do you want to confirm?", "Yes", "No");
        }
        4 => {
            sdk::ux::review_pairs(
                "Review the pairs",
                "It's important",
                &vec![
                    sdk::ux::TagValue {
                        tag: "tag1".into(),
                        value: "value1".into(),
                    },
                    sdk::ux::TagValue {
                        tag: "tag2".into(),
                        value: "value2".into(),
                    },
                    sdk::ux::TagValue {
                        tag: "tag3".into(),
                        value: "value3".into(),
                    },
                    sdk::ux::TagValue {
                        tag: "tag4".into(),
                        value: "value4".into(),
                    },
                    sdk::ux::TagValue {
                        tag: "tag5".into(),
                        value: "value5".into(),
                    },
                ],
                "Hope you checked",
                "Confirm",
                true,
            );
        }
        _ => panic!("Unknown screen id"),
    }

    sdk::ux::ux_idle();

    vec![]
}
