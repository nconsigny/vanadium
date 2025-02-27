use alloc::{string::String, vec::Vec};

use super::codec::*;

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Action {
    Confirm = 0,
    Reject = 1,
    Quit = 2,
    Skip = 3,
    PreviousPage = 4, // TODO: page index is part of the event data
    NextPage = 5,
    TitleBack = 6,
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum EventCode {
    Ticker = 0,
    Action = 1,
    Unknown = 0xFFFFFFFF,
}

impl From<u32> for EventCode {
    fn from(value: u32) -> Self {
        match value {
            0 => EventCode::Ticker,
            1 => EventCode::Action,
            _ => EventCode::Unknown,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union EventData {
    pub ticker: TickerEvent,
    pub action: Action,
    // Reserve space for future expansions. Each event's raw data is exactly 16 bytes.
    // For events that do not define the meaning of the raw data, the value of those bytes is undefined
    // and could change in future versions.
    pub raw: [u8; 16],
}

impl Default for EventData {
    fn default() -> Self {
        EventData { raw: [0; 16] }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct TickerEvent {}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Event {
    Ticker,
    Action(Action),
    Unknown([u8; 16]),
}

/// For the Icon page, define whether the icon indicates success or failure.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Icon {
    None,
    Success,
    Failure,
}

impl Serializable for Icon {
    #[inline(always)]
    fn get_serialized_length(&self) -> usize {
        1
    }

    #[inline(always)]
    fn serialize(&self, buf: &mut [u8], pos: &mut usize) {
        let tag: u8 = match self {
            Icon::None => 0,
            Icon::Success => 1,
            Icon::Failure => 2,
        };
        tag.serialize(buf, pos);
    }

    fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if slice.len() < 1 {
            return Err("slice too short for icon tag");
        }
        let (tag, rest) = slice.split_first().unwrap();
        match tag {
            0 => Ok((Icon::None, rest)),
            1 => Ok((Icon::Success, rest)),
            2 => Ok((Icon::Failure, rest)),
            _ => Err("invalid icon tag"),
        }
    }
}

#[cfg(feature = "wrapped_serializable")]
impl Wrappable for Icon {
    type Wrapped = MaybeConst<Icon>;
}

impl Makeable<'_> for Icon {
    type ArgType = Icon;
}

// Structured types

define_serializable_enum! {
    NavInfo {
        0x01u8 => NavWithButtons {
            has_back_button: bool,
            has_page_indicator: bool,
            quit_text: Option<String>,
        } as (make_nav_with_buttons, make_nav_with_buttons_wrapped),
    },
    wrapped: WrappedNavInfo
}

define_serializable_struct! {
    NavigationInfo {
        active_page: u32,
        n_pages: u32,
        skip_text: Option<String>,
        nav_info: NavInfo
    },
    wrapped: WrappedNavigationInfo
}

define_serializable_struct! {
    TagValue {
        tag: String,
        value: String,
    },
    wrapped: WrappedTagValue
}

define_serializable_enum! {
    PageContent {
        0x01u8 => TextSubtext {
            text: String,
            subtext: String,
        } as (make_text_subtext, make_text_subtext_wrapped),
        0x02u8 => TagValueList {
            list: Vec<TagValue>,
        } as (make_tag_value_list, make_tag_value_list_wrapped),
        0x03u8 => ConfirmationButton {
            text: String,
            button_text: String,
        } as (make_confirmation_button, make_confirmation_button_wrapped),
        0x04u8 => ConfirmationLongPress {
            text: String,
            long_press_text: String,
        } as (make_confirmation_long_press, make_confirmation_long_press_wrapped),
    },
    wrapped: WrappedPageContent
}

// nbgl_pageContent_t
define_serializable_struct! {
    PageContentInfo {
        title: Option<String>,
        top_right_icon: Icon,
        page_content: PageContent,
    },
    wrapped: WrappedPageContentInfo
}

define_serializable_enum! {
    Page {
        // A page showing a spinner and some text.
        0x01u8 => Spinner {
            text: String,
        } as (make_spinner, make_spinner_wrapped),
        // A page showing an icon (either success or failure) and some text.
        0x02u8 => Info {
            icon: Icon,
            text: String,
        } as (make_info, make_info_wrapped),
        // A page with a title, text, a "confirm" button, and a "reject" button.
        0x03u8 => ConfirmReject {
            title: String,
            text: String,
            confirm: String,
            reject: String,
        } as (make_confirm_reject, make_confirm_reject_wrapped),
        // A generic page with navigation, implementing a subset of the pages supported by nbgl_pageDrawGenericContent
        0x04u8 => GenericPage {
            navigation_info: Option<NavigationInfo>,
            page_content_info: PageContentInfo }
            as (make_generic_page, make_generic_page_wrapped),
    },
    wrapped: WrappedPage
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{string::ToString, vec};

    // Helper function for round-trip serialization/deserialization tests.
    fn round_trip<T>(value: &T)
    where
        T: Serializable + PartialEq + core::fmt::Debug,
    {
        let serialized = value.serialized();
        let (deserialized, rest) = T::deserialize(&serialized).unwrap();
        assert!(rest.is_empty(), "There should be no remaining bytes");
        assert_eq!(value, &deserialized);
    }

    #[test]
    fn test_spinner_page() {
        let page = Page::Spinner {
            text: "Loading".to_string(),
        };
        round_trip(&page);
    }

    #[test]
    fn test_icon_page() {
        let page = Page::Info {
            icon: Icon::Failure,
            text: "Error occurred".to_string(),
        };
        round_trip(&page);
    }

    #[test]
    fn test_confirm_reject_page() {
        let page = Page::ConfirmReject {
            title: "Confirm Action".to_string(),
            text: "Are you sure you want to proceed?".to_string(),
            confirm: "Yes".to_string(),
            reject: "No".to_string(),
        };
        round_trip(&page);
    }

    #[test]
    fn test_generic_page() {
        // Create a NavigationInfo with a NavWithButtons variant.
        let nav_info = NavigationInfo {
            active_page: 2,
            n_pages: 5,
            skip_text: Some("Skip".to_string()),
            nav_info: NavInfo::NavWithButtons {
                has_back_button: true,
                has_page_indicator: false,
                quit_text: Some("Quit".to_string()),
            },
        };
        // Create a PageContentInfo using the TextSubtext variant.
        let page_content_info = PageContentInfo {
            title: Some("Generic Page".to_string()),
            top_right_icon: Icon::Success,
            page_content: PageContent::TextSubtext {
                text: "Welcome".to_string(),
                subtext: "to the generic page".to_string(),
            },
        };
        let page = Page::GenericPage {
            navigation_info: Some(nav_info),
            page_content_info,
        };
        round_trip(&page);
    }

    #[test]
    fn test_page_content_text_subtext() {
        let content = PageContent::TextSubtext {
            text: "Main text".to_string(),
            subtext: "Additional info".to_string(),
        };
        round_trip(&content);
    }

    #[test]
    fn test_page_content_tag_value_list() {
        let tag_value1 = TagValue {
            tag: "tag1".to_string(),
            value: "value1".to_string(),
        };
        let tag_value2 = TagValue {
            tag: "tag2".to_string(),
            value: "value2".to_string(),
        };
        let content = PageContent::TagValueList {
            list: vec![tag_value1, tag_value2],
        };
        round_trip(&content);
    }

    #[test]
    fn test_page_content_confirmation_button() {
        let content = PageContent::ConfirmationButton {
            text: "Confirm?".to_string(),
            button_text: "OK".to_string(),
        };
        round_trip(&content);
    }

    #[test]
    fn test_page_content_confirmation_long_press() {
        let content = PageContent::ConfirmationLongPress {
            text: "Hold to confirm".to_string(),
            long_press_text: "Long press here".to_string(),
        };
        round_trip(&content);
    }

    #[test]
    fn test_navigation_info() {
        let nav_info = NavigationInfo {
            active_page: 1,
            n_pages: 3,
            skip_text: None,
            nav_info: NavInfo::NavWithButtons {
                has_back_button: false,
                has_page_indicator: true,
                quit_text: None,
            },
        };
        round_trip(&nav_info);
    }

    #[test]
    fn test_deserialize_full_extra_bytes() {
        // Serialize a page and then append an extra byte.
        let page = Page::Spinner {
            text: "Loading".to_string(),
        };
        let mut serialized = page.serialized();
        serialized.push(42); // Append extra data.
        let result = Page::deserialize_full(&serialized);
        assert!(
            result.is_err(),
            "deserialize_full should error if extra bytes remain"
        );
    }

    #[test]
    fn test_invalid_tag() {
        // Serialize a valid page and then change its tag to an invalid value.
        let mut serialized = Page::Spinner {
            text: "Loading".to_string(),
        }
        .serialized();
        serialized[0] = 0xFF; // 0xFF is not a valid tag.
        let result = Page::deserialize(&serialized);
        assert!(result.is_err(), "Invalid tag should result in an error");
    }

    #[test]
    fn test_truncated_data() {
        // Serialize a valid ConfirmReject page and then truncate the data.
        let serialized = Page::ConfirmReject {
            title: "Confirm".to_string(),
            text: "Proceed?".to_string(),
            confirm: "Yes".to_string(),
            reject: "No".to_string(),
        }
        .serialized();
        let truncated = &serialized[..serialized.len() - 2]; // Remove last 2 bytes.
        let result = Page::deserialize(truncated);
        assert!(
            result.is_err(),
            "Truncated data should fail deserialization"
        );
    }

    #[test]
    fn test_too_short() {
        // An empty slice should fail.
        let empty: &[u8] = &[];
        assert!(
            Page::deserialize(empty).is_err(),
            "Empty slice should return an error"
        );
    }
}
