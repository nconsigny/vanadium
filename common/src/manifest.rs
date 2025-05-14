use serde::{self, Deserialize, Serialize};

use crate::constants::{page_start, PAGE_SIZE};

const APP_NAME_LEN: usize = 32; // Define a suitable length
const APP_VERSION_LEN: usize = 32; // Define a suitable length

// TODO: copied from vanadium-legacy without much thought; fields are subject to change
/// The manifest contains all the required info that the application needs in order to execute a V-App.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Manifest {
    pub manifest_version: u32,
    pub app_name: [u8; APP_NAME_LEN],
    pub app_version: [u8; APP_VERSION_LEN],
    pub entrypoint: u32,
    pub code_start: u32,
    pub code_end: u32,
    pub code_merkle_root: [u8; 32],
    pub data_start: u32,
    pub data_end: u32,
    pub data_merkle_root: [u8; 32],
    pub stack_start: u32,
    pub stack_end: u32,
    pub stack_merkle_root: [u8; 32],
}

impl Manifest {
    // Helper function to create a Manifest with the app_name and app_version set from &str
    pub fn new(
        manifest_version: u32,
        app_name: &str,
        app_version: &str,
        entrypoint: u32,
        code_start: u32,
        code_end: u32,
        code_merkle_root: [u8; 32],
        data_start: u32,
        data_end: u32,
        data_merkle_root: [u8; 32],
        stack_start: u32,
        stack_end: u32,
        stack_merkle_root: [u8; 32],
    ) -> Result<Self, &'static str> {
        if app_name.len() > APP_NAME_LEN {
            return Err("app_name is too long");
        }
        if app_version.len() > APP_VERSION_LEN {
            return Err("app_version is too long");
        }

        let mut app_name_arr = [0u8; APP_NAME_LEN];
        let mut app_version_arr = [0u8; APP_VERSION_LEN];

        let name_bytes = app_name.as_bytes();
        let version_bytes = app_version.as_bytes();

        app_name_arr[..name_bytes.len()].copy_from_slice(name_bytes);
        app_version_arr[..version_bytes.len()].copy_from_slice(version_bytes);

        Ok(Self {
            manifest_version,
            app_name: app_name_arr,
            app_version: app_version_arr,
            entrypoint,
            code_start,
            code_end,
            code_merkle_root,
            data_start,
            data_end,
            data_merkle_root,
            stack_start,
            stack_end,
            stack_merkle_root,
        })
    }

    pub fn get_app_name(&self) -> &str {
        core::str::from_utf8(
            &self.app_name[..self.app_name.iter().position(|&c| c == 0).unwrap_or(32)],
        )
        .unwrap() // doesn't fail, as the new() function creates it from a valid string
    }

    pub fn get_app_version(&self) -> &str {
        core::str::from_utf8(
            &self.app_version[..self.app_version.iter().position(|&c| c == 0).unwrap_or(32)],
        )
        .unwrap() // doesn't fail, as the new() function creates it from a valid string
    }

    #[inline]
    fn n_pages(start: u32, end: u32) -> u32 {
        1 + (page_start(end - 1) - page_start(start)) / PAGE_SIZE as u32
    }

    #[inline]
    pub fn n_code_pages(&self) -> u32 {
        Self::n_pages(self.code_start, self.code_end)
    }

    #[inline]
    pub fn n_data_pages(&self) -> u32 {
        Self::n_pages(self.data_start, self.data_end)
    }

    #[inline]
    pub fn n_stack_pages(&self) -> u32 {
        Self::n_pages(self.stack_start, self.stack_end)
    }

    #[cfg(feature = "serde_json")]
    pub fn to_json(&self) -> Result<alloc::string::String, serde_json::Error> {
        serde_json::to_string(self)
    }

    #[cfg(feature = "serde_json")]
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}
