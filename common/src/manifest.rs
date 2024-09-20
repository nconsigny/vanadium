use serde::{self, Deserialize, Serialize};

const APP_NAME_LEN: usize = 32; // Define a suitable length
const APP_VERSION_LEN: usize = 32; // Define a suitable length

// TODO: copied from vanadium-legacy without much thought; fields are subject to change
/// The manifest contains all the required info that the application needs in order to execute a V-App.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Manifest {
    pub manifest_version: u32,
    pub app_name: [u8; APP_NAME_LEN],
    pub app_version: [u8; APP_VERSION_LEN],
    pub app_hash: [u8; 32],
    pub entrypoint: u32,
    pub bss: u32,
    pub code_start: u32,
    pub code_end: u32,
    pub stack_start: u32,
    pub stack_end: u32,
    pub data_start: u32,
    pub data_end: u32,
    pub mt_root_hash: [u8; 32],
    pub mt_size: u32,
}

impl Manifest {
    // Helper function to create a Manifest with the app_name and app_version set from &str
    pub fn new(
        manifest_version: u32,
        app_name: &str,
        app_version: &str,
        app_hash: [u8; 32],
        entrypoint: u32,
        bss: u32,
        code_start: u32,
        code_end: u32,
        stack_start: u32,
        stack_end: u32,
        data_start: u32,
        data_end: u32,
        mt_root_hash: [u8; 32],
        mt_size: u32,
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
            app_hash,
            entrypoint,
            bss,
            code_start,
            code_end,
            stack_start,
            stack_end,
            data_start,
            data_end,
            mt_root_hash,
            mt_size,
        })
    }
}
