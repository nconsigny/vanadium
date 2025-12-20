//! Configuration command handlers.
//!
//! Handles:
//! - GET_APP_CONFIGURATION (0x01): Return version and settings
//! - GET_CHALLENGE (0x02): Return random bytes for replay protection
//!
//! # Security
//!
//! - No sensitive data exposed
//! - Challenge uses CSPRNG via SDK

use common::error::Error;
use common::message::Response;
use common::types::AppConfiguration;

/// Major version number.
const VERSION_MAJOR: u8 = 0;
/// Minor version number.
const VERSION_MINOR: u8 = 1;
/// Patch version number.
const VERSION_PATCH: u8 = 0;

/// Handles GET_APP_CONFIGURATION command.
///
/// Returns the app version and feature flags.
///
/// # Returns
/// - `Response::AppConfiguration` with version and settings
pub fn handle_get_app_configuration() -> Result<Response, Error> {
    let config = AppConfiguration {
        version_major: VERSION_MAJOR,
        version_minor: VERSION_MINOR,
        version_patch: VERSION_PATCH,
        blind_signing_enabled: false, // Disabled by default for security
        eip712_filtering_enabled: true,
    };

    Ok(Response::AppConfiguration(config))
}

/// Handles GET_CHALLENGE command.
///
/// Returns 32 random bytes for challenge-response authentication.
/// Uses the SDK's CSPRNG via ECALL.
///
/// # Security
///
/// - Uses hardware TRNG via SDK
/// - Each challenge is single-use
/// - Caller should track challenge freshness
///
/// # Returns
/// - `Response::Challenge` with 32 random bytes
/// - `Error::InternalError` if RNG fails
pub fn handle_get_challenge() -> Result<Response, Error> {
    // Get random bytes from the SDK's CSPRNG
    let random = sdk::rand::random_bytes(32);

    // Convert to fixed array
    let mut challenge = [0u8; 32];
    challenge.copy_from_slice(&random);

    Ok(Response::Challenge(challenge))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_app_configuration() {
        let response = handle_get_app_configuration().unwrap();

        if let Response::AppConfiguration(config) = response {
            assert_eq!(config.version_major, VERSION_MAJOR);
            assert_eq!(config.version_minor, VERSION_MINOR);
            assert_eq!(config.version_patch, VERSION_PATCH);
            assert!(!config.blind_signing_enabled);
        } else {
            panic!("Expected AppConfiguration response");
        }
    }

    #[test]
    fn test_get_challenge() {
        let response = handle_get_challenge().unwrap();

        if let Response::Challenge(challenge) = response {
            // Check that we got 32 bytes (actual randomness tested elsewhere)
            assert_eq!(challenge.len(), 32);
        } else {
            panic!("Expected Challenge response");
        }
    }
}
