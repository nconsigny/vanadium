// This module implements conversions from the protobuf messages to the internal types

use alloc::vec::Vec;
use bitcoin::bip32::{ChildNumber, Xpub};

use super::{
    Account, Coordinates, KeyInformation, KeyOrigin, WalletPolicy, WalletPolicyCoordinates,
};

impl<'a> TryFrom<&'a common::message::KeyInformation<'a>> for KeyInformation {
    type Error = &'static str;

    fn try_from(key_info: &'a common::message::KeyInformation<'a>) -> Result<Self, Self::Error> {
        let pubkey = Xpub::decode(&key_info.pubkey).map_err(|_| "Invalid xpub")?;
        let origin_info = key_info.origin.as_ref().map(|origin| KeyOrigin {
            fingerprint: origin.fingerprint,
            derivation_path: origin
                .path
                .iter()
                .map(|&step| ChildNumber::from(step))
                .collect(),
        });

        Ok(KeyInformation {
            pubkey,
            origin_info,
        })
    }
}

impl<'a> TryFrom<&'a common::message::WalletPolicy<'a>> for WalletPolicy {
    type Error = &'static str;

    fn try_from(policy: &'a common::message::WalletPolicy<'a>) -> Result<Self, Self::Error> {
        let key_information = policy
            .keys_info
            .iter()
            .map(KeyInformation::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(WalletPolicy::new(
            &policy.descriptor_template,
            key_information,
        )?)
    }
}

impl<'a> TryFrom<&'a common::message::Account<'a>> for Account {
    type Error = &'static str;

    fn try_from(account: &'a common::message::Account<'a>) -> Result<Self, Self::Error> {
        match &account.account {
            common::message::mod_Account::OneOfaccount::wallet_policy(wp) => {
                let wallet_policy: WalletPolicy = WalletPolicy::try_from(wp)?;
                Ok(Account::WalletPolicy(wallet_policy))
            }
            common::message::mod_Account::OneOfaccount::None => Err("Invalid account"),
        }
    }
}

impl TryFrom<&common::message::AccountCoordinates> for Coordinates {
    type Error = &'static str;

    fn try_from(coords: &common::message::AccountCoordinates) -> Result<Self, Self::Error> {
        match &coords.account {
            common::message::mod_AccountCoordinates::OneOfaccount::wallet_policy_coordinates(
                wpc,
            ) => Ok(Coordinates::WalletPolicy(WalletPolicyCoordinates {
                is_change: wpc.is_change,
                address_index: wpc.address_index,
            })),
            common::message::mod_AccountCoordinates::OneOfaccount::None => {
                Err("Unknown coordinates")
            }
        }
    }
}
