use alloc::vec::Vec;
use bitcoin::bip32::{ChildNumber, Xpub};

use crate::{
    account::{Account, Coordinates, WalletPolicyCoordinates},
    bip388::WalletPolicy,
};

impl<'a> TryFrom<&'a crate::message::KeyInformation<'a>> for crate::bip388::KeyInformation {
    type Error = &'static str;

    fn try_from(key_info: &'a crate::message::KeyInformation<'a>) -> Result<Self, Self::Error> {
        let pubkey = Xpub::decode(&key_info.pubkey).map_err(|_| "Invalid xpub")?;
        let origin_info = key_info
            .origin
            .as_ref()
            .map(|origin| crate::bip388::KeyOrigin {
                fingerprint: origin.fingerprint,
                derivation_path: origin
                    .path
                    .iter()
                    .map(|&step| ChildNumber::from(step))
                    .collect(),
            });

        Ok(crate::bip388::KeyInformation {
            pubkey,
            origin_info,
        })
    }
}

impl<'a> TryFrom<&'a crate::message::WalletPolicy<'a>> for crate::bip388::WalletPolicy {
    type Error = &'static str;

    fn try_from(policy: &'a crate::message::WalletPolicy<'a>) -> Result<Self, Self::Error> {
        let key_information = policy
            .keys_info
            .iter()
            .map(crate::bip388::KeyInformation::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(crate::bip388::WalletPolicy::new(
            &policy.descriptor_template,
            key_information,
        )?)
    }
}

impl<'a> TryFrom<&'a crate::message::Account<'a>> for Account {
    type Error = &'static str;

    fn try_from(account: &'a crate::message::Account<'a>) -> Result<Self, Self::Error> {
        match &account.account {
            crate::message::mod_Account::OneOfaccount::wallet_policy(wp) => {
                let wallet_policy: WalletPolicy = WalletPolicy::try_from(wp)?;
                Ok(Account::WalletPolicy(wallet_policy))
            }
            crate::message::mod_Account::OneOfaccount::None => Err("Invalid account"),
        }
    }
}

impl TryFrom<&crate::message::AccountCoordinates> for Coordinates {
    type Error = &'static str;

    fn try_from(coords: &crate::message::AccountCoordinates) -> Result<Self, Self::Error> {
        match &coords.account {
            crate::message::mod_AccountCoordinates::OneOfaccount::wallet_policy_coordinates(
                wpc,
            ) => Ok(Coordinates::WalletPolicy(WalletPolicyCoordinates {
                is_change: wpc.is_change,
                address_index: wpc.address_index,
            })),
            crate::message::mod_AccountCoordinates::OneOfaccount::None => {
                Err("Unknown coordinates")
            }
        }
    }
}
