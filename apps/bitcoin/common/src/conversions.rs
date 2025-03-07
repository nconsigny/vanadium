use alloc::{borrow::Cow, vec::Vec};
use bitcoin::bip32::{ChildNumber, Xpub};

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

impl<'a> TryFrom<&'a crate::message::Account<'a>> for crate::bip388::WalletPolicy {
    type Error = &'static str;

    fn try_from(account: &'a crate::message::Account<'a>) -> Result<Self, Self::Error> {
        match &account.account {
            crate::message::mod_Account::OneOfaccount::wallet_policy(wp) => {
                let wallet_policy = crate::bip388::WalletPolicy::try_from(wp)?;
                Ok(wallet_policy)
            }
            crate::message::mod_Account::OneOfaccount::None => Err("Invalid account"),
        }
    }
}

impl<'a> From<&'a crate::bip388::WalletPolicy> for crate::message::Account<'a> {
    fn from(policy: &'a crate::bip388::WalletPolicy) -> Self {
        // Convert each bip388 key information back into its message representation.
        let keys_info = policy
            .key_information
            .iter()
            .map(|key_info| {
                crate::message::KeyInformation {
                    // Assume that `pubkey` can be re-encoded into the expected format.
                    pubkey: Cow::Owned(key_info.pubkey.encode().to_vec()),
                    origin: key_info
                        .origin_info
                        .as_ref()
                        .map(|origin| crate::message::KeyOrigin {
                            fingerprint: origin.fingerprint,
                            // Convert each derivation step to the message representation.
                            path: origin
                                .derivation_path
                                .iter()
                                .map(|&child| child.into())
                                .collect(),
                        }),
                }
            })
            .collect();

        // Build the message WalletPolicy.
        let msg_wallet_policy = crate::message::WalletPolicy {
            descriptor_template: Cow::Borrowed(policy.descriptor_template_raw()),
            keys_info,
        };

        // Wrap it in the Account enum variant.
        crate::message::Account {
            account: crate::message::mod_Account::OneOfaccount::wallet_policy(msg_wallet_policy),
        }
    }
}

impl TryFrom<&crate::message::AccountCoordinates> for crate::account::WalletPolicyCoordinates {
    type Error = &'static str;

    fn try_from(coords: &crate::message::AccountCoordinates) -> Result<Self, Self::Error> {
        match &coords.account {
            crate::message::mod_AccountCoordinates::OneOfaccount::wallet_policy_coordinates(
                wpc,
            ) => Ok(crate::account::WalletPolicyCoordinates {
                is_change: wpc.is_change,
                address_index: wpc.address_index,
            }),
            crate::message::mod_AccountCoordinates::OneOfaccount::None => {
                Err("Unknown coordinates")
            }
        }
    }
}

impl From<&crate::account::WalletPolicyCoordinates> for crate::message::AccountCoordinates {
    fn from(coords: &crate::account::WalletPolicyCoordinates) -> Self {
        crate::message::AccountCoordinates {
            account:
                crate::message::mod_AccountCoordinates::OneOfaccount::wallet_policy_coordinates(
                    crate::message::WalletPolicyCoordinates {
                        is_change: coords.is_change,
                        address_index: coords.address_index,
                    },
                ),
        }
    }
}
