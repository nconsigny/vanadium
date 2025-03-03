use alloc::borrow::Cow;
use common::message;

use crate::accounts::{Account, AccountType, Coordinates};

#[cfg(not(test))]
fn display_address(addr: &str) -> bool {
    sdk::ux::review_pairs(
        "Verify Bitcoin\naddress",
        "",
        &alloc::vec![sdk::ux::TagValue {
            tag: "Address".into(),
            value: addr.into(),
        }],
        "",
        "Confirm",
        false,
    )
}

#[cfg(test)]
fn display_address(_addr: &str) -> bool {
    true
}

pub fn handle_get_address<'a, 'b>(
    req: &message::RequestGetAddress<'a>,
) -> Result<message::ResponseGetAddress<'b>, &'static str> {
    let account: Account = req.account.as_ref().ok_or("Missing account")?.try_into()?;

    // TODO: necessary checks, for now we're accepting any policy

    let Account::WalletPolicy(wallet_policy) = account;
    let coords: Coordinates = req
        .account_coordinates
        .as_ref()
        .ok_or("Missing coordinates")?
        .try_into()?;

    let wpc = match coords {
        Coordinates::WalletPolicy(wpc) => wpc,
    };

    let address = wallet_policy.get_address(&wpc)?;
    if req.display {
        if !display_address(&address) {
            return Err("Rejected by the user");
        }
    }

    Ok(message::ResponseGetAddress {
        address: Cow::Owned(address),
    })
}

#[cfg(test)]
mod tests {
    use crate::accounts::KeyInformation;

    use super::*;

    fn ki(key_info_str: &str) -> message::KeyInformation {
        let info = KeyInformation::try_from(key_info_str).unwrap();

        let origin = info.origin_info.map(|info| message::KeyOrigin {
            fingerprint: info.fingerprint,
            path: info
                .derivation_path
                .iter()
                .map(|step| u32::from(*step))
                .collect(),
        });

        message::KeyInformation {
            pubkey: Cow::Owned(info.pubkey.encode().to_vec()),
            origin,
        }
    }

    #[test]
    fn test_get_address_singlesig_wit() {
        let req = message::RequestGetAddress {
            display: false,
            name: Cow::Borrowed(""),
            account: Some(message::Account {
                account: message::mod_Account::OneOfaccount::wallet_policy(message::WalletPolicy {
                    descriptor_template: Cow::Borrowed("wpkh(@0/**)"),
                    keys_info: vec![
                        ki("[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P"),
                    ]
                }),
            }),
            account_coordinates: Some(message::AccountCoordinates {
                account: message::mod_AccountCoordinates::OneOfaccount::wallet_policy_coordinates(
                    message::WalletPolicyCoordinates {
                        is_change: false,
                        address_index: 0,
                    },
                ),
            }),
        };

        let resp = handle_get_address(&req).unwrap();

        assert_eq!(resp.address, "tb1qzdr7s2sr0dwmkwx033r4nujzk86u0cy6fmzfjk");
    }
}
