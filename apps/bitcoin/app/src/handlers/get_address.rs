use alloc::borrow::Cow;
use common::{account::Account, message};

#[cfg(not(test))]
fn display_address(account_name: Option<&str>, addr: &str) -> bool {
    use alloc::vec;
    use sdk::ux::TagValue;

    let pairs = match account_name {
        Some(account_name) => {
            vec![TagValue {
                tag: "Account".into(),
                value: account_name.into(),
            }]
        }
        None => {
            vec![]
        }
    };
    sdk::ux::review_pairs(
        "Verify Bitcoin\naddress",
        "",
        &pairs,
        addr,
        "Confirm",
        false,
    )
}

#[cfg(test)]
fn display_address(_account_name: Option<&str>, _addr: &str) -> bool {
    true
}

pub fn handle_get_address<'a, 'b>(
    req: &message::RequestGetAddress<'a>,
) -> Result<message::ResponseGetAddress<'b>, &'static str> {
    let wallet_policy: common::bip388::WalletPolicy =
        req.account.as_ref().ok_or("Missing account")?.try_into()?;

    let coords: common::account::WalletPolicyCoordinates = req
        .account_coordinates
        .as_ref()
        .ok_or("Missing coordinates")?
        .try_into()?;

    let address = wallet_policy.get_address(&coords)?;

    let account_name = req.name.as_ref();
    let account_name = if account_name.is_empty() {
        None
    } else {
        Some(account_name)
    };

    if req.display {
        if !display_address(account_name, &address) {
            return Err("Rejected by the user");
        }
    }

    Ok(message::ResponseGetAddress {
        address: Cow::Owned(address),
    })
}

#[cfg(test)]
mod tests {
    use common::account::KeyInformation;

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
