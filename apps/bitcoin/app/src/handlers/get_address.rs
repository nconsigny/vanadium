use common::{account::Account, bip388, message::Response};

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

pub fn handle_get_address(
    name: Option<&str>,
    account: &common::message::Account,
    _hmac: Option<&[u8; 32]>,
    coordinates: &common::message::AccountCoordinates,
    display: bool,
) -> Result<Response, &'static str> {
    // TODO: check hmac if appropriate

    let wallet_policy: bip388::WalletPolicy = account.try_into()?;
    let common::message::AccountCoordinates::WalletPolicy(coordinates) = coordinates;
    let address = wallet_policy.get_address(&common::account::WalletPolicyCoordinates {
        is_change: coordinates.is_change,
        address_index: coordinates.address_index,
    })?;

    if display {
        if !display_address(name, &address) {
            return Err("Rejected by the user");
        }
    }

    Ok(Response::Address(address))
}

#[cfg(test)]
mod tests {
    use common::{account::KeyInformation, message};

    use super::*;

    fn ki(key_info_str: &str) -> message::PubkeyInfo {
        let info = KeyInformation::try_from(key_info_str).unwrap();

        let origin = info.origin_info.map(|info| message::KeyOrigin {
            fingerprint: info.fingerprint,
            path: message::Bip32Path(
                info.derivation_path
                    .iter()
                    .map(|step| u32::from(*step))
                    .collect(),
            ),
        });

        message::PubkeyInfo {
            pubkey: info.pubkey.encode().to_vec(),
            origin,
        }
    }

    #[test]
    fn test_get_address_singlesig_wit() {
        let account = message::Account::WalletPolicy(message::WalletPolicy {
            template: "wpkh(@0/**)".into(),
            keys_info: vec![ki(
                "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P",
            )],
        });

        let resp = handle_get_address(
            None,
            &account,
            None,
            &message::AccountCoordinates::WalletPolicy(message::WalletPolicyCoordinates {
                is_change: false,
                address_index: 0,
            }),
            false,
        )
        .unwrap();

        assert_eq!(
            resp,
            Response::Address("tb1qzdr7s2sr0dwmkwx033r4nujzk86u0cy6fmzfjk".into())
        );
    }
}
