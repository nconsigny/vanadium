This is the Bitcoin application for Vanadium. It (will be) a next-generation application that generalizes the functionality of the [Ledger Bitcoin application](https://github.com/LedgerHQ/app-bitcoin-new) with more general signing flows, and advanced use cases.

It is also based around the [PSBT standard](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki), but fully implements the signing model based on _accounts_, represented initially with [BIP-388 wallet policies](https://github.com/bitcoin/bips/blob/master/bip-0388.mediawiki) - more account types (like [silent payment addresses](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)) maybe be added in the future.

In the future, experimenting with features like _signed addresses_, _known contacts_, _identity_, etc is planned, in order to further enhance the UX and avoid users from having to manually check addresses whenever possible.

# Commands

This is a draft of the specs of the app.

## `get_master_fingerprint`

**Inputs:** Nothing.\
**Outputs:** The fingerprint of the fingerprint of the master public key as defined in [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki).

No interaction with the user is required.

## `get_extended pubkey`
**Inputs:** A BIP-32 derivation path, and a boolean `display` parameter.\
**Outputs:** The [serialized extended public key](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format) as a 78-byte array for the given derivation path.

If `display == True`, the public key, encoded in base58check, is displayed to the user for confirmation, and the command returns only after the user approves.

TBD: What paths should allow `display == False`?

## `register_account`

**Inputs:** The account name and description.\
**Outputs:** The *Proof-of-Registration* of the account.

Shows an account for inspection to the user; after confirmation, it returns the hmac Registers a new account with a name.

*Remark*: this is similar to the `REGISTER_WALLET` command of the Ledger Bitcoin app. The proof of registration allows to recognize in the future that this account was registered with the chosen name.

*Remark*: we want to allow registering *external* accounts (for which the device is not a cosigner), in order to enable recognizing their addresses among the outputs during `sign_psbt` even if not spending from them in the inputs.


## `get_address`

**Inputs:** The account name and description; the coordinates of the specific address; a boolean `display` parameter.
**Outputs:** The address of the account. (other optional result based on the account type.)

Initially, only BIP-388 wallet policies are supported as accounts; the coordinates are `(is_change: bool, address_index: 0..2**31-1)`.

## `sign_psbt`

**Inputs:** A psbt filled with all the necessary information to sign the transaction.
**Outputs:** Partial signatures (or any other object the signer intends to add to the psbt).

Processes (and, if appropriate, signs) a PSBT, after validating the action with the user.

The transaction is analyzed in an account-centric manner: for each of the affected accounts in the inputs, shows how much money is spent/received in total.

Account info and coordinates can also be used to identify external outputs belonging to known accounts (allowing the user to validate the destination account, rather than the actual address).

*Remark*: The Ledger bitcoin app also takes the `wallet_policy` (and its *Proof-of-Registration* if needed). Instead, here we well include the account information, and the coordinates, in the PSBT (for each affected input/output of the transaction).
