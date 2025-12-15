# Ethereum V-App Commands

## Configuration Commands

### GET_APP_CONFIGURATION (0x01)
Returns app version and settings.

**Input:** None
**Output:** `{ version: [u8;3], blind_signing: bool, eip712_filtering: bool }`
**State:** IDLE -> IDLE
**UX:** None
**Security:** None

### GET_CHALLENGE (0x02)
Returns random challenge for replay protection.

**Input:** None
**Output:** `{ challenge: [u8;32] }`
**State:** IDLE -> IDLE
**UX:** None
**Security:** Challenge valid for single use

## Transaction Signing

### SIGN_TRANSACTION (0x03)
Signs legacy or EIP-2718 typed transaction.

**Input:** `{ path: [u32], tx_data: bytes }` (chunked)
**Output:** `{ v: u8, r: [u8;32], s: [u8;32] }`
**State:** IDLE -> RECEIVING_TX -> AWAITING_CONFIRM -> IDLE
**UX:** Display recipient, value, gas, data summary
**Security:**
- Validate BIP44 path
- Parse and validate TX structure
- Low-S normalization
- EIP-155 v value

### CLEAR_SIGN_TRANSACTION (0x30)
Signs transaction with full metadata parsing.

**Input:** `{ path: [u32], tx_data: bytes, context: bytes }` (chunked)
**Output:** `{ v: u8, r: [u8;32], s: [u8;32] }`
**State:** Same as SIGN_TRANSACTION
**UX:** Display decoded contract call (requires prior metadata)
**Security:** Requires metadata for known contracts; blind-sign fallback

## Message Signing

### SIGN_PERSONAL_MESSAGE (0x04)
Signs EIP-191 personal message.

**Input:** `{ path: [u32], message: bytes }` (chunked)
**Output:** `{ v: u8, r: [u8;32], s: [u8;32] }`
**State:** IDLE -> AWAITING_CONFIRM -> IDLE
**UX:** Display message (truncate if too long, show length)
**Security:**
- Prefix with "\x19Ethereum Signed Message:\n{len}"
- Show raw hex if non-printable

### SIGN_EIP712_HASHED (0x05)
Signs pre-hashed EIP-712 data.

**Input:** `{ path: [u32], domain_hash: [u8;32], message_hash: [u8;32] }`
**Output:** `{ v: u8, r: [u8;32], s: [u8;32] }`
**State:** IDLE -> AWAITING_CONFIRM -> IDLE
**UX:** Display domain hash and message hash (blind signing)
**Security:** Requires blind-signing enabled

### SIGN_EIP712_MESSAGE (0x06)
Signs full EIP-712 typed data.

**Input:** `{ path: [u32], typed_data: bytes }` (chunked JSON or encoded)
**Output:** `{ v: u8, r: [u8;32], s: [u8;32] }`
**State:** IDLE -> RECEIVING -> AWAITING_CONFIRM -> IDLE
**UX:** Display domain name, type, key fields
**Security:**
- Parse and validate type structure
- Display human-readable field values
- Reject malformed types

## Eth2 Staking Commands

### ETH2_GET_PUBLIC_KEY (0x10)
Returns BLS public key for validator.

**Input:** `{ path: [u32] }`
**Output:** `{ pubkey: [u8;48] }`
**State:** IDLE -> IDLE
**UX:** Display path, optionally pubkey
**Security:** Validate EIP-2334 path format

### ETH2_SET_WITHDRAWAL_INDEX (0x11)
Configures withdrawal credential index.

**Input:** `{ index: u32 }`
**Output:** `{ success: bool }`
**State:** IDLE -> AWAITING_CONFIRM -> IDLE
**UX:** Display withdrawal index being set
**Security:** Requires user confirmation

## Metadata Provision

### PROVIDE_ERC20_TOKEN_INFO (0x20)
Provides verified token metadata.

**Input:** `{ chain_id: u64, address: [u8;20], ticker: string, decimals: u8, signature: bytes }`
**Output:** `{ accepted: bool }`
**State:** IDLE -> IDLE
**UX:** None
**Security:** Verify CAL signature, cache if valid

### PROVIDE_NFT_INFO (0x21)
Provides verified NFT collection metadata.

**Input:** `{ chain_id: u64, address: [u8;20], name: string, signature: bytes }`
**Output:** `{ accepted: bool }`
**State:** IDLE -> IDLE
**UX:** None
**Security:** Verify CAL signature

### PROVIDE_DOMAIN_NAME (0x22)
Provides verified domain resolution.

**Input:** `{ address: [u8;20], domain: string, signature: bytes }`
**Output:** `{ accepted: bool }`
**State:** IDLE -> IDLE
**UX:** None
**Security:** Verify domain resolution signature

### LOAD_CONTRACT_METHOD_INFO (0x23)
Provides verified contract ABI info.

**Input:** `{ chain_id: u64, address: [u8;20], selector: [u8;4], abi: bytes, signature: bytes }`
**Output:** `{ accepted: bool }`
**State:** IDLE -> IDLE
**UX:** None
**Security:** Verify CAL signature

### BY_CONTRACT_ADDRESS_AND_CHAIN (0x24)
Context binding for subsequent commands.

**Input:** `{ chain_id: u64, address: [u8;20] }`
**Output:** `{ bound: bool }`
**State:** IDLE -> IDLE
**UX:** None
**Security:** Sets context for metadata lookup
