# Ethereum V-App for Vanadium

A minimal Ethereum signing application for the Vanadium VM on Ledger Secure Elements.

## Overview

This V-App provides secure transaction and message signing for Ethereum and EVM-compatible chains. It implements:

- **Transaction signing**: Legacy and EIP-1559 transactions with EIP-155 replay protection
- **Personal message signing**: EIP-191 signed messages
- **EIP-712 typed data signing**: Both pre-hashed and full typed data
- **Metadata provision**: Token info, NFT info, domain names, contract methods

## Security Model

The host environment (PC/phone) is treated as **fully compromised**. The V-App:

- Parses all transaction data inside the secure element
- Never trusts host-provided metadata without verification
- Displays transaction details on the secure screen before signing
- Uses SDK cryptographic primitives (side-channel protected)
- Fails closed on any ambiguity

See `CLAUDE.md` and `docs/` for the full security model.

## Project Structure

```
apps/ethereum/
+-- common/          # Shared types (no_std)
|   +-- src/
|       +-- lib.rs        # Crate root
|       +-- commands.rs   # Command IDs
|       +-- error.rs      # Error codes
|       +-- types.rs      # Core types
|       +-- message.rs    # Request/Response enums
+-- app/             # V-App (riscv + native)
|   +-- src/
|       +-- main.rs       # Entry point
|       +-- handlers/     # Command handlers
|       +-- parsing/      # RLP and TX parsing
|       +-- state.rs      # Session state
|       +-- utils.rs      # Utilities
+-- client/          # Host client (native only)
|   +-- src/
|       +-- lib.rs        # Client library
|       +-- client.rs     # EthereumClient impl
|       +-- main.rs       # CLI
+-- docs/            # Design documentation
+-- CLAUDE.md        # Security model and invariants
```

## Building

### Prerequisites

- Rust with `rustup target add riscv32imc-unknown-none-elf`
- `just` command runner

### Build Commands

```bash
# Build for both native and riscv
cd app && just build

# Build native only (for testing)
cd app && just build-native

# Build riscv only (for deployment)
cd app && just build-riscv

# Run tests
cd app && cargo test
```

## Running

### Native Mode (Development)

```bash
# Terminal 1: Start the V-App
cd app && cargo run

# Terminal 2: Start the client
cd client && cargo run -- --native
```

### Speculos Mode (Emulator)

```bash
# Terminal 1: Start Vanadium VM on Speculos
cd vm && just run-flex

# Terminal 2: Start the client
cd client && cargo run -- --sym
```

## CLI Commands

Once connected, the CLI provides these commands:

```
get_config              # Get app version and settings
get_challenge           # Get random challenge bytes
sign_message            # Sign EIP-191 personal message
  --path=m/44'/60'/0'/0/0
  --message="Hello"
sign_tx                 # Sign transaction
  --path=m/44'/60'/0'/0/0
  --tx_hex=0xf86c...
sign_eip712             # Sign pre-hashed EIP-712
  --path=m/44'/60'/0'/0/0
  --domain_hash=0x...
  --message_hash=0x...
provide_token           # Provide ERC-20 token info
  --chain_id=1
  --address=0x...
  --ticker=USDC
  --decimals=6
set_context             # Set metadata context
  --chain_id=1
  --address=0x...
exit                    # Exit the CLI
```

## Implemented Commands

| Command | Status | Description |
|---------|--------|-------------|
| GET_APP_CONFIGURATION | Done | Version and settings |
| GET_CHALLENGE | Done | Random bytes for replay protection |
| SIGN_TRANSACTION | Done | Legacy/EIP-1559 signing |
| SIGN_PERSONAL_MESSAGE | Done | EIP-191 message signing |
| SIGN_EIP712_HASHED | Done | Pre-hashed EIP-712 |
| SIGN_EIP712_MESSAGE | Partial | Full typed data parsing |
| PROVIDE_ERC20_TOKEN_INFO | Done | Token metadata caching |
| PROVIDE_NFT_INFO | Done | NFT metadata caching |
| PROVIDE_DOMAIN_NAME | Done | Domain resolution caching |
| LOAD_CONTRACT_METHOD_INFO | Done | ABI metadata caching |
| BY_CONTRACT_ADDRESS_AND_CHAIN | Done | Context setting |
| CLEAR_SIGN_TRANSACTION | Partial | Clear signing with metadata |

## Limitations (Minimal Implementation)

This is a minimal implementation. Not yet implemented:

- Full CAL signature verification for metadata
- Complete EIP-712 JSON parsing
- Recovery ID calculation for signatures
- Keccak256 (uses SHA256 placeholder)
- Eth2 BLS signing
- Full clear signing with decoded contract calls
- Chunked message handling for large transactions

## Testing

```bash
# Run unit tests
cd app && cargo test

# Run with autoapprove for integration tests
cd app && cargo test --features autoapprove
```

## Documentation

- `CLAUDE.md` - Security model and invariants
- `docs/architecture.md` - System design
- `docs/protocol.md` - Wire protocol specification
- `docs/commands.md` - Command details
- `docs/metadata-auth.md` - Metadata verification
- `docs/ux-spec.md` - User interface flows

## License

See repository root for license information.
