# Ethereum Client (client/) - CLAUDE.md

## Purpose

The client runs on the host machine (PC/phone). It handles:
- Communication with the V-App via `vanadium-client-sdk`
- Protocol framing and chunking
- Metadata fetching and caching
- Integration with dApps/wallets

**SECURITY NOTE:** This code runs in an UNTRUSTED environment. It provides convenience, not security. All security-critical verification happens in the V-App.

## Build Configuration

**Target:** Native only (not no_std)

**Dependencies:**
- `vanadium-client-sdk` - Transport layer
- `vnd-ethereum-common` - Shared types
- `tokio` or similar for async (optional)

**Build:** `cargo build` / `cargo run`

## Responsibilities

### Protocol Framing
- Serialize commands per wire protocol spec
- Handle chunking for large payloads (transactions, EIP-712 data)
- Manage request/response correlation
- Implement timeouts

### Metadata Services
The client fetches and provides metadata to help the V-App display human-readable information:
- ERC-20 token info (symbol, decimals)
- NFT collection info
- ENS/domain resolution
- Contract method signatures

**CRITICAL:** Client provides metadata, but V-App verifies signatures. Client cannot forge trusted metadata.

### Caching Rules
Metadata can be cached locally for performance:
```
cache/
  tokens/{chainId}/{address}.json
  nfts/{chainId}/{address}.json
  domains/{name}.json
  methods/{selector}.json
```

**Cache invalidation:**
- TTL-based (e.g., 24 hours for token info)
- Version-based (CAL version changes)
- User can force refresh

### Error Handling
- Map V-App errors to user-friendly messages
- Retry transient failures (transport errors)
- Never retry security rejections

## Integration Points

### Transport Layer
```rust
use vanadium_client_sdk::{Client, Transport};

// Connect to device
let client = Client::new(transport).await?;

// Send command, receive response
let response = client.exchange(&request).await?;
```

### Speculos Testing
```rust
#[cfg(feature = "speculos-tests")]
// Tests run against Speculos emulator
```

### dApp Integration
The client exposes a clean API for wallet integrations:
```rust
pub async fn sign_transaction(&self, tx: &Transaction) -> Result<Signature>;
pub async fn sign_message(&self, msg: &[u8]) -> Result<Signature>;
pub async fn get_address(&self, path: &DerivationPath) -> Result<Address>;
```

## Chunking Protocol

Large payloads must be chunked due to APDU size limits:

```
Total payload > MAX_CHUNK_SIZE:
  1. Send first chunk with FIRST flag
  2. Send middle chunks with CONTINUE flag
  3. Send final chunk with LAST flag
  V-App streams and processes incrementally
```

Chunk metadata includes:
- Sequence number
- Total expected length (in first chunk)
- Continuation flag

## Metadata Authentication Flow

1. Client fetches metadata from Ledger CAL or trusted source
2. Client sends `provide*` command with metadata + signature
3. V-App verifies signature against embedded public key
4. V-App stores verified metadata for current session
5. V-App uses metadata when displaying transaction

```
Client                          V-App
  |                               |
  |-- provideERC20TokenInfo ---->|
  |   (data + CAL signature)     |
  |                               |-- verify signature
  |                               |-- if valid, cache for session
  |<-- OK --------------------   |
  |                               |
  |-- signTransaction ---------->|
  |                               |-- lookup cached token info
  |                               |-- display "Send 1.5 USDC"
```

## Testing

- Unit: `cargo test`
- Integration: `just integration-tests` (requires Speculos)
- Manual: Start VM (`cd ../../vm && just run-flex`), then `cargo run`

## Security Reminders

- Never trust client-side validation alone
- Metadata signatures are mandatory
- Never log secrets or sensitive data
- Implement proper timeout handling
