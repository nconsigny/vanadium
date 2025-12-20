# Ethereum V-App Architecture

## Overview

The Ethereum V-App enables secure transaction and message signing for Ethereum and EVM chains within the Vanadium environment.

## System Components

```
+------------------+                    +------------------+
|   dApp/Wallet    |                    |   Metadata       |
|   (web3, ethers) |                    |   Services       |
+--------+---------+                    |   (ENS)          |
         |                              +--------+---------+
         v                                       |
+------------------+                             |
|  Ethereum Client |<----------------------------+
|  (native, std)   |
+--------+---------+
         | APDU-like protocol
         v
+------------------+     Merkle proofs     +------------------+
|  Vanadium VM     |<--------------------->|  Page Storage    |
|  (ARM, SE)       |                       |  (encrypted)     |
+--------+---------+                       +------------------+
         |
         v
+------------------+
|  Ethereum V-App  |
|  (riscv, no_std) |
+------------------+
         |
         v
+------------------+
|  Secure Display  |
|  (device screen) |
+------------------+
```

## Data Flow: Transaction Signing

1. **dApp** constructs transaction, sends to client
2. **Client** fetches relevant metadata (token info, domain names)
3. **Client** sends `provide*` commands with metadata + signatures
4. **V-App** verifies metadata signatures, caches valid entries
5. **Client** sends `signTransaction` with chunked TX data
6. **V-App** parses TX, looks up cached metadata
7. **V-App** displays transaction details on secure screen
8. **User** reviews and confirms/rejects
9. **V-App** derives key, signs transaction hash
10. **V-App** returns signature to client
11. **Client** returns signature to dApp

## Cryptographic Operations Location

| Operation | Location | Rationale |
|-----------|----------|-----------|
| Key derivation (BIP32/44) | V-App via ECALL | Keys never leave SE |
| ECDSA signing | V-App via ECALL | Side-channel protected |
| BLS signing (eth2) | V-App via ECALL | Side-channel protected |
| Keccak256 hashing | V-App | Needed for address/tx hash |
| RLP encoding/decoding | V-App | Security-critical parsing |
| Metadata signature verify | V-App | Trust establishment |
| Address checksum | V-App | Display correctness |

## Memory Model

### V-App Memory Constraints
- All RAM is outsourced in 256-byte pages
- Pages are Merkle-tree authenticated
- Pages are encrypted before leaving SE
- Host observes page access pattern (NOT content)

### Implications for Design
- Avoid large contiguous allocations
- Stream-process large inputs
- Fixed-size buffers where possible
- No secret-dependent memory access

## Session State

### Per-Session State (in V-App)
- Cached verified metadata (tokens, domains, methods)
- Current command state machine
- Pending transaction context (during signing)

### Persistent State (via ECALL)
- Device seed (managed by OS)
- App registration HMAC
- User preferences (blind-sign setting)

## Caching Strategy

### Client-Side Cache (untrusted)
- Can be stale or tampered
- Performance optimization only

### V-App Session Cache (trusted after verification)
- Verified token info: `Map<(chainId, address), TokenInfo>`
- Verified domain names: `Map<address, DomainName>`
- Verified method info: `Map<selector, MethodInfo>`
- Cleared on app exit or explicit reset

## Chain Support

### Native Support
- Ethereum mainnet (chainId 1)
- Standard EVM semantics

### Generic EVM Support
- Any chain with valid chainId
- EIP-155 replay protection

## Error Propagation

```
V-App Error -> Protocol Error Code -> Client Exception -> dApp Error
```

Error categories:
- `REJECTED` - User declined
- `INVALID_DATA` - Malformed input
- `SECURITY_VIOLATION` - Failed verification
- `UNSUPPORTED` - Unknown command/feature
- `INTERNAL` - Unexpected V-App state
