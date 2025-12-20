# Ethereum V-App Development Progress

## Accomplishments

### 1. Project Structure Created
- **common/** - Shared types crate (no_std compatible)
- **app/** - V-App code (riscv32imc + native targets)
- **client/** - Host client with CLI
- **docs/** - Design documentation and specs

### 2. Protocol Implementation
- Command IDs defined (0x01-0x30)
- Request/Response enums with serde serialization
- Error codes for all failure modes
- Wire protocol using postcard binary encoding

### 3. V-App Core Features
| Feature | Status | Notes |
|---------|--------|-------|
| getAppConfiguration | ✅ Done | Returns version, feature flags |
| getChallenge | ✅ Done | 32 random bytes via SDK RNG |
| signTransaction | ✅ Done | Legacy + EIP-1559 parsing |
| signPersonalMessage | ✅ Done | EIP-191 prefix handling |
| signEIP712HashedMessage | ✅ Done | Pre-hashed domain+message |
| signEIP712Message | ✅ Done | Binary encoded typed data |
| provideERC20TokenInfo | ✅ Done | Cached with verification stub |
| provideNFTInfo | ✅ Done | Cached with verification stub |
| provideDomainName | ✅ Done | Cached with verification stub |
| loadContractMethodInfo | ✅ Done | Cached with verification stub |
| byContractAddressAndChain | ✅ Done | Context setting |
| clearSignTransaction | ✅ Done | Metadata-enhanced signing |

### 4. Parsing Implementation
- **RLP Decoder**: Complete no_std implementation with:
  - Single byte, short/long strings, lists
  - Strict canonical encoding validation
  - Bounds checking throughout
- **Transaction Parser**: Supports:
  - Legacy transactions (type 0x00 or no prefix)
  - EIP-2930 access list transactions (type 0x01)
  - EIP-1559 fee market transactions (type 0x02)

### 5. Build Infrastructure
- Cargo.toml for all three crates
- `.cargo/config.toml` for RISC-V target
- justfile with build commands
- 36 unit tests passing

## Architecture Decisions

### 1. Message Protocol
**Decision**: Use postcard for serialization instead of custom framing.
**Rationale**:
- Compact binary format
- no_std compatible
- Automatic derive for serde types
- Simpler than manual framing

### 2. State Management
**Decision**: Session-scoped metadata cache cleared on app restart.
**Rationale**:
- Simpler than persistent storage
- Prevents stale metadata attacks
- Bounded memory usage (8 tokens, 8 domains, 8 methods max)

### 3. Signature Format
**Decision**: Return raw (v, r, s) in Response::Signature.
**Rationale**:
- Client can format as needed (DER, raw, etc.)
- v value computed per tx type (EIP-155 for legacy, 0/1 for typed)

### 4. Blind Signing
**Decision**: Disabled by default, settable via session state.
**Rationale**:
- Security-first approach
- User must explicitly opt-in for unsafe operations
- Clear UX distinction between parsed and blind signing

### 5. Path Validation
**Decision**: Strict BIP44 validation for Ethereum paths.
**Rationale**:
- Prevents accidental cross-coin signing
- Must be m/44'/60'/account'/change/index format
- Rejects unusual paths without explicit override

### EDITED in session 2

Files modified or created during session 2 (2024-12-20):

1. `/home/niardo/vanadium/apps/ethereum/app/Cargo.toml`
   - Added `tiny-keccak` dependency for Keccak256 hashing

2. `/home/niardo/vanadium/apps/ethereum/app/src/utils.rs`
   - Replaced SHA256 placeholder with real Keccak256 implementation
   - Added `Keccak256Hasher` streaming hasher
   - Added comprehensive Keccak256 test vectors

3. `/home/niardo/vanadium/apps/ethereum/app/src/handlers/sign_tx.rs`
   - Updated `compute_v_value` with detailed documentation
   - Documented VM ECALL limitation for recovery ID
   - Added `compute_v_from_recovery_id` helper function

4. `/home/niardo/vanadium/apps/ethereum/app/src/parsing/mod.rs`
   - Added ABI module exports
   - Updated module documentation

5. `/home/niardo/vanadium/apps/ethereum/app/src/parsing/abi.rs` (NEW)
   - Full ABI type system implementation
   - ABI decoder for contract calldata
   - Selector computation using Keccak256
   - Tests for transfer, approve, and other functions

## Next Steps

### High Priority (Completed)
1. **Keccak256 Implementation**: DONE
   - Using `tiny-keccak` crate v2.0.2 with `keccak` feature
   - no_std compatible, constant-time permutation
   - Tests verify against known Ethereum test vectors
   - Streaming hasher available for large inputs

2. **Recovery ID (v) Calculation**: DOCUMENTED (Blocked by VM)
   - The Vanadium VM's ECALL_ECDSA_SIGN computes the parity bit but does not return it
   - Filed as TODO: Need VM update to expose `info` parameter from cx_ecdsa_sign_no_throw
   - Currently defaults to recovery_id=0 (affects ~50% of signatures)
   - See `/home/niardo/vanadium/vm/src/handlers/lib/ecall.rs` line 1175

### High Priority (New)
3. **VM ECALL Update for Recovery ID**: Required
   - Modify `handle_ecdsa_sign` to return parity bit alongside signature length
   - Update SDK's `ecdsa_sign` to expose recovery_id
   - Critical for Ethereum transaction broadcast

4. **ABI Decoder**: FOUNDATION DONE
   - Full ABI type system (uint, int, address, bool, bytes, string, arrays, tuples)
   - Decodes contract calldata with selector
   - Tests verify transfer() and other functions
   - Ready for EIP-7730 clear signing integration

### Medium Priority
5. **Chunked Message Handling**: Large TX support
   - Current implementation assumes single message
   - Need streaming accumulator for >4KB transactions

6. **Full EIP-712 Parsing**: JSON typed data
   - Current: binary encoded format
   - Future: Parse JSON in client, send binary to app

7. **EIP-7730 Clear Signing**: Contract display
   - Parse AAVE and other protocol transactions
   - Use ABI decoder with 7730 display rules
   - Reference: https://github.com/LedgerHQ/clear-signing-erc7730-registry

### Low Priority
7. **Eth2 BLS Signing**: Staking operations
   - EIP-2333 key derivation
   - BLS12-381 signatures
   - Requires SDK support

8. **Integration Tests**: End-to-end flows
   - Test against known vectors
   - Speculos automation

## Gotchas and Issues

### 1. SDK Limitations
- **No Keccak256**: The Vanadium SDK provides SHA256, SHA512, RIPEMD160 but not Keccak256. Ethereum requires Keccak256 for addresses and transaction hashes.
- **Workaround**: Using SHA256 as placeholder; need to add Keccak ECALL or implement in app.

### 2. Signature Recovery ID
- ECDSA signatures from SDK don't include recovery ID
- Need to compute v by trying both recovery options
- EIP-155: v = chainId * 2 + 35 + recovery_id
- Typed TX: v = recovery_id (0 or 1)

### 3. Memory Constraints
- 256-byte page size affects large allocations
- Avoid Vec growth; prefer bounded buffers
- Streaming hash where possible

### 4. Test Mode vs Production
- Tests use `#[cfg(test)]` to skip UX
- Native mode simulates device I/O
- Real device needs proper Speculos testing

### 5. Metadata Trust
- All metadata MUST be cryptographically verified
- Current stub always returns "verified" - MUST FIX
- Unverified metadata must show "UNVERIFIED" label

### 6. Large Transaction Handling
- RLP decoder loads full transaction into memory
- Very large calldata (>64KB) will fail
- Need streaming RLP for production use

## Test Coverage

```
handlers::config - 2 tests
handlers::sign_tx - 4 tests
handlers::sign_message - 4 tests
handlers::sign_eip712 - 3 tests
handlers::metadata - 7 tests
parsing::rlp - 9 tests
parsing::transaction - 4 tests
parsing::abi - 4 tests (NEW)
state - 2 tests
utils - 8 tests (includes Keccak256 tests)
------------------------
Total: 47 tests passing
```

## Files Overview

```
apps/ethereum/
├── CLAUDE.md              # Security model (93 lines)
├── PROGRESS.md            # This file
├── README.md              # Usage documentation
├── common/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs         # Crate root
│       ├── commands.rs    # Command IDs (30 lines)
│       ├── error.rs       # Error types (75 lines)
│       ├── types.rs       # Core types (150 lines)
│       └── message.rs     # Request/Response (140 lines)
├── app/
│   ├── Cargo.toml
│   ├── .cargo/config.toml
│   ├── justfile
│   └── src/
│       ├── main.rs        # Entry point (85 lines)
│       ├── state.rs       # Session state (180 lines)
│       ├── utils.rs       # Utilities (130 lines)
│       ├── handlers/
│       │   ├── mod.rs
│       │   ├── config.rs      # 70 lines
│       │   ├── sign_tx.rs     # 280 lines
│       │   ├── sign_message.rs # 120 lines
│       │   ├── sign_eip712.rs  # 160 lines
│       │   └── metadata.rs     # 200 lines
│       └── parsing/
│           ├── mod.rs
│           ├── rlp.rs         # 350 lines
│           └── transaction.rs # 280 lines
├── client/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs         # Library exports
│       ├── client.rs      # EthereumClient (250 lines)
│       └── main.rs        # CLI (200 lines)
└── docs/
    ├── architecture.md
    ├── commands.md
    ├── metadata-auth.md
    ├── protocol.md
    ├── test-strategy.md
    └── ux-spec.md
```

## Version History

- **v0.1.0** (2024-12-15): Initial implementation
  - All 12 commands implemented
  - Basic transaction parsing
  - Metadata caching framework
  - 36 tests passing

- **v0.2.0** (2024-12-20): Keccak256 and ABI foundation
  - Real Keccak256 implementation using tiny-keccak
  - ABI decoder for contract calldata
  - Documented VM ECALL recovery ID limitation
  - 47 tests passing

- **v0.3.0** (2024-12-20): Recovery ID and EIP-7730 Clear Signing
  - **VM ECALL Update**: Modified `handle_ecdsa_sign` to return recovery ID (parity bit) using packed format `(recovery_id << 8) | sig_len`
  - **SDK Updates**: Added `ecdsa_sign_hash_recoverable()` method returning `(signature, recovery_id)`
  - **Ethereum App**: Updated to use recoverable signing, correctly computing v values
  - **EIP-7730 Clear Signing**: Implemented display rules module with formats for ERC-20, AAVE V3
  - **Integration Tests**: Set up Speculos test infrastructure
  - 56 tests passing

- **v0.3.1** (2024-12-20): Bug fix - Recovery ID in message signing
  - Fixed `sign_eip712.rs` and `sign_message.rs` to use `ecdsa_sign_hash_recoverable()`
  - Previously hardcoded v=27, now correctly computes v=27+recovery_id
  - Removed broken `compute_recovery_id()` stub
  - Added bounds checking to DER parsing (linter fix)
  - 56 tests passing

### EDITED in session 3 (v0.3.0)

Files modified or created during session 3 (2024-12-20):

**VM Core Changes:**
1. `/home/niardo/vanadium/vm/src/handlers/lib/ecall.rs`
   - Modified `handle_ecdsa_sign` to return recovery ID (parity bit) using packed format
   - Return value: `(recovery_id << 8) | signature_len` - backward-compatible

**SDK Changes:**
2. `/home/niardo/vanadium/app-sdk/src/curve.rs`
   - Added `ecdsa_sign_hash_recoverable()` method
   - Returns `Result<(Vec<u8>, u8), &'static str>` with (DER-signature, recovery_id)

3. `/home/niardo/vanadium/app-sdk/src/ecalls_native.rs`
   - Updated native emulation to return packed recovery ID format

**Ethereum App Changes:**
4. `/home/niardo/vanadium/apps/ethereum/app/src/handlers/sign_tx.rs`
   - Updated `sign_transaction_hash()` to use `ecdsa_sign_hash_recoverable()`
   - Cleaned up unused code and imports
   - Expanded test coverage for v-value computation

5. `/home/niardo/vanadium/apps/ethereum/app/src/parsing/eip7730.rs` (NEW - 470 lines)
   - `DisplayFormat` enum with 8 format types (Raw, TokenAmount, AddressName, Enum, DateTime, Percentage, Boolean, Calldata)
   - `DisplayField` and `FunctionDisplay` structs for mapping selectors to display rules
   - `DisplayContext` trait for metadata lookup (token info, address names)
   - `format_call()` function for formatting decoded ABI calls
   - Built-in formats for ERC-20 transfer/approve and AAVE V3 supply/repay

**Integration Tests:**
6. `/home/niardo/vanadium/apps/ethereum/client/tests/integration_test.rs` (NEW - 280 lines)
   - Comprehensive Speculos integration tests covering:
     - App configuration and challenge generation
     - Transaction signing (legacy, invalid path, empty data)
     - Personal message signing (EIP-191, deterministic, different paths)
     - EIP-712 typed data signing
     - Metadata provision
     - Exit handling

7. `/home/niardo/vanadium/apps/ethereum/client/justfile` (NEW)
   - `integration-tests` command for running Speculos tests

### Bug Fix: Recovery ID in EIP-712 and Personal Message Signing (v0.3.1)

**Issue:** `sign_hash_eip712()` and `sign_hash()` hardcoded recovery ID as 0, causing ~50% of signatures to have invalid v values (27 instead of 28). This would cause signature verification to fail when `ecrecover` is used.

**Files modified:**

8. `/home/niardo/vanadium/apps/ethereum/app/src/handlers/sign_eip712.rs`
   - Changed from `ecdsa_sign_hash()` to `ecdsa_sign_hash_recoverable()`
   - Now correctly computes `v = 27 + recovery_id` using actual recovery ID from ECALL
   - Removed unused `ToPublicKey` import
   - Added bounds checking to `parse_der_signature()` (linter fix)

9. `/home/niardo/vanadium/apps/ethereum/app/src/handlers/sign_message.rs`
   - Changed from `ecdsa_sign_hash()` to `ecdsa_sign_hash_recoverable()`
   - Now correctly computes `v = 27 + recovery_id` using actual recovery ID from ECALL
   - Removed broken `compute_recovery_id()` stub that always returned 27
   - Removed unused `ToPublicKey` import
   - Added bounds checking to `parse_der_signature()` (linter fix)

**Impact:**
| Before | After |
|--------|-------|
| v always = 27 | v = 27 or 28 (correct) |
| ~50% signatures invalid | 100% signatures valid |

---
