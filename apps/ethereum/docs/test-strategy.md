# Ethereum V-App Test Strategy

## Overview

Testing ensures security invariants hold and the V-App correctly implements Ethereum signing operations. Tests span unit, integration, and security-focused approaches.

## Test Categories

### 1. Unit Tests (V-App)
Location: `apps/ethereum/app/src/**/*_test.rs`
Target: Native (`cargo test`)

**Coverage:**
- RLP encoding/decoding
- Transaction parsing (legacy, EIP-2718)
- EIP-712 type hashing
- Address checksum validation
- BIP44 path validation
- Signature normalization (low-S)

### 2. Unit Tests (Client)
Location: `apps/ethereum/client/src/**/*_test.rs`
Target: Native

**Coverage:**
- Protocol framing
- Chunking logic
- Metadata serialization
- Error mapping

### 3. Integration Tests
Location: `apps/ethereum/client/tests/`
Target: Speculos emulator

**Coverage:**
- Full command flows
- Multi-step transactions
- Error handling
- State machine transitions

### 4. Fuzzing
Location: `apps/ethereum/app/fuzz/`
Target: Native (libfuzzer/cargo-fuzz)

**Targets:**
- `fuzz_rlp_decode` - RLP parser
- `fuzz_tx_parse` - Transaction parser
- `fuzz_eip712_parse` - EIP-712 parser
- `fuzz_protocol_message` - Protocol framing

### 5. Golden Vector Tests
Location: `apps/ethereum/app/tests/vectors/`

**Sources:**
- ethereum/tests repository
- EIP reference implementations
- Known transaction hashes from mainnet

## Security Test Cases

### S1: Malformed Input Handling
- Truncated RLP
- Invalid RLP length prefixes
- Oversized fields
- Integer overflow in values
- Invalid UTF-8 in messages

### S2: Signature Verification
- Invalid CAL signatures
- Replayed signatures
- Wrong chain ID in metadata
- Expired metadata

### S3: Path Validation
- Non-hardened paths where hardened expected
- Invalid purpose/coin_type
- Path too deep
- Empty path

### S4: Boundary Conditions
- Max gas price/limit
- Max value (2^256-1)
- Zero value transactions
- Empty data
- Max data size

### S5: State Machine
- Commands in wrong state
- Interrupted chunking
- Timeout handling
- Double signing attempts

## Test Infrastructure

### Speculos Setup
```bash
# Install speculos
pipx install speculos

# Run VM
cd vm && just run-flex

# Run tests
cd apps/ethereum/client
cargo test --features speculos-tests
```

### Native Testing
```bash
cd apps/ethereum/app
cargo test
```

### Fuzzing
```bash
cd apps/ethereum/app
cargo +nightly fuzz run fuzz_rlp_decode
```

## Milestones

| Phase | Scope | Tests |
|-------|-------|-------|
| M1 (Wk 1-2) | Core signing, ETH transfers | Unit tests |
| M2 (Wk 3) | Message signing (EIP-191/712) | Integration |
| M3 (Wk 4-5) | Clear signing, metadata | E2E |
| M4 (Wk 6) | Security hardening | Fuzz, vectors |
| M5 (Wk 7-8) | Polish, docs | Full suite |

## CI/CD

- **Per-commit**: fmt, clippy, native tests
- **Per-PR**: Speculos integration, short fuzz
- **Nightly**: Extended fuzz, full vectors, profiling
