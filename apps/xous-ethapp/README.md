# Xous Ethereum App (ethapp)

Native Ethereum signing application for Baochip-1x running Xous OS.

## Overview

This is a native implementation of the Ethereum signing app designed to run directly on Xous
as a system service, without the Vanadium VM layer. It provides the same security guarantees
as the Vanadium V-App but leverages Xous's microkernel architecture for process isolation.

**Key Design Principles:**
- Direct Xous service implementation (no VM overhead)
- Message-passing based IPC using standard Xous patterns
- Hardware-backed cryptography via Xous services (TRNG, etc.)
- Secure display via GAM for user confirmations
- PDDB integration for persistent storage

## Architecture

```
+------------------+     Xous IPC      +------------------+
|  Client App      | <--------------> |  EthApp Service  |
|  (ethapp-api)    |                   |  (ethapp)        |
+------------------+                   +------------------+
                                              |
                    +-------------------------+-------------------------+
                    |                         |                         |
              +-----+-----+           +-------+-------+         +-------+-------+
              | TRNG Svc  |           | GAM (Display) |         | PDDB Storage  |
              +-----------+           +---------------+         +---------------+
```

## Crate Structure

- **ethapp/** - Main Xous service implementation
  - Registers as `ethapp.ethereum` server
  - Handles all signing operations
  - Interfaces with TRNG, GAM, PDDB

- **ethapp-api/** - Client library for other Xous processes
  - Provides type-safe API for calling ethapp
  - Handles serialization/deserialization
  - Connection management

- **ethapp-common/** - Shared types (no_std compatible)
  - Message opcodes and types
  - Error definitions
  - Protocol constants

- **ethapp-cli/** - Test CLI client
  - For local testing and demonstration
  - Command-line interface to ethapp

## Security Model

### Threat Model
- **Host is untrusted**: All external input is adversarial
- **Process isolation**: Xous microkernel enforces memory separation
- **Secure display**: GAM provides trusted UI path
- **Key protection**: Private keys never leave service memory

### Security Invariants
1. **INV-1**: No secret-dependent memory access patterns
2. **INV-2**: User sees exactly what they sign on secure display
3. **INV-3**: All metadata must be verified before display
4. **INV-4**: Fail closed on any parsing/validation error
5. **INV-5**: Signatures are low-S normalized (BIP-62/EIP-2)
6. **INV-6**: BIP44 paths validated against Ethereum patterns

## Supported Operations

### Transaction Signing
- `SignTransaction` - Legacy/EIP-1559/EIP-2930 transactions
- `ClearSignTransaction` - With verified metadata display

### Message Signing
- `SignPersonalMessage` - EIP-191 personal_sign
- `SignEip712Hashed` - Pre-hashed EIP-712 (blind signing)
- `SignEip712Message` - Full EIP-712 with type parsing

### Configuration
- `GetAppConfiguration` - Version, feature flags
- `GetChallenge` - Anti-phishing challenge

### Metadata
- `ProvideErc20TokenInfo` - Token metadata
- `ProvideNftInfo` - NFT collection metadata
- `ProvideDomainName` - ENS resolution
- `LoadContractMethodInfo` - ABI/selector info
- `ByContractAddressAndChain` - Context binding

### Eth2 (Optional)
- `Eth2GetPublicKey` - BLS pubkey (if BLS available)
- `Eth2SetWithdrawalIndex` - Configure withdrawal

## Building

### Prerequisites
- Rust toolchain with riscv32imac-unknown-xous-elf target
- Xous build environment (see xous-core documentation)

### Build Commands

```bash
# Build all ethapp crates
cd apps/xous-ethapp
cargo build --target riscv32imac-unknown-xous-elf

# Run tests (host)
cargo test

# Include in Xous image via xtask
cd /path/to/xous-core
cargo xtask baosec --app ethapp
```

### Development Mode

For development, the app can run with an ephemeral test seed:
```bash
# Set development mode flag
export ETHAPP_DEV_MODE=1
```
**WARNING**: Development mode uses an insecure test seed. Never use for real funds.

## Configuration

### Feature Flags
- `blind-signing`: Enable pre-hashed EIP-712 signing (default: off)
- `eth2`: Enable Eth2/BLS operations (requires BLS crate)
- `dev-mode`: Use ephemeral test seed (INSECURE)

### PDDB Keys
- `ethapp.settings`: App configuration
- `ethapp.tokens`: Cached token metadata
- `ethapp.domains`: Cached domain resolutions

## Testing

### Unit Tests
```bash
cargo test
```

### Golden Vectors
Test vectors from ethereum/tests are used to verify:
- RLP encoding/decoding
- Transaction hash computation
- Signature normalization
- EIP-155 v value calculation

### Integration Tests
```bash
# Requires Xous emulator or hardware
cargo test --features xous-tests
```

## License

Apache-2.0 OR MIT

## References

- [Xous Book](https://betrusted.io/xous-book/)
- [Baochip-1x Documentation](https://baochip.github.io/baochip-1x/)
- [EIP-155](https://eips.ethereum.org/EIPS/eip-155) - Replay Attack Protection
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712) - Typed Structured Data
- [EIP-191](https://eips.ethereum.org/EIPS/eip-191) - Signed Data Standard
- [EIP-1559](https://eips.ethereum.org/EIPS/eip-1559) - Fee Market
