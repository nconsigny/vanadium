# Ethereum V-App - CLAUDE.md

## Overview

The Ethereum V-App provides secure transaction signing and message authentication for Ethereum and EVM-compatible chains. It runs inside the Vanadium VM on Ledger Secure Elements.

**Component Structure:**
- `app/` - V-App code (riscv/no_std) - runs in secure element
- `client/` - Host client (native) - runs on untrusted PC/phone
- `common/` - Shared types (no_std) - protocol definitions

## Threat Model

### Adversary Capabilities
The host is **fully compromised**. Assume the adversary can:
- Craft arbitrary malformed protocol messages
- Replay, delay, reorder, or drop messages
- Observe timing and memory access patterns (which pages accessed)
- Provide fake metadata (token info, domain names, contract ABIs)
- Phish users with misleading display data

### Assets to Protect
1. **Private keys** - MUST never leave SE, never in host memory
2. **Signature integrity** - User MUST see exactly what they sign
3. **Address derivation** - Correct BIP44/EIP-2333 paths only
4. **User intent** - Display MUST match signed payload

### Trust Boundaries
```
+------------------+     UNTRUSTED      +------------------+
|   Host Client    | <-- boundary -->   |  V-App in SE     |
|   (compromised)  |                    |  (trusted)       |
+------------------+                    +------------------+
        |                                       |
        v                                       v
  User's PC/phone                      Ledger device screen
  (untrusted)                          (trusted display)
```

## Security Invariants (MUST HOLD)

### INV-1: No Secret-Dependent Memory Access
All cryptographic operations MUST use constant-time algorithms with fixed memory access patterns. The host observes page access.

### INV-2: All Metadata Cryptographically Authenticated
Token info, NFT info, domain names, contract methods - ALL must be verified against a trusted signature (e.g., Ledger's CAL) before display.

### INV-3: User Sees What They Sign
The secure display MUST show the actual transaction/message content. If parsing fails or metadata unavailable, either:
- Refuse to sign, OR
- Show "blind signing" warning with raw data hash

### INV-4: Fail Closed
On any parsing error, validation failure, or unexpected state: REJECT. Never sign ambiguous data.

### INV-5: Signature Normalization
All ECDSA signatures MUST be low-S normalized per BIP-62/EIP-2. Recovery ID (v) MUST follow EIP-155 for transactions.

### INV-6: Path Validation
BIP44 paths must match expected Ethereum patterns. Reject unusual derivation paths unless user explicitly approves.

## API Surface Summary

### Transaction Signing
- `signTransaction` - Legacy/EIP-2718 transactions
- `clearSignTransaction` - With full metadata parsing

### Message Signing
- `signPersonalMessage` - EIP-191 personal_sign
- `signEIP712HashedMessage` - Pre-hashed EIP-712
- `signEIP712Message` - Full EIP-712 with type parsing

### Key Operations
- `getAppConfiguration` - Version, settings
- `getChallenge` - Anti-phishing challenge
- `eth2GetPublicKey` - BLS pubkey for staking
- `eth2SetWithdrawalIndex` - Configure withdrawal

### Metadata Provision (host provides, V-App verifies)
- `provideERC20TokenInformation` - Verified token metadata
- `provideNFTInformation` - Verified NFT metadata
- `provideDomainName` - ENS/verified domain resolution
- `loadInfosForContractMethod` - Verified ABI/selector info
- `byContractAddressAndChainId` - Context binding

## Documentation Map
- `docs/ethereum/architecture.md` - Data flow, crypto locations
- `docs/ethereum/protocol.md` - Wire protocol specification
- `docs/ethereum/commands.md` - Command-by-command details
- `docs/ethereum/metadata-auth.md` - Metadata verification model
- `docs/ethereum/ux-spec.md` - Required display screens
- `docs/ethereum/test-strategy.md` - Testing approach
