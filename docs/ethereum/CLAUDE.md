# Ethereum Documentation - CLAUDE.md

## Purpose

This directory contains design documentation for the Ethereum V-App. These are specifications and design documents, NOT implementation code.

## Document Organization

| Document | Purpose | Read When |
|----------|---------|-----------|
| `architecture.md` | System overview, data flow, trust boundaries | Starting design work |
| `protocol.md` | Wire protocol specification | Implementing transport |
| `commands.md` | Command-by-command specification | Implementing handlers |
| `metadata-auth.md` | Metadata verification model | Working with tokens/NFTs/domains |
| `ux-spec.md` | Required user interface flows | Implementing display logic |
| `test-strategy.md` | Testing approach and milestones | Planning QA |

## Reading Order

1. **Start with `architecture.md`** - Understand the big picture
2. **Review `protocol.md`** - Understand communication model
3. **Check `commands.md`** for specific command - Implementation details
4. **Consult `metadata-auth.md`** - When handling any `provide*` command
5. **Follow `ux-spec.md`** - When implementing any user-facing flow
6. **Plan with `test-strategy.md`** - Before marking work complete

## Cross-References

### To App Code
- `apps/ethereum/app/CLAUDE.md` - V-App implementation rules
- `apps/ethereum/client/CLAUDE.md` - Client implementation rules
- `apps/ethereum/CLAUDE.md` - Threat model and invariants

### To Vanadium Core
- `docs/security.md` - Vanadium security model (CRITICAL)
- `docs/ecalls.md` - Available system calls
- `app-sdk/src/ecalls.rs` - ECALL interface

## Design Principles

These documents follow key principles:

### Security-First
Every design decision considers:
- What can a compromised host do?
- What does the user see before signing?
- What happens on malformed input?

### Fail Closed
Default behavior on any ambiguity: REJECT.
Blind signing only with explicit user opt-in.

### Streaming by Default
Large inputs (transactions, EIP-712) must be processable without loading entire payload into memory.

### Metadata is Untrusted
All metadata from host requires cryptographic authentication before display as trusted information.

## Document Format

Each document follows a consistent structure:
- **Overview** - What and why
- **Specification** - Technical details
- **Security Considerations** - Threat analysis
- **Examples** - Concrete scenarios
- **References** - Related specs (EIPs, BIPs)

## Maintenance

When updating these documents:
1. Update version/date header
2. Note breaking changes prominently
3. Keep implementation code OUT of docs
4. Cross-reference related documents
5. Ensure security considerations stay current

## Related EIPs and Standards

Key external specifications referenced:
- EIP-155: Replay protection (chainId in v)
- EIP-191: Signed data standard (personal_sign)
- EIP-712: Typed structured data signing
- EIP-2718: Typed transaction envelope
- EIP-2333: BLS key derivation
- EIP-2334: BLS key paths
- BIP-32/44: HD key derivation
- BIP-62: Signature malleability (low-S)
