# Ethereum V-App (app/) - CLAUDE.md

## Purpose

This crate contains the V-App code that runs inside the Vanadium VM on the Ledger Secure Element. It handles all security-critical operations: key derivation, transaction parsing, user confirmation, and signing.

## Build Configuration

```rust
#![cfg_attr(target_arch = "riscv32", no_std, no_main)]
```

**Targets:**
- `riscv32imc-unknown-none-elf` - Production (secure)
- `native` - Development only (INSECURE)

**Build:** `just build` / `just build-riscv`

## no_std Constraints

### Prohibited
- Standard library (`std`)
- Heap allocation without `alloc` (use sparingly)
- File/network I/O
- Threads, async runtime
- Floating point (soft-float only on riscv)

### Allowed
- `core` library
- `alloc` with care (Vec, String via `alloc::`)
- `heapless` collections preferred for fixed-size buffers
- `vanadium-app-sdk` APIs

## Memory Safety Rules

### CRITICAL: No Secret-Dependent Memory Access
The host observes which 256-byte pages are accessed. NEVER:
```rust
// FORBIDDEN - leaks secret bits via page access
let index = secret_byte as usize;
let value = lookup_table[index];

// FORBIDDEN - conditional access based on secret
if secret_bit { access_page_a(); } else { access_page_b(); }
```

### Safe Patterns
- Use `app-sdk` crypto primitives exclusively
- Fixed iteration counts
- Constant-time comparisons (`subtle` crate patterns)
- Process all branches, select result with constant-time mux

## ECALL Usage

All privileged operations go through ECALLs. Key ones for Ethereum:

```rust
// Key derivation (BIP32/BIP44)
derive_hd_node(curve, path, path_len, privkey, chain_code)

// Signing (RFC6979 deterministic)
ecdsa_sign(curve, mode, hash_id, privkey, msg_hash, signature)

// User interaction
show_page(page_desc, len)  // Flex/Stax
show_step(step_desc, len)  // Nano S+/X
get_event(data) -> event_code

// Communication with host
xrecv(buffer, max_size) -> size
xsend(buffer, size)

// Randomness
get_random_bytes(buffer, size)
```

## Parsing Responsibilities (V-App vs Client)

### V-App MUST Parse (security-critical)
- Transaction envelope (EIP-2718 type byte)
- RLP structure of transaction fields
- EIP-712 domain separator and type hashes
- BIP44 derivation paths
- Signature requests

### Client Prepares (convenience, untrusted)
- Chunking large payloads
- Pre-computing hashes for display (V-App re-verifies)
- Metadata lookup and formatting
- Protocol framing

### V-App MUST Verify
- All metadata signatures before trusting
- Transaction field bounds (gas, value, chainId)
- Address checksums
- Message length limits

## Error Handling

### Panic-Free in Production
```rust
// FORBIDDEN in production paths
.unwrap()
.expect("...")
panic!()

// REQUIRED
match result {
    Ok(v) => v,
    Err(e) => return Err(AppError::from(e)),
}
```

### Fail Closed
On any error: return error response, do NOT sign.

## State Machine

Commands may require multi-step flows:
1. Receive transaction chunk
2. Continue receiving (streaming)
3. Show UI, await user decision
4. Sign or reject

State MUST be explicitly tracked. Clear state on:
- Command completion (success or error)
- Timeout
- Unexpected command sequence

## Signature Output

### ECDSA (secp256k1)
- DER encoding or raw (r,s) per command
- Low-S normalization (BIP-62/EIP-2)
- Recovery ID (v): EIP-155 for txs, 27/28 for messages

### BLS (eth2)
- BLS12-381 signatures for validator operations
- EIP-2333 key derivation, EIP-2334 paths

## Testing

- Unit tests: `cargo test` (native)
- Integration: via client against Speculos
- Fuzzing: parser inputs (native, libfuzzer)
