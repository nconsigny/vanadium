# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Vanadium is a RISC-V Virtual Machine that runs in embedded Ledger Secure Elements. It allows running V-Apps (Vanadium Apps) with outsourced encrypted, authenticated memory pages.

**Warning:** This is experimental. The native target is insecure and only intended for development/testing.

## CRITICAL SECURITY MODEL

### Host is Compromised
The host environment (PC/phone) MUST be treated as **fully compromised**. It can:
- Send arbitrary malformed inputs
- Replay, omit, or reorder messages
- Observe memory access patterns (which pages are accessed)

### Memory Access Pattern Leakage
**NEVER use secret-dependent memory access.** The client can observe which 256-byte pages are accessed. Unsafe patterns include:
- Lookup tables indexed by secret bits
- Conditional branches affecting memory access based on secrets
- Variable-time algorithms with secret-dependent memory patterns

Use ONLY `app-sdk` crypto primitives - they are hardened for Vanadium's threat model.

### Trust Boundaries
- V-App code in SE: TRUSTED
- Device screen/buttons: TRUSTED
- Host client code: UNTRUSTED
- All host-provided data: UNTRUSTED until cryptographically verified

## Build Commands

### V-App Development (in `apps/*/app/`)
```bash
just build              # Build for native and riscv targets
just build-native       # Build native only
just build-riscv        # Build riscv only
cargo run               # Run natively (testing)
cargo test              # Run tests
```

### VM (in `vm/`)
```bash
bash download_vanadium.sh       # Download precompiled VM binaries
just run-nanosplus              # Run on Speculos (options: run-nanox, run-flex, run-stax)
```

### Integration Tests (in `apps/*/client/`)
```bash
just integration-tests          # cargo test --features speculos-tests
```

## Architecture

### Compilation Targets
- **native**: Development/testing on host machine (INSECURE)
- **riscv**: `riscv32imc-unknown-none-elf` for production deployment

### Core Crates
- `app-sdk` (`vanadium-app-sdk`): V-App SDK, `no_std`, riscv and native
- `client-sdk` (`vanadium-client-sdk`): Client SDK, native only
- `common`: Shared code, `no_std`
- `ecalls` (`vanadium-ecalls`): ECALL definitions
- `macros` (`vanadium_macros`): Procedural macros

### V-App Structure
Each V-App should have:
- `apps/{name}/app`: App code (riscv + native, `no_std`)
- `apps/{name}/client`: Client code (native only)
- `apps/{name}/common`: Shared types (riscv + native, `no_std`)

### Outsourced Memory Security
- Memory organized in 256-byte pages in Merkle tree
- Pages encrypted before sending to client
- Client must provide Merkle proofs for page retrieval
- VM aborts if proof invalid

## ECALLs (System Calls)

ECALLs provide access to VM services. See `app-sdk/src/ecalls.rs` for interface.

**Key ECALLs for Apps:**
- `derive_hd_node`: BIP32 key derivation (secp256k1)
- `ecdsa_sign`: Sign with derived key
- `get_random_bytes`: CSPRNG
- `show_page`/`show_step`: UX primitives
- `xsend`/`xrecv`: Host communication

**Adding ECALLs requires changes in:**
1. `common/src/ecall_constants.rs`
2. `app-sdk/src/ecalls.rs`
3. `app-sdk/src/ecalls_native.rs`
4. `app-sdk/src/ecalls_riscv.rs` + `ecalls/src/lib.rs`
5. `vm/src/handlers/lib/ecall.rs`
6. Tests in `apps/sadik/`

## Development Workflow

Create new V-App:
```bash
cargo vnd new --name myapp
```

Run native (two terminals):
```bash
# Terminal 1: App
cd myapp/app && cargo run

# Terminal 2: Client
cd myapp/client && cargo run
```

Run on Speculos:
```bash
# Terminal 1: VM
cd vm && just run-flex

# Terminal 2: Client
cd myapp/client && cargo run
```

## Prerequisites
- Rust with `rustup target add riscv32imc-unknown-none-elf`
- `just` command runner
- `cargo-vnd`: `cargo install --git https://github.com/LedgerHQ/vanadium cargo-vnd`
- System deps (Ubuntu): `libssl-dev pkg-config libudev-dev`

## Key Documentation
- `docs/security.md` - Security model (READ FIRST for security work)
- `docs/ecalls.md` - ECALL patterns
- `docs/manifest.md` - V-App registration and hashing
