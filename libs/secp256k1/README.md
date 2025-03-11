This crate is mostly a clone of [rust-secp256k1](https://github.com/rust-bitcoin/rust-secp256k1), but modified in order to use the Vanadium V-App SDK for cryptography-related code.

## Rationale

`rust-secp256k1` natively implements all the necessary cryptographic primitives, and can be compiled to Risc-V. However, this would lose the benefits of the cryptographic accelerator available in signing devices, and made accessible to V-Apps via the Vanadium V-App SDK.

This library supports the modified version of rust-bitcoin that we use in Vanadium apps.

## Compatibility

This folder started from a fork of `rust-secp256k1`, at commit [31237ffd604b78baba4a90e35fe8a50c3f48a23b](https://github.com/rust-bitcoin/rust-secp256k1/commit/31237ffd604b78baba4a90e35fe8a50c3f48a23b).

## Licence

The code in this crate is liberally adapted from rust-secp256k1, and dual-licensed as Apache License v2, and Creative Commons Zero v1.0 Universal.
