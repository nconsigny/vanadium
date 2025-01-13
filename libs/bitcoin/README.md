This crate is mostly a clone of [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin), but modified in order to use the Vanadium V-App SDK for cryptography-related code.

## Rationale

`rust-bitcoin` natively implements all the necessary cryptographic primitives, and can be compiled to Risc-V. However, this would lose the benefits of the cryptographic accelerator available in signing devices, and made accessible to V-Apps via the Vanadium V-App SDK.

By implementing a subset of `rust-bitcoin` while keeping the public API of this library as compatible as possible, we aim to minimize the burden of porting existing code using `rust-bitcoin` into Vanadium V-Apps.

## Compatibility

The reference implementation of `rust-bitcoin` is [release 0.32.5](https://github.com/rust-bitcoin/rust-bitcoin/releases/tag/bitcoin-0.32.5) (commit [17ce61c171905ec0a23155a1a31b0c67776ee436](https://github.com/rust-bitcoin/rust-bitcoin/tree/17ce61c171905ec0a23155a1a31b0c67776ee436)).

## Licence

The code in this crate is liberally adapted from rust-bitcoin, and dual-licensed as Apache License v2, and Creative Commons Zero v1.0 Universal.
