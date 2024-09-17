# Risc-V calling conventions for ECALLs

ECALLs use the following calling convention:

- ECALL code in `t0`
- Up to 8 ECALL arguments in `a0`, `a1`, ..., `a8`, in this order.

No ECALLs with more than 8 argments (using the stack) are currently defined.

# Currently defined ECALLs

See [ecalls.rs](../app-sdk/src/ecalls.rs).
