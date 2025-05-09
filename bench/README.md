# Vanadium Benchmarks

This directory contains several benchmarks Vanadium VM. Each benchmark measures the performance of a specific operation or algorithm implemented for the Vanadium platform.

## Structure

- Each benchmark case is located in the `cases/` directory, and it's a full V-App as its own crate.
- The main runner is in `src/main.rs`.
- Testcases are defined in the `TEST_CASES` array in `main.rs`.

## Build the testcases

Compile all the the testcases. If you use `just`, you can simply run

```sh
just build-cases
```

## Running Benchmarks

The benchmark can only be executed on a real device (not on speculos). Make sure the device is plugged and the Vanadium app is open.

To run all benchmark testcases:

```sh
cargo run
```

To run only specific testcases, pass one or more substrings of the testcase names as command line arguments. Only testcases whose names include at least one of the arguments will be run. For example:

```sh
cargo run -- sha256 base58
```

This will run all testcases whose names include either `sha256` or `base58`.

## Output

The benchmark runner will print a summary table with the total and average execution time for each testcase, adjusted by a baseline measurement.
