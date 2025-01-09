This is the Bitcoin app for Vanadium. It is composed of the following crates:

- [app](app) contains the V-app.
- [client](client) contains the client of the V-app.
- [common](common) contains the code shared between the V-App and the client.

The `client` is a library crate (see [lib.rs](client/src/lib.rs)), but it also has a test executable ([main.rs](client/src/main.rs)) to interact with the app from the command line.

## Build the V-App

### Risc-V

In order to build the app for the Risc-V target, enter the `app` folder and run:

   ```sh
   cargo build --release --target=riscv32i-unknown-none-elf
   ```

### Native

In order to build the app for the native target, enter the `app` folder and run:

   ```sh
  cargo build --release --target=x86_64-unknown-linux-gnu
   ```

## Run the V-App

Make sure you built the V-App for the Risc-V target.

Launch Vanadium on speculos. Then execute:

From the `client` folder

   ```sh
   cargo run
   ```

If you want to run the V-app on a real device, execute instead:

   ```sh
   cargo run -- --hid
   ```

If you want to run the V-app natively, after building it for the native target, use:

   ```sh
   cargo run -- --native
   ```


### Client commands

TODO
