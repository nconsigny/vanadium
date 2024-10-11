This will be a test V-app.

- [app](app) contains the Risc-V app, based on the V-app Sdk.
- [client](client) folder contains the client of the app, based on the V-app Client Sdk.

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

## Run the V-App on Vanadium

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

If you want to run the V-app natively, use:

   ```sh
   cargo run -- --native
   ```


### Client commands

Once the client is running, these are the available commands:

- `reverse <hex_buffer>` - Reversed the given buffer.
- `sha256 <hex_buffer>` - Computes the sha256 hash of the given buffer.
- `b58enc <hex_buffer>` - Computes the base58 encoding of the given buffer (the output is in hex as well).
- `addnumbers <n>` - Computes the sum of the numbers between `1` and `n`.
- `nprimes <n>` - Counts the number of primes up to `n` using the Sieve of Erathostenes.
- `panic <panic message>` - Cause the V-App to panic. Everything written after 'panic' is the panic message.
- An empty command will exit the V-App.
