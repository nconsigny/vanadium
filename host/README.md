The content in this folder is temporary; it currently contains code that was in the `/host` folder in the [vanadium-legacy](https://github.com/LedgerHQ/vanadium-legacy) repo.

It contains a standalone executable that parses the elf file of a V-App, builds the Manifest, and starts its execution in the Vanadium VM.

Once it's more mature, most of the code here will be moved to either the `common` crate or the `client_sdk`.
