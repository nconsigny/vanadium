The module corresponding to `message.proto` is automatically generated at build time via [build.rs](../../build.rs).

You can generate it manually with:

$ cargo install pb-rs
$ pb-rs --nostd ./message.proto
