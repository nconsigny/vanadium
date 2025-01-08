use std::process::Command;

fn main() {
    let proto_files = &["src/message/message.proto"];

    for proto_file in proto_files {
        let output = Command::new("pb-rs")
            .args(&["--nostd", proto_file])
            .output()
            .expect("Failed to execute pb-rs");

        if !output.status.success() {
            panic!(
                "pb-rs failed with error: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
