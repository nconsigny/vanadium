mod test_aes;

pub fn run_tests() {
    test_aes::test_aes();
    crate::println!("All test passed!");
}
