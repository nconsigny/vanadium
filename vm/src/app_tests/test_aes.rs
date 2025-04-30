use hex_literal::hex;

use crate::aes::{self, AesCtr};

pub fn test_aes() {
    // test derived from the CTR-AES128 text vectors in https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

    let aes_key_raw = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let aes_key = aes::AesKey::from_slice(&aes_key_raw).unwrap();

    let initial_nonce = hex!("f0f1f2f3f4f5f6f7f8f9fafb");
    let initial_counter = 0xfcfdfeffu32;
    let mut aesctr = AesCtr::new_with_nonce(aes_key, initial_nonce.clone());

    let plaintext = hex!("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
    let (nonce, ciphertext) = aesctr
        .encrypt_with_initial_counter(&plaintext, initial_counter)
        .expect("Encryption failed");

    assert_eq!(nonce, initial_nonce, "Nonce does not match");
    assert_eq!(
        ciphertext,
        hex!("874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee").to_vec()
    );

    // Test decryption
    let decrypted = aesctr
        .decrypt_with_initial_counter(&nonce, &ciphertext, initial_counter)
        .expect("Decryption failed");
    assert_eq!(
        decrypted, plaintext,
        "Decrypted plaintext does not match the original plaintext"
    );
}
