#![cfg(feature = "speculos-tests")]

mod test_common;

use common::HashId;
use hex_literal::hex;

#[tokio::test]
async fn test_ripemd160() {
    let mut setup = test_common::setup().await;

    #[rustfmt::skip]
    let testcases: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (hex!("").to_vec(), hex!("9c1185a5c5e9fc54612808977ee8f548b2258d31").to_vec()),
        (hex!("54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67").to_vec(), hex!("37f332f68db77bd9d7edd4969571ad671cf9dd3b").to_vec()),
    ];

    for (input, expected) in testcases {
        assert_eq!(
            setup.client.hash(HashId::Ripemd160, &input).await.unwrap(),
            expected
        );
    }
}

#[tokio::test]
async fn test_sha256() {
    let mut setup = test_common::setup().await;

    #[rustfmt::skip]
    let testcases: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (hex!("").to_vec(), hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
        (hex!("54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67").to_vec(), hex!("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592").to_vec()),
    ];

    for (input, expected) in testcases {
        assert_eq!(
            setup.client.hash(HashId::Sha256, &input).await.unwrap(),
            expected
        );
    }
}

#[tokio::test]
async fn test_sha512() {
    let mut setup = test_common::setup().await;

    #[rustfmt::skip]
    let testcases: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (hex!("").to_vec(), hex!("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e").to_vec()),
        (hex!("54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67").to_vec(), hex!("07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6").to_vec()),
    ];

    for (input, expected) in testcases {
        assert_eq!(
            setup.client.hash(HashId::Sha512, &input).await.unwrap(),
            expected
        );
    }
}
