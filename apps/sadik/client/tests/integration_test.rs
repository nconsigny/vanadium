#![cfg(feature = "speculos-tests")]

mod test_common;

use common::{BigIntOperator, HashId};
use hex_literal::hex;

#[tokio::test]
#[rustfmt::skip]
async fn test_big_num() {
    let mut setup = test_common::setup().await;

    let zero_large = [0u8; 64].to_vec();
    let minus_one_large = [0xffu8; 64].to_vec();
    let one_large = {
        let mut one = [0u8; 64];
        one[63] = 1;
        one.to_vec()
    };

    // additions
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Add, &hex!("77989873"), &hex!("a4589234"), &[]).await.unwrap(),
        hex!("1bf12aa7")
    );
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Add, &hex!("47989873"), &hex!("a4589234"), &[]).await.unwrap(),
        hex!("ebf12aa7")
    );
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Add, &hex!("ffffffff"), &hex!("00000001"), &[]).await.unwrap(),
        hex!("00000000")
    );

    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Add, &minus_one_large, &one_large, &[]).await.unwrap(),
        zero_large
    );

    // subtractions
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Sub, &hex!("a4589234"), &hex!("77989873"), &[]).await.unwrap(),
        hex!("2cbff9c1")
    );
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Sub, &hex!("77989873"), &hex!("a4589234"), &[]).await.unwrap(),
        hex!("d340063f")
    );
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Sub, &hex!("00000000"), &hex!("00000001"), &[]).await.unwrap(),
        hex!("ffffffff")
    );

    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Sub, &zero_large, &one_large, &[]).await.unwrap(),
        minus_one_large
    );
}

#[tokio::test]
#[rustfmt::skip]
async fn test_big_num_mod() {
    let mut setup = test_common::setup().await;

    let M: Vec<u8> = hex!("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f").to_vec();
    let M2: Vec<u8> = hex!("3d4b0f9e4e4d5b6e5e5d6e7e8e8d9e9e8e8d9e9e8e8d9e9e8e8d9e9e8e8d9e9d").to_vec();

    let zero: Vec<u8> = hex!("0000000000000000000000000000000000000000000000000000000000000000").to_vec();
    let one: Vec<u8> = hex!("0000000000000000000000000000000000000000000000000000000000000001").to_vec();

    // addition
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Add, &hex!("a247598432980432940980983408039480095809832048509809580984320985"), &hex!("7390984098209380980948098230840982340294098092384092834923840923"), &M).await.unwrap(),
        hex!("15d7f1c4cab897b32c12c8a1b638879e023d5a9d8ca0da88d89bdb53a7b61679")
    );

    // subtraction
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Sub, &hex!("a247598432980432940980983408039480095809832048509809580984320985"), &hex!("7390984098209380980948098230840982340294098092384092834923840923"), &M).await.unwrap(),
        hex!("2eb6c1439a7770b1fc00388eb1d77f8afdd55575799fb6185776d4c060ae0062")
    );
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Sub, &hex!("7390984098209380980948098230840982340294098092384092834923840923"), &hex!("a247598432980432940980983408039480095809832048509809580984320985"), &M).await.unwrap(),
        hex!("d1493ebc65888f4e03ffc7714e288075022aaa8a866049e7a8892b3e9f51fbcd")
    );

    // multiplication
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Mul, &hex!("a247598432980432940980983408039480095809832048509809580984320985"), &zero, &M).await.unwrap(),
        zero
    );
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Mul, &hex!("a247598432980432940980983408039480095809832048509809580984320985"), &one, &M).await.unwrap(),
        hex!("a247598432980432940980983408039480095809832048509809580984320985")
    );
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Mul, &hex!("a247598432980432940980983408039480095809832048509809580984320985"), &hex!("7390984098209380980948098230840982340294098092384092834923840923"), &M).await.unwrap(),
        hex!("2d5daeb3ed823bef5a4480a2c5aa0708e8e37ed7302d2b21c9b442b244d48ce6")
    );

    // TODO: disabled until speculos is fixed as per https://github.com/LedgerHQ/speculos/pull/52
    // powers: 0
    // assert_eq!(
    //     setup.client.bignum_operation(BigIntOperator::Pow, &hex!("a247598432980432940980983408039480095809832048509809580984320985"), &hex!("00"), &M2).await.unwrap(),
    //     one
    // );
    // assert_eq!(
    //     setup.client.bignum_operation(BigIntOperator::Pow, &hex!("a247598432980432940980983408039480095809832048509809580984320985"), &zero, &M2).await.unwrap(),
    //     one
    // );

    // powers: 1
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Pow, &hex!("a247598432980432940980983408039480095809832048509809580984320985"), &one, &M).await.unwrap(),
        hex!("a247598432980432940980983408039480095809832048509809580984320985")
    );
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Pow, &hex!("a247598432980432940980983408039480095809832048509809580984320985"), &hex!("01"), &M).await.unwrap(),
        hex!("a247598432980432940980983408039480095809832048509809580984320985")
    );

    // powers: 2
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Pow, &hex!("a247598432980432940980983408039480095809832048509809580984320985"), &hex!("02"), &M2).await.unwrap(),
        hex!("2378a937274b6304f12d26e7170d5d757087246a2db3d5c776faf10984d3331b")
    );
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Pow, &hex!("a247598432980432940980983408039480095809832048509809580984320985"), &hex!("00000002"), &M2).await.unwrap(),
        hex!("2378a937274b6304f12d26e7170d5d757087246a2db3d5c776faf10984d3331b")
    );
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Pow, &hex!("a247598432980432940980983408039480095809832048509809580984320985"), &hex!("0000000000000000000000000000000000000000000000000000000000000002"), &M2).await.unwrap(),
        hex!("2378a937274b6304f12d26e7170d5d757087246a2db3d5c776faf10984d3331b")
    );

    // powers: large
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Pow, &hex!("a247598432980432940980983408039480095809832048509809580984320985"), &hex!("22e0b80916f2f35efab04d6d61155f9d1aa9f8f0dff2a2b656cdee1bb7b6dcd722e0b80916f2f35efab04d6d61155f9d1aa9f8f0dff2a2b656cdee1bb7b6dcd7"), &M2).await.unwrap(),
        hex!("3c0baee8c4e2f7220615013d7402fa5e69e43bc10e55500a5af4f8b966658846")
    );
}

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

#[tokio::test]
async fn test_secp256k1_get_master_fingerprint() {
    let mut setup = test_common::setup().await;

    assert_eq!(
        setup
            .client
            .get_master_fingerprint(common::Curve::Secp256k1)
            .await
            .unwrap(),
        hex!("f5acc2fd").to_vec()
    );
}

#[tokio::test]
async fn test_secp256k1_derive_hd_node() {
    let mut setup = test_common::setup().await;

    let test_cases: Vec<(Vec<u32>, ([u8; 32], [u8; 32]))> = vec![
        (
            vec![],
            (
                hex!("eb473a0fa0af5031f14db9fe7c37bb8416a4ff01bb69dae9966dc83b5e5bf921"),
                hex!("34ac5d784ebb4df4727bcddf6a6743f5d5d46d83dd74aa825866390c694f2938"),
            ),
        ),
        (
            vec![0x8000002c, 0x80000000, 0x80000001, 0, 3],
            (
                hex!("6da5f32f47232b3b9b2d6b59b802e2b313afa7cbda242f73da607139d8e04989"),
                hex!("239841e64103fd024b01283e752a213fee1a8969f6825204ee3617a45c5e4a91"),
            ),
        ),
    ];

    for (path, (exp_chaincode, exp_privkey)) in test_cases {
        let res = setup
            .client
            .derive_hd_node(common::Curve::Secp256k1, path)
            .await
            .unwrap();

        assert_eq!(res.len(), exp_chaincode.len() + exp_privkey.len());
        let chaincode = &res[0..exp_chaincode.len()];
        let privkey = &res[exp_chaincode.len()..];

        assert_eq!(exp_chaincode, chaincode);
        assert_eq!(exp_privkey, privkey);
    }
}
