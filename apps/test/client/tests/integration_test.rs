#![cfg(feature = "speculos-tests")]

mod common;

#[tokio::test]
async fn test_add_numbers() {
    let mut setup = common::setup().await;

    #[rustfmt::skip]
    let testcases: Vec<(u32, u64)> = vec![
        (0, 0),
        (1, 1),
        (100, 5050),
    ];

    for (input, expected) in testcases {
        assert_eq!(setup.client.add_numbers(input).await.unwrap(), expected);
    }
}

// TODO: add other tests
