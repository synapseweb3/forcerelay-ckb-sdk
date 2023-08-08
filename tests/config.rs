use forcerelay_ckb_sdk::config::AddressOrScript;

#[test]
fn test_address_serde() {
    let json = r#""ckt1qq6pngwqn6e9vlm92th84rk0l4jp2h8lurchjmnwv8kq3rt5psf4vqw4d73hmzmlqsy623f5rlezcw9v4z792ggyx235x""#;
    let x: AddressOrScript = serde_json::from_str(json).unwrap();
    let json1 = serde_json::to_string(&x).unwrap();
    assert_eq!(json, json1);
}
