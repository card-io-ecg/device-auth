use device_auth_firmware::{Counter, SigningKey, parse_code, registration, request_token};
use device_auth_server::{claimed_device, parse_registration, verify_request};

fn key() -> SigningKey {
    SigningKey::from_bytes(&[5; 32].into()).unwrap()
}

fn token(counter: u64, method: &str, path: &str) -> String {
    let mut token = String::new();
    request_token(&key(), "kitchen-sensor", counter, method, path, &mut token).unwrap();
    token
}

#[test]
fn firmware_registration_matches_its_code() {
    let code = parse_code("7kq2m-x9d4f").unwrap();
    let mut body = String::new();
    registration(&key(), "kitchen-sensor", &code, &mut body).unwrap();

    let parsed = parse_registration(&body).unwrap();
    assert_eq!(parsed.name, "kitchen-sensor");
    assert_eq!(
        parsed.public_key.as_slice(),
        key().verifying_key().to_encoded_point(false).as_bytes()
    );
    let pending = ["AAAAAAAAAA", "7KQ2MX9D4F"];
    assert_eq!(parsed.matching_code(&pending), Some(&"7KQ2MX9D4F"));
}

#[test]
fn firmware_request_token_verifies_with_its_counter() {
    let public_key = key().verifying_key().to_encoded_point(false);
    let mut counter = Counter::new();
    counter.resync(41);
    let token = token(counter.next_jti(), "GET", "/items?page=2");

    assert_eq!(claimed_device(&token).unwrap(), "kitchen-sensor");
    assert_eq!(
        verify_request(&token, public_key.as_bytes(), "GET", "/items?page=2"),
        Ok(42)
    );
}

#[test]
fn firmware_request_token_verifies_with_json_special_characters() {
    let public_key = key().verifying_key().to_encoded_point(false);
    let method = "GE\"T";
    let path = "/a\\b\"c\u{1}d\n\u{1f}?q=é";
    let token = token(9223372036854775807, method, path);

    assert_eq!(
        verify_request(&token, public_key.as_bytes(), method, path),
        Ok(i64::MAX)
    );
}
