use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
pub use device_auth_core::{
    ALPHABET, CODE_LEN, COUNTER_HEADER, Code, NAME_MAX_LEN, PUBLIC_KEY_LEN, valid_name,
};
use device_auth_core::{CODE_MAC_LEN, verify_code_mac};
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use rand_core::CryptoRngCore;
use serde::Deserialize;

const COORDINATE_LEN: usize = 32;

/// Draws a canonical pairing code from `rng`. Show it to a person through its `Display` form,
/// and store [`Code::as_str`] until the code is used or expires.
pub fn new_code(rng: &mut impl CryptoRngCore) -> Code {
    let mut bytes = [0; CODE_LEN];
    rng.fill_bytes(&mut bytes);
    Code::from_random(bytes)
}

/// A registration whose signature verified with its own `jwk`. It is not yet tied to a code:
/// call [`Registration::matching_code`] with the pending codes.
#[derive(Clone, Debug)]
pub struct Registration {
    /// Satisfies [`valid_name`].
    pub name: String,
    /// The uncompressed SEC1 point: `0x04`, then the 32-byte `x` and `y`.
    pub public_key: [u8; PUBLIC_KEY_LEN],
    code_mac: [u8; CODE_MAC_LEN],
}

impl Registration {
    /// Returns the first code in `codes` whose `code_mac` matches, or `None`.
    ///
    /// Each entry is a canonical code as [`Code::as_str`] gives it. An entry that is not
    /// canonical never matches.
    pub fn matching_code<'a, C: AsRef<str>>(&self, codes: &'a [C]) -> Option<&'a C> {
        codes.iter().find(|code| {
            Code::from_canonical(code.as_ref())
                .is_some_and(|code| verify_code_mac(&code, &self.public_key, &self.code_mac))
        })
    }
}

/// Why [`parse_registration`] refused a body. [`RegistrationError::Signature`] means the
/// registration is unauthorized. Every other variant means it is malformed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, docsplay::Display, thiserror::Error)]
pub enum RegistrationError {
    /// The header is unreadable.
    Header,
    /// `alg` is not ES256.
    Algorithm,
    /// The header has no `jwk`.
    MissingJwk,
    /// `jwk` is not an EC key.
    JwkType,
    /// `jwk` is not on P-256.
    JwkCurve,
    /// `jwk` `x` is not 32 bytes of base64url.
    JwkX,
    /// `jwk` `y` is not 32 bytes of base64url.
    JwkY,
    /// `jwk` is not a P-256 point.
    JwkPoint,
    /// `name` or `code_mac` is missing.
    Claims,
    /// `name` is not 1 to 32 bytes of ASCII letters, digits, and `-`.
    Name,
    /// `code_mac` is not 32 bytes of base64url.
    CodeMac,
    /// The signature does not verify with `jwk`.
    Signature,
}

/// Why [`claimed_device`] or [`verify_request`] refused a token. Every variant means the
/// request is unauthorized.
#[derive(Clone, Copy, Debug, PartialEq, Eq, docsplay::Display, thiserror::Error)]
pub enum RequestError {
    /// `sub` is missing or not a device name.
    Subject,
    /// The public key is not a P-256 point.
    Key,
    /// The token or its signature is invalid.
    Token,
    /// `jti` is not a counter in the accepted range.
    Counter,
    /// `htm` does not match the request method.
    Method,
    /// `htu` does not match the request path.
    Path,
}

#[derive(Deserialize)]
struct RegistrationClaims {
    name: String,
    code_mac: String,
}

#[derive(Deserialize)]
struct Subject {
    sub: String,
}

#[derive(Deserialize)]
struct RequestClaims {
    jti: String,
    htm: String,
    htu: String,
}

/// Parses a registration body and verifies its signature against the `jwk` it carries.
///
/// Checks run in the order of the [`RegistrationError`] variants, and the first failure is
/// returned.
pub fn parse_registration(token: &str) -> Result<Registration, RegistrationError> {
    use RegistrationError as E;

    let header = jsonwebtoken::decode_header(token).map_err(|_| E::Header)?;
    if header.alg != Algorithm::ES256 {
        return Err(E::Algorithm);
    }
    let jwk = header.jwk.ok_or(E::MissingJwk)?;
    let AlgorithmParameters::EllipticCurve(params) = &jwk.algorithm else {
        return Err(E::JwkType);
    };
    if params.curve != EllipticCurve::P256 {
        return Err(E::JwkCurve);
    }
    let x = coordinate(&params.x).ok_or(E::JwkX)?;
    let y = coordinate(&params.y).ok_or(E::JwkY)?;
    let mut public_key = [0; PUBLIC_KEY_LEN];
    public_key[0] = 0x04;
    public_key[1..=COORDINATE_LEN].copy_from_slice(&x);
    public_key[1 + COORDINATE_LEN..].copy_from_slice(&y);
    let key = decoding_key(&public_key).ok_or(E::JwkPoint)?;

    let claims: RegistrationClaims =
        jsonwebtoken::dangerous::insecure_decode_claims(token).map_err(|_| E::Claims)?;
    if !valid_name(&claims.name) {
        return Err(E::Name);
    }
    let code_mac = URL_SAFE_NO_PAD
        .decode(&claims.code_mac)
        .ok()
        .and_then(|mac| mac.try_into().ok())
        .ok_or(E::CodeMac)?;

    jsonwebtoken::decode::<RegistrationClaims>(token, &key, &validation())
        .map_err(|_| E::Signature)?;
    Ok(Registration {
        name: claims.name,
        public_key,
        code_mac,
    })
}

/// Reads `sub` from a request token without verifying it, so the caller can look up the
/// device's public key for [`verify_request`].
pub fn claimed_device(token: &str) -> Result<String, RequestError> {
    let Subject { sub } = jsonwebtoken::dangerous::insecure_decode_claims(token)
        .map_err(|_| RequestError::Subject)?;
    if valid_name(&sub) {
        Ok(sub)
    } else {
        Err(RequestError::Subject)
    }
}

/// Verifies a request token against the device's stored `public_key` and returns its `jti`.
///
/// `public_key` is the 65-byte uncompressed SEC1 point. `method` and `path_and_query` are
/// compared with `htm` and `htu` byte for byte. The returned counter is from 1 to
/// 9223372036854775807. The caller accepts it only if it is greater than the stored counter.
pub fn verify_request(
    token: &str,
    public_key: &[u8],
    method: &str,
    path_and_query: &str,
) -> Result<i64, RequestError> {
    let key = decoding_key(public_key).ok_or(RequestError::Key)?;
    let claims = jsonwebtoken::decode::<RequestClaims>(token, &key, &validation())
        .map_err(|_| RequestError::Token)?
        .claims;
    let counter = parse_counter(&claims.jti).ok_or(RequestError::Counter)?;
    if claims.htm != method {
        return Err(RequestError::Method);
    }
    if claims.htu != path_and_query {
        return Err(RequestError::Path);
    }
    Ok(counter)
}

fn validation() -> Validation {
    let mut validation = Validation::new(Algorithm::ES256);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation
}

fn coordinate(encoded: &str) -> Option<[u8; COORDINATE_LEN]> {
    URL_SAFE_NO_PAD.decode(encoded).ok()?.try_into().ok()
}

fn decoding_key(public_key: &[u8]) -> Option<DecodingKey> {
    if public_key.len() != PUBLIC_KEY_LEN {
        return None;
    }
    p256::PublicKey::from_sec1_bytes(public_key).ok()?;
    let x = URL_SAFE_NO_PAD.encode(&public_key[1..=COORDINATE_LEN]);
    let y = URL_SAFE_NO_PAD.encode(&public_key[1 + COORDINATE_LEN..]);
    DecodingKey::from_ec_components(&x, &y).ok()
}

// Decimal with no sign and no leading zeros, from 1 to i64::MAX.
fn parse_counter(jti: &str) -> Option<i64> {
    if jti.starts_with('0') || !jti.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    jti.parse().ok().filter(|&counter| counter > 0)
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    use rand_core::{CryptoRng, RngCore};
    use serde_json::{Value, json};

    use super::*;

    const PATH: &str = "/items?page=2";
    const CODE: &str = "7KQ2MX9D4F";

    struct FixedRng<'a>(&'a [u8]);

    impl RngCore for FixedRng<'_> {
        fn next_u32(&mut self) -> u32 {
            unimplemented!()
        }

        fn next_u64(&mut self) -> u64 {
            unimplemented!()
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let (head, rest) = self.0.split_at(dest.len());
            dest.copy_from_slice(head);
            self.0 = rest;
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for FixedRng<'_> {}

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32].into()).unwrap()
    }

    fn public_key(key: &SigningKey) -> [u8; PUBLIC_KEY_LEN] {
        key.verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .unwrap()
    }

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn jws(key: &SigningKey, header: &Value, claims: &Value) -> String {
        let input = format!(
            "{}.{}",
            b64(header.to_string().as_bytes()),
            b64(claims.to_string().as_bytes())
        );
        let signature: Signature = key.sign(input.as_bytes());
        format!("{input}.{}", b64(&signature.to_bytes()))
    }

    fn jwk(key: &SigningKey) -> Value {
        let point = key.verifying_key().to_encoded_point(false);
        json!({"kty": "EC", "crv": "P-256", "x": b64(point.x().unwrap()), "y": b64(point.y().unwrap())})
    }

    fn code_mac(code: &str, key: &SigningKey) -> String {
        let code = Code::from_canonical(code).unwrap();
        b64(&device_auth_core::code_mac(&code, &public_key(key)))
    }

    fn es256() -> Value {
        json!({"alg": "ES256", "typ": "JWT"})
    }

    fn registration(key: &SigningKey, mut header: Value, claims: Value) -> String {
        if header.get("jwk").is_none() {
            header["jwk"] = jwk(key);
        }
        jws(key, &header, &claims)
    }

    fn registration_claims() -> Value {
        json!({"name": "kitchen", "code_mac": code_mac(CODE, &key(3))})
    }

    fn request_claims() -> Value {
        json!({"sub": "kitchen-sensor", "jti": "42", "htm": "GET", "htu": PATH})
    }

    fn verify(token: &str) -> Result<i64, RequestError> {
        verify_request(token, &public_key(&key(1)), "GET", PATH)
    }

    #[test]
    fn new_code_maps_random_bytes_to_the_alphabet() {
        let bytes = [0, 1, 9, 10, 31, 32, 0x41, 0xff, 0xe0, 0x1f];
        assert_eq!(new_code(&mut FixedRng(&bytes)).as_str(), "019AZ01Z0Z");
        let other = [7, 19, 23, 2, 20, 29, 9, 13, 4, 15];
        assert_eq!(new_code(&mut FixedRng(&other)).as_str(), CODE);
    }

    #[test]
    fn registration_matches_its_code() {
        let body = registration(&key(3), es256(), registration_claims());
        let parsed = parse_registration(&body).unwrap();
        assert_eq!(parsed.name, "kitchen");
        assert_eq!(parsed.public_key, public_key(&key(3)));
        let codes = ["AAAAAAAAAA", CODE];
        assert_eq!(parsed.matching_code(&codes), Some(&CODE));
        assert_eq!(parsed.matching_code(&codes[..1]), None);
        assert_eq!(parsed.matching_code(&["7KQ2M-X9D4F"]), None);
        let owned = vec![CODE.to_owned()];
        assert_eq!(parsed.matching_code(&owned), Some(&owned[0]));
    }

    #[test]
    fn registration_signed_by_another_key_is_unauthorized() {
        let mut header = es256();
        header["jwk"] = jwk(&key(3));
        let body = jws(&key(4), &header, &registration_claims());
        assert_eq!(
            parse_registration(&body).unwrap_err(),
            RegistrationError::Signature
        );
    }

    #[test]
    fn malformed_registrations_name_their_fault() {
        use RegistrationError as E;

        let parse = |body: &str| parse_registration(body).unwrap_err();
        let with_jwk = |jwk: Value| {
            registration(
                &key(3),
                json!({"alg": "ES256", "jwk": jwk}),
                registration_claims(),
            )
        };

        assert_eq!(parse("not a jwt"), E::Header);
        let hs256 = registration(&key(3), json!({"alg": "HS256"}), registration_claims());
        assert_eq!(parse(&hs256), E::Algorithm);
        assert_eq!(
            parse(&jws(&key(3), &es256(), &registration_claims())),
            E::MissingJwk
        );
        let oct = json!({"kty": "oct", "k": b64(b"secret")});
        assert_eq!(parse(&with_jwk(oct)), E::JwkType);

        let mut wrong_curve = jwk(&key(3));
        wrong_curve["crv"] = json!("P-384");
        assert_eq!(parse(&with_jwk(wrong_curve)), E::JwkCurve);
        let mut short_x = jwk(&key(3));
        short_x["x"] = json!(b64(&[1; 31]));
        assert_eq!(parse(&with_jwk(short_x)), E::JwkX);
        let mut short_y = jwk(&key(3));
        short_y["y"] = json!(b64(&[1; 31]));
        assert_eq!(parse(&with_jwk(short_y)), E::JwkY);
        let mut off_curve = jwk(&key(3));
        off_curve["y"] = json!(b64(&[1; 32]));
        assert_eq!(parse(&with_jwk(off_curve)), E::JwkPoint);

        for (claims, fault) in [
            (json!({"name": "kitchen"}), E::Claims),
            (json!({"code_mac": code_mac(CODE, &key(3))}), E::Claims),
            (
                json!({"name": 7, "code_mac": code_mac(CODE, &key(3))}),
                E::Claims,
            ),
            (
                json!({"name": "kitchen sink", "code_mac": code_mac(CODE, &key(3))}),
                E::Name,
            ),
            (json!({"name": "kitchen", "code_mac": "short"}), E::CodeMac),
            (
                json!({"name": "kitchen", "code_mac": b64(&[0; 31])}),
                E::CodeMac,
            ),
        ] {
            assert_eq!(
                parse(&registration(&key(3), es256(), claims.clone())),
                fault,
                "{claims}"
            );
        }
    }

    #[test]
    fn signed_request_yields_its_counter() {
        let token = jws(&key(1), &es256(), &request_claims());
        assert_eq!(claimed_device(&token).unwrap(), "kitchen-sensor");
        assert_eq!(verify(&token), Ok(42));

        let largest = {
            let mut claims = request_claims();
            claims["jti"] = json!("9223372036854775807");
            jws(&key(1), &es256(), &claims)
        };
        assert_eq!(verify(&largest), Ok(i64::MAX));
    }

    #[test]
    fn typ_is_not_checked() {
        let token = jws(&key(1), &json!({"alg": "ES256"}), &request_claims());
        assert_eq!(verify(&token), Ok(42));
    }

    #[test]
    fn other_keys_and_algorithms_are_rejected() {
        assert_eq!(
            verify(&jws(&key(2), &es256(), &request_claims())),
            Err(RequestError::Token)
        );

        let hs256 = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(Algorithm::HS256),
            &request_claims(),
            &jsonwebtoken::EncodingKey::from_secret(b"0123456789abcdef0123456789abcdef"),
        )
        .unwrap();
        assert_eq!(verify(&hs256), Err(RequestError::Token));

        let none = format!(
            "{}.{}.",
            b64(json!({"alg": "none"}).to_string().as_bytes()),
            b64(request_claims().to_string().as_bytes())
        );
        assert_eq!(verify(&none), Err(RequestError::Token));
    }

    #[test]
    fn stored_key_must_be_a_point() {
        let token = jws(&key(1), &es256(), &request_claims());
        let mut off_curve = public_key(&key(1));
        off_curve[64] ^= 1;
        assert_eq!(
            verify_request(&token, &off_curve, "GET", PATH),
            Err(RequestError::Key)
        );
        assert_eq!(
            verify_request(&token, &[4; 3], "GET", PATH),
            Err(RequestError::Key)
        );
        let compressed = key(1).verifying_key().to_encoded_point(true);
        assert_eq!(
            verify_request(&token, compressed.as_bytes(), "GET", PATH),
            Err(RequestError::Key)
        );
    }

    #[test]
    fn claims_must_be_present_and_strings() {
        for name in ["jti", "htm", "htu"] {
            let mut claims = request_claims();
            claims.as_object_mut().unwrap().remove(name);
            assert_eq!(
                verify(&jws(&key(1), &es256(), &claims)),
                Err(RequestError::Token),
                "{name}"
            );
        }
        for (name, value) in [
            ("jti", json!(42)),
            ("htm", json!(null)),
            ("htu", json!(["/"])),
        ] {
            let mut claims = request_claims();
            claims[name] = value;
            assert_eq!(
                verify(&jws(&key(1), &es256(), &claims)),
                Err(RequestError::Token),
                "{name}"
            );
        }
    }

    #[test]
    fn jti_must_be_a_decimal_counter_in_range() {
        for jti in [
            "0",
            "-1",
            "+1",
            "01",
            "1.0",
            " 1",
            "",
            "9223372036854775808",
        ] {
            let mut claims = request_claims();
            claims["jti"] = json!(jti);
            assert_eq!(
                verify(&jws(&key(1), &es256(), &claims)),
                Err(RequestError::Counter),
                "{jti:?}"
            );
        }
    }

    #[test]
    fn sub_must_be_a_device_name() {
        for sub in [
            json!(""),
            json!("a".repeat(33)),
            json!("sensor_1"),
            json!(7),
        ] {
            let mut claims = request_claims();
            claims["sub"] = sub.clone();
            assert_eq!(
                claimed_device(&jws(&key(1), &es256(), &claims)),
                Err(RequestError::Subject),
                "{sub}"
            );
        }
        let mut claims = request_claims();
        claims.as_object_mut().unwrap().remove("sub");
        assert_eq!(
            claimed_device(&jws(&key(1), &es256(), &claims)),
            Err(RequestError::Subject)
        );
        assert_eq!(claimed_device("not a jwt"), Err(RequestError::Subject));
    }

    #[test]
    fn claimed_device_does_not_check_the_signature() {
        let token = jws(&key(2), &es256(), &request_claims());
        assert_eq!(claimed_device(&token).unwrap(), "kitchen-sensor");
    }

    #[test]
    fn request_binding_is_checked() {
        let token = jws(&key(1), &es256(), &request_claims());
        let public = public_key(&key(1));
        assert_eq!(
            verify_request(&token, &public, "POST", PATH),
            Err(RequestError::Method)
        );
        assert_eq!(
            verify_request(&token, &public, "GET", "/items"),
            Err(RequestError::Path)
        );
    }

    #[test]
    fn errors_display_their_doc_comment() {
        assert_eq!(
            RegistrationError::Signature.to_string(),
            "The signature does not verify with `jwk`."
        );
        assert_eq!(
            RequestError::Counter.to_string(),
            "`jti` is not a counter in the accepted range."
        );
    }
}
