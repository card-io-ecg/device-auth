#![cfg_attr(not(test), no_std)]

use core::fmt::{self, Write};

use device_auth_core::code_mac;
pub use device_auth_core::{
    ALPHABET, CODE_LEN, COUNTER_HEADER, Code, NAME_MAX_LEN, PUBLIC_KEY_LEN, valid_name,
};
use p256::ecdsa::Signature;
pub use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::DigestSigner;
use sha2::{Digest, Sha256};

/// Normalizes a code a person typed: drops `-` and spaces, reads `O` as `0` and `I` or `L` as
/// `1`, and upper-cases letters. Returns `None` when another character is outside [`ALPHABET`]
/// or the result is not 10 characters.
pub fn parse_code(typed: &str) -> Option<Code> {
    let mut code = [0; CODE_LEN];
    let mut len = 0;
    for ch in typed.chars() {
        let ch = match ch {
            '-' | ' ' => continue,
            'o' | 'O' => '0',
            'i' | 'I' | 'l' | 'L' => '1',
            other => other.to_ascii_uppercase(),
        };
        if !ALPHABET.contains(ch) {
            return None;
        }
        *code.get_mut(len)? = u8::try_from(ch).ok()?;
        len += 1;
    }
    Code::from_canonical(core::str::from_utf8(&code[..len]).ok()?)
}

/// The counter of one request class. The server defines the classes, and the device keeps one
/// `Counter` for each.
#[derive(Debug, Default)]
pub struct Counter(u64);

impl Counter {
    pub const fn new() -> Self {
        Self(0)
    }

    /// Advances the counter and returns the `jti` for the next request, starting at 1.
    ///
    /// The server refuses a `jti` above 9223372036854775807 as malformed.
    pub fn next_jti(&mut self) -> u64 {
        self.0 = self.0.saturating_add(1);
        self.0
    }

    /// Takes the server's last accepted counter, read from the [`COUNTER_HEADER`] of a refusal.
    /// The following [`next_jti`](Self::next_jti) returns `last + 1`.
    pub fn resync(&mut self, last: u64) {
        self.0 = last;
    }
}

/// Writes the registration body to `out`: a compact ES256 JWS carrying `key`'s public key as
/// `jwk`, `name`, and the `code_mac` proving knowledge of `code`.
///
/// `name` should satisfy [`valid_name`]. The server refuses any other name. Fails only when
/// `out` fails, and the text written up to then is not a valid body.
pub fn registration(
    key: &SigningKey,
    name: &str,
    code: &Code,
    out: &mut impl Write,
) -> fmt::Result {
    let point = key.verifying_key().to_encoded_point(false);
    let public_key: &[u8; PUBLIC_KEY_LEN] = point
        .as_bytes()
        .try_into()
        .expect("an uncompressed P-256 point is 65 bytes");
    // SEC1 uncompressed: 0x04, then the 32-byte x and y coordinates.
    let (x, y) = public_key[1..].split_at(32);

    jws(
        key,
        out,
        |header| {
            header
                .write_str(r#"{"alg":"ES256","typ":"JWT","jwk":{"kty":"EC","crv":"P-256","x":""#)?;
            base64url(x, header)?;
            header.write_str(r#"","y":""#)?;
            base64url(y, header)?;
            header.write_str(r#""}}"#)
        },
        |claims| {
            claims.write_str(r#"{"name":"#)?;
            json_string(name, claims)?;
            claims.write_str(r#","code_mac":""#)?;
            base64url(&code_mac(code, public_key), claims)?;
            claims.write_str(r#""}"#)
        },
    )
}

/// Writes a request token to `out`: a compact ES256 JWS with `sub`, `jti`, `htm`, and `htu`.
///
/// `path` is the path and query exactly as the server receives them. Any `method` and `path`
/// give valid JSON, because string values are escaped. Fails only when `out` fails, and the
/// text written up to then is not a valid token.
pub fn request_token(
    key: &SigningKey,
    name: &str,
    counter: u64,
    method: &str,
    path: &str,
    out: &mut impl Write,
) -> fmt::Result {
    jws(
        key,
        out,
        |header| header.write_str(r#"{"alg":"ES256","typ":"JWT"}"#),
        |claims| {
            claims.write_str(r#"{"sub":"#)?;
            json_string(name, claims)?;
            write!(claims, r#","jti":"{counter}","htm":"#)?;
            json_string(method, claims)?;
            claims.write_str(r#","htu":"#)?;
            json_string(path, claims)?;
            claims.write_char('}')
        },
    )
}

// The signing input is hashed while it is written, so no buffer holds the token.
fn jws(
    key: &SigningKey,
    out: &mut impl Write,
    header: impl FnOnce(&mut dyn Write) -> fmt::Result,
    payload: impl FnOnce(&mut dyn Write) -> fmt::Result,
) -> fmt::Result {
    let mut input = SigningInput {
        out,
        digest: Sha256::new(),
    };
    let mut part = Base64Url::new(&mut input);
    header(&mut part)?;
    part.finish()?;
    input.write_char('.')?;
    let mut part = Base64Url::new(&mut input);
    payload(&mut part)?;
    part.finish()?;

    // RFC 6979 nonce, as `Signer::sign` uses. The JWS form of an ES256 signature is r ‖ s.
    let signature: Signature = key.sign_digest(input.digest);
    input.out.write_char('.')?;
    base64url(&signature.to_bytes(), input.out)
}

struct SigningInput<'a, W> {
    out: &'a mut W,
    digest: Sha256,
}

impl<W: Write> Write for SigningInput<'_, W> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.digest.update(s.as_bytes());
        self.out.write_str(s)
    }
}

// RFC 8259 requires escaping `"`, `\`, and U+0000 to U+001F. Nothing else is escaped.
fn json_string(value: &str, out: &mut (impl Write + ?Sized)) -> fmt::Result {
    out.write_char('"')?;
    let mut rest = value;
    while let Some(index) = rest.find(|ch| matches!(ch, '"' | '\\' | '\u{0}'..='\u{1f}')) {
        out.write_str(&rest[..index])?;
        match rest.as_bytes()[index] {
            b'"' => out.write_str(r#"\""#)?,
            b'\\' => out.write_str(r"\\")?,
            byte => write!(out, r"\u{byte:04x}")?,
        }
        rest = &rest[index + 1..];
    }
    out.write_str(rest)?;
    out.write_char('"')
}

fn base64url(bytes: &[u8], out: &mut (impl Write + ?Sized)) -> fmt::Result {
    let mut encoder = Base64Url::new(out);
    encoder.write_bytes(bytes)?;
    encoder.finish()
}

// RFC 4648 base64url without padding, encoding text as it is written.
struct Base64Url<W> {
    out: W,
    pending: [u8; 3],
    len: usize,
}

impl<W: Write> Base64Url<W> {
    fn new(out: W) -> Self {
        Self {
            out,
            pending: [0; 3],
            len: 0,
        }
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> fmt::Result {
        for &byte in bytes {
            self.pending[self.len] = byte;
            self.len += 1;
            if self.len == 3 {
                self.emit()?;
            }
        }
        Ok(())
    }

    fn finish(mut self) -> fmt::Result {
        if self.len > 0 { self.emit() } else { Ok(()) }
    }

    // `len` bytes give `len + 1` characters. Bytes past `len` are zero.
    fn emit(&mut self) -> fmt::Result {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let [a, b, c] = self.pending.map(u32::from);
        let bits = (a << 16) | (b << 8) | c;
        let chars = [18, 12, 6, 0].map(|shift| ALPHABET[((bits >> shift) & 0x3f) as usize]);
        let count = self.len + 1;
        self.pending = [0; 3];
        self.len = 0;
        self.out
            .write_str(core::str::from_utf8(&chars[..count]).expect("base64url is ASCII"))
    }
}

impl<W: Write> Write for Base64Url<W> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_bytes(s.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use p256::ecdsa::signature::{Signer, Verifier};

    use super::*;

    struct Fixed<const N: usize> {
        buf: [u8; N],
        len: usize,
    }

    impl<const N: usize> Fixed<N> {
        fn new() -> Self {
            Self {
                buf: [0; N],
                len: 0,
            }
        }

        fn as_str(&self) -> &str {
            core::str::from_utf8(&self.buf[..self.len]).unwrap()
        }
    }

    impl<const N: usize> Write for Fixed<N> {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            let end = self.len + s.len();
            self.buf
                .get_mut(self.len..end)
                .ok_or(fmt::Error)?
                .copy_from_slice(s.as_bytes());
            self.len = end;
            Ok(())
        }
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[1; 32].into()).unwrap()
    }

    fn token(name: &str, counter: u64, method: &str, path: &str) -> String {
        let mut out = String::new();
        request_token(&key(), name, counter, method, path, &mut out).unwrap();
        out
    }

    fn parts(token: &str) -> (String, String, Vec<u8>) {
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "{token}");
        let decode = |part: &str| URL_SAFE_NO_PAD.decode(part).unwrap();
        (
            String::from_utf8(decode(parts[0])).unwrap(),
            String::from_utf8(decode(parts[1])).unwrap(),
            decode(parts[2]),
        )
    }

    fn assert_signed_by_key(token: &str) {
        let (input, signature) = token.rsplit_once('.').unwrap();
        let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(signature).unwrap()).unwrap();
        key()
            .verifying_key()
            .verify(input.as_bytes(), &signature)
            .unwrap();
        let signed: Signature = key().sign(input.as_bytes());
        assert_eq!(signature, signed);
    }

    #[test]
    fn typed_codes_normalize_to_canonical_form() {
        let canonical = |typed| parse_code(typed).map(|code| code.as_str().to_owned());
        assert_eq!(canonical("7KQ2M-X9D4F").as_deref(), Some("7KQ2MX9D4F"));
        assert_eq!(canonical(" 7kq2m x9d4f ").as_deref(), Some("7KQ2MX9D4F"));
        assert_eq!(canonical("oOiI-lL0123").as_deref(), Some("0011110123"));
    }

    #[test]
    fn typed_codes_outside_the_alphabet_or_length_are_refused() {
        assert!(parse_code("7KQ2M-X9D4U").is_none());
        assert!(parse_code("7KQ2M_X9D4F").is_none());
        assert!(parse_code("7KQ2M-X9D4").is_none());
        assert!(parse_code("7KQ2M-X9D4FF").is_none());
        assert!(parse_code("7KQ2M-X9D4é").is_none());
        assert!(parse_code("").is_none());
    }

    #[test]
    fn counter_starts_at_one_and_resyncs() {
        let mut counter = Counter::new();
        assert_eq!(counter.next_jti(), 1);
        assert_eq!(counter.next_jti(), 2);
        counter.resync(41);
        assert_eq!(counter.next_jti(), 42);
        counter.resync(0);
        assert_eq!(counter.next_jti(), 1);
    }

    #[test]
    fn base64url_follows_rfc_4648() {
        for (input, expected) in [
            (&b""[..], ""),
            (b"f", "Zg"),
            (b"fo", "Zm8"),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg"),
            (b"fooba", "Zm9vYmE"),
            (b"foobar", "Zm9vYmFy"),
            (&[0xfb, 0xff], "-_8"),
        ] {
            let mut out = String::new();
            base64url(input, &mut out).unwrap();
            assert_eq!(out, expected);
        }
    }

    #[test]
    fn base64url_carries_bytes_across_writes() {
        let mut out = String::new();
        let mut encoder = Base64Url::new(&mut out);
        for piece in ["f", "oob", "", "ar", "!"] {
            encoder.write_str(piece).unwrap();
        }
        encoder.finish().unwrap();
        assert_eq!(out, "Zm9vYmFyIQ");
    }

    #[test]
    fn registration_matches_the_protocol_vector() {
        let code = Code::from_canonical("7KQ2MX9D4F").unwrap();
        let mut token = String::new();
        registration(&key(), "kitchen", &code, &mut token).unwrap();
        let (header, claims, signature) = parts(&token);
        assert_eq!(
            header,
            r#"{"alg":"ES256","typ":"JWT","jwk":{"kty":"EC","crv":"P-256","x":"b_A7lJJBzh2t1DUZ5pYOCoW0GmmgXDKBA6orzhWUyhY","y":"PE91OlW_AdxT9sCwx-7ni0DG_30lqW4igrmJzvccFEo"}}"#
        );
        assert_eq!(
            claims,
            r#"{"name":"kitchen","code_mac":"4B-lnFSLFl2S6cWWBxIdJfae5QeTA6PugpvA3LSsw24"}"#
        );
        assert_eq!(signature.len(), 64);
        assert_signed_by_key(&token);
    }

    #[test]
    fn request_token_carries_the_claims_in_order() {
        let token = token("kitchen", 42, "GET", "/items?page=2");
        let (header, claims, _) = parts(&token);
        assert_eq!(header, r#"{"alg":"ES256","typ":"JWT"}"#);
        assert_eq!(
            claims,
            r#"{"sub":"kitchen","jti":"42","htm":"GET","htu":"/items?page=2"}"#
        );
        assert_signed_by_key(&token);
    }

    #[test]
    fn request_token_escapes_json_strings() {
        let token = token("kitchen", 7, "G\"E\\T", "/a\u{1}b\n\u{1f}é\u{7f}");
        let (_, claims, _) = parts(&token);
        assert_eq!(
            claims,
            format!(
                r#"{{"sub":"kitchen","jti":"7","htm":"G\"E\\T","htu":"/a\u0001b\u000a\u001fé{}"}}"#,
                '\u{7f}'
            )
        );
        assert_signed_by_key(&token);
    }

    #[test]
    fn tokens_fit_a_fixed_buffer() {
        let mut out = Fixed::<256>::new();
        request_token(&key(), "kitchen", 42, "GET", "/items?page=2", &mut out).unwrap();
        assert_eq!(out.as_str(), token("kitchen", 42, "GET", "/items?page=2"));

        let mut short = Fixed::<64>::new();
        assert_eq!(
            request_token(&key(), "kitchen", 42, "GET", "/items?page=2", &mut short),
            Err(fmt::Error)
        );
    }
}
