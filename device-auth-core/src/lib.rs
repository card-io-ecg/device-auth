#![cfg_attr(not(test), no_std)]

use core::fmt;

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Response header that carries the server's last accepted counter when it refuses a stale `jti`.
pub const COUNTER_HEADER: &str = "X-Request-Counter";

/// Pairing-code alphabet. A code byte's low 5 bits index into it.
pub const ALPHABET: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub const CODE_LEN: usize = 10;

pub const NAME_MAX_LEN: usize = 32;

/// Length of an uncompressed SEC1 P-256 public key.
pub const PUBLIC_KEY_LEN: usize = 65;

pub const CODE_MAC_LEN: usize = 32;

/// Returns whether `name` is 1 to 32 bytes of ASCII letters, digits, and `-`.
pub fn valid_name(name: &str) -> bool {
    (1..=NAME_MAX_LEN).contains(&name.len())
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// A canonical pairing code: 10 characters of [`ALPHABET`], without the display hyphen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Code([u8; CODE_LEN]);

impl Code {
    /// Accepts exactly 10 characters of [`ALPHABET`]. A hyphen, a lower-case letter, or any
    /// other character returns `None`. Typed input is normalized by the firmware crate first.
    pub fn from_canonical(code: &str) -> Option<Self> {
        let bytes: [u8; CODE_LEN] = code.as_bytes().try_into().ok()?;
        bytes
            .iter()
            .all(|b| ALPHABET.as_bytes().contains(b))
            .then_some(Self(bytes))
    }

    /// Maps each byte's low 5 bits to a character. Uniform random bytes give a uniform code.
    pub fn from_random(bytes: [u8; CODE_LEN]) -> Self {
        Self(bytes.map(|b| ALPHABET.as_bytes()[usize::from(b & 0x1f)]))
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.0).expect("the alphabet is ASCII")
    }
}

/// Formats the form shown to a person: two groups of five joined by `-`, such as
/// `7KQ2M-X9D4F`. Store [`Code::as_str`] instead, because only the canonical form matches.
impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (first, second) = self.as_str().split_at(CODE_LEN / 2);
        write!(f, "{first}-{second}")
    }
}

/// HMAC-SHA256 over `public_key`, keyed with the canonical code's ASCII bytes.
///
/// `public_key` is the uncompressed SEC1 point: `0x04`, then the 32-byte `x` and `y`.
pub fn code_mac(code: &Code, public_key: &[u8; PUBLIC_KEY_LEN]) -> [u8; CODE_MAC_LEN] {
    mac(code, public_key).finalize().into_bytes().into()
}

/// Compares `expected` with [`code_mac`] in constant time.
pub fn verify_code_mac(
    code: &Code,
    public_key: &[u8; PUBLIC_KEY_LEN],
    expected: &[u8; CODE_MAC_LEN],
) -> bool {
    mac(code, public_key).verify_slice(expected).is_ok()
}

fn mac(code: &Code, public_key: &[u8; PUBLIC_KEY_LEN]) -> Hmac<Sha256> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&code.0).expect("HMAC accepts a key of any length");
    mac.update(public_key);
    mac
}

#[cfg(test)]
mod tests {
    use super::*;

    // The P-256 public key of the scalar 32 bytes of 0x01.
    const PUBLIC_KEY: &str = "046ff03b949241ce1dadd43519e6960e0a85b41a69a05c328103aa2bce1594ca163c4f753a55bf01dc53f6c0b0c7eee78b40c6ff7d25a96e2282b989cef71c144a";
    const MAC: &str = "e01fa59c548b165d92e9c59607121d25f69ee5079303a3ee829bc0dcb4acc36e";

    fn hex<const N: usize>(text: &str) -> [u8; N] {
        let mut bytes = [0; N];
        for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().chunks(2)) {
            *byte = u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap();
        }
        bytes
    }

    fn code() -> Code {
        Code::from_canonical("7KQ2MX9D4F").unwrap()
    }

    #[test]
    fn names_are_short_ascii_words() {
        assert!(valid_name("kitchen-sensor-2"));
        assert!(valid_name(&"a".repeat(32)));
        assert!(!valid_name(""));
        assert!(!valid_name(&"a".repeat(33)));
        assert!(!valid_name("sensor_1"));
        assert!(!valid_name("sensor 1"));
        assert!(!valid_name("sensör"));
    }

    #[test]
    fn canonical_codes_are_ten_alphabet_characters() {
        assert_eq!(code().as_str(), "7KQ2MX9D4F");
        assert_eq!(Code::from_canonical("7KQ2M-X9D4"), None);
        assert_eq!(Code::from_canonical("7kq2mx9d4f"), None);
        assert_eq!(Code::from_canonical("7KQ2MX9D4"), None);
        assert_eq!(Code::from_canonical("7KQ2MX9D4FF"), None);
        assert_eq!(Code::from_canonical("7KQ2MX9D4U"), None);
    }

    #[test]
    fn random_bytes_use_the_low_five_bits() {
        let code = Code::from_random([0, 1, 9, 10, 31, 32, 0x41, 0xff, 0xe0, 0x1f]);
        assert_eq!(code.as_str(), "019AZ01Z0Z");
    }

    #[test]
    fn display_groups_by_five() {
        assert_eq!(code().to_string(), "7KQ2M-X9D4F");
    }

    #[test]
    fn code_mac_matches_the_protocol_vector() {
        let public_key = hex::<PUBLIC_KEY_LEN>(PUBLIC_KEY);
        assert_eq!(code_mac(&code(), &public_key), hex::<CODE_MAC_LEN>(MAC));
        assert!(verify_code_mac(&code(), &public_key, &hex(MAC)));
        let other = Code::from_canonical("7KQ2MX9D4G").unwrap();
        assert!(!verify_code_mac(&other, &public_key, &hex(MAC)));
    }

    #[test]
    fn counter_header_name() {
        assert_eq!(COUNTER_HEADER, "X-Request-Counter");
    }
}
