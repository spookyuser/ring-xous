extern crate libc;

#[path = "../src/c2rust/aes_nohw.rs"]
mod aes_nohw;
use aes_nohw::GFp_aes_nohw_set_encrypt_key;
use aes_nohw::AES_KEY;
use ring::aead;

use ring::error;

struct OneNonceSequence(Option<aead::Nonce>);

impl OneNonceSequence {
    /// Constructs the sequence allowing `advance()` to be called
    /// `allowed_invocations` times.
    fn new(nonce: aead::Nonce) -> Self {
        Self(Some(nonce))
    }
}

fn consume_string(key: &str) -> String {
    key.to_string()
}

/// doesn't have the attribute.
fn from_hex_digit(d: u8) -> Result<u8, String> {
    use core::ops::RangeInclusive;
    const DECIMAL: (u8, RangeInclusive<u8>) = (0, b'0'..=b'9');
    const HEX_LOWER: (u8, RangeInclusive<u8>) = (10, b'a'..=b'f');
    const HEX_UPPER: (u8, RangeInclusive<u8>) = (10, b'A'..=b'F');
    for (offset, range) in &[DECIMAL, HEX_LOWER, HEX_UPPER] {
        if range.contains(&d) {
            return Ok(d - range.start() + offset);
        }
    }
    Err(format!("Invalid hex digit '{}'", d as char))
}

impl aead::NonceSequence for OneNonceSequence {
    fn advance(&mut self) -> Result<aead::Nonce, error::Unspecified> {
        self.0.take().ok_or(error::Unspecified)
    }
}

fn make_key<K: aead::BoundKey<OneNonceSequence>>(
    algorithm: &'static aead::Algorithm,
    key: &[u8],
    nonce: aead::Nonce,
) -> K {
    let key = aead::UnboundKey::new(algorithm, key).unwrap();
    let nonce_sequence = OneNonceSequence::new(nonce);
    K::new(key, nonce_sequence)
}

/// Returns the value of an attribute that is encoded as a sequence of an
/// even number of hex digits, or as a double-quoted UTF-8 string. The
/// empty (zero-length) value is represented as "".
fn consume_bytes(key: &str) -> Vec<u8> {
    let s = consume_string(key);
    if s.starts_with('\"') {
        // The value is a quoted UTF-8 string.

        let mut bytes = Vec::with_capacity(s.as_bytes().len() - 2);
        let mut s = s.as_bytes().iter().skip(1);
        loop {
            let b = match s.next() {
                Some(b'\\') => {
                    match s.next() {
                        // We don't allow all octal escape sequences, only "\0" for null.
                        Some(b'0') => 0u8,
                        Some(b't') => b'\t',
                        Some(b'n') => b'\n',
                        // "\xHH"
                        Some(b'x') => {
                            let hi = s.next().expect("Invalid hex escape sequence in string.");
                            let lo = s.next().expect("Invalid hex escape sequence in string.");
                            if let (Ok(hi), Ok(lo)) = (from_hex_digit(*hi), from_hex_digit(*lo)) {
                                (hi << 4) | lo
                            } else {
                                panic!("Invalid hex escape sequence in string.");
                            }
                        }
                        _ => {
                            panic!("Invalid hex escape sequence in string.");
                        }
                    }
                }
                Some(b'"') => {
                    if s.next().is_some() {
                        panic!("characters after the closing quote of a quoted string.");
                    }
                    break;
                }
                Some(b) => *b,
                None => panic!("Missing terminating '\"' in string literal."),
            };
            bytes.push(b);
        }
        bytes
    } else {
        // The value is hex encoded.
        match from_hex(&s) {
            Ok(s) => s,
            Err(err_str) => {
                panic!("{} in {}", err_str, s);
            }
        }
    }
}

fn from_hex(hex_str: &str) -> Result<Vec<u8>, String> {
    if hex_str.len() % 2 != 0 {
        return Err(String::from(
            "Hex string does not have an even number of digits",
        ));
    }

    let mut result = Vec::with_capacity(hex_str.len() / 2);
    for digits in hex_str.as_bytes().chunks(2) {
        let hi = from_hex_digit(digits[0])?;
        let lo = from_hex_digit(digits[1])?;
        result.push((hi * 0x10) | lo);
    }
    Ok(result)
}

fn seal_with_key(
    algorithm: &'static aead::Algorithm,
    key: &[u8],
    nonce: aead::Nonce,
    aad: aead::Aad<&[u8]>,
    in_out: &mut Vec<u8>,
) -> Result<(), error::Unspecified> {
    let mut s_key: aead::SealingKey<OneNonceSequence> = make_key(algorithm, key, nonce);
    s_key.seal_in_place_append_tag(aad, in_out)
}

#[cfg(test)]
mod tests {
    // use ring::c2rust::aes_nohw::aes_key_st;

    use aes_nohw::GFp_aes_nohw_encrypt;

    use super::*;
    use std::os::raw::c_void;

    #[test]
    fn test_GFP_aes_nohw_set_encrypt_key() {
        let key = "your test aes key here".as_bytes();
        let len = key.len();
        // let aes_key: *mut u8 = unsafe { libc::malloc(len) } as *mut _;
        // let mut aes_key = UnboundKey::new(&ring::aead::AES_128_GCM, key).unwrap() as *mut u8;
        let mut key_aes = AES_KEY {
            rd_key: [0u32; 60],
            rounds: 2,
        };

        // if aes_key.is_null() {
        //     panic!("Failed to allocate memory for aes_key");
        // }

        // Call your function
        unsafe {
            GFp_aes_nohw_set_encrypt_key(key.as_ptr(), len as u32, &mut key_aes);
        }

        // Add your assertions here to inspect the result

        // Clean up the allocated memory
        // unsafe { libc::free(aes_key as *mut c_void) };
    }

    #[test]
    fn test_aead_key_debug() {
        let key_bytes = [0; 32];
        let nonce = [0; aead::NONCE_LEN];

        let key: aead::UnboundKey = aead::UnboundKey::new(&aead::AES_256_GCM, &key_bytes).unwrap();
        assert_eq!(
            "UnboundKey { algorithm: AES_256_GCM }",
            format!("{:?}", key)
        );

        let sealing_key: aead::SealingKey<OneNonceSequence> = make_key(
            &aead::AES_256_GCM,
            &key_bytes,
            aead::Nonce::try_assume_unique_for_key(&nonce).unwrap(),
        );
        assert_eq!(
            "SealingKey { algorithm: AES_256_GCM }",
            format!("{:?}", sealing_key)
        );
    }

    #[test]
    fn test_seal_key() {
        let key_bytes = consume_bytes("d480429666d48b400633921c5407d1d1");
        let nonce_bytes = consume_bytes("3388c676dc754acfa66e172a");
        let nonce = aead::Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
        let aad = "hi there".as_bytes();
        let mut in_out = b"plaintext".to_vec();
        let algorithm = &aead::AES_128_GCM;
        seal_with_key(
            algorithm,
            &key_bytes,
            nonce,
            aead::Aad::from(&aad[..]),
            &mut in_out,
        )
        .unwrap();
    }
}
