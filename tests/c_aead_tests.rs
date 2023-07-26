// Copyright 2015-2016 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use core::ops::RangeFrom;
use log::{debug, error, info, log_enabled, Level};
use ring::{aead, error, test, test_file};
use std::env;

fn init() {
    env::set_var("RUST_LOG", "debug");
    let _ = env_logger::builder().is_test(true).try_init();
    // Set the default log level to debug for tests.
}

#[test]
fn testy_test() {
    init();
    // Make some variables for the key_bytes etc before we consume them
    let key_bytes_str = "3881e7be1bb3bbcaff20bdb78e5d1b67";
    let nonce_bytes_str = "dcf5b7ae2d7552e2297fcfa9";
    let plaintext_str = "0a2714aa7d";
    let aad_str = "c60c64bbf7";
    let ct_str = "5626f96ecb";
    let tag_str = "ff4c4f1d92b0abb1d0820833d9eb83c7";

    // Debug all inputs

    let key_bytes = consume_bytes(key_bytes_str);
    let nonce_bytes = consume_bytes(nonce_bytes_str);
    let plaintext = consume_bytes(plaintext_str);
    let aad: Vec<u8> = consume_bytes(aad_str);
    let mut ct: Vec<u8> = consume_bytes(ct_str);
    let tag = consume_bytes(tag_str);
    let error = consume_string("Error");
    let algorithm = &aead::AES_128_GCM;

    debug!("key_bytes: {:?}", key_bytes_str);
    debug!("nonce_bytes: {:?}", nonce_bytes_str);
    debug!("plaintext: {:?}", plaintext_str);
    debug!("aad: {:?}", aad_str);
    debug!("ct: {:?}", ct_str);
    debug!("tag: {:?}", tag_str);

    // match &error {
    //     Some(err) if err == "WRONG_NONCE_LENGTH" => {
    //         assert!(aead::Nonce::try_assume_unique_for_key(&nonce_bytes).is_err());
    //         return Ok(());
    //     }
    //     _ => (),
    // };

    let mut s_in_out = plaintext.clone();
    let nonce: aead::Nonce = aead::Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
    let s_result = seal_with_key(
        algorithm,
        &key_bytes[..],
        nonce,
        aead::Aad::from(&aad[..]),
        &mut s_in_out,
    );

    ct.extend(tag);
    debug!("Expected ct: {:?}", ct_str);
    debug!(
        "Actual ct: {:?}",
        hex::encode(&s_in_out).split_at(ct_str.len()).0
    );

    if s_result.is_ok() {
        assert_eq!(&ct, &s_in_out);
        debug!("Okay")
    }

    // In release builds, test all prefix lengths from 0 to 4096 bytes.
    // Debug builds are too slow for this, so for those builds, only
    // test a smaller subset.

    // TLS record headers are 5 bytes long.
    // TLS explicit nonces for AES-GCM are 8 bytes long.
    static MINIMAL_IN_PREFIX_LENS: [usize; 36] = [
        // No input prefix to overwrite; i.e. the opening is exactly
        // "in place."
        0,
        1,
        2,
        // Proposed TLS 1.3 header (no explicit nonce).
        5,
        8,
        // Probably the most common use of a non-zero `in_prefix_len`
        // would be to write a decrypted TLS record over the top of the
        // TLS header and nonce.
        5 /* record header */ + 8, /* explicit nonce */
        // The stitched AES-GCM x86-64 code works on 6-block (96 byte)
        // units. Some of the ChaCha20 code is even weirder.
        15,  // The maximum partial AES block.
        16,  // One AES block.
        17,  // One byte more than a full AES block.
        31,  // 2 AES blocks or 1 ChaCha20 block, minus 1.
        32,  // Two AES blocks, one ChaCha20 block.
        33,  // 2 AES blocks or 1 ChaCha20 block, plus 1.
        47,  // Three AES blocks - 1.
        48,  // Three AES blocks.
        49,  // Three AES blocks + 1.
        63,  // Four AES blocks or two ChaCha20 blocks, minus 1.
        64,  // Four AES blocks or two ChaCha20 blocks.
        65,  // Four AES blocks or two ChaCha20 blocks, plus 1.
        79,  // Five AES blocks, minus 1.
        80,  // Five AES blocks.
        81,  // Five AES blocks, plus 1.
        95,  // Six AES blocks or three ChaCha20 blocks, minus 1.
        96,  // Six AES blocks or three ChaCha20 blocks.
        97,  // Six AES blocks or three ChaCha20 blocks, plus 1.
        111, // Seven AES blocks, minus 1.
        112, // Seven AES blocks.
        113, // Seven AES blocks, plus 1.
        127, // Eight AES blocks or four ChaCha20 blocks, minus 1.
        128, // Eight AES blocks or four ChaCha20 blocks.
        129, // Eight AES blocks or four ChaCha20 blocks, plus 1.
        143, // Nine AES blocks, minus 1.
        144, // Nine AES blocks.
        145, // Nine AES blocks, plus 1.
        255, // 16 AES blocks or 8 ChaCha20 blocks, minus 1.
        256, // 16 AES blocks or 8 ChaCha20 blocks.
        257, // 16 AES blocks or 8 ChaCha20 blocks, plus 1.
    ];

    let mut more_comprehensive_in_prefix_lengths = [0; 4096];
    let in_prefix_lengths = if cfg!(debug_assertions) {
        &MINIMAL_IN_PREFIX_LENS[..]
    } else {
        #[allow(clippy::needless_range_loop)]
        for b in 0..more_comprehensive_in_prefix_lengths.len() {
            more_comprehensive_in_prefix_lengths[b] = b;
        }
        &more_comprehensive_in_prefix_lengths[..]
    };
    let mut o_in_out = vec![123u8; 4096];

    for &in_prefix_len in in_prefix_lengths.iter() {
        o_in_out.truncate(0);
        o_in_out.resize(in_prefix_len, 123);
        o_in_out.extend_from_slice(&ct[..]);

        let nonce = aead::Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
        let o_result = open_with_key(
            algorithm,
            &key_bytes,
            nonce,
            aead::Aad::from(&aad[..]),
            &mut o_in_out,
            in_prefix_len..,
        );
    }
}

fn consume_bytes(key: &str) -> Vec<u8> {
    let s = consume_string(key);
    if s.starts_with('\"') {
        // The value is a quoted UTF-8 string.

        let mut bytes = Vec::with_capacity(s.as_bytes().len() - 2);
        let mut s: std::iter::Skip<std::slice::Iter<'_, u8>> = s.as_bytes().iter().skip(1);
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

fn consume_string(key: &str) -> String {
    key.to_string()
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

fn open_with_key<'a>(
    algorithm: &'static aead::Algorithm,
    key: &[u8],
    nonce: aead::Nonce,
    aad: aead::Aad<&[u8]>,
    in_out: &'a mut [u8],
    ciphertext_and_tag: RangeFrom<usize>,
) -> Result<&'a mut [u8], error::Unspecified> {
    let mut o_key: aead::OpeningKey<OneNonceSequence> = make_key(algorithm, key, nonce);
    o_key.open_within(aad, in_out, ciphertext_and_tag)
}

fn seal_with_less_safe_key(
    algorithm: &'static aead::Algorithm,
    key: &[u8],
    nonce: aead::Nonce,
    aad: aead::Aad<&[u8]>,
    in_out: &mut Vec<u8>,
) -> Result<(), error::Unspecified> {
    let key = make_less_safe_key(algorithm, key);
    key.seal_in_place_append_tag(nonce, aad, in_out)
}

fn open_with_less_safe_key<'a>(
    algorithm: &'static aead::Algorithm,
    key: &[u8],
    nonce: aead::Nonce,
    aad: aead::Aad<&[u8]>,
    in_out: &'a mut [u8],
    ciphertext_and_tag: RangeFrom<usize>,
) -> Result<&'a mut [u8], error::Unspecified> {
    let key = make_less_safe_key(algorithm, key);
    key.open_within(nonce, aad, in_out, ciphertext_and_tag)
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn test_aead_key_debug() {
    let key_bytes = [0; 32];
    let nonce = [0; aead::NONCE_LEN];

    let key = aead::UnboundKey::new(&aead::AES_256_GCM, &key_bytes).unwrap();
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

    let opening_key: aead::OpeningKey<OneNonceSequence> = make_key(
        &aead::AES_256_GCM,
        &key_bytes,
        aead::Nonce::try_assume_unique_for_key(&nonce).unwrap(),
    );
    assert_eq!(
        "OpeningKey { algorithm: AES_256_GCM }",
        format!("{:?}", opening_key)
    );

    let key: aead::LessSafeKey = make_less_safe_key(&aead::AES_256_GCM, &key_bytes);
    assert_eq!(
        "LessSafeKey { algorithm: AES_256_GCM }",
        format!("{:?}", key)
    );
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

fn make_less_safe_key(algorithm: &'static aead::Algorithm, key: &[u8]) -> aead::LessSafeKey {
    let key = aead::UnboundKey::new(algorithm, key).unwrap();
    aead::LessSafeKey::new(key)
}

struct OneNonceSequence(Option<aead::Nonce>);

impl OneNonceSequence {
    /// Constructs the sequence allowing `advance()` to be called
    /// `allowed_invocations` times.
    fn new(nonce: aead::Nonce) -> Self {
        Self(Some(nonce))
    }
}

impl aead::NonceSequence for OneNonceSequence {
    fn advance(&mut self) -> Result<aead::Nonce, error::Unspecified> {
        self.0.take().ok_or(error::Unspecified)
    }
}
