#[path = "../src/c2rust/aes_nohw.rs"]
mod aes_nohw;
use aes_gcm::aead::{generic_array, Aead, KeyInit, Payload};
use aes_gcm::Aes128Gcm;
use aes_nohw::AES_KEY;
use generic_array::typenum::U16;
use generic_array::GenericArray;
use hex_literal::hex;
use log::{debug, error, info, log_enabled, Level};
use std::env;
use std::mem::{self, MaybeUninit};
/// Testuse std::env; vectors

fn init() {
    env::set_var("RUST_LOG", "debug");
    let _ = env_logger::builder().is_test(true).try_init();
    // Set the default log level to debug for tests.
}

#[derive(Debug)]
pub struct TestVector<K: 'static> {
    pub key: &'static K,
    pub nonce: &'static [u8; 12],
    pub aad: &'static [u8],
    pub plaintext: &'static [u8],
    pub ciphertext: &'static [u8],
    pub tag: &'static [u8; 16],
}

const TEST_VECTORS: &[TestVector<[u8; 16]>] = &[TestVector {
    key: &hex!("11754cd72aec309bf52f7687212e8957"),
    nonce: &hex!("3c819d9a9bed087615030b65"),
    plaintext: &hex!(""),
    aad: &hex!(""),
    ciphertext: &hex!(""),
    tag: &hex!("250327c674aaf477aef2675748cf6971"),
}];
