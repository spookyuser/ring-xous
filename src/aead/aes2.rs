use core::convert::TryInto;
use core::iter::FromIterator;
use core::ptr::slice_from_raw_parts;

use super::aes::AES_KEY;
use super::{counter, iv::Iv, quic::Sample, Block, Direction, BLOCK_LEN};
use aes::cipher::Block as BlockCipher;
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256};
use alloc::vec::{self, Vec};
use core::{mem, slice};
// use aes_ctr::Aes128Ctr;
use crate::{bits::BitLength, c, cpu, debug, endian::*, error, polyfill};

const MAX_ROUNDS: usize = 14;

pub enum Cipher {
    Aes128(Aes128),
    Aes256(Aes256),
}

pub enum Variant {
    AES_128,
    AES_256,
}

pub struct Key {
    inner: Cipher,
}

pub fn block_to_bytes(block: &Block) -> &[u8] {
    unsafe {
        let ptr = block as *const Block as *const u8;
        slice::from_raw_parts(ptr, mem::size_of::<Block>())
    }
}

pub fn bytes_to_block(bytes: &[u8]) -> &Block {
    unsafe {
        let ptr: *const Block = bytes.as_ptr() as *const Block;
        &*ptr
    }
}

impl Key {
    pub fn new(bytes: &[u8], variant: Variant) -> Result<Self, error::Unspecified> {
        let cipher: Cipher = match variant {
            Variant::AES_128 => Cipher::Aes128(Aes128::new_from_slice(bytes).unwrap()),
            Variant::AES_256 => Cipher::Aes256(Aes256::new_from_slice(bytes).unwrap()),
        };

        Ok(Self { inner: cipher })
    }

    pub fn encrypt_block(&self, input: &Block) -> Result<Block, ()> {
        let input = block_to_bytes(input);
        let mut block = GenericArray::clone_from_slice(input);

        match &self.inner {
            Cipher::Aes128(cipher) => cipher.encrypt_block(&mut block),
            Cipher::Aes256(cipher) => cipher.encrypt_block(&mut block),
        }
        // Turn the beneric block arraay into a block
        Ok(*bytes_to_block(&block))
    }

    // pub fn ctr32_encrypt_blocks(&self, input: &[u8], iv: &[u8], n: usize) -> Result<Vec<u8>, ()> {
    //     if input.len() % 16 != 0 || iv.len() != 16 {
    //         return Err(());
    //     }

    //     let mut nonce = GenericArray::clone_from_slice(iv);
    //     let mut buffer = vec![0u8; n * 16];
    //     let key = GenericArray::clone_from_slice(&self.inner);

    //     let mut cipher = Aes128Ctr::from_block_cipher(key, &nonce);
    //     cipher.apply_keystream(&mut buffer);

    //     Ok(buffer)
    // }
}

#[cfg(test)]
mod tests {
    use super::{super::BLOCK_LEN, *};
    use crate::test;
    use core::convert::TryInto;

    #[test]
    pub fn test_aes() {
        test::run(test_file!("aes_tests.txt"), |section, test_case| {
            assert_eq!(section, "");
            let key = consume_key(test_case, "Key");
            let input = test_case.consume_bytes("Input");
            let input: &[u8; BLOCK_LEN] = input.as_slice().try_into()?;
            let expected_output = test_case.consume_bytes("Output");

            let block = Block::from(input);
            let output = key.encrypt_block(&block).unwrap();
            assert_eq!(output.as_ref(), &expected_output[..]);

            Ok(())
        })
    }

    fn consume_key(test_case: &mut test::TestCase, name: &str) -> Key {
        let key = test_case.consume_bytes(name);
        let variant = match key.len() {
            16 => Variant::AES_128,
            32 => Variant::AES_256,
            _ => unreachable!(),
        };
        Key::new(&key[..], variant).unwrap()
    }
}
