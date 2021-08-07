// Copyright 2021 Jedrzej Stuczynski
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pub use cipher::{self, generic_array::GenericArray, BlockCipher, NewBlockCipher};
use cipher::{
    generic_array::{
        typenum::{bit::B1, Double, Sum, Unsigned},
        ArrayLength,
    },
    BlockCipherKey, CipherKey, NewCipher, StreamCipher,
};
use crypto_mac::{Key as MacKey, Mac, NewMac};
use std::ops::{Add, Shl};

#[cfg(feature = "block-cipher")]
pub use cipher::{Block, BlockDecrypt, BlockEncrypt};
#[cfg(feature = "block-cipher")]
use generic_array::typenum::U1;
#[cfg(feature = "block-cipher")]
use std::marker::PhantomData;

fn xor_in_place(a: &mut [u8], b: &[u8]) {
    for (ai, bi) in a.iter_mut().zip(b.iter()) {
        *ai ^= *bi;
    }
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(ai, bi)| *ai ^ *bi).collect()
}

fn left_xor_assign_digest<H>(left: &mut [u8], right: &[u8], digest_key: &MacKey<H>)
where
    H: Mac + NewMac,
{
    let mut h = H::new(digest_key);
    h.update(right);
    let tmp = h.finalize().into_bytes();
    xor_in_place(left, &*tmp);
}

fn right_xor_assign_stream<S>(left: &[u8], right: &mut [u8], stream_key_half: &CipherKey<S>)
where
    S: StreamCipher + NewCipher,
{
    let stream_key = xor(left, stream_key_half);

    // TODO: a potential change in the future: allow for optionally passing non-zero IVs
    let mut s = S::new(
        &GenericArray::from_exact_iter(stream_key).unwrap(),
        &Default::default(),
    );
    s.apply_keystream(right); // XORs keystream with data
}

#[derive(Debug)]
pub struct InvalidBlockLength;

pub struct Lioness<S, H>
where
    S: StreamCipher + NewCipher,
    H: Mac + NewMac,
{
    k1: GenericArray<u8, S::KeySize>,
    k2: GenericArray<u8, H::KeySize>,
    k3: GenericArray<u8, S::KeySize>,
    k4: GenericArray<u8, H::KeySize>,
}

impl<S, H> Lioness<S, H>
where
    S: StreamCipher + NewCipher,
    H: Mac + NewMac,
{
    pub fn encrypt_block(&self, block: &mut [u8]) -> Result<(), InvalidBlockLength> {
        if block.len() <= H::OutputSize::to_usize() {
            return Err(InvalidBlockLength);
        }

        let (left, right) = block.split_at_mut(H::OutputSize::to_usize());

        //// R = R ^ S(L ^ K1)
        right_xor_assign_stream::<S>(left, right, &self.k1);

        //// L = L ^ H(K2, R)
        left_xor_assign_digest::<H>(left, right, &self.k2);

        //// R = R ^ S(L ^ K3)
        right_xor_assign_stream::<S>(left, right, &self.k3);

        //// L = L ^ H(K4, R)
        left_xor_assign_digest::<H>(left, right, &self.k4);

        Ok(())
    }

    // TODO: return error if block is too small
    pub fn decrypt_block(&self, block: &mut [u8]) -> Result<(), InvalidBlockLength> {
        if block.len() <= H::OutputSize::to_usize() {
            return Err(InvalidBlockLength);
        }

        let (left, right) = block.split_at_mut(H::OutputSize::to_usize());

        //// L = L ^ H(K4, R)
        left_xor_assign_digest::<H>(left, right, &self.k4);

        //// R = R ^ S(L ^ K3)
        right_xor_assign_stream::<S>(left, right, &self.k3);

        //// L = L ^ H(K2, R)
        left_xor_assign_digest::<H>(left, right, &self.k2);

        //// R = R ^ S(L ^ K1)
        right_xor_assign_stream::<S>(left, right, &self.k1);

        Ok(())
    }
}

impl<S, H> NewBlockCipher for Lioness<S, H>
where
    S: StreamCipher + NewCipher,
    H: Mac + NewMac,

    // requirements for being able to sum key lengths
    S::KeySize: Add<H::KeySize>,
    Sum<S::KeySize, H::KeySize>: ArrayLength<u8>,

    // requirements for being able to double the sum
    Sum<S::KeySize, H::KeySize>: Shl<B1>,
    Double<Sum<S::KeySize, H::KeySize>>: ArrayLength<u8>,
{
    type KeySize = Double<Sum<S::KeySize, H::KeySize>>;

    fn new(key: &BlockCipherKey<Self>) -> Self {
        assert!(H::OutputSize::to_usize() >= S::KeySize::to_usize());

        let sck = S::KeySize::to_usize();
        let hk = H::KeySize::to_usize();
        Lioness {
            k1: GenericArray::clone_from_slice(&key[..sck]),
            k2: GenericArray::clone_from_slice(&key[sck..sck + hk]),
            k3: GenericArray::clone_from_slice(&key[sck + hk..2 * sck + hk]),
            k4: GenericArray::clone_from_slice(&key[2 * sck + hk..]),
        }
    }
}

#[cfg(feature = "block-cipher")]
pub struct BlockLioness<S, H, N>
where
    S: StreamCipher + NewCipher,
    H: Mac + NewMac,
{
    inner: Lioness<S, H>,
    block_size: PhantomData<*const N>,
}

#[cfg(feature = "block-cipher")]
impl<S, H, N> NewBlockCipher for BlockLioness<S, H, N>
where
    S: StreamCipher + NewCipher,
    H: Mac + NewMac,
    N: ArrayLength<u8>,

    // requirements for being able to sum key lengths
    S::KeySize: Add<H::KeySize>,
    Sum<S::KeySize, H::KeySize>: ArrayLength<u8>,

    // requirements for being able to double the sum
    Sum<S::KeySize, H::KeySize>: Shl<B1>,
    Double<Sum<S::KeySize, H::KeySize>>: ArrayLength<u8>,
{
    type KeySize = Double<Sum<S::KeySize, H::KeySize>>;

    fn new(key: &BlockCipherKey<Self>) -> Self {
        assert!(N::to_usize() > H::OutputSize::to_usize());

        BlockLioness {
            inner: Lioness::new(key),
            block_size: Default::default(),
        }
    }
}

#[cfg(feature = "block-cipher")]
impl<S, H, N> BlockCipher for BlockLioness<S, H, N>
where
    S: StreamCipher + NewCipher,
    H: Mac + NewMac,
    N: ArrayLength<u8>,
{
    type BlockSize = N;
    type ParBlocks = U1;
}

#[cfg(feature = "block-cipher")]
impl<S, H, N> BlockEncrypt for BlockLioness<S, H, N>
where
    S: StreamCipher + NewCipher,
    H: Mac + NewMac,
    N: ArrayLength<u8>,
{
    fn encrypt_block(&self, block: &mut Block<Self>) {
        self.inner.encrypt_block(block).unwrap()
    }
}

#[cfg(feature = "block-cipher")]
impl<S, H, N> BlockDecrypt for BlockLioness<S, H, N>
where
    S: StreamCipher + NewCipher,
    H: Mac + NewMac,
    N: ArrayLength<u8>,
{
    fn decrypt_block(&self, block: &mut Block<Self>) {
        self.inner.decrypt_block(block).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blake3::Hasher as Blake3;
    use chacha20::ChaCha20;

    #[test]
    fn cipher_creation_works_for_chacha20_blake3_variant() {
        type Cipher = Lioness<ChaCha20, Blake3>;
        let zero_key = GenericArray::default();
        Cipher::new(&zero_key);
    }

    #[test]
    fn encryption_is_reciprocal_to_decryption_for_chacha20_blake3_variant() {
        type Cipher = Lioness<ChaCha20, Blake3>;

        let key = GenericArray::from(b"my-awesome-key-that-is-perfect-length-to-work-with-chacha20-and-blake3-lioness-cipher-after-adding-a-little-bit-of-extra-padding".to_owned());

        let data = b"Hello there! This is some test data that has length at least as long as the digest size of Blake3.";
        let mut block = *data;

        let cipher = Cipher::new(&key);
        cipher.encrypt_block(&mut block).unwrap();

        // make sure encryption actually did something
        assert_ne!(data.to_vec(), block.to_vec());

        cipher.decrypt_block(&mut block).unwrap();
        assert_eq!(data.to_vec(), block.to_vec());
    }

    #[cfg(feature = "block-cipher")]
    #[test]
    fn cipher_creation_works_for_block_chacha20_blake3_variant() {
        use generic_array::typenum::U64;

        type Cipher = BlockLioness<ChaCha20, Blake3, U64>;
        let zero_key = GenericArray::default();
        Cipher::new(&zero_key);
    }

    #[cfg(feature = "block-cipher")]
    #[test]
    fn encryption_is_reciprocal_to_decryption_for_block_chacha20_blake3_variant() {
        use generic_array::typenum::U64;

        type Cipher = BlockLioness<ChaCha20, Blake3, U64>;

        let key = GenericArray::from(b"my-awesome-key-that-is-perfect-length-to-work-with-chacha20-and-blake3-lioness-cipher-after-adding-a-little-bit-of-extra-padding".to_owned());

        let data = b"This is some test data of the same length as specified blockSize".to_owned();
        let mut block = GenericArray::from(data);

        let cipher = Cipher::new(&key);
        cipher.encrypt_block(&mut block);

        // make sure encryption actually did something
        assert_ne!(data.to_vec(), block.to_vec());

        cipher.decrypt_block(&mut block);
        assert_eq!(data.to_vec(), block.to_vec());
    }

    // TODO: further testing with proper vectors, edge cases, etc.
}
