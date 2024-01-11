use libsm::sm4::{cipher_mode::Sm4CipherMode, Cipher, Mode};
use wasm_bindgen::prelude::*;

const DEFAULT_KEY: &[u8; 16] = b"\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10";

#[wasm_bindgen]
pub struct SM4 {
    cipher: Sm4CipherMode,
    key: Vec<u8>,
}

#[wasm_bindgen]
impl SM4 {
    #[wasm_bindgen(constructor)]
    pub fn new() -> SM4 {
        SM4 {
            cipher: Cipher::new(DEFAULT_KEY, Mode::Cbc),
            key: DEFAULT_KEY.to_vec(),
        }
    }

    pub fn new_with_key(key: &[u8]) -> SM4 {
        SM4 {
            cipher: Cipher::new(key, Mode::Cbc),
            key: key.to_vec(),
        }
    }

    #[wasm_bindgen]
    pub fn encrypt(&self, plain_buffer: &[u8]) -> Vec<u8> {
        self.cipher.encrypt(plain_buffer, &self.key)
    }

    #[wasm_bindgen]
    pub fn decrypt(&self, cipher_buffer: &[u8]) -> Vec<u8> {
        self.cipher.decrypt(cipher_buffer, &self.key)
    }
}
