use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use getrandom::fill;
use zeroize::{Zeroize, Zeroizing};

use crate::{CryptoError, Result};

const KEY_WRAP_MAGIC: [u8; 8] = *b"USTOYKW1";
const PIN_SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const PROFILE_KEY_LEN: usize = 32;
const KEY_WRAP_LEN: usize = KEY_WRAP_MAGIC.len() + PIN_SALT_LEN + NONCE_LEN + 48;

pub struct PinKeyWrap {
    salt: [u8; PIN_SALT_LEN],
    nonce: [u8; NONCE_LEN],
    ciphertext: Zeroizing<[u8; 48]>,
}

impl PinKeyWrap {
    pub fn create(pin: &str, data_key: &[u8; PROFILE_KEY_LEN]) -> Result<Self> {
        if pin.len() < 8 {
            return Err(CryptoError::InvalidPin);
        }
        let mut salt = [0u8; PIN_SALT_LEN];
        fill(&mut salt).map_err(|_| CryptoError::Randomness)?;
        let wrapping_key = argon2id_key(pin, &salt)?;
        let cipher = ChaCha20Poly1305::new_from_slice(wrapping_key.as_ref())
            .map_err(|_| CryptoError::CryptoOperation)?;
        let mut nonce = [0u8; NONCE_LEN];
        fill(&mut nonce).map_err(|_| CryptoError::Randomness)?;
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: data_key,
                    aad: &KEY_WRAP_MAGIC,
                },
            )
            .map_err(|_| CryptoError::CryptoOperation)?;
        let ciphertext = encrypted
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::CryptoOperation)?;
        Ok(Self {
            salt,
            nonce,
            ciphertext: Zeroizing::new(ciphertext),
        })
    }

    pub fn from_bytes(encoded: &[u8]) -> Result<Self> {
        if encoded.len() != KEY_WRAP_LEN || encoded[..8] != KEY_WRAP_MAGIC {
            return Err(CryptoError::InvalidSnapshot);
        }
        let salt = encoded[8..8 + PIN_SALT_LEN]
            .try_into()
            .map_err(|_| CryptoError::InvalidSnapshot)?;
        let nonce = encoded[8 + PIN_SALT_LEN..8 + PIN_SALT_LEN + NONCE_LEN]
            .try_into()
            .map_err(|_| CryptoError::InvalidSnapshot)?;
        let ciphertext = encoded[8 + PIN_SALT_LEN + NONCE_LEN..]
            .try_into()
            .map_err(|_| CryptoError::InvalidSnapshot)?;
        Ok(Self {
            salt,
            nonce,
            ciphertext: Zeroizing::new(ciphertext),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(KEY_WRAP_LEN);
        encoded.extend_from_slice(&KEY_WRAP_MAGIC);
        encoded.extend_from_slice(&self.salt);
        encoded.extend_from_slice(&self.nonce);
        encoded.extend_from_slice(&self.ciphertext[..]);
        encoded
    }

    pub fn unwrap(&self, pin: &str) -> Result<Option<Zeroizing<[u8; PROFILE_KEY_LEN]>>> {
        let wrapping_key = argon2id_key(pin, &self.salt)?;
        let cipher = ChaCha20Poly1305::new_from_slice(wrapping_key.as_ref())
            .map_err(|_| CryptoError::CryptoOperation)?;
        let plaintext = match cipher.decrypt(
            Nonce::from_slice(&self.nonce),
            Payload {
                msg: &self.ciphertext[..],
                aad: &KEY_WRAP_MAGIC,
            },
        ) {
            Ok(plaintext) => Zeroizing::new(plaintext),
            Err(_) => return Ok(None),
        };
        let key = <[u8; PROFILE_KEY_LEN]>::try_from(plaintext.as_slice())
            .map_err(|_| CryptoError::InvalidPin)?;
        Ok(Some(Zeroizing::new(key)))
    }

    pub fn erase(&mut self) {
        self.salt.zeroize();
        self.nonce.zeroize();
        self.ciphertext.zeroize();
    }
}

impl Drop for PinKeyWrap {
    fn drop(&mut self) {
        self.erase();
    }
}

fn argon2id_key(pin: &str, salt: &[u8; PIN_SALT_LEN]) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(65_536, 3, 1, Some(32)).map_err(|_| CryptoError::CryptoOperation)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(pin.as_bytes(), salt, key.as_mut())
        .map_err(|_| CryptoError::CryptoOperation)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_key_wrap_round_trips_and_rejects_wrong_pins() {
        let data_key = [0x72; PROFILE_KEY_LEN];
        let wrapped = PinKeyWrap::create("correct-horse-42", &data_key).unwrap();
        let encoded = wrapped.to_bytes();
        let restored = PinKeyWrap::from_bytes(&encoded).unwrap();

        assert_eq!(
            restored.unwrap("correct-horse-42").unwrap().as_ref(),
            &data_key
        );
        assert!(restored.unwrap("wrong-pin-42").unwrap().is_none());
    }

    #[test]
    fn rejects_malformed_wrappers() {
        assert!(matches!(
            PinKeyWrap::from_bytes(&[0; KEY_WRAP_LEN]),
            Err(CryptoError::InvalidSnapshot)
        ));
        assert!(matches!(
            PinKeyWrap::create("short", &[0x11; PROFILE_KEY_LEN]),
            Err(CryptoError::InvalidPin)
        ));
    }
}
