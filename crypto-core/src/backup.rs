use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use getrandom::fill;
use zeroize::Zeroizing;

use crate::{CryptoError, Result, key_wrap::PinKeyWrap};

const BACKUP_MAGIC: [u8; 8] = *b"USTOYBP1";
const KEY_WRAP_LEN: usize = 8 + 16 + 12 + 48;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const MAX_BACKUP_SIZE: usize = 128 * 1024 * 1024;

/// Encrypts an optional backup layer using the same Argon2id key-wrap parameters as profile PINs.
pub fn encrypt_backup(password: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    if plaintext.len() > MAX_BACKUP_SIZE {
        return Err(CryptoError::PayloadTooLarge);
    }

    let mut data_key = Zeroizing::new([0u8; 32]);
    fill(&mut *data_key).map_err(|_| CryptoError::Randomness)?;
    let wrapped_key = PinKeyWrap::create(password, &data_key)?.to_bytes();
    let cipher = ChaCha20Poly1305::new_from_slice(data_key.as_ref())
        .map_err(|_| CryptoError::CryptoOperation)?;
    let mut nonce = [0u8; NONCE_LEN];
    fill(&mut nonce).map_err(|_| CryptoError::Randomness)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &BACKUP_MAGIC,
            },
        )
        .map_err(|_| CryptoError::CryptoOperation)?;

    let mut output =
        Vec::with_capacity(BACKUP_MAGIC.len() + KEY_WRAP_LEN + NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&BACKUP_MAGIC);
    output.extend_from_slice(&wrapped_key);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypts a password-protected backup; the password-derived key never leaves this function.
pub fn decrypt_backup(password: &str, encoded: &[u8]) -> Result<Vec<u8>> {
    let header_len = BACKUP_MAGIC.len() + KEY_WRAP_LEN + NONCE_LEN;
    if encoded.len() < header_len + TAG_LEN
        || encoded.len() > header_len + MAX_BACKUP_SIZE + TAG_LEN
        || encoded[..BACKUP_MAGIC.len()] != BACKUP_MAGIC
    {
        return Err(CryptoError::InvalidSnapshot);
    }

    let wrapped =
        PinKeyWrap::from_bytes(&encoded[BACKUP_MAGIC.len()..BACKUP_MAGIC.len() + KEY_WRAP_LEN])?;
    let data_key = wrapped.unwrap(password)?.ok_or(CryptoError::InvalidPin)?;
    let nonce_start = BACKUP_MAGIC.len() + KEY_WRAP_LEN;
    let cipher = ChaCha20Poly1305::new_from_slice(data_key.as_ref())
        .map_err(|_| CryptoError::CryptoOperation)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&encoded[nonce_start..nonce_start + NONCE_LEN]),
                Payload {
                    msg: &encoded[header_len..],
                    aad: &BACKUP_MAGIC,
                },
            )
            .map_err(|_| CryptoError::Authentication)?,
    );
    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_round_trips_with_argon2id_password_and_authenticates_contents() {
        let plaintext = b"encrypted IndexedDB container";
        let encoded = encrypt_backup("backup-password-42", plaintext).unwrap();
        assert_eq!(
            decrypt_backup("backup-password-42", &encoded).unwrap(),
            plaintext
        );
        assert!(matches!(
            decrypt_backup("wrong-password-42", &encoded),
            Err(CryptoError::InvalidPin)
        ));

        let last = encoded.len() - 1;
        let mut tampered = encoded;
        tampered[last] ^= 1;
        assert!(matches!(
            decrypt_backup("backup-password-42", &tampered),
            Err(CryptoError::Authentication)
        ));
    }
}
