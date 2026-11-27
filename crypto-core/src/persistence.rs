use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use getrandom::fill;
use zeroize::Zeroizing;

use crate::{CryptoError, session::SessionState};

const LOCAL_RECORD_MAGIC: [u8; 8] = *b"USTOYLR1";
const LOCAL_RECORD_NONCE_LEN: usize = 12;
const MAX_LOCAL_RECORD_SIZE: usize = 16 * 1024 * 1024;

pub trait StateStorage {
    type Error;

    fn store_encrypted_session(
        &mut self,
        local_session_key: &[u8; 32],
        snapshot: &[u8],
    ) -> std::result::Result<(), Self::Error>;

    fn load_encrypted_session(
        &self,
        local_session_key: &[u8; 32],
    ) -> std::result::Result<Option<Vec<u8>>, Self::Error>;

    fn delete_encrypted_session(
        &mut self,
        local_session_key: &[u8; 32],
    ) -> std::result::Result<(), Self::Error>;
}

/// Encrypts an opaque IndexedDB record. `record_key` is local-only and bound
/// into AEAD associated data to prevent swapping ciphertext between records.
pub fn seal_local_record(
    profile_data_key: &[u8; 32],
    record_key: &[u8; 32],
    plaintext: &[u8],
) -> crate::Result<Vec<u8>> {
    if plaintext.len() > MAX_LOCAL_RECORD_SIZE {
        return Err(CryptoError::PayloadTooLarge);
    }
    let cipher = ChaCha20Poly1305::new_from_slice(profile_data_key)
        .map_err(|_| CryptoError::CryptoOperation)?;
    let mut nonce = [0u8; LOCAL_RECORD_NONCE_LEN];
    fill(&mut nonce).map_err(|_| CryptoError::Randomness)?;
    let mut associated_data = [0u8; LOCAL_RECORD_MAGIC.len() + 32];
    associated_data[..LOCAL_RECORD_MAGIC.len()].copy_from_slice(&LOCAL_RECORD_MAGIC);
    associated_data[LOCAL_RECORD_MAGIC.len()..].copy_from_slice(record_key);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &associated_data,
            },
        )
        .map_err(|_| CryptoError::CryptoOperation)?;
    let mut output = Vec::with_capacity(LOCAL_RECORD_MAGIC.len() + nonce.len() + ciphertext.len());
    output.extend_from_slice(&LOCAL_RECORD_MAGIC);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Authenticates and decrypts one local record, returning no data on key,
/// nonce, record-key, or ciphertext mismatch.
pub fn open_local_record(
    profile_data_key: &[u8; 32],
    record_key: &[u8; 32],
    encrypted_record: &[u8],
) -> crate::Result<Vec<u8>> {
    let header_len = LOCAL_RECORD_MAGIC.len() + LOCAL_RECORD_NONCE_LEN;
    if encrypted_record.len() < header_len + 16
        || encrypted_record.len() > header_len + MAX_LOCAL_RECORD_SIZE + 16
        || encrypted_record[..LOCAL_RECORD_MAGIC.len()] != LOCAL_RECORD_MAGIC
    {
        return Err(CryptoError::InvalidSnapshot);
    }
    let cipher = ChaCha20Poly1305::new_from_slice(profile_data_key)
        .map_err(|_| CryptoError::CryptoOperation)?;
    let mut associated_data = [0u8; LOCAL_RECORD_MAGIC.len() + 32];
    associated_data[..LOCAL_RECORD_MAGIC.len()].copy_from_slice(&LOCAL_RECORD_MAGIC);
    associated_data[LOCAL_RECORD_MAGIC.len()..].copy_from_slice(record_key);
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&encrypted_record[LOCAL_RECORD_MAGIC.len()..header_len]),
                Payload {
                    msg: &encrypted_record[header_len..],
                    aad: &associated_data,
                },
            )
            .map_err(|_| CryptoError::Authentication)?,
    );
    Ok(plaintext.to_vec())
}

#[derive(Debug)]
pub enum PersistenceError<E> {
    Crypto(CryptoError),
    Storage(E),
}

impl<E> From<CryptoError> for PersistenceError<E> {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl SessionState {
    pub fn persist<S: StateStorage>(
        &self,
        storage: &mut S,
        local_session_key: &[u8; 32],
        profile_data_key: &[u8; 32],
    ) -> std::result::Result<(), PersistenceError<S::Error>> {
        let snapshot = self.serialize_encrypted(profile_data_key)?;
        storage
            .store_encrypted_session(local_session_key, &snapshot)
            .map_err(PersistenceError::Storage)
    }

    pub fn restore_from<S: StateStorage>(
        storage: &S,
        local_session_key: &[u8; 32],
        profile_data_key: &[u8; 32],
    ) -> std::result::Result<Option<Self>, PersistenceError<S::Error>> {
        storage
            .load_encrypted_session(local_session_key)
            .map_err(PersistenceError::Storage)?
            .map(|snapshot| Self::restore_encrypted(&snapshot, profile_data_key))
            .transpose()
            .map_err(PersistenceError::Crypto)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::{
        handshake::{HybridOffer, authentication_string, respond},
        session::VerificationStatus,
    };

    use super::*;

    #[derive(Default)]
    struct MemoryStateStorage {
        snapshots: HashMap<[u8; 32], Vec<u8>>,
    }

    impl StateStorage for MemoryStateStorage {
        type Error = ();

        fn store_encrypted_session(
            &mut self,
            local_session_key: &[u8; 32],
            snapshot: &[u8],
        ) -> std::result::Result<(), Self::Error> {
            self.snapshots.insert(*local_session_key, snapshot.to_vec());
            Ok(())
        }

        fn load_encrypted_session(
            &self,
            local_session_key: &[u8; 32],
        ) -> std::result::Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.snapshots.get(local_session_key).cloned())
        }

        fn delete_encrypted_session(
            &mut self,
            local_session_key: &[u8; 32],
        ) -> std::result::Result<(), Self::Error> {
            self.snapshots.remove(local_session_key);
            Ok(())
        }
    }

    #[test]
    fn ratchet_state_survives_restart_with_skipped_out_of_order_keys() {
        let offer = HybridOffer::create().unwrap();
        let offer_public = offer.public().clone();
        let (response, responder_ratchet) = respond(&offer_public).unwrap();
        let mut initiator = SessionState::new_unverified(
            offer.finish(&response).unwrap(),
            &offer_public,
            &response,
        );
        let mut responder =
            SessionState::new_unverified(responder_ratchet, &offer_public, &response);
        assert_eq!(
            initiator.verification_status(),
            VerificationStatus::Unverified
        );
        assert_eq!(
            responder.verification_status(),
            VerificationStatus::Unverified
        );
        let sas = authentication_string(&offer_public, &response);
        assert!(matches!(
            initiator.confirm_sas("000000000000"),
            Err(CryptoError::SasMismatch)
        ));
        assert_eq!(
            initiator.verification_status(),
            VerificationStatus::Unverified
        );
        initiator.confirm_sas(&sas).unwrap();
        responder.confirm_sas(&sas).unwrap();

        let message0 = initiator.encrypt(b"packet zero").unwrap();
        let message1 = initiator.encrypt(b"packet one").unwrap();
        let message2 = initiator.encrypt(b"packet two").unwrap();
        assert_eq!(responder.decrypt(&message2).unwrap(), b"packet two");

        let profile_key = [0xA7; 32];
        let initiator_id = [0x01; 32];
        let responder_id = [0x02; 32];
        let mut storage = MemoryStateStorage::default();
        initiator
            .persist(&mut storage, &initiator_id, &profile_key)
            .unwrap();
        responder
            .persist(&mut storage, &responder_id, &profile_key)
            .unwrap();

        let mut initiator = SessionState::restore_from(&storage, &initiator_id, &profile_key)
            .unwrap()
            .unwrap();
        let mut responder = SessionState::restore_from(&storage, &responder_id, &profile_key)
            .unwrap()
            .unwrap();
        assert_eq!(responder.decrypt(&message0).unwrap(), b"packet zero");
        assert_eq!(responder.decrypt(&message1).unwrap(), b"packet one");

        let reply = responder.encrypt(b"continued after restart").unwrap();
        assert_eq!(
            initiator.decrypt(&reply).unwrap(),
            b"continued after restart"
        );
        assert_eq!(
            initiator.verification_status(),
            VerificationStatus::Verified
        );
        assert_eq!(
            responder.verification_status(),
            VerificationStatus::Verified
        );
    }

    #[test]
    fn encrypted_snapshot_rejects_tampering_and_wrong_profile_key() {
        let offer = HybridOffer::create().unwrap();
        let offer_public = offer.public().clone();
        let (response, responder) = respond(&offer_public).unwrap();
        let state = SessionState::new_unverified(responder, &offer_public, &response);
        let key = [0x42; 32];
        let mut snapshot = state.serialize_encrypted(&key).unwrap();
        let restored = SessionState::restore_encrypted(&snapshot, &key).unwrap();
        assert_eq!(
            restored.verification_status(),
            VerificationStatus::Unverified
        );
        assert!(matches!(
            SessionState::restore_encrypted(&snapshot, &[0x24; 32]),
            Err(CryptoError::Authentication)
        ));
        let last = snapshot.len() - 1;
        snapshot[last] ^= 0x80;
        assert!(matches!(
            SessionState::restore_encrypted(&snapshot, &key),
            Err(CryptoError::Authentication)
        ));
    }

    #[test]
    fn local_record_encryption_is_bound_to_profile_and_record_key() {
        let profile_key = [0x51; 32];
        let record_key = [0x27; 32];
        let encrypted =
            seal_local_record(&profile_key, &record_key, b"private local record").unwrap();
        assert_eq!(
            open_local_record(&profile_key, &record_key, &encrypted).unwrap(),
            b"private local record"
        );
        assert!(matches!(
            open_local_record(&[0x52; 32], &record_key, &encrypted),
            Err(CryptoError::Authentication)
        ));
        assert!(matches!(
            open_local_record(&profile_key, &[0x28; 32], &encrypted),
            Err(CryptoError::Authentication)
        ));
    }
}
