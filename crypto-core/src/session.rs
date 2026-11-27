use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    CryptoError, Result,
    handshake::{HybridOfferPublic, HybridResponse, authentication_bytes},
    ratchet::{DoubleRatchet, RatchetMessage, RatchetSnapshot},
};

const SESSION_SNAPSHOT_MAGIC: [u8; 8] = *b"USTOYSS1";
const SESSION_SNAPSHOT_VERSION: u8 = 1;
const MAX_SNAPSHOT_SIZE: usize = 1_000_000;
const NONCE_SIZE: usize = 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationStatus {
    Unverified,
    Verified,
}

#[derive(Serialize, Deserialize, Zeroize)]
struct SessionSnapshot {
    version: u8,
    verified: bool,
    expected_sas: Option<[u8; 6]>,
    ratchet: RatchetSnapshot,
}

pub struct SessionState {
    ratchet: DoubleRatchet,
    verification: VerificationStatus,
    expected_sas: Option<[u8; 6]>,
}

impl SessionState {
    pub fn new_unverified(
        ratchet: DoubleRatchet,
        offer: &HybridOfferPublic,
        response: &HybridResponse,
    ) -> Self {
        Self {
            ratchet,
            verification: VerificationStatus::Unverified,
            expected_sas: Some(authentication_bytes(offer, response)),
        }
    }

    pub fn verification_status(&self) -> VerificationStatus {
        self.verification
    }

    pub fn sas(&self) -> Option<String> {
        self.expected_sas.as_ref().map(|bytes| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
                .to_uppercase()
        })
    }

    pub fn confirm_sas(&mut self, entered_sas: &str) -> Result<()> {
        let expected = self.expected_sas.as_ref().ok_or(CryptoError::SasMismatch)?;
        let entered = parse_sas(entered_sas).ok_or(CryptoError::SasMismatch)?;
        if !bool::from(expected.ct_eq(&entered)) {
            return Err(CryptoError::SasMismatch);
        }
        self.expected_sas.zeroize();
        self.expected_sas = None;
        self.verification = VerificationStatus::Verified;
        Ok(())
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<RatchetMessage> {
        self.ratchet.encrypt(plaintext)
    }

    pub fn decrypt(&mut self, message: &RatchetMessage) -> Result<Vec<u8>> {
        self.ratchet.decrypt(message)
    }

    pub fn serialize_encrypted(&self, profile_data_key: &[u8; 32]) -> Result<Vec<u8>> {
        let expected_sas = match (self.verification, self.expected_sas) {
            (VerificationStatus::Unverified, Some(code)) => Some(code),
            (VerificationStatus::Verified, None) => None,
            _ => return Err(CryptoError::InvalidSnapshot),
        };
        let snapshot = Zeroizing::new(SessionSnapshot {
            version: SESSION_SNAPSHOT_VERSION,
            verified: self.verification == VerificationStatus::Verified,
            expected_sas,
            ratchet: self.ratchet.snapshot(),
        });
        let plaintext = Zeroizing::new(
            postcard::to_allocvec(&*snapshot).map_err(|_| CryptoError::Serialization)?,
        );
        if plaintext.len() > MAX_SNAPSHOT_SIZE {
            return Err(CryptoError::InvalidSnapshot);
        }

        let cipher = ChaCha20Poly1305::new_from_slice(profile_data_key)
            .map_err(|_| CryptoError::CryptoOperation)?;
        let mut nonce = [0u8; NONCE_SIZE];
        getrandom::fill(&mut nonce).map_err(|_| CryptoError::Randomness)?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &SESSION_SNAPSHOT_MAGIC,
                },
            )
            .map_err(|_| CryptoError::CryptoOperation)?;

        let mut output =
            Vec::with_capacity(SESSION_SNAPSHOT_MAGIC.len() + nonce.len() + ciphertext.len());
        output.extend_from_slice(&SESSION_SNAPSHOT_MAGIC);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    pub fn restore_encrypted(
        encrypted_snapshot: &[u8],
        profile_data_key: &[u8; 32],
    ) -> Result<Self> {
        let header_len = SESSION_SNAPSHOT_MAGIC.len() + NONCE_SIZE;
        if encrypted_snapshot.len() < header_len + 16
            || encrypted_snapshot.len() > header_len + MAX_SNAPSHOT_SIZE + 16
            || encrypted_snapshot[..SESSION_SNAPSHOT_MAGIC.len()] != SESSION_SNAPSHOT_MAGIC
        {
            return Err(CryptoError::InvalidSnapshot);
        }
        let cipher = ChaCha20Poly1305::new_from_slice(profile_data_key)
            .map_err(|_| CryptoError::CryptoOperation)?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(
                        &encrypted_snapshot[SESSION_SNAPSHOT_MAGIC.len()..header_len],
                    ),
                    Payload {
                        msg: &encrypted_snapshot[header_len..],
                        aad: &SESSION_SNAPSHOT_MAGIC,
                    },
                )
                .map_err(|_| CryptoError::Authentication)?,
        );
        let (snapshot, remainder) = postcard::take_from_bytes::<SessionSnapshot>(&plaintext)
            .map_err(|_| CryptoError::InvalidSnapshot)?;
        if !remainder.is_empty() || snapshot.version != SESSION_SNAPSHOT_VERSION {
            return Err(CryptoError::InvalidSnapshot);
        }
        let snapshot = Zeroizing::new(snapshot);
        let (verification, expected_sas) = match (snapshot.verified, snapshot.expected_sas) {
            (false, Some(code)) => (VerificationStatus::Unverified, Some(code)),
            (true, None) => (VerificationStatus::Verified, None),
            _ => return Err(CryptoError::InvalidSnapshot),
        };
        Ok(Self {
            ratchet: DoubleRatchet::restore(&snapshot.ratchet)?,
            verification,
            expected_sas,
        })
    }
}

impl Drop for SessionState {
    fn drop(&mut self) {
        self.expected_sas.zeroize();
    }
}

fn parse_sas(input: &str) -> Option<[u8; 6]> {
    if input.len() != 12 || !input.is_ascii() {
        return None;
    }
    let mut output = [0u8; 6];
    for (index, chunk) in input.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?;
    }
    Some(output)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
