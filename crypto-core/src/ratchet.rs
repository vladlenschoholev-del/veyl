use std::collections::HashMap;

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    CryptoError, Result,
    padding::{self, PADDING_BUCKETS},
};

const ROOT_INFO: &[u8] = b"veyl/double-ratchet/root/v1";
const MAX_SKIP: u32 = 2000;
type SecretKey = Zeroizing<[u8; 32]>;
type KdfPair = (SecretKey, SecretKey);
const RATCHET_SNAPSHOT_VERSION: u8 = 1;

#[derive(Serialize, Deserialize, Zeroize)]
pub(crate) struct RatchetSnapshot {
    version: u8,
    root_key: [u8; 32],
    sending_chain_key: Option<[u8; 32]>,
    receiving_chain_key: Option<[u8; 32]>,
    local_dh_secret: [u8; 32],
    remote_dh_public: [u8; 32],
    send_number: u32,
    receive_number: u32,
    previous_send_length: u32,
    skipped_message_keys: Vec<SkippedMessageKey>,
}

#[derive(Serialize, Deserialize, Zeroize)]
struct SkippedMessageKey {
    dh_public: [u8; 32],
    message_number: u32,
    message_key: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RatchetHeader {
    pub dh_public: [u8; 32],
    pub previous_chain_length: u32,
    pub message_number: u32,
}

impl RatchetHeader {
    fn associated_data(&self) -> [u8; 40] {
        let mut out = [0u8; 40];
        out[..32].copy_from_slice(&self.dh_public);
        out[32..36].copy_from_slice(&self.previous_chain_length.to_be_bytes());
        out[36..].copy_from_slice(&self.message_number.to_be_bytes());
        out
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RatchetMessage {
    pub header: RatchetHeader,
    /// The 12-byte nonce is prefixed to the authenticated ciphertext.
    pub ciphertext: Vec<u8>,
}

impl RatchetMessage {
    pub fn to_relay_payload(&self) -> Vec<u8> {
        let header = self.header.associated_data();
        let mut payload = Vec::with_capacity(header.len() + self.ciphertext.len());
        payload.extend_from_slice(&header);
        payload.extend_from_slice(&self.ciphertext);
        payload
    }

    pub fn from_relay_payload(payload: &[u8]) -> Result<Self> {
        if payload.len() < 40 + 12 + 16 {
            return Err(CryptoError::InvalidRatchetMessage);
        }
        let ciphertext_len = payload.len() - 40;
        if !PADDING_BUCKETS
            .iter()
            .any(|bucket| ciphertext_len == 12 + bucket + 16)
        {
            return Err(CryptoError::InvalidRatchetMessage);
        }
        Ok(Self {
            header: RatchetHeader {
                dh_public: payload[..32]
                    .try_into()
                    .map_err(|_| CryptoError::InvalidRatchetMessage)?,
                previous_chain_length: u32::from_be_bytes(
                    payload[32..36]
                        .try_into()
                        .map_err(|_| CryptoError::InvalidRatchetMessage)?,
                ),
                message_number: u32::from_be_bytes(
                    payload[36..40]
                        .try_into()
                        .map_err(|_| CryptoError::InvalidRatchetMessage)?,
                ),
            },
            ciphertext: payload[40..].to_vec(),
        })
    }
}

pub struct DoubleRatchet {
    root_key: Zeroizing<[u8; 32]>,
    sending_chain_key: Option<Zeroizing<[u8; 32]>>,
    receiving_chain_key: Option<Zeroizing<[u8; 32]>>,
    local_dh_secret: StaticSecret,
    remote_dh_public: [u8; 32],
    send_number: u32,
    receive_number: u32,
    previous_send_length: u32,
    skipped_message_keys: HashMap<([u8; 32], u32), Zeroizing<[u8; 32]>>,
}

impl DoubleRatchet {
    pub(crate) fn snapshot(&self) -> RatchetSnapshot {
        let mut skipped_message_keys = self
            .skipped_message_keys
            .iter()
            .map(
                |((dh_public, message_number), message_key)| SkippedMessageKey {
                    dh_public: *dh_public,
                    message_number: *message_number,
                    message_key: **message_key,
                },
            )
            .collect::<Vec<_>>();
        skipped_message_keys.sort_by(|left, right| {
            left.dh_public
                .cmp(&right.dh_public)
                .then(left.message_number.cmp(&right.message_number))
        });

        RatchetSnapshot {
            version: RATCHET_SNAPSHOT_VERSION,
            root_key: *self.root_key,
            sending_chain_key: self.sending_chain_key.as_ref().map(|key| **key),
            receiving_chain_key: self.receiving_chain_key.as_ref().map(|key| **key),
            local_dh_secret: self.local_dh_secret.to_bytes(),
            remote_dh_public: self.remote_dh_public,
            send_number: self.send_number,
            receive_number: self.receive_number,
            previous_send_length: self.previous_send_length,
            skipped_message_keys,
        }
    }

    pub(crate) fn restore(snapshot: &RatchetSnapshot) -> Result<Self> {
        if snapshot.version != RATCHET_SNAPSHOT_VERSION
            || snapshot.skipped_message_keys.len() > MAX_SKIP as usize
            || (snapshot.receiving_chain_key.is_none() && !snapshot.skipped_message_keys.is_empty())
        {
            return Err(CryptoError::InvalidSnapshot);
        }

        let mut skipped_message_keys = HashMap::with_capacity(snapshot.skipped_message_keys.len());
        for skipped in &snapshot.skipped_message_keys {
            if skipped_message_keys
                .insert(
                    (skipped.dh_public, skipped.message_number),
                    Zeroizing::new(skipped.message_key),
                )
                .is_some()
            {
                return Err(CryptoError::InvalidSnapshot);
            }
        }

        Ok(Self {
            root_key: Zeroizing::new(snapshot.root_key),
            sending_chain_key: snapshot.sending_chain_key.map(Zeroizing::new),
            receiving_chain_key: snapshot.receiving_chain_key.map(Zeroizing::new),
            local_dh_secret: StaticSecret::from(snapshot.local_dh_secret),
            remote_dh_public: snapshot.remote_dh_public,
            send_number: snapshot.send_number,
            receive_number: snapshot.receive_number,
            previous_send_length: snapshot.previous_send_length,
            skipped_message_keys,
        })
    }

    pub(crate) fn new_initiator(
        root: &[u8; 32],
        local_dh_secret: StaticSecret,
        remote_dh_public: [u8; 32],
    ) -> Result<Self> {
        let dh = dh(&local_dh_secret, &remote_dh_public)?;
        let (root_key, sending_chain_key) = kdf_root(root, &dh)?;
        Ok(Self {
            root_key,
            sending_chain_key: Some(sending_chain_key),
            receiving_chain_key: None,
            local_dh_secret,
            remote_dh_public,
            send_number: 0,
            receive_number: 0,
            previous_send_length: 0,
            skipped_message_keys: HashMap::new(),
        })
    }

    pub(crate) fn new_responder(
        root: &[u8; 32],
        local_dh_secret: StaticSecret,
        remote_dh_public: [u8; 32],
    ) -> Result<Self> {
        let dh = dh(&local_dh_secret, &remote_dh_public)?;
        let (root_key, receiving_chain_key) = kdf_root(root, &dh)?;
        Ok(Self {
            root_key,
            sending_chain_key: None,
            receiving_chain_key: Some(receiving_chain_key),
            local_dh_secret,
            remote_dh_public,
            send_number: 0,
            receive_number: 0,
            previous_send_length: 0,
            skipped_message_keys: HashMap::new(),
        })
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<RatchetMessage> {
        let padded = Zeroizing::new(padding::pad(plaintext)?);
        if self.sending_chain_key.is_none() {
            self.begin_sending_chain()?;
        }
        let chain_key = self
            .sending_chain_key
            .as_ref()
            .ok_or(CryptoError::KeyDerivation)?;
        let (message_key, next_chain_key) = kdf_chain(chain_key)?;
        let header = RatchetHeader {
            dh_public: PublicKey::from(&self.local_dh_secret).to_bytes(),
            previous_chain_length: self.previous_send_length,
            message_number: self.send_number,
        };
        let next_number = self
            .send_number
            .checked_add(1)
            .ok_or(CryptoError::CounterOverflow)?;
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce).map_err(|_| CryptoError::Randomness)?;
        let cipher = ChaCha20Poly1305::new_from_slice(message_key.as_ref())
            .map_err(|_| CryptoError::CryptoOperation)?;
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &padded,
                    aad: &header.associated_data(),
                },
            )
            .map_err(|_| CryptoError::CryptoOperation)?;

        self.sending_chain_key = Some(next_chain_key);
        self.send_number = next_number;

        let mut ciphertext = Vec::with_capacity(nonce.len() + encrypted.len());
        ciphertext.extend_from_slice(&nonce);
        ciphertext.extend_from_slice(&encrypted);
        Ok(RatchetMessage { header, ciphertext })
    }

    pub fn decrypt(&mut self, message: &RatchetMessage) -> Result<Vec<u8>> {
        if !PADDING_BUCKETS
            .iter()
            .any(|bucket| message.ciphertext.len() == 12 + bucket + 16)
        {
            return Err(CryptoError::Authentication);
        }

        // Stage changes on a clone so unauthenticated input cannot advance live state.
        let mut staged = self.clone_state();
        let plaintext = Zeroizing::new(staged.decrypt_in_place(message)?);
        *self = staged;
        Ok(padding::unpad(&plaintext)?.to_vec())
    }

    fn decrypt_in_place(&mut self, message: &RatchetMessage) -> Result<Vec<u8>> {
        let header = &message.header;
        let skipped_key_id = (header.dh_public, header.message_number);
        let message_key = if let Some(key) = self.skipped_message_keys.remove(&skipped_key_id) {
            key
        } else {
            if header.dh_public != self.remote_dh_public {
                self.skip_message_keys(header.previous_chain_length)?;
                self.previous_send_length = self.send_number;
                self.send_number = 0;
                self.receive_number = 0;
                self.remote_dh_public = header.dh_public;

                let receiving_dh = dh(&self.local_dh_secret, &self.remote_dh_public)?;
                let (root, receiving_chain) = kdf_root(&self.root_key, &receiving_dh)?;
                self.root_key = root;
                self.receiving_chain_key = Some(receiving_chain);

                let mut local_bytes = [0u8; 32];
                getrandom::fill(&mut local_bytes).map_err(|_| CryptoError::Randomness)?;
                self.local_dh_secret = StaticSecret::from(local_bytes);
                local_bytes.zeroize();
                let sending_dh = dh(&self.local_dh_secret, &self.remote_dh_public)?;
                let (root, sending_chain) = kdf_root(&self.root_key, &sending_dh)?;
                self.root_key = root;
                self.sending_chain_key = Some(sending_chain);
            }

            if header.message_number < self.receive_number {
                return Err(CryptoError::InvalidRatchetMessage);
            }
            self.skip_message_keys(header.message_number)?;
            let chain_key = self
                .receiving_chain_key
                .as_ref()
                .ok_or(CryptoError::InvalidRatchetMessage)?;
            let (message_key, next_chain_key) = kdf_chain(chain_key)?;
            self.receiving_chain_key = Some(next_chain_key);
            self.receive_number = self
                .receive_number
                .checked_add(1)
                .ok_or(CryptoError::CounterOverflow)?;
            message_key
        };

        let nonce: [u8; 12] = message.ciphertext[..12]
            .try_into()
            .map_err(|_| CryptoError::Authentication)?;
        let cipher = ChaCha20Poly1305::new_from_slice(message_key.as_ref())
            .map_err(|_| CryptoError::CryptoOperation)?;
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &message.ciphertext[12..],
                    aad: &header.associated_data(),
                },
            )
            .map_err(|_| CryptoError::Authentication)
    }

    fn skip_message_keys(&mut self, until: u32) -> Result<()> {
        if until < self.receive_number || until - self.receive_number > MAX_SKIP {
            return Err(CryptoError::InvalidRatchetMessage);
        }
        while self.receive_number < until {
            let chain_key = self
                .receiving_chain_key
                .as_ref()
                .ok_or(CryptoError::InvalidRatchetMessage)?;
            let (message_key, next_chain_key) = kdf_chain(chain_key)?;
            self.skipped_message_keys
                .insert((self.remote_dh_public, self.receive_number), message_key);
            self.receiving_chain_key = Some(next_chain_key);
            self.receive_number = self
                .receive_number
                .checked_add(1)
                .ok_or(CryptoError::CounterOverflow)?;
        }
        if self.skipped_message_keys.len() > MAX_SKIP as usize {
            return Err(CryptoError::InvalidRatchetMessage);
        }
        Ok(())
    }

    fn begin_sending_chain(&mut self) -> Result<()> {
        let mut local_bytes = [0u8; 32];
        getrandom::fill(&mut local_bytes).map_err(|_| CryptoError::Randomness)?;
        self.local_dh_secret = StaticSecret::from(local_bytes);
        local_bytes.zeroize();
        self.previous_send_length = self.send_number;
        self.send_number = 0;
        let sending_dh = dh(&self.local_dh_secret, &self.remote_dh_public)?;
        let (root, chain) = kdf_root(&self.root_key, &sending_dh)?;
        self.root_key = root;
        self.sending_chain_key = Some(chain);
        Ok(())
    }

    fn clone_state(&self) -> Self {
        Self {
            root_key: Zeroizing::new(*self.root_key),
            sending_chain_key: self
                .sending_chain_key
                .as_ref()
                .map(|key| Zeroizing::new(**key)),
            receiving_chain_key: self
                .receiving_chain_key
                .as_ref()
                .map(|key| Zeroizing::new(**key)),
            local_dh_secret: StaticSecret::from(self.local_dh_secret.to_bytes()),
            remote_dh_public: self.remote_dh_public,
            send_number: self.send_number,
            receive_number: self.receive_number,
            previous_send_length: self.previous_send_length,
            skipped_message_keys: self
                .skipped_message_keys
                .iter()
                .map(|(key, value)| (*key, Zeroizing::new(**value)))
                .collect(),
        }
    }
}

pub(crate) fn dh(secret: &StaticSecret, remote_public: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let shared = secret
        .diffie_hellman(&PublicKey::from(*remote_public))
        .to_bytes();
    if bool::from(shared.ct_eq(&[0u8; 32])) {
        return Err(CryptoError::InvalidHandshake);
    }
    Ok(Zeroizing::new(shared))
}

fn kdf_root(root_key: &[u8; 32], dh_output: &[u8; 32]) -> Result<KdfPair> {
    let hkdf = Hkdf::<Sha256>::new(Some(root_key), dh_output);
    let mut output = Zeroizing::new([0u8; 64]);
    hkdf.expand(ROOT_INFO, output.as_mut())
        .map_err(|_| CryptoError::KeyDerivation)?;
    let mut root = Zeroizing::new([0u8; 32]);
    let mut chain = Zeroizing::new([0u8; 32]);
    root.copy_from_slice(&output[..32]);
    chain.copy_from_slice(&output[32..]);
    Ok((root, chain))
}

fn kdf_chain(chain_key: &[u8; 32]) -> Result<KdfPair> {
    let mut message_mac =
        <Hmac<Sha256> as Mac>::new_from_slice(chain_key).map_err(|_| CryptoError::KeyDerivation)?;
    message_mac.update(&[1]);
    let mut message_key = Zeroizing::new([0u8; 32]);
    message_key.copy_from_slice(&message_mac.finalize().into_bytes());

    let mut chain_mac =
        <Hmac<Sha256> as Mac>::new_from_slice(chain_key).map_err(|_| CryptoError::KeyDerivation)?;
    chain_mac.update(&[2]);
    let mut next_chain_key = Zeroizing::new([0u8; 32]);
    next_chain_key.copy_from_slice(&chain_mac.finalize().into_bytes());
    Ok((message_key, next_chain_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{HybridOffer, respond};

    fn pair() -> (DoubleRatchet, DoubleRatchet) {
        let offer = HybridOffer::create().unwrap();
        let (response, responder) = respond(offer.public()).unwrap();
        (offer.finish(&response).unwrap(), responder)
    }

    #[test]
    fn sends_messages_in_both_directions_and_ratchets_dh_keys() {
        let (mut alice, mut bob) = pair();
        let first = alice.encrypt(b"one").unwrap();
        assert_eq!(bob.decrypt(&first).unwrap(), b"one");

        let reply = bob.encrypt(b"two").unwrap();
        assert_eq!(alice.decrypt(&reply).unwrap(), b"two");

        let next = alice.encrypt(b"three").unwrap();
        assert_eq!(bob.decrypt(&next).unwrap(), b"three");
    }

    #[test]
    fn skipped_messages_are_decryptable_once() {
        let (mut alice, mut bob) = pair();
        let first = alice.encrypt(b"one").unwrap();
        let second = alice.encrypt(b"two").unwrap();
        assert_eq!(bob.decrypt(&second).unwrap(), b"two");
        assert_eq!(bob.decrypt(&first).unwrap(), b"one");
        assert!(matches!(
            bob.decrypt(&first),
            Err(CryptoError::InvalidRatchetMessage)
        ));
    }

    #[test]
    fn unauthenticated_input_does_not_advance_ratchet_state() {
        let (mut alice, mut bob) = pair();
        let mut message = alice.encrypt(b"secret").unwrap();
        message.ciphertext[12] ^= 0x80;
        assert!(matches!(
            bob.decrypt(&message),
            Err(CryptoError::Authentication)
        ));
        let valid = alice.encrypt(b"still works").unwrap();
        assert_eq!(bob.decrypt(&valid).unwrap(), b"still works");
    }

    #[test]
    fn relay_payload_round_trip_preserves_fixed_size_and_authentication() {
        let (mut alice, mut bob) = pair();
        let message = alice.encrypt(b"padded").unwrap();
        let payload = message.to_relay_payload();
        assert_eq!(payload.len(), 40 + 12 + 1024 + 16);
        let parsed = RatchetMessage::from_relay_payload(&payload).unwrap();
        assert_eq!(bob.decrypt(&parsed).unwrap(), b"padded");
    }

    #[test]
    fn rejects_non_contributory_x25519_public_keys() {
        let secret = StaticSecret::from([0x42; 32]);
        assert!(matches!(
            dh(&secret, &[0; 32]),
            Err(CryptoError::InvalidHandshake)
        ));
    }
}
