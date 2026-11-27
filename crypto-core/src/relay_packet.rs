use std::fmt;

use crate::{CryptoError, Result, padding::PADDING_BUCKETS};
use zeroize::Zeroizing;

pub const PROTOCOL_VERSION: u8 = 1;
pub const RELAY_HEADER_LEN: usize = 65;
const RATCHET_HEADER_LEN: usize = 40;
const AEAD_NONCE_LEN: usize = 12;
const AEAD_TAG_LEN: usize = 16;

#[derive(Clone, Eq, PartialEq)]
pub struct RelayPacket {
    pub queue_id: [u8; 32],
    pub write_capability: Zeroizing<[u8; 32]>,
    /// Opaque ratchet header, nonce, and ciphertext; the relay must not parse it.
    pub encrypted_payload: Vec<u8>,
}

impl fmt::Debug for RelayPacket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayPacket")
            .field("queue_id", &self.queue_id)
            .field("write_capability", &"[REDACTED]")
            .field("encrypted_payload_len", &self.encrypted_payload.len())
            .finish()
    }
}

impl RelayPacket {
    pub fn encode(&self) -> Result<Vec<u8>> {
        validate_payload_len(self.encrypted_payload.len())?;
        let mut output = Vec::with_capacity(RELAY_HEADER_LEN + self.encrypted_payload.len());
        output.push(PROTOCOL_VERSION);
        output.extend_from_slice(&self.queue_id);
        output.extend_from_slice(&self.write_capability[..]);
        output.extend_from_slice(&self.encrypted_payload);
        Ok(output)
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() < RELAY_HEADER_LEN || input[0] != PROTOCOL_VERSION {
            return Err(CryptoError::InvalidHandshake);
        }
        let payload = &input[RELAY_HEADER_LEN..];
        validate_payload_len(payload.len())?;
        Ok(Self {
            queue_id: input[1..33]
                .try_into()
                .map_err(|_| CryptoError::InvalidHandshake)?,
            write_capability: Zeroizing::new(
                input[33..65]
                    .try_into()
                    .map_err(|_| CryptoError::InvalidHandshake)?,
            ),
            encrypted_payload: payload.to_vec(),
        })
    }
}

fn validate_payload_len(length: usize) -> Result<()> {
    if PADDING_BUCKETS
        .iter()
        .any(|bucket| length == RATCHET_HEADER_LEN + AEAD_NONCE_LEN + bucket + AEAD_TAG_LEN)
    {
        Ok(())
    } else {
        Err(CryptoError::InvalidHandshake)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_packet_round_trips_without_sender_field() {
        let packet = RelayPacket {
            queue_id: [0x11; 32],
            write_capability: Zeroizing::new([0x22; 32]),
            encrypted_payload: vec![
                0x33;
                RATCHET_HEADER_LEN + AEAD_NONCE_LEN + 1024 + AEAD_TAG_LEN
            ],
        };
        let encoded = packet.encode().unwrap();
        assert_eq!(
            encoded.len(),
            RELAY_HEADER_LEN + packet.encrypted_payload.len()
        );
        assert_eq!(RelayPacket::decode(&encoded).unwrap(), packet);
    }

    #[test]
    fn rejects_unknown_version_and_non_bucket_payloads() {
        let mut encoded =
            vec![0; RELAY_HEADER_LEN + RATCHET_HEADER_LEN + AEAD_NONCE_LEN + 1024 + AEAD_TAG_LEN];
        encoded[0] = 2;
        assert!(RelayPacket::decode(&encoded).is_err());
        encoded[0] = PROTOCOL_VERSION;
        encoded.push(0);
        assert!(RelayPacket::decode(&encoded).is_err());
    }
}
