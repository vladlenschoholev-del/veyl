use hkdf::Hkdf;
use ml_kem::{
    Ciphertext, DecapsulationKey768, EncapsulationKey768, MlKem768,
    kem::{Encapsulate, Kem, KeyExport, TryDecapsulate, TryKeyInit},
};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::{CryptoError, Result, ratchet::DoubleRatchet};

const TRANSCRIPT_DOMAIN: &[u8] = b"veyl/hybrid-x25519-ml-kem-768/v1";
const HANDSHAKE_WIRE_VERSION: u8 = 1;
const X25519_PUBLIC_LEN: usize = 32;
const ML_KEM_768_PUBLIC_LEN: usize = 1184;
const ML_KEM_768_CIPHERTEXT_LEN: usize = 1088;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HybridOfferPublic {
    pub x25519_public: [u8; 32],
    pub ml_kem_public: Vec<u8>,
}

impl HybridOfferPublic {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(1 + X25519_PUBLIC_LEN + ML_KEM_768_PUBLIC_LEN);
        encoded.push(HANDSHAKE_WIRE_VERSION);
        encoded.extend_from_slice(&self.x25519_public);
        encoded.extend_from_slice(&self.ml_kem_public);
        encoded
    }

    pub fn from_bytes(encoded: &[u8]) -> Result<Self> {
        if encoded.len() != 1 + X25519_PUBLIC_LEN + ML_KEM_768_PUBLIC_LEN
            || encoded[0] != HANDSHAKE_WIRE_VERSION
        {
            return Err(CryptoError::InvalidHandshake);
        }
        Ok(Self {
            x25519_public: encoded[1..1 + X25519_PUBLIC_LEN]
                .try_into()
                .map_err(|_| CryptoError::InvalidHandshake)?,
            ml_kem_public: encoded[1 + X25519_PUBLIC_LEN..].to_vec(),
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HybridResponse {
    pub x25519_public: [u8; 32],
    pub ml_kem_ciphertext: Vec<u8>,
}

impl HybridResponse {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(1 + X25519_PUBLIC_LEN + ML_KEM_768_CIPHERTEXT_LEN);
        encoded.push(HANDSHAKE_WIRE_VERSION);
        encoded.extend_from_slice(&self.x25519_public);
        encoded.extend_from_slice(&self.ml_kem_ciphertext);
        encoded
    }

    pub fn from_bytes(encoded: &[u8]) -> Result<Self> {
        if encoded.len() != 1 + X25519_PUBLIC_LEN + ML_KEM_768_CIPHERTEXT_LEN
            || encoded[0] != HANDSHAKE_WIRE_VERSION
        {
            return Err(CryptoError::InvalidHandshake);
        }
        Ok(Self {
            x25519_public: encoded[1..1 + X25519_PUBLIC_LEN]
                .try_into()
                .map_err(|_| CryptoError::InvalidHandshake)?,
            ml_kem_ciphertext: encoded[1 + X25519_PUBLIC_LEN..].to_vec(),
        })
    }
}

pub struct HybridOffer {
    public: HybridOfferPublic,
    x25519_secret: StaticSecret,
    ml_kem_secret: DecapsulationKey768,
}

impl HybridOffer {
    pub fn create() -> Result<Self> {
        let mut x25519_bytes = [0u8; 32];
        getrandom::fill(&mut x25519_bytes).map_err(|_| CryptoError::Randomness)?;
        let x25519_secret = StaticSecret::from(x25519_bytes);
        x25519_bytes.zeroize();
        let x25519_public = PublicKey::from(&x25519_secret).to_bytes();
        let (ml_kem_secret, ml_kem_public) = MlKem768::generate_keypair();
        let public = HybridOfferPublic {
            x25519_public,
            ml_kem_public: ml_kem_public.to_bytes().as_slice().to_vec(),
        };
        Ok(Self {
            public,
            x25519_secret,
            ml_kem_secret,
        })
    }

    pub fn public(&self) -> &HybridOfferPublic {
        &self.public
    }

    pub fn finish(self, response: &HybridResponse) -> Result<DoubleRatchet> {
        if response.ml_kem_ciphertext.len() != 1088 {
            return Err(CryptoError::InvalidHandshake);
        }
        let ciphertext: Ciphertext<MlKem768> = response
            .ml_kem_ciphertext
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidHandshake)?;
        let mut kem_secret = self
            .ml_kem_secret
            .try_decapsulate(&ciphertext)
            .map_err(|_| CryptoError::InvalidHandshake)?;
        let kem_secret_copy = <[u8; 32]>::try_from(kem_secret.as_slice());
        kem_secret.zeroize();
        let kem_secret_copy =
            Zeroizing::new(kem_secret_copy.map_err(|_| CryptoError::InvalidHandshake)?);
        let dh_secret = crate::ratchet::dh(&self.x25519_secret, &response.x25519_public)?;
        let root = derive_handshake_secret(&self.public, response, &dh_secret, &kem_secret_copy)?;
        DoubleRatchet::new_initiator(&root, self.x25519_secret, response.x25519_public)
    }
}

/// Returns a short transcript authentication string for users to compare out of
/// band before trusting this handshake.
pub fn authentication_string(offer: &HybridOfferPublic, response: &HybridResponse) -> String {
    authentication_bytes(offer, response)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .concat()
}

pub fn authentication_bytes(offer: &HybridOfferPublic, response: &HybridResponse) -> [u8; 6] {
    let transcript_hash = transcript_hash(offer, response);
    let mut digest = Sha256::new();
    digest.update(b"veyl/authentication-string/v1");
    digest.update(transcript_hash);
    digest.finalize()[..6]
        .try_into()
        .expect("fixed six-byte SAS")
}

pub fn respond(offer: &HybridOfferPublic) -> Result<(HybridResponse, DoubleRatchet)> {
    if offer.ml_kem_public.len() != 1184 {
        return Err(CryptoError::InvalidHandshake);
    }
    let encapsulation_key = EncapsulationKey768::new_from_slice(&offer.ml_kem_public)
        .map_err(|_| CryptoError::InvalidHandshake)?;

    let mut x25519_bytes = [0u8; 32];
    getrandom::fill(&mut x25519_bytes).map_err(|_| CryptoError::Randomness)?;
    let x25519_secret = StaticSecret::from(x25519_bytes);
    x25519_bytes.zeroize();
    let x25519_public = PublicKey::from(&x25519_secret).to_bytes();
    let dh_secret = crate::ratchet::dh(&x25519_secret, &offer.x25519_public)?;

    let (ciphertext, mut kem_secret) = encapsulation_key.encapsulate();
    let kem_secret_copy =
        <[u8; 32]>::try_from(kem_secret.as_slice()).map_err(|_| CryptoError::InvalidHandshake);
    kem_secret.zeroize();
    let kem_secret_copy = Zeroizing::new(kem_secret_copy?);
    let response = HybridResponse {
        x25519_public,
        ml_kem_ciphertext: ciphertext.as_slice().to_vec(),
    };
    let root = derive_handshake_secret(offer, &response, &dh_secret, &kem_secret_copy)?;
    let ratchet = DoubleRatchet::new_responder(&root, x25519_secret, offer.x25519_public)?;
    Ok((response, ratchet))
}

fn derive_handshake_secret(
    offer: &HybridOfferPublic,
    response: &HybridResponse,
    dh_secret: &[u8; 32],
    kem_secret: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    let transcript_hash = transcript_hash(offer, response);
    let mut input = Zeroizing::new([0u8; 64]);
    input[..32].copy_from_slice(dh_secret);
    input[32..].copy_from_slice(kem_secret);
    let hkdf = Hkdf::<Sha256>::new(Some(&transcript_hash), input.as_ref());
    let mut root = Zeroizing::new([0u8; 32]);
    hkdf.expand(TRANSCRIPT_DOMAIN, root.as_mut())
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(root)
}

fn transcript_hash(offer: &HybridOfferPublic, response: &HybridResponse) -> [u8; 32] {
    let mut transcript = Sha256::new();
    transcript.update(TRANSCRIPT_DOMAIN);
    transcript.update(offer.x25519_public);
    transcript.update(&offer.ml_kem_public);
    transcript.update(response.x25519_public);
    transcript.update(&response.ml_kem_ciphertext);
    transcript.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_handshake_establishes_matching_ratchet_chains() {
        let offer = HybridOffer::create().unwrap();
        let (response, mut responder) = respond(offer.public()).unwrap();
        let sas = authentication_string(offer.public(), &response);
        assert_eq!(sas.len(), 12);
        let mut altered = response.clone();
        altered.x25519_public[0] ^= 1;
        assert_ne!(authentication_string(offer.public(), &altered), sas);
        let mut initiator = offer.finish(&response).unwrap();

        let first = initiator.encrypt(b"first").unwrap();
        assert_eq!(responder.decrypt(&first).unwrap(), b"first");
        let reply = responder.encrypt(b"reply").unwrap();
        assert_eq!(initiator.decrypt(&reply).unwrap(), b"reply");
    }

    #[test]
    fn malformed_handshake_is_rejected() {
        let offer = HybridOffer::create().unwrap();
        let malformed = HybridResponse {
            x25519_public: [0; 32],
            ml_kem_ciphertext: vec![0; 12],
        };
        assert!(matches!(
            offer.finish(&malformed),
            Err(CryptoError::InvalidHandshake)
        ));
    }

    #[test]
    fn handshake_messages_have_strict_versioned_binary_encodings() {
        let offer = HybridOffer::create().unwrap();
        let encoded_offer = offer.public().to_bytes();
        assert_eq!(
            HybridOfferPublic::from_bytes(&encoded_offer).unwrap(),
            *offer.public()
        );
        let mut malformed_offer = encoded_offer;
        malformed_offer[0] = 2;
        assert!(matches!(
            HybridOfferPublic::from_bytes(&malformed_offer),
            Err(CryptoError::InvalidHandshake)
        ));

        let (response, _) = respond(offer.public()).unwrap();
        assert_eq!(
            HybridResponse::from_bytes(&response.to_bytes()).unwrap(),
            response
        );
        let mut malformed_response = response.to_bytes();
        malformed_response.pop();
        assert!(matches!(
            HybridResponse::from_bytes(&malformed_response),
            Err(CryptoError::InvalidHandshake)
        ));
    }
}
