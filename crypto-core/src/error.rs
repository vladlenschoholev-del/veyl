use thiserror::Error;

pub type Result<T> = std::result::Result<T, CryptoError>;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("secure random number generation failed")]
    Randomness,
    #[error("invalid key material or handshake message")]
    InvalidHandshake,
    #[error("SAS confirmation did not match the handshake transcript")]
    SasMismatch,
    #[error("key derivation failed")]
    KeyDerivation,
    #[error("message authentication failed")]
    Authentication,
    #[error("ratchet message is invalid, replayed, or outside the skip window")]
    InvalidRatchetMessage,
    #[error("counter overflow")]
    CounterOverflow,
    #[error("plaintext exceeds the largest supported padding bucket")]
    PayloadTooLarge,
    #[error("malformed padded payload")]
    InvalidPaddedPayload,
    #[error("unsupported or malformed media format")]
    UnsupportedMedia,
    #[error("invalid PIN or profile key")]
    InvalidPin,
    #[error("PIN vault has already erased its real-profile key")]
    RealProfileErased,
    #[error("runtime profile is not active")]
    InvalidProfileState,
    #[error("cryptographic operation failed")]
    CryptoOperation,
    #[error("invalid or unsupported encrypted session snapshot")]
    InvalidSnapshot,
    #[error("session snapshot serialization failed")]
    Serialization,
    #[error("image codec failed: {0}")]
    Image(#[from] image::ImageError),
}
