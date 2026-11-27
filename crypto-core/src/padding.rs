use getrandom::fill;

use crate::{CryptoError, Result};

pub const PADDING_BUCKETS: [usize; 3] = [1024, 4096, 16384];
const LENGTH_PREFIX_SIZE: usize = 4;

pub fn pad(plaintext: &[u8]) -> Result<Vec<u8>> {
    let required = LENGTH_PREFIX_SIZE
        .checked_add(plaintext.len())
        .ok_or(CryptoError::PayloadTooLarge)?;
    let bucket = PADDING_BUCKETS
        .iter()
        .copied()
        .find(|bucket| *bucket >= required)
        .ok_or(CryptoError::PayloadTooLarge)?;

    let mut output = vec![0u8; bucket];
    output[..4].copy_from_slice(
        &u32::try_from(plaintext.len())
            .map_err(|_| CryptoError::PayloadTooLarge)?
            .to_be_bytes(),
    );
    output[4..required].copy_from_slice(plaintext);
    fill(&mut output[required..]).map_err(|_| CryptoError::Randomness)?;
    Ok(output)
}

pub fn unpad(padded: &[u8]) -> Result<&[u8]> {
    if !PADDING_BUCKETS.contains(&padded.len()) || padded.len() < LENGTH_PREFIX_SIZE {
        return Err(CryptoError::InvalidPaddedPayload);
    }
    let length = u32::from_be_bytes(
        padded[..4]
            .try_into()
            .map_err(|_| CryptoError::InvalidPaddedPayload)?,
    ) as usize;
    let end = LENGTH_PREFIX_SIZE
        .checked_add(length)
        .ok_or(CryptoError::InvalidPaddedPayload)?;
    if end > padded.len() {
        return Err(CryptoError::InvalidPaddedPayload);
    }
    Ok(&padded[LENGTH_PREFIX_SIZE..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pads_to_the_smallest_bucket_and_round_trips() {
        for (len, bucket) in [(0, 1024), (1020, 1024), (1021, 4096), (4092, 4096)] {
            let plaintext = vec![0x5a; len];
            let padded = pad(&plaintext).unwrap();
            assert_eq!(padded.len(), bucket);
            assert_eq!(unpad(&padded).unwrap(), plaintext);
        }
    }

    #[test]
    fn rejects_too_large_and_malformed_payloads() {
        assert!(matches!(
            pad(&vec![0; 16_381]),
            Err(CryptoError::PayloadTooLarge)
        ));
        assert!(matches!(
            unpad(&[0; 100]),
            Err(CryptoError::InvalidPaddedPayload)
        ));
        let mut malformed = vec![0; 1024];
        malformed[..4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            unpad(&malformed),
            Err(CryptoError::InvalidPaddedPayload)
        ));
    }
}
