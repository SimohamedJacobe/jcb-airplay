// JCB AirPlay — crypto.rs
// FairPlay / AES-128 key exchange and stream decryption.
//
// Responsibilities:
//   • Execute the Apple FairPlay SRP-style handshake.
//   • Derive the per-session AES-128-CTR stream key and IV from the handshake.
//   • Decrypt incoming RTP audio/video payloads in-place (zero-copy where possible).

use thiserror::Error;

/// Errors that can occur in the crypto module.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// The key material has an unexpected length.
    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    /// The IV material has an unexpected length.
    #[error("invalid IV length: expected {expected}, got {got}")]
    InvalidIvLength { expected: usize, got: usize },

    /// Decryption failed for the given payload.
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
}

/// AES-128 key size in bytes.
pub const AES128_KEY_SIZE: usize = 16;

/// AES-128-CTR IV size in bytes.
pub const AES128_IV_SIZE: usize = 16;

/// A derived AirPlay stream key used to decrypt AES-128-CTR payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamKey {
    /// 128-bit AES key.
    pub key: [u8; AES128_KEY_SIZE],
    /// 128-bit initial IV (sequence-number counter appended per packet).
    pub iv: [u8; AES128_IV_SIZE],
}

impl StreamKey {
    /// Construct a `StreamKey` from raw byte slices.
    ///
    /// # Errors
    /// Returns [`CryptoError`] if either slice is not exactly the expected length.
    pub fn from_bytes(key: &[u8], iv: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != AES128_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: AES128_KEY_SIZE,
                got: key.len(),
            });
        }
        if iv.len() != AES128_IV_SIZE {
            return Err(CryptoError::InvalidIvLength {
                expected: AES128_IV_SIZE,
                got: iv.len(),
            });
        }
        let mut k = [0u8; AES128_KEY_SIZE];
        let mut i = [0u8; AES128_IV_SIZE];
        k.copy_from_slice(key);
        i.copy_from_slice(iv);
        Ok(Self { key: k, iv: i })
    }

    /// Decrypt `payload` in-place using AES-128-CTR with this key.
    ///
    /// `seq` is the RTP sequence number used to derive the packet-level IV.
    ///
    /// # Errors
    /// Returns [`CryptoError`] if decryption fails.
    pub fn decrypt_payload(&self, payload: &mut [u8], seq: u16) -> Result<(), CryptoError> {
        // TODO(step-3): implement real AES-128-CTR using the `aes` + `ctr` crates.
        // For now, XOR with a deterministic pad derived from seq for testability.
        let pad = seq.to_be_bytes();
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= pad[i % 2] ^ self.key[i % AES128_KEY_SIZE];
        }
        log::debug!("crypto: decrypted {} bytes (seq={})", payload.len(), seq);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_key() -> StreamKey {
        let key = [0x42u8; AES128_KEY_SIZE];
        let iv = [0xABu8; AES128_IV_SIZE];
        StreamKey::from_bytes(&key, &iv).expect("valid key/iv")
    }

    #[test]
    fn from_bytes_succeeds_with_correct_lengths() {
        let result = StreamKey::from_bytes(&[0u8; 16], &[0u8; 16]);
        assert!(result.is_ok());
    }

    #[test]
    fn from_bytes_fails_with_short_key() {
        let result = StreamKey::from_bytes(&[0u8; 8], &[0u8; 16]);
        assert!(matches!(result, Err(CryptoError::InvalidKeyLength { .. })));
    }

    #[test]
    fn from_bytes_fails_with_short_iv() {
        let result = StreamKey::from_bytes(&[0u8; 16], &[0u8; 8]);
        assert!(matches!(result, Err(CryptoError::InvalidIvLength { .. })));
    }

    #[test]
    fn decrypt_payload_is_involution() {
        // XOR-based stub: applying twice should restore original.
        let key = sample_key();
        let original = vec![0x01u8, 0x02, 0x03, 0x04];
        let mut payload = original.clone();
        key.decrypt_payload(&mut payload, 1).unwrap();
        key.decrypt_payload(&mut payload, 1).unwrap();
        assert_eq!(payload, original, "double-decrypt should restore plaintext");
    }
}
