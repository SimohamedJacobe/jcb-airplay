// JCB AirPlay — crypto.rs
// Cryptographic Pairing & Session Key Derivation Engine for JCB AirPlay.
//
// Responsibilities:
//   • Ephemeral X25519 Diffie-Hellman key agreement (`x25519-dalek`).
//   • Ed25519 digital signature generation and verification (`ed25519-dalek`).
//   • AES-128-CTR & AES-128-CBC stream/block cipher primitives (`aes`, `ctr`, `cbc`, `sha2`).
//   • Multi-Phase Session Handshake State Machine (`PairSetup`, `PairVerify`, `SessionKeySetup`).
//   • Zero-copy in-place AES-128-CTR payload decryption with packet-level counter management.

use aes::Aes128;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut};
use ctr::cipher::{KeyIvInit, StreamCipher};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// AES-128 key size in bytes.
pub const AES128_KEY_SIZE: usize = 16;

/// AES-128-CTR / AES-128-CBC IV size in bytes.
pub const AES128_IV_SIZE: usize = 16;

/// Ed25519 public key size in bytes.
pub const ED25519_PUBKEY_SIZE: usize = 32;

/// Ed25519 signature size in bytes.
pub const ED25519_SIGNATURE_SIZE: usize = 64;

/// X25519 public key size in bytes.
pub const X25519_PUBKEY_SIZE: usize = 32;

/// PairVerify Phase 1 packet size: 4-byte header + 32-byte X25519 pub + 32-byte Ed25519 pub.
pub const PAIR_VERIFY_PHASE1_LEN: usize = 68;

/// PairVerify Phase 1 response size: 32-byte server X25519 pub + 64-byte encrypted signature.
pub const PAIR_VERIFY_RESPONSE1_LEN: usize = 96;

/// PairVerify Phase 2 packet size: 4-byte header + 64-byte encrypted signature.
pub const PAIR_VERIFY_PHASE2_LEN: usize = 68;

/// Type alias for AES-128 in Counter Mode with Big-Endian 128-bit counter.
pub type Aes128Ctr = ctr::Ctr128BE<Aes128>;

/// Type alias for AES-128 in CBC Encryption Mode with PKCS7 padding.
pub type Aes128CbcEnc = cbc::Encryptor<Aes128>;

/// Type alias for AES-128 in CBC Decryption Mode with PKCS7 padding.
pub type Aes128CbcDec = cbc::Decryptor<Aes128>;

/// Errors that can occur in the cryptographic engine.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    /// The key material has an unexpected length.
    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    /// The IV material has an unexpected length.
    #[error("invalid IV length: expected {expected}, got {got}")]
    InvalidIvLength { expected: usize, got: usize },

    /// Packet length did not match protocol expectations.
    #[error("invalid packet length: expected {expected}, got {got}")]
    InvalidPacketLength { expected: usize, got: usize },

    /// The state machine encountered an operation invalid in the current state.
    #[error("invalid handshake state: {0}")]
    InvalidState(String),

    /// Digital signature verification failed.
    #[error("signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    /// Stream or block cipher decryption failed.
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    /// Generic cryptographic operation failure.
    #[error("cryptographic operation failed: {0}")]
    OperationFailed(String),
}

/// Applies AES-128-CTR in-place on the provided slice using the given 16-byte key and 16-byte IV.
pub fn aes128_ctr_apply(key: &[u8; 16], iv: &[u8; 16], buffer: &mut [u8]) {
    let mut cipher = Aes128Ctr::new(key.into(), iv.into());
    cipher.apply_keystream(buffer);
}

/// Encrypts plaintext using AES-128-CBC with PKCS7 padding.
pub fn aes128_cbc_encrypt(
    key: &[u8; 16],
    iv: &[u8; 16],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut buf = vec![0u8; plaintext.len() + 16];
    buf[..plaintext.len()].copy_from_slice(plaintext);
    let cipher = Aes128CbcEnc::new(key.into(), iv.into());
    let ct = cipher
        .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
        .map_err(|e| CryptoError::OperationFailed(format!("CBC encrypt error: {e}")))?;
    Ok(ct.to_vec())
}

/// Decrypts ciphertext using AES-128-CBC with PKCS7 padding.
pub fn aes128_cbc_decrypt(
    key: &[u8; 16],
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return Err(CryptoError::DecryptionFailed(
            "ciphertext length must be a non-zero multiple of 16".to_string(),
        ));
    }
    let mut buf = ciphertext.to_vec();
    let cipher = Aes128CbcDec::new(key.into(), iv.into());
    let pt = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| CryptoError::DecryptionFailed(format!("CBC decrypt error: {e}")))?;
    Ok(pt.to_vec())
}

/// A derived AirPlay stream key used to decrypt incoming AES-128-CTR payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamKey {
    /// 128-bit AES key.
    pub key: [u8; AES128_KEY_SIZE],
    /// 128-bit initial base IV.
    pub iv: [u8; AES128_IV_SIZE],
}

impl StreamKey {
    /// Construct a `StreamKey` from raw byte slices.
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

    /// Derives the 16-byte stream key and 16-byte IV from a session seed using SHA-512 salted hashing.
    ///
    /// Uses the standard AirPlay salt labels: `"AirPlayStreamKey"` and `"AirPlayStreamIV"`.
    pub fn derive_from_seed(seed: &[u8]) -> Self {
        let mut key_hasher = Sha512::new();
        key_hasher.update(b"AirPlayStreamKey");
        key_hasher.update(seed);
        let key_digest = key_hasher.finalize();

        let mut iv_hasher = Sha512::new();
        iv_hasher.update(b"AirPlayStreamIV");
        iv_hasher.update(seed);
        let iv_digest = iv_hasher.finalize();

        let mut key = [0u8; AES128_KEY_SIZE];
        let mut iv = [0u8; AES128_IV_SIZE];
        key.copy_from_slice(&key_digest[0..AES128_KEY_SIZE]);
        iv.copy_from_slice(&iv_digest[0..AES128_IV_SIZE]);

        Self { key, iv }
    }

    /// Decrypts payload in-place using real AES-128-CTR with sequence-number packet IV mixing.
    ///
    /// In AirPlay media transport, the 16-bit RTP sequence number is incorporated into the
    /// least-significant bytes of the base IV to establish per-packet counter uniqueness.
    pub fn decrypt_payload(&self, payload: &mut [u8], seq: u16) -> Result<(), CryptoError> {
        let mut packet_iv = self.iv;
        packet_iv[14] ^= (seq >> 8) as u8;
        packet_iv[15] ^= (seq & 0xFF) as u8;

        aes128_ctr_apply(&self.key, &packet_iv, payload);
        log::debug!("crypto: decrypted {} bytes (seq={})", payload.len(), seq);
        Ok(())
    }

    /// Encrypts payload in-place using real AES-128-CTR (keystream symmetry with `decrypt_payload`).
    pub fn encrypt_payload(&self, payload: &mut [u8], seq: u16) -> Result<(), CryptoError> {
        self.decrypt_payload(payload, seq)
    }
}

/// Handler for the `/pair-setup` identity exchange stage.
pub struct PairSetupHandler {
    signing_key: SigningKey,
    client_public_key: Option<[u8; ED25519_PUBKEY_SIZE]>,
}

impl Default for PairSetupHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl PairSetupHandler {
    /// Creates a new handler with a freshly generated random Ed25519 identity key.
    pub fn new() -> Self {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        Self {
            signing_key,
            client_public_key: None,
        }
    }

    /// Creates a handler with an explicit SigningKey (useful for deterministic tests).
    pub fn with_signing_key(signing_key: SigningKey) -> Self {
        Self {
            signing_key,
            client_public_key: None,
        }
    }

    /// Returns the receiver's 32-byte Ed25519 public key.
    pub fn public_key(&self) -> [u8; ED25519_PUBKEY_SIZE] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Returns the verified client public key if setup has occurred.
    pub fn client_public_key(&self) -> Option<[u8; ED25519_PUBKEY_SIZE]> {
        self.client_public_key
    }

    /// Handles a 32-byte client Ed25519 public key setup frame, returns the receiver's public key.
    pub fn handle_setup(&mut self, client_payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if client_payload.len() != ED25519_PUBKEY_SIZE {
            return Err(CryptoError::InvalidPacketLength {
                expected: ED25519_PUBKEY_SIZE,
                got: client_payload.len(),
            });
        }
        let mut client_pk = [0u8; ED25519_PUBKEY_SIZE];
        client_pk.copy_from_slice(client_payload);
        self.client_public_key = Some(client_pk);

        Ok(self.public_key().to_vec())
    }
}

/// State tracking for the `/pair-verify` handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairVerifyState {
    /// Unverified; awaiting Phase 1 client initiation.
    Unverified,
    /// Phase 1 complete; waiting for client Phase 2 signature payload.
    Phase1Complete,
    /// Successfully authenticated and verified.
    Verified,
}

/// Handler for the 2-phase `/pair-verify` protocol.
pub struct PairVerifyHandler {
    state: PairVerifyState,
    server_signing_key: SigningKey,
    server_ephemeral_secret: Option<StaticSecret>,
    server_ephemeral_public: [u8; X25519_PUBKEY_SIZE],
    client_ephemeral_public: [u8; X25519_PUBKEY_SIZE],
    client_verifying_key: Option<VerifyingKey>,
    shared_secret: [u8; 32],
    aes_key: [u8; AES128_KEY_SIZE],
    aes_iv: [u8; AES128_IV_SIZE],
}

impl PairVerifyHandler {
    /// Creates a new PairVerify handler using the server's long-term identity key.
    pub fn new(server_signing_key: SigningKey) -> Self {
        Self {
            state: PairVerifyState::Unverified,
            server_signing_key,
            server_ephemeral_secret: None,
            server_ephemeral_public: [0u8; X25519_PUBKEY_SIZE],
            client_ephemeral_public: [0u8; X25519_PUBKEY_SIZE],
            client_verifying_key: None,
            shared_secret: [0u8; 32],
            aes_key: [0u8; AES128_KEY_SIZE],
            aes_iv: [0u8; AES128_IV_SIZE],
        }
    }

    /// Current verification status of the handler.
    pub fn state(&self) -> PairVerifyState {
        self.state
    }

    /// Returns the 32-byte shared secret derived in Phase 1.
    pub fn shared_secret(&self) -> [u8; 32] {
        self.shared_secret
    }

    /// Processes Phase 1 (68-byte client request) and produces the 96-byte server response.
    ///
    /// Request layout (68 bytes):
    ///   - bytes 0..4: flag/header (0x01, 0x00, 0x00, 0x00)
    ///   - bytes 4..36: client ephemeral X25519 public key (32 bytes)
    ///   - bytes 36..68: client Ed25519 public key (32 bytes)
    ///
    /// Response layout (96 bytes):
    ///   - bytes 0..32: server ephemeral X25519 public key (32 bytes)
    ///   - bytes 32..96: AES-128-CTR encrypted server Ed25519 signature (64 bytes)
    pub fn handle_phase1(&mut self, packet: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if packet.len() != PAIR_VERIFY_PHASE1_LEN {
            return Err(CryptoError::InvalidPacketLength {
                expected: PAIR_VERIFY_PHASE1_LEN,
                got: packet.len(),
            });
        }

        let mut client_eph_pub = [0u8; X25519_PUBKEY_SIZE];
        client_eph_pub.copy_from_slice(&packet[4..36]);
        self.client_ephemeral_public = client_eph_pub;

        let mut client_ed_pub = [0u8; ED25519_PUBKEY_SIZE];
        client_ed_pub.copy_from_slice(&packet[36..68]);
        let client_vk = VerifyingKey::from_bytes(&client_ed_pub).map_err(|e| {
            CryptoError::OperationFailed(format!("invalid client Ed25519 public key: {e}"))
        })?;
        self.client_verifying_key = Some(client_vk);

        // Generate server ephemeral keypair using StaticSecret from OsRng
        let server_secret = StaticSecret::random_from_rng(OsRng);
        let server_pub = X25519PublicKey::from(&server_secret);
        self.server_ephemeral_public = server_pub.to_bytes();

        // Calculate Diffie-Hellman shared secret: X25519(server_secret, client_eph_pub)
        let client_pub_point = X25519PublicKey::from(self.client_ephemeral_public);
        let shared = server_secret.diffie_hellman(&client_pub_point);
        self.shared_secret = shared.to_bytes();
        self.server_ephemeral_secret = Some(server_secret);

        // Derive AES key and IV via SHA-512 with Pair-Verify salt tags
        let mut key_hasher = Sha512::new();
        key_hasher.update(b"Pair-Verify-AES-Key");
        key_hasher.update(self.shared_secret);
        let key_hash = key_hasher.finalize();
        self.aes_key.copy_from_slice(&key_hash[0..AES128_KEY_SIZE]);

        let mut iv_hasher = Sha512::new();
        iv_hasher.update(b"Pair-Verify-AES-IV");
        iv_hasher.update(self.shared_secret);
        let iv_hash = iv_hasher.finalize();
        self.aes_iv.copy_from_slice(&iv_hash[0..AES128_IV_SIZE]);

        // Construct message to sign: server_ephemeral_pub (32) || client_ephemeral_pub (32)
        let mut msg_to_sign = [0u8; 64];
        msg_to_sign[0..32].copy_from_slice(&self.server_ephemeral_public);
        msg_to_sign[32..64].copy_from_slice(&self.client_ephemeral_public);

        let signature: Signature = self.server_signing_key.sign(&msg_to_sign);
        let mut sig_bytes = signature.to_bytes();

        // Encrypt the 64-byte signature with AES-128-CTR
        aes128_ctr_apply(&self.aes_key, &self.aes_iv, &mut sig_bytes);

        // Construct 96-byte response
        let mut response = Vec::with_capacity(PAIR_VERIFY_RESPONSE1_LEN);
        response.extend_from_slice(&self.server_ephemeral_public);
        response.extend_from_slice(&sig_bytes);

        self.state = PairVerifyState::Phase1Complete;
        Ok(response)
    }

    /// Processes Phase 2 (68-byte client signature payload), verifies signature, completes pairing.
    ///
    /// Request layout (68 bytes):
    ///   - bytes 0..4: flag/header (0x00, 0x00, 0x00, 0x00)
    ///   - bytes 4..68: AES-128-CTR encrypted client Ed25519 signature (64 bytes)
    pub fn handle_phase2(&mut self, packet: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.state != PairVerifyState::Phase1Complete {
            return Err(CryptoError::InvalidState(
                "Phase 1 must be completed before executing Phase 2".to_string(),
            ));
        }

        if packet.len() != PAIR_VERIFY_PHASE2_LEN {
            return Err(CryptoError::InvalidPacketLength {
                expected: PAIR_VERIFY_PHASE2_LEN,
                got: packet.len(),
            });
        }

        let client_vk = self.client_verifying_key.as_ref().ok_or_else(|| {
            CryptoError::InvalidState("client verifying key not found from Phase 1".to_string())
        })?;

        // Decrypt the 64-byte client signature
        let mut sig_bytes = [0u8; ED25519_SIGNATURE_SIZE];
        sig_bytes.copy_from_slice(&packet[4..68]);
        aes128_ctr_apply(&self.aes_key, &self.aes_iv, &mut sig_bytes);

        let client_sig = Signature::from_bytes(&sig_bytes);

        // Client signed: client_ephemeral_pub (32) || server_ephemeral_pub (32)
        let mut expected_msg = [0u8; 64];
        expected_msg[0..32].copy_from_slice(&self.client_ephemeral_public);
        expected_msg[32..64].copy_from_slice(&self.server_ephemeral_public);

        client_vk
            .verify(&expected_msg, &client_sig)
            .map_err(|e| CryptoError::SignatureVerificationFailed(e.to_string()))?;

        self.state = PairVerifyState::Verified;
        // Return 0-length success acknowledgment or 4-byte zero payload
        Ok(vec![0x00, 0x00, 0x00, 0x00])
    }
}

/// Simulated client-side helper for PairVerify (used in automated end-to-end integration tests).
pub struct PairVerifyClient {
    client_signing_key: SigningKey,
    client_ephemeral_secret: StaticSecret,
    client_ephemeral_public: [u8; X25519_PUBKEY_SIZE],
    server_ephemeral_public: [u8; X25519_PUBKEY_SIZE],
    server_verifying_key: VerifyingKey,
    shared_secret: [u8; 32],
    aes_key: [u8; AES128_KEY_SIZE],
    aes_iv: [u8; AES128_IV_SIZE],
}

impl PairVerifyClient {
    /// Creates a simulated client pairing session.
    pub fn new(client_signing_key: SigningKey, server_verifying_key: VerifyingKey) -> Self {
        let eph_secret = StaticSecret::random_from_rng(OsRng);
        let eph_pub = X25519PublicKey::from(&eph_secret).to_bytes();

        Self {
            client_signing_key,
            client_ephemeral_secret: eph_secret,
            client_ephemeral_public: eph_pub,
            server_ephemeral_public: [0u8; X25519_PUBKEY_SIZE],
            server_verifying_key,
            shared_secret: [0u8; 32],
            aes_key: [0u8; AES128_KEY_SIZE],
            aes_iv: [0u8; AES128_IV_SIZE],
        }
    }

    /// Constructs the 68-byte Phase 1 request packet.
    pub fn build_phase1_request(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(PAIR_VERIFY_PHASE1_LEN);
        packet.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        packet.extend_from_slice(&self.client_ephemeral_public);
        packet.extend_from_slice(&self.client_signing_key.verifying_key().to_bytes());
        packet
    }

    /// Processes the 96-byte server Phase 1 response, verifies server signature, and generates Phase 2 request.
    pub fn process_phase1_response(&mut self, response: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if response.len() != PAIR_VERIFY_RESPONSE1_LEN {
            return Err(CryptoError::InvalidPacketLength {
                expected: PAIR_VERIFY_RESPONSE1_LEN,
                got: response.len(),
            });
        }

        self.server_ephemeral_public
            .copy_from_slice(&response[0..32]);

        // Compute client-side shared secret
        let server_pub = X25519PublicKey::from(self.server_ephemeral_public);
        let shared = self.client_ephemeral_secret.diffie_hellman(&server_pub);
        self.shared_secret = shared.to_bytes();

        // Derive AES key and IV
        let mut key_hasher = Sha512::new();
        key_hasher.update(b"Pair-Verify-AES-Key");
        key_hasher.update(self.shared_secret);
        let key_hash = key_hasher.finalize();
        self.aes_key.copy_from_slice(&key_hash[0..AES128_KEY_SIZE]);

        let mut iv_hasher = Sha512::new();
        iv_hasher.update(b"Pair-Verify-AES-IV");
        iv_hasher.update(self.shared_secret);
        let iv_hash = iv_hasher.finalize();
        self.aes_iv.copy_from_slice(&iv_hash[0..AES128_IV_SIZE]);

        // Decrypt server signature
        let mut sig_bytes = [0u8; ED25519_SIGNATURE_SIZE];
        sig_bytes.copy_from_slice(&response[32..96]);
        aes128_ctr_apply(&self.aes_key, &self.aes_iv, &mut sig_bytes);

        let server_sig = Signature::from_bytes(&sig_bytes);

        // Verify server signed: server_ephemeral_pub (32) || client_ephemeral_pub (32)
        let mut expected_msg = [0u8; 64];
        expected_msg[0..32].copy_from_slice(&self.server_ephemeral_public);
        expected_msg[32..64].copy_from_slice(&self.client_ephemeral_public);

        self.server_verifying_key
            .verify(&expected_msg, &server_sig)
            .map_err(|e| {
                CryptoError::SignatureVerificationFailed(format!("server sig invalid: {e}"))
            })?;

        // Client signs: client_ephemeral_pub (32) || server_ephemeral_pub (32)
        let mut client_msg = [0u8; 64];
        client_msg[0..32].copy_from_slice(&self.client_ephemeral_public);
        client_msg[32..64].copy_from_slice(&self.server_ephemeral_public);

        let client_signature = self.client_signing_key.sign(&client_msg);
        let mut client_sig_bytes = client_signature.to_bytes();

        // Encrypt with client's derived AES key and IV
        aes128_ctr_apply(&self.aes_key, &self.aes_iv, &mut client_sig_bytes);

        // Build 68-byte Phase 2 request
        let mut phase2_pkt = Vec::with_capacity(PAIR_VERIFY_PHASE2_LEN);
        phase2_pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        phase2_pkt.extend_from_slice(&client_sig_bytes);

        Ok(phase2_pkt)
    }

    /// Returns the client's derived shared secret.
    pub fn shared_secret(&self) -> [u8; 32] {
        self.shared_secret
    }
}

/// Handler for the 2-step `/fp-setup` session key handshake frames.
pub struct SessionKeySetup {
    challenge_processed: bool,
}

impl Default for SessionKeySetup {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionKeySetup {
    /// Creates a new SessionKeySetup handler.
    pub fn new() -> Self {
        Self {
            challenge_processed: false,
        }
    }

    /// Handles Step 1: 16-byte challenge frame.
    ///
    /// Returns a deterministic 16-byte challenge response.
    pub fn handle_challenge(&mut self, challenge: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if challenge.len() != 16 {
            return Err(CryptoError::InvalidPacketLength {
                expected: 16,
                got: challenge.len(),
            });
        }

        let mut hasher = Sha512::new();
        hasher.update(b"AirPlayChallengeResponse");
        hasher.update(challenge);
        let digest = hasher.finalize();

        let mut response = vec![0u8; 16];
        response.copy_from_slice(&digest[0..16]);
        self.challenge_processed = true;
        Ok(response)
    }

    /// Handles Step 2: 72-byte or 164-byte session key parameter frame and derives the [`StreamKey`].
    pub fn handle_key_exchange(&self, parameter_block: &[u8]) -> Result<StreamKey, CryptoError> {
        // AirPlay session frames are typically 72 bytes (FairPlay SAP v2) or 164 bytes (FairPlay SAP v3)
        if parameter_block.len() != 72 && parameter_block.len() != 164 {
            return Err(CryptoError::InvalidPacketLength {
                expected: 72,
                got: parameter_block.len(),
            });
        }

        // Derive stream key and IV from the session parameter block seed
        let seed = &parameter_block[0..32.min(parameter_block.len())];
        Ok(StreamKey::derive_from_seed(seed))
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
        // AES-CTR keystream application applied twice restores original plaintext.
        let key = sample_key();
        let original = vec![0x01u8, 0x02, 0x03, 0x04, 0xAA, 0xBB, 0xCC, 0xDD];
        let mut payload = original.clone();
        key.decrypt_payload(&mut payload, 1).unwrap();
        assert_ne!(
            payload, original,
            "encrypted buffer should differ from plaintext"
        );
        key.decrypt_payload(&mut payload, 1).unwrap();
        assert_eq!(payload, original, "double-decrypt should restore plaintext");
    }

    #[test]
    fn test_cbc_roundtrip() {
        let key = [0x55u8; 16];
        let iv = [0x33u8; 16];
        let plaintext = b"Hello JCB AirPlay Cryptographic Pipeline!";
        let ciphertext = aes128_cbc_encrypt(&key, &iv, plaintext).expect("CBC encrypt");
        assert_ne!(ciphertext, plaintext);
        let decrypted = aes128_cbc_decrypt(&key, &iv, &ciphertext).expect("CBC decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_pair_setup_flow() {
        let mut server = PairSetupHandler::new();
        let client_dummy_pk = [0x77u8; 32];
        let server_resp = server.handle_setup(&client_dummy_pk).expect("setup ok");
        assert_eq!(server_resp.len(), 32);
        assert_eq!(server.client_public_key(), Some(client_dummy_pk));
    }
}
