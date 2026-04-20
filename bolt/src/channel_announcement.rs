//! BOLT 7 `channel_announcement` message.

use bitcoin::hashes::{Hash, sha256d};
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

use crate::BoltError;
use crate::types::CHAIN_HASH_SIZE;
use crate::wire::WireFormat;

/// BOLT 7 `channel_announcement` message (type 256).
///
/// This message is broadcast to the network to announce a new public
/// channel. It contains four signatures (one from each endpoint's
/// node key and one from each endpoint's funding key) that together
/// prove control of the channel's funding output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelAnnouncement {
    /// Signature of the announcement by `node_id_1`.
    pub node_signature_1: Signature,
    /// Signature of the announcement by `node_id_2`.
    pub node_signature_2: Signature,
    /// Signature of the announcement by `bitcoin_key_1`.
    pub bitcoin_signature_1: Signature,
    /// Signature of the announcement by `bitcoin_key_2`.
    pub bitcoin_signature_2: Signature,
    /// Feature bits for the channel.
    pub features: Vec<u8>,
    /// Genesis block hash of the chain this channel belongs to.
    pub chain_hash: [u8; CHAIN_HASH_SIZE],
    /// Compact encoding of the funding tx outpoint (`block << 40 | tx_index << 16 | output_index`).
    pub short_channel_id: u64,
    /// The numerically lesser of the two node public keys.
    pub node_id_1: PublicKey,
    /// The numerically greater of the two node public keys.
    pub node_id_2: PublicKey,
    /// The funding public key for `node_id_1`.
    pub bitcoin_key_1: PublicKey,
    /// The funding public key for `node_id_2`.
    pub bitcoin_key_2: PublicKey,
}

impl ChannelAnnouncement {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.node_signature_1.write(&mut out);
        self.node_signature_2.write(&mut out);
        self.bitcoin_signature_1.write(&mut out);
        self.bitcoin_signature_2.write(&mut out);
        self.features.write(&mut out);
        self.chain_hash.write(&mut out);
        self.short_channel_id.write(&mut out);
        self.node_id_1.write(&mut out);
        self.node_id_2.write(&mut out);
        self.bitcoin_key_1.write(&mut out);
        self.bitcoin_key_2.write(&mut out);
        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `BoltError` if the payload is truncated or contains
    /// invalid signatures or public keys.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let node_signature_1 = Signature::read(&mut cursor)?;
        let node_signature_2 = Signature::read(&mut cursor)?;
        let bitcoin_signature_1 = Signature::read(&mut cursor)?;
        let bitcoin_signature_2 = Signature::read(&mut cursor)?;
        let features = Vec::<u8>::read(&mut cursor)?;
        let chain_hash = <[u8; CHAIN_HASH_SIZE]>::read(&mut cursor)?;
        let short_channel_id = u64::read(&mut cursor)?;
        let node_id_1 = PublicKey::read(&mut cursor)?;
        let node_id_2 = PublicKey::read(&mut cursor)?;
        let bitcoin_key_1 = PublicKey::read(&mut cursor)?;
        let bitcoin_key_2 = PublicKey::read(&mut cursor)?;

        Ok(Self {
            node_signature_1,
            node_signature_2,
            bitcoin_signature_1,
            bitcoin_signature_2,
            features,
            chain_hash,
            short_channel_id,
            node_id_1,
            node_id_2,
            bitcoin_key_1,
            bitcoin_key_2,
        })
    }

    /// Returns the short channel ID formatted as `block x tx x output`.
    #[must_use]
    pub fn scid_str(&self) -> String {
        let block = self.short_channel_id >> 40;
        let tx_index = (self.short_channel_id >> 16) & 0xFF_FFFF;
        let output = self.short_channel_id & 0xFFFF;
        format!("{block}x{tx_index}x{output}")
    }

    /// Computes the double-SHA256 hash that must be signed.
    ///
    /// Per BOLT 7, the hash covers the encoded message starting at byte
    /// offset 256 (after the four 64-byte signatures), i.e. from the
    /// `features` field through the end.
    #[must_use]
    pub fn signature_hash(&self) -> bitcoin::secp256k1::Message {
        let mut data = Vec::new();
        self.features.write(&mut data);
        self.chain_hash.write(&mut data);
        self.short_channel_id.write(&mut data);
        self.node_id_1.write(&mut data);
        self.node_id_2.write(&mut data);
        self.bitcoin_key_1.write(&mut data);
        self.bitcoin_key_2.write(&mut data);
        let hash = sha256d::Hash::hash(&data);
        bitcoin::secp256k1::Message::from_digest(hash.to_byte_array())
    }

    /// Creates a new `ChannelAnnouncement` and signs it with the provided keys.
    ///
    /// `node_sk_1` / `node_sk_2` are the node secrets for `node_id_1` / `node_id_2`.
    /// `bitcoin_sk_1` / `bitcoin_sk_2` are the funding key secrets.
    ///
    /// The caller must ensure that `node_id_1 < node_id_2` lexicographically
    /// (compressed public key bytes), as required by BOLT 7.
    #[must_use]
    pub fn new_signed(
        features: Vec<u8>,
        chain_hash: [u8; CHAIN_HASH_SIZE],
        short_channel_id: u64,
        node_sk_1: &SecretKey,
        node_sk_2: &SecretKey,
        bitcoin_sk_1: &SecretKey,
        bitcoin_sk_2: &SecretKey,
    ) -> Self {
        let secp = Secp256k1::signing_only();

        let node_id_1 = PublicKey::from_secret_key(&secp, node_sk_1);
        let node_id_2 = PublicKey::from_secret_key(&secp, node_sk_2);
        let bitcoin_key_1 = PublicKey::from_secret_key(&secp, bitcoin_sk_1);
        let bitcoin_key_2 = PublicKey::from_secret_key(&secp, bitcoin_sk_2);

        // signature_hash() only hashes from `features` onward (BOLT 7 offset
        // 256), so the signature fields don't affect the hash.  Use a throwaway
        // signature as placeholder, compute the real hash, then overwrite.
        let placeholder = secp.sign_ecdsa(
            &bitcoin::secp256k1::Message::from_digest([0u8; 32]),
            node_sk_1,
        );

        let mut ann = Self {
            node_signature_1: placeholder,
            node_signature_2: placeholder,
            bitcoin_signature_1: placeholder,
            bitcoin_signature_2: placeholder,
            features,
            chain_hash,
            short_channel_id,
            node_id_1,
            node_id_2,
            bitcoin_key_1,
            bitcoin_key_2,
        };

        let msg = ann.signature_hash();
        ann.node_signature_1 = secp.sign_ecdsa(&msg, node_sk_1);
        ann.node_signature_2 = secp.sign_ecdsa(&msg, node_sk_2);
        ann.bitcoin_signature_1 = secp.sign_ecdsa(&msg, bitcoin_sk_1);
        ann.bitcoin_signature_2 = secp.sign_ecdsa(&msg, bitcoin_sk_2);

        ann
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    /// Helper: create a deterministic signature for testing.
    fn test_signature(seed: u8) -> Signature {
        let secp = Secp256k1::signing_only();
        let mut secret = [0u8; 32];
        secret[31] = seed.max(1); // must be non-zero
        let sk = SecretKey::from_slice(&secret).unwrap();
        let msg = bitcoin::secp256k1::Message::from_digest([seed; 32]);
        secp.sign_ecdsa(&msg, &sk)
    }

    /// Helper: create a deterministic public key for testing.
    fn test_pubkey(seed: u8) -> PublicKey {
        let secp = Secp256k1::signing_only();
        let mut secret = [0u8; 32];
        secret[31] = seed.max(1);
        let sk = SecretKey::from_slice(&secret).unwrap();
        sk.public_key(&secp)
    }

    fn sample_announcement() -> ChannelAnnouncement {
        ChannelAnnouncement {
            node_signature_1: test_signature(1),
            node_signature_2: test_signature(2),
            bitcoin_signature_1: test_signature(3),
            bitcoin_signature_2: test_signature(4),
            features: vec![0x01, 0x02],
            chain_hash: [0xab; 32],
            short_channel_id: (700_000 << 40) | (42 << 16) | 1,
            node_id_1: test_pubkey(1),
            node_id_2: test_pubkey(2),
            bitcoin_key_1: test_pubkey(3),
            bitcoin_key_2: test_pubkey(4),
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let ann = sample_announcement();
        let encoded = ann.encode();
        let decoded = ChannelAnnouncement::decode(&encoded).unwrap();
        assert_eq!(decoded, ann);
    }

    #[test]
    fn scid_formatting() {
        let ann = sample_announcement();
        assert_eq!(ann.scid_str(), "700000x42x1");
    }

    #[test]
    fn decode_truncated() {
        let result = ChannelAnnouncement::decode(&[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn features_preserved() {
        let mut ann = sample_announcement();
        ann.features = vec![0xff; 100];
        let encoded = ann.encode();
        let decoded = ChannelAnnouncement::decode(&encoded).unwrap();
        assert_eq!(decoded.features, vec![0xff; 100]);
    }
}
