//! BOLT 7 `node_announcement` message.

use bitcoin::hashes::{Hash, sha256d};
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

use crate::BoltError;
use crate::wire::WireFormat;

/// BOLT 7 `node_announcement` message (type 257).
///
/// Allows a node to advertise extra data associated with its public key
/// (features, alias, color, network addresses). The message carries a single
/// signature from the node key, committing to everything after the signature
/// field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeAnnouncement {
    /// Signature of `node_id` over the double-SHA256 of the message body
    /// following this signature field (see [`Self::signature_hash`]).
    pub signature: Signature,
    /// Feature bits, BOLT 9.
    pub features: Vec<u8>,
    /// Monotonic per-node timestamp; receivers reject older announcements.
    pub timestamp: u32,
    /// Compressed secp256k1 public key identifying the announcing node.
    pub node_id: PublicKey,
    /// RGB color triple for UI display.
    pub rgb_color: [u8; 3],
    /// UTF-8 node alias, zero-padded to 32 bytes.
    pub alias: [u8; 32],
    /// Network address descriptors.
    pub addresses: Vec<u8>,
}

impl NodeAnnouncement {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.signature.write(&mut out);
        self.features.write(&mut out);
        self.timestamp.write(&mut out);
        self.node_id.write(&mut out);
        self.rgb_color.write(&mut out);
        self.alias.write(&mut out);
        self.addresses.write(&mut out);
        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `BoltError` if the payload is truncated or contains an
    /// invalid signature or public key.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let signature = Signature::read(&mut cursor)?;
        let features = Vec::<u8>::read(&mut cursor)?;
        let timestamp = u32::read(&mut cursor)?;
        let node_id = PublicKey::read(&mut cursor)?;
        let rgb_color = <[u8; 3]>::read(&mut cursor)?;
        let alias = <[u8; 32]>::read(&mut cursor)?;
        let addresses = Vec::<u8>::read(&mut cursor)?;

        Ok(Self {
            signature,
            features,
            timestamp,
            node_id,
            rgb_color,
            alias,
            addresses,
        })
    }

    /// Computes the double-SHA256 hash that must be signed.
    ///
    /// Per BOLT 7, the hash covers the encoded message starting at byte
    /// offset 64 (after the 64-byte signature), i.e. from the `features`
    /// field through the end.
    #[must_use]
    pub fn signature_hash(&self) -> bitcoin::secp256k1::Message {
        let mut data = Vec::new();
        self.features.write(&mut data);
        self.timestamp.write(&mut data);
        self.node_id.write(&mut data);
        self.rgb_color.write(&mut data);
        self.alias.write(&mut data);
        self.addresses.write(&mut data);
        let hash = sha256d::Hash::hash(&data);
        bitcoin::secp256k1::Message::from_digest(hash.to_byte_array())
    }

    /// Verifies `self.signature` against the embedded `node_id` per BOLT 7.
    ///
    /// Returns `true` if the signature is valid.
    #[must_use]
    pub fn verify(&self) -> bool {
        Secp256k1::verification_only()
            .verify_ecdsa(&self.signature_hash(), &self.signature, &self.node_id)
            .is_ok()
    }

    /// Creates a new `NodeAnnouncement` and signs it with the provided node secret.
    ///
    /// `node_sk` is the secret for the announcing node; `node_id` is derived
    /// from it. The signature commits to the message body (everything following
    /// the `signature` field), as required by BOLT 7.
    #[must_use]
    pub fn new_signed(
        features: Vec<u8>,
        timestamp: u32,
        rgb_color: [u8; 3],
        alias: [u8; 32],
        addresses: Vec<u8>,
        node_sk: &SecretKey,
    ) -> Self {
        let secp = Secp256k1::signing_only();
        let node_id = PublicKey::from_secret_key(&secp, node_sk);

        // signature_hash() only hashes from `features` onward (BOLT 7 offset
        // 64), so the signature field doesn't affect the hash.  Use a throwaway
        // signature as placeholder, compute the real hash, then overwrite.
        let placeholder = secp.sign_ecdsa(
            &bitcoin::secp256k1::Message::from_digest([0u8; 32]),
            node_sk,
        );

        let mut ann = Self {
            signature: placeholder,
            features,
            timestamp,
            node_id,
            rgb_color,
            alias,
            addresses,
        };

        ann.signature = secp.sign_ecdsa(&ann.signature_hash(), node_sk);
        ann
    }

    /// Creates a minimal `NodeAnnouncement` signed with `node_sk`.
    ///
    /// All optional fields are left empty/zero and `timestamp` is `0` — the
    /// smallest, broadly-acceptable announcement a BOLT 7 node will take.
    /// `node_id` is derived from `node_sk`, so passing the same node secret
    /// used elsewhere (e.g. when building `channel_update`s) yields a matching
    /// `node_id` and a valid signature.
    #[must_use]
    pub fn default_signed(node_sk: &SecretKey) -> Self {
        Self::new_signed(Vec::new(), 0, [0; 3], [0; 32], Vec::new(), node_sk)
    }
}

#[cfg(test)]
#[allow(clippy::range_plus_one)]
mod tests {
    use super::super::{COMPACT_SIGNATURE_SIZE, PUBLIC_KEY_SIZE};
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    /// Valid `NodeAnnouncement` for testing.
    fn sample_node_announcement() -> NodeAnnouncement {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).expect("valid secret");

        let mut na = NodeAnnouncement {
            signature: Signature::from_compact(&[0u8; 64]).unwrap(),
            features: vec![0x01, 0x02],
            timestamp: 1_700_000_000,
            node_id: PublicKey::from_secret_key(&secp, &sk),
            rgb_color: [0xaa, 0xbb, 0xcc],
            alias: [0x42; 32],
            addresses: vec![0x01, 0x7f, 0x00, 0x00, 0x01, 0x23, 0x45],
        };
        na.signature = secp.sign_ecdsa(&na.signature_hash(), &sk);
        na
    }

    #[test]
    fn encode_decode_roundtrip() {
        let original = sample_node_announcement();
        let encoded = original.encode();
        let decoded = NodeAnnouncement::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn new_signed_roundtrips_and_verifies() {
        let sk = SecretKey::from_slice(&[0x11; 32]).unwrap();
        let na = NodeAnnouncement::new_signed(
            vec![0x01, 0x02],
            1_700_000_000,
            [0xaa, 0xbb, 0xcc],
            [0x42; 32],
            vec![0x01, 0x7f, 0x00, 0x00, 0x01, 0x23, 0x45],
            &sk,
        );
        assert!(na.verify());
        let decoded = NodeAnnouncement::decode(&na.encode()).unwrap();
        assert_eq!(na, decoded);
    }

    #[test]
    fn default_signed_uses_node_secret_and_verifies() {
        // Same node secret used by the channel_update sample messages, so the
        // resulting node_id matches that node's other gossip messages.
        let sk = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let na = NodeAnnouncement::default_signed(&sk);

        let secp = Secp256k1::new();
        assert_eq!(na.node_id, PublicKey::from_secret_key(&secp, &sk));
        assert_eq!(na.timestamp, 0);
        assert!(na.features.is_empty());
        assert!(na.addresses.is_empty());
        assert!(na.verify());

        let decoded = NodeAnnouncement::decode(&na.encode()).unwrap();
        assert_eq!(decoded, na);
    }

    #[test]
    fn verify_succeeds_after_sign() {
        let original = sample_node_announcement();
        assert!(original.verify());
    }

    #[test]
    fn verify_fails_on_tampered_body() {
        let mut na = sample_node_announcement();
        na.timestamp = na.timestamp.wrapping_add(1);
        assert!(!na.verify());
    }

    #[test]
    fn verify_fails_on_invalid_signature() {
        // Overwrite a valid sig with a structurally-parseable but
        // cryptographically-invalid one (r = s = 0).
        let mut na = sample_node_announcement();
        na.signature = Signature::from_compact(&[0u8; 64]).unwrap();
        assert!(!na.verify());
    }

    #[test]
    fn encode_size_with_empty_variable_fields() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).unwrap();
        let na = NodeAnnouncement {
            signature: Signature::from_compact(&[0u8; 64]).unwrap(),
            features: vec![],
            timestamp: 0,
            node_id: PublicKey::from_secret_key(&secp, &sk),
            rgb_color: [0; 3],
            alias: [0; 32],
            addresses: vec![],
        };
        // 64 (sig) + 2 (flen=0) + 4 (timestamp) + 33 (node_id) + 3 (rgb) + 32 (alias) + 2 (addrlen=0) = 140
        assert_eq!(na.encode().len(), 140);
    }

    #[test]
    fn decode_truncated_signature() {
        assert_eq!(
            NodeAnnouncement::decode(&[0u8; 20]),
            Err(BoltError::Truncated {
                expected: COMPACT_SIGNATURE_SIZE,
                actual: 20,
            })
        );
    }

    #[test]
    fn decode_truncated_features_len() {
        // Valid sig + 1 byte (need 2 for u16 len)
        let encoded = sample_node_announcement().encode();
        let data = &encoded[..COMPACT_SIGNATURE_SIZE + 1];
        assert_eq!(
            NodeAnnouncement::decode(data),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1,
            })
        );
    }

    #[test]
    fn decode_truncated_features_data() {
        // Valid sig + features_len=5 + only 2 bytes follow
        let mut data = sample_node_announcement().encode()[..COMPACT_SIGNATURE_SIZE].to_vec();
        data.extend_from_slice(&[0x00, 0x05, 0xaa, 0xbb]);
        assert_eq!(
            NodeAnnouncement::decode(&data),
            Err(BoltError::Truncated {
                expected: 5,
                actual: 2,
            })
        );
    }

    #[test]
    fn decode_truncated_timestamp() {
        // sig(64) + features(2 len + 2 data = 4) + 1 byte of timestamp
        let encoded = sample_node_announcement().encode();
        let data = &encoded[..COMPACT_SIGNATURE_SIZE + 4 + 1];
        assert_eq!(
            NodeAnnouncement::decode(data),
            Err(BoltError::Truncated {
                expected: 4,
                actual: 1,
            })
        );
    }

    #[test]
    fn decode_truncated_node_id() {
        // sig(64) + features(4) + timestamp(4) + 10 bytes of node_id (need 33)
        let encoded = sample_node_announcement().encode();
        let data = &encoded[..COMPACT_SIGNATURE_SIZE + 4 + 4 + 10];
        assert_eq!(
            NodeAnnouncement::decode(data),
            Err(BoltError::Truncated {
                expected: PUBLIC_KEY_SIZE,
                actual: 10,
            })
        );
    }

    #[test]
    fn decode_truncated_rgb_color() {
        // sig(64) + features(4) + timestamp(4) + node_id(33) + 2 bytes of rgb (need 3)
        let encoded = sample_node_announcement().encode();
        let data = &encoded[..COMPACT_SIGNATURE_SIZE + 4 + 4 + PUBLIC_KEY_SIZE + 2];
        assert_eq!(
            NodeAnnouncement::decode(data),
            Err(BoltError::Truncated {
                expected: 3,
                actual: 2,
            })
        );
    }

    #[test]
    fn decode_truncated_alias() {
        // sig(64) + features(4) + timestamp(4) + node_id(33) + rgb(3) + 10 bytes of alias (need 32)
        let encoded = sample_node_announcement().encode();
        let data = &encoded[..COMPACT_SIGNATURE_SIZE + 4 + 4 + PUBLIC_KEY_SIZE + 3 + 10];
        assert_eq!(
            NodeAnnouncement::decode(data),
            Err(BoltError::Truncated {
                expected: 32,
                actual: 10,
            })
        );
    }

    #[test]
    fn decode_truncated_addresses_len() {
        // All fields up to and including alias + 1 byte (need 2 for addrlen)
        let encoded = sample_node_announcement().encode();
        let data = &encoded[..COMPACT_SIGNATURE_SIZE + 4 + 4 + PUBLIC_KEY_SIZE + 3 + 32 + 1];
        assert_eq!(
            NodeAnnouncement::decode(data),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1,
            })
        );
    }

    #[test]
    fn decode_truncated_addresses_data() {
        // All fixed fields valid, addrlen declares 5 but only 2 bytes follow
        let encoded = sample_node_announcement().encode();
        let prefix_end = COMPACT_SIGNATURE_SIZE + 4 + 4 + PUBLIC_KEY_SIZE + 3 + 32;
        let mut data = encoded[..prefix_end].to_vec();
        data.extend_from_slice(&[0x00, 0x05, 0xaa, 0xbb]);
        assert_eq!(
            NodeAnnouncement::decode(&data),
            Err(BoltError::Truncated {
                expected: 5,
                actual: 2,
            })
        );
    }

    #[test]
    fn decode_invalid_signature() {
        let mut encoded = sample_node_announcement().encode();
        // r and s are both above curve order.
        let bad_sig = [0xff; COMPACT_SIGNATURE_SIZE];
        encoded[..COMPACT_SIGNATURE_SIZE].copy_from_slice(&bad_sig);
        assert_eq!(
            NodeAnnouncement::decode(&encoded),
            Err(BoltError::InvalidSignature(bad_sig))
        );
    }

    #[test]
    fn decode_invalid_node_id() {
        let mut encoded = sample_node_announcement().encode();
        // All-zero bytes are not a valid compressed pubkey.
        let bad_pubkey = [0u8; PUBLIC_KEY_SIZE];
        let node_id_offset = COMPACT_SIGNATURE_SIZE + 4 + 4;
        encoded[node_id_offset..node_id_offset + PUBLIC_KEY_SIZE].copy_from_slice(&bad_pubkey);
        assert_eq!(
            NodeAnnouncement::decode(&encoded),
            Err(BoltError::InvalidPublicKey(bad_pubkey))
        );
    }

    #[test]
    fn decode_ignores_trailing_bytes() {
        let original = sample_node_announcement();
        let mut encoded = original.encode();
        encoded.extend_from_slice(&[0x42, 0x42]);
        let decoded = NodeAnnouncement::decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }
}
