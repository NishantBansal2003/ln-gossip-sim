//! BOLT 7 `channel_update` message.

use bitcoin::hashes::{Hash, sha256d};
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{Secp256k1, SecretKey};

use crate::BoltError;
use crate::types::CHAIN_HASH_SIZE;
use crate::wire::WireFormat;

/// BOLT 7 `channel_update` message (type 258).
///
/// Each side of a channel independently announces its forwarding parameters
/// using `channel_update`. The message carries a single signature from the
/// originating node key, committing to everything after the signature field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelUpdate {
    /// Signature of `node_id` over the double-SHA256 of the message body
    /// following this signature field (see [`Self::signature_hash`]).
    pub signature: Signature,
    /// Genesis block hash of the chain this channel belongs to.
    pub chain_hash: [u8; CHAIN_HASH_SIZE],
    /// Compact encoding of the funding tx outpoint (`block << 40 | tx_index << 16 | output_index`).
    pub short_channel_id: u64,
    /// Update timestamp; intended to be a UNIX timestamp.
    pub timestamp: u32,
    /// `message_flags` bitfield (`must_be_one`, `dont_forward`).
    pub message_flags: u8,
    /// `channel_flags` bitfield (`direction`, `disable`).
    pub channel_flags: u8,
    /// Number of blocks to subtract from an incoming HTLC's `cltv_expiry`.
    pub cltv_expiry_delta: u16,
    /// Minimum HTLC value (millisatoshi) the channel peer will accept.
    pub htlc_minimum_msat: u64,
    /// Base fee charged per HTLC (millisatoshi).
    pub fee_base_msat: u32,
    /// Proportional fee per transferred satoshi (millionths).
    pub fee_proportional_millionths: u32,
    /// Maximum HTLC value (millisatoshi) the channel peer will route.
    pub htlc_maximum_msat: u64,
}

impl ChannelUpdate {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.signature.write(&mut out);
        self.chain_hash.write(&mut out);
        self.short_channel_id.write(&mut out);
        self.timestamp.write(&mut out);
        self.message_flags.write(&mut out);
        self.channel_flags.write(&mut out);
        self.cltv_expiry_delta.write(&mut out);
        self.htlc_minimum_msat.write(&mut out);
        self.fee_base_msat.write(&mut out);
        self.fee_proportional_millionths.write(&mut out);
        self.htlc_maximum_msat.write(&mut out);
        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `BoltError` if the payload is truncated or contains an
    /// invalid signature.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let signature = Signature::read(&mut cursor)?;
        let chain_hash = <[u8; CHAIN_HASH_SIZE]>::read(&mut cursor)?;
        let short_channel_id = u64::read(&mut cursor)?;
        let timestamp = u32::read(&mut cursor)?;
        let message_flags = u8::read(&mut cursor)?;
        let channel_flags = u8::read(&mut cursor)?;
        let cltv_expiry_delta = u16::read(&mut cursor)?;
        let htlc_minimum_msat = u64::read(&mut cursor)?;
        let fee_base_msat = u32::read(&mut cursor)?;
        let fee_proportional_millionths = u32::read(&mut cursor)?;
        let htlc_maximum_msat = u64::read(&mut cursor)?;

        Ok(Self {
            signature,
            chain_hash,
            short_channel_id,
            timestamp,
            message_flags,
            channel_flags,
            cltv_expiry_delta,
            htlc_minimum_msat,
            fee_base_msat,
            fee_proportional_millionths,
            htlc_maximum_msat,
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
    /// offset 64 (after the 64-byte signature), i.e. from the `chain_hash`
    /// field through the end.
    #[must_use]
    pub fn signature_hash(&self) -> bitcoin::secp256k1::Message {
        let mut data = Vec::new();
        self.chain_hash.write(&mut data);
        self.short_channel_id.write(&mut data);
        self.timestamp.write(&mut data);
        self.message_flags.write(&mut data);
        self.channel_flags.write(&mut data);
        self.cltv_expiry_delta.write(&mut data);
        self.htlc_minimum_msat.write(&mut data);
        self.fee_base_msat.write(&mut data);
        self.fee_proportional_millionths.write(&mut data);
        self.htlc_maximum_msat.write(&mut data);
        let hash = sha256d::Hash::hash(&data);
        bitcoin::secp256k1::Message::from_digest(hash.to_byte_array())
    }

    /// Creates a new `ChannelUpdate` and signs it with the provided node secret.
    ///
    /// `node_sk` is the secret for the node that owns this side of the channel.
    ///
    /// The signature commits to the message body (everything following the
    /// `signature` field), as required by BOLT 7.
    #[must_use]
    #[allow(clippy::too_many_arguments)] // mirrors the message's flat wire layout
    pub fn new_signed(
        chain_hash: [u8; CHAIN_HASH_SIZE],
        short_channel_id: u64,
        timestamp: u32,
        message_flags: u8,
        channel_flags: u8,
        cltv_expiry_delta: u16,
        htlc_minimum_msat: u64,
        fee_base_msat: u32,
        fee_proportional_millionths: u32,
        htlc_maximum_msat: u64,
        node_sk: &SecretKey,
    ) -> Self {
        let secp = Secp256k1::signing_only();

        // signature_hash() only hashes from `chain_hash` onward (BOLT 7 offset
        // 64), so the signature field doesn't affect the hash.  Use a throwaway
        // signature as placeholder, compute the real hash, then overwrite.
        let placeholder = secp.sign_ecdsa(
            &bitcoin::secp256k1::Message::from_digest([0u8; 32]),
            node_sk,
        );

        let mut update = Self {
            signature: placeholder,
            chain_hash,
            short_channel_id,
            timestamp,
            message_flags,
            channel_flags,
            cltv_expiry_delta,
            htlc_minimum_msat,
            fee_base_msat,
            fee_proportional_millionths,
            htlc_maximum_msat,
        };

        update.signature = secp.sign_ecdsa(&update.signature_hash(), node_sk);
        update
    }
}

#[cfg(test)]
mod tests {
    use super::super::COMPACT_SIGNATURE_SIZE;
    use super::*;
    use bitcoin::secp256k1::SecretKey;

    /// Bitcoin mainnet genesis block hash.
    const BITCOIN_MAINNET: [u8; CHAIN_HASH_SIZE] = [
        0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7,
        0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];

    /// Secret key used to sign sample messages in tests.
    const SAMPLE_SK_BYTES: [u8; 32] = [0x42; 32];

    /// Short channel ID used in sample messages (`539268x845x1`).
    const SAMPLE_SCID: u64 = (539_268 << 40) | (845 << 16) | 1;

    /// Helper: the secret key behind every sample message.
    fn sample_sk() -> SecretKey {
        SecretKey::from_slice(&SAMPLE_SK_BYTES).expect("valid secret")
    }

    /// Helper: a signed `channel_update` with sample parameters.
    fn sample_update() -> ChannelUpdate {
        ChannelUpdate::new_signed(
            BITCOIN_MAINNET,
            SAMPLE_SCID,
            1_715_000_000,
            1, // message_flags: must_be_one
            0, // channel_flags
            144,
            1_000,
            1_000,
            100,
            99_000_000,
            &sample_sk(),
        )
    }

    #[test]
    fn encode_decode_roundtrip() {
        let original = sample_update();
        let encoded = original.encode();
        let decoded = ChannelUpdate::decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn scid_formatting() {
        let msg = sample_update();
        assert_eq!(msg.scid_str(), "539268x845x1");
    }

    #[test]
    fn decode_truncated_signature() {
        assert_eq!(
            ChannelUpdate::decode(&[0u8; 30]),
            Err(BoltError::Truncated {
                expected: COMPACT_SIGNATURE_SIZE,
                actual: 30
            })
        );
    }

    #[test]
    fn decode_truncated_body() {
        let msg = sample_update();
        let encoded = msg.encode();
        // Drop the last byte of htlc_maximum_msat.
        let truncated = &encoded[..encoded.len() - 1];
        assert!(matches!(
            ChannelUpdate::decode(truncated),
            Err(BoltError::Truncated { .. })
        ));
    }

    #[test]
    fn decode_invalid_signature() {
        let msg = sample_update();
        let mut encoded = msg.encode();
        encoded[..COMPACT_SIGNATURE_SIZE].copy_from_slice(&[0xff; COMPACT_SIGNATURE_SIZE]);
        assert!(matches!(
            ChannelUpdate::decode(&encoded),
            Err(BoltError::InvalidSignature(_))
        ));
    }

    #[test]
    fn decode_preserves_unknown_flag_bits() {
        // The codec is intentionally lenient: it preserves all flag bits and
        // leaves policy decisions (e.g. `must_be_one` enforcement) to the caller.
        let mut msg = sample_update();
        msg.message_flags = 0xff;
        msg.channel_flags = 0xff;
        let decoded = ChannelUpdate::decode(&msg.encode()).unwrap();
        assert_eq!(decoded.message_flags, 0xff);
        assert_eq!(decoded.channel_flags, 0xff);
    }
}
