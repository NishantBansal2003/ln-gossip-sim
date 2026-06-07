//! BOLT 7 `reply_channel_range` message.

use crate::BoltError;
use crate::tlv::TlvStream;
use crate::types::CHAIN_HASH_SIZE;
use crate::wire::WireFormat;

/// TLV type for the optional per-channel timestamps.
pub(crate) const TLV_TIMESTAMPS: u64 = 1;

/// TLV type for the optional per-channel checksums.
pub(crate) const TLV_CHECKSUMS: u64 = 3;

/// `encoding_type` for an uncompressed list of short channel IDs.
pub const ENCODING_UNCOMPRESSED: u8 = 0;

/// Size of a short channel ID on the wire.
const SCID_SIZE: usize = 8;

/// BOLT 7 `reply_channel_range` message (type 264).
///
/// Sent in response to [`QueryChannelRange`](crate::QueryChannelRange). One
/// query may be answered by several replies; the `first_blocknum` /
/// `number_of_blocks` fields chunk the originally requested range, and
/// `sync_complete` is set on the final reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyChannelRange {
    /// Genesis block hash of the chain this reply covers.
    pub chain_hash: [u8; CHAIN_HASH_SIZE],
    /// First block of the range covered by this reply.
    pub first_blocknum: u32,
    /// Number of blocks covered by this reply.
    pub number_of_blocks: u32,
    /// Set (to `1`) on the final reply for the original query.
    pub sync_complete: u8,
    /// Encoded short channel IDs: a one-byte `encoding_type` followed by the
    /// encoded IDs. See [`Self::from_scids`] / [`Self::short_channel_ids`] for
    /// the uncompressed ([`ENCODING_UNCOMPRESSED`]) form.
    pub encoded_short_ids: Vec<u8>,
    /// Optional TLV extensions (timestamps, checksums).
    pub tlvs: ReplyChannelRangeTlvs,
}

/// TLV extensions for the `reply_channel_range` message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplyChannelRangeTlvs {
    /// Per-channel update timestamps (TLV type 1), stored as the raw value:
    /// a one-byte `encoding_type` followed by the encoded timestamps.
    pub timestamps: Option<Vec<u8>>,
    /// Per-channel `channel_update` checksums (TLV type 3), stored as the raw
    /// concatenation of 32-bit checksums.
    pub checksums: Option<Vec<u8>>,
}

impl ReplyChannelRange {
    /// Builds a reply whose `encoded_short_ids` is the uncompressed
    /// ([`ENCODING_UNCOMPRESSED`]) encoding of `scids`.
    #[must_use]
    pub fn from_scids(
        chain_hash: [u8; CHAIN_HASH_SIZE],
        first_blocknum: u32,
        number_of_blocks: u32,
        sync_complete: bool,
        scids: &[u64],
    ) -> Self {
        let mut encoded_short_ids = Vec::with_capacity(1 + scids.len() * SCID_SIZE);
        ENCODING_UNCOMPRESSED.write(&mut encoded_short_ids);
        for scid in scids {
            scid.write(&mut encoded_short_ids);
        }

        Self {
            chain_hash,
            first_blocknum,
            number_of_blocks,
            sync_complete: u8::from(sync_complete),
            encoded_short_ids,
            tlvs: ReplyChannelRangeTlvs::default(),
        }
    }

    /// Decodes the short channel IDs when uncompressed
    /// ([`ENCODING_UNCOMPRESSED`]).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if `encoded_short_ids` is empty or its length is
    /// not a whole number of 8-byte IDs after the encoding-type byte.
    /// Returns `UnknownEncoding` for any non-uncompressed encoding type.
    pub fn short_channel_ids(&self) -> Result<Vec<u64>, BoltError> {
        let mut cursor = self.encoded_short_ids.as_slice();
        let encoding_type = u8::read(&mut cursor)?;
        if encoding_type != ENCODING_UNCOMPRESSED {
            return Err(BoltError::UnknownEncoding(encoding_type));
        }

        let (chunks, remainder) = cursor.as_chunks::<SCID_SIZE>();
        if !remainder.is_empty() {
            return Err(BoltError::Truncated {
                expected: (chunks.len() + 1) * SCID_SIZE,
                actual: cursor.len(),
            });
        }
        Ok(chunks.iter().map(|c| u64::from_be_bytes(*c)).collect())
    }

    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.chain_hash.write(&mut out);
        self.first_blocknum.write(&mut out);
        self.number_of_blocks.write(&mut out);
        self.sync_complete.write(&mut out);
        self.encoded_short_ids.write(&mut out);

        let mut tlv_stream = TlvStream::new();
        if let Some(timestamps) = &self.tlvs.timestamps {
            tlv_stream.add(TLV_TIMESTAMPS, timestamps.clone());
        }
        if let Some(checksums) = &self.tlvs.checksums {
            tlv_stream.add(TLV_CHECKSUMS, checksums.clone());
        }
        out.extend(tlv_stream.encode());

        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the fixed fields or `encoded_short_ids` are
    /// incomplete, or a TLV error if the trailing TLV stream is malformed.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let chain_hash = <[u8; CHAIN_HASH_SIZE]>::read(&mut cursor)?;
        let first_blocknum = u32::read(&mut cursor)?;
        let number_of_blocks = u32::read(&mut cursor)?;
        let sync_complete = u8::read(&mut cursor)?;
        let encoded_short_ids = Vec::<u8>::read(&mut cursor)?;

        // reply_channel_range TLVs are all odd, so no known even types.
        let tlv_stream = TlvStream::decode(cursor)?;
        let tlvs = ReplyChannelRangeTlvs {
            timestamps: tlv_stream.get(TLV_TIMESTAMPS).map(Vec::from),
            checksums: tlv_stream.get(TLV_CHECKSUMS).map(Vec::from),
        };

        Ok(Self {
            chain_hash,
            first_blocknum,
            number_of_blocks,
            sync_complete,
            encoded_short_ids,
            tlvs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bitcoin mainnet genesis block hash.
    const BITCOIN_MAINNET: [u8; CHAIN_HASH_SIZE] = [
        0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7,
        0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];

    const SCIDS: [u64; 3] = [
        500_000 << 40,
        (500_100 << 40) | (7 << 16) | 2,
        (500_999 << 40) | (3 << 16) | 1,
    ];

    fn sample() -> ReplyChannelRange {
        ReplyChannelRange::from_scids(BITCOIN_MAINNET, 500_000, 1_000, true, &SCIDS)
    }

    #[test]
    fn encode_decode_roundtrip() {
        let original = sample();
        let decoded = ReplyChannelRange::decode(&original.encode()).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn from_scids_sets_sync_complete() {
        assert_eq!(sample().sync_complete, 1);
        let incomplete =
            ReplyChannelRange::from_scids(BITCOIN_MAINNET, 0, 10, false, &SCIDS);
        assert_eq!(incomplete.sync_complete, 0);
    }

    #[test]
    fn short_channel_ids_roundtrip() {
        assert_eq!(sample().short_channel_ids().unwrap(), SCIDS);
    }

    #[test]
    fn short_channel_ids_empty_list() {
        let reply = ReplyChannelRange::from_scids(BITCOIN_MAINNET, 0, 10, true, &[]);
        assert_eq!(reply.short_channel_ids().unwrap(), Vec::<u64>::new());
    }

    #[test]
    fn short_channel_ids_unknown_encoding() {
        let mut reply = sample();
        reply.encoded_short_ids[0] = 1; // zlib (unsupported here)
        assert_eq!(
            reply.short_channel_ids(),
            Err(BoltError::UnknownEncoding(1))
        );
    }

    #[test]
    fn short_channel_ids_misaligned() {
        let mut reply = sample();
        reply.encoded_short_ids.push(0xff); // trailing partial id
        assert!(matches!(
            reply.short_channel_ids(),
            Err(BoltError::Truncated { .. })
        ));
    }

    #[test]
    fn short_channel_ids_empty_payload() {
        let reply = ReplyChannelRange {
            encoded_short_ids: Vec::new(),
            ..sample()
        };
        assert!(matches!(
            reply.short_channel_ids(),
            Err(BoltError::Truncated { .. })
        ));
    }

    #[test]
    fn tlvs_roundtrip() {
        let mut reply = sample();
        reply.tlvs.timestamps = Some(vec![0x00, 0xde, 0xad, 0xbe, 0xef]);
        reply.tlvs.checksums = Some(vec![0x01, 0x02, 0x03, 0x04]);
        let decoded = ReplyChannelRange::decode(&reply.encode()).unwrap();
        assert_eq!(decoded.tlvs.timestamps, reply.tlvs.timestamps);
        assert_eq!(decoded.tlvs.checksums, reply.tlvs.checksums);
    }

    #[test]
    fn decode_truncated() {
        assert!(matches!(
            ReplyChannelRange::decode(&[0u8; 10]),
            Err(BoltError::Truncated { .. })
        ));
    }
}
