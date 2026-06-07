//! BOLT 7 `query_channel_range` message.

use crate::BoltError;
use crate::tlv::TlvStream;
use crate::types::{BigSize, CHAIN_HASH_SIZE};
use crate::wire::WireFormat;

/// TLV type for the optional `query_option` flags.
pub(crate) const TLV_QUERY_OPTION: u64 = 1;

/// `query_option_flags` bit requesting per-channel timestamps in the reply.
pub const QUERY_OPTION_WANT_TIMESTAMPS: u64 = 0b01;

/// `query_option_flags` bit requesting per-channel checksums in the reply.
pub const QUERY_OPTION_WANT_CHECKSUMS: u64 = 0b10;

/// BOLT 7 `query_channel_range` message (type 263).
///
/// Asks a peer to enumerate the channels it knows about within a block
/// range, so the sender can discover channels it is missing. The peer
/// answers with one or more [`ReplyChannelRange`](crate::ReplyChannelRange)
/// messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryChannelRange {
    /// Genesis block hash of the chain being queried.
    pub chain_hash: [u8; CHAIN_HASH_SIZE],
    /// First block of the queried range.
    pub first_blocknum: u32,
    /// Number of blocks in the queried range.
    pub number_of_blocks: u32,
    /// Optional `query_option_flags` (TLV type 1).
    ///
    /// When present, the low bits request additional data in the reply:
    /// [`QUERY_OPTION_WANT_TIMESTAMPS`] and [`QUERY_OPTION_WANT_CHECKSUMS`].
    pub query_option: Option<u64>,
}

impl QueryChannelRange {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.chain_hash.write(&mut out);
        self.first_blocknum.write(&mut out);
        self.number_of_blocks.write(&mut out);

        let mut tlv_stream = TlvStream::new();
        if let Some(flags) = self.query_option {
            let mut value = Vec::new();
            BigSize::new(flags).write(&mut value);
            tlv_stream.add(TLV_QUERY_OPTION, value);
        }
        out.extend(tlv_stream.encode());

        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the fixed fields are incomplete, or a TLV
    /// error if the trailing TLV stream is malformed.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let chain_hash = <[u8; CHAIN_HASH_SIZE]>::read(&mut cursor)?;
        let first_blocknum = u32::read(&mut cursor)?;
        let number_of_blocks = u32::read(&mut cursor)?;

        // query_channel_range TLVs are all odd, so no known even types.
        let tlv_stream = TlvStream::decode(cursor)?;
        let query_option = match tlv_stream.get(TLV_QUERY_OPTION) {
            Some(mut value) => Some(BigSize::read(&mut value)?.value()),
            None => None,
        };

        Ok(Self {
            chain_hash,
            first_blocknum,
            number_of_blocks,
            query_option,
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

    fn sample() -> QueryChannelRange {
        QueryChannelRange {
            chain_hash: BITCOIN_MAINNET,
            first_blocknum: 500_000,
            number_of_blocks: 1_000,
            query_option: None,
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let original = sample();
        let decoded = QueryChannelRange::decode(&original.encode()).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn encode_without_tlv_is_fixed_length() {
        let encoded = sample().encode();
        // chain_hash(32) + first_blocknum(4) + number_of_blocks(4)
        assert_eq!(encoded.len(), CHAIN_HASH_SIZE + 4 + 4);
    }

    #[test]
    fn query_option_roundtrip() {
        let mut msg = sample();
        msg.query_option = Some(QUERY_OPTION_WANT_TIMESTAMPS | QUERY_OPTION_WANT_CHECKSUMS);
        let decoded = QueryChannelRange::decode(&msg.encode()).unwrap();
        assert_eq!(decoded.query_option, Some(0b11));
    }

    #[test]
    fn query_option_large_flags_use_bigsize() {
        let mut msg = sample();
        msg.query_option = Some(300); // forces multi-byte BigSize encoding
        let decoded = QueryChannelRange::decode(&msg.encode()).unwrap();
        assert_eq!(decoded.query_option, Some(300));
    }

    #[test]
    fn decode_truncated() {
        assert!(matches!(
            QueryChannelRange::decode(&[0u8; 10]),
            Err(BoltError::Truncated { .. })
        ));
    }

    #[test]
    fn decode_unknown_odd_tlv_ignored() {
        let mut data = sample().encode();
        data.push(0x05); // unknown odd TLV type 5
        data.push(0x01); // length 1
        data.push(0xaa);
        let decoded = QueryChannelRange::decode(&data).unwrap();
        assert_eq!(decoded.query_option, None);
    }
}
