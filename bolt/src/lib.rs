//! BOLT message encoding and decoding.

pub mod channel_announcement;
pub mod channel_update;
pub mod error;
pub mod funding_created;
pub mod init;
pub mod open_channel;
pub mod ping;
pub mod pong;
pub mod query_channel_range;
pub mod reply_channel_range;
pub mod tlv;
pub mod types;
pub mod warning;
pub mod wire;

pub use channel_announcement::ChannelAnnouncement;
pub use channel_update::ChannelUpdate;
pub use error::Error;
pub use funding_created::FundingCreated;
pub use init::{Init, InitTlvs};
pub use open_channel::{OpenChannel, OpenChannelTlvs};
pub use ping::Ping;
pub use pong::Pong;
pub use query_channel_range::QueryChannelRange;
pub use reply_channel_range::{ReplyChannelRange, ReplyChannelRangeTlvs};
pub use tlv::{TlvRecord, TlvStream};
pub use types::{
    BigSize, CHAIN_HASH_SIZE, CHANNEL_ID_SIZE, COMPACT_SIGNATURE_SIZE, ChannelId, MAX_MESSAGE_SIZE,
    PUBLIC_KEY_SIZE, TXID_SIZE,
};
pub use warning::Warning;
pub use wire::WireFormat;

/// Errors that can occur during BOLT message encoding/decoding.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BoltError {
    #[error("TRUNCATED expected {expected} got {actual}")]
    Truncated { expected: usize, actual: usize },
    #[error("UNKNOWN_EVEN_TYPE {0}")]
    UnknownEvenType(u16),
    #[error("INVALID_PUBLIC_KEY {}", hex::encode(.0))]
    InvalidPublicKey([u8; PUBLIC_KEY_SIZE]),
    #[error("INVALID_SIGNATURE {}", hex::encode(.0))]
    InvalidSignature([u8; COMPACT_SIGNATURE_SIZE]),
    #[error("UNKNOWN_ENCODING {0}")]
    UnknownEncoding(u8),
    #[error("BIGSIZE_NOT_MINIMAL")]
    BigSizeNotMinimal,
    #[error("BIGSIZE_TRUNCATED")]
    BigSizeTruncated,
    #[error("TLV_NOT_INCREASING previous {previous} current {current}")]
    TlvNotIncreasing { previous: u64, current: u64 },
    #[error("TLV_LENGTH_OVERFLOW")]
    TlvLengthOverflow,
    #[error("TLV_UNKNOWN_EVEN_TYPE {0}")]
    TlvUnknownEvenType(u64),
}

/// BOLT message type constants.
pub mod msg_type {
    pub const WARNING: u16 = 1;
    pub const INIT: u16 = 16;
    pub const ERROR: u16 = 17;
    pub const PING: u16 = 18;
    pub const PONG: u16 = 19;
    pub const OPEN_CHANNEL: u16 = 32;
    pub const FUNDING_CREATED: u16 = 34;
    pub const CHANNEL_ANNOUNCEMENT: u16 = 256;
    pub const CHANNEL_UPDATE: u16 = 258;
    pub const QUERY_CHANNEL_RANGE: u16 = 263;
    pub const REPLY_CHANNEL_RANGE: u16 = 264;
}

/// A decoded BOLT message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Warning(Warning),
    Init(Init),
    Error(Error),
    Ping(Ping),
    Pong(Pong),
    OpenChannel(Box<OpenChannel>),
    FundingCreated(Box<FundingCreated>),
    ChannelAnnouncement(Box<ChannelAnnouncement>),
    ChannelUpdate(Box<ChannelUpdate>),
    QueryChannelRange(QueryChannelRange),
    ReplyChannelRange(Box<ReplyChannelRange>),
    /// Unknown message type (odd types accepted, even rejected).
    Unknown {
        msg_type: u16,
        payload: Vec<u8>,
    },
}

impl Message {
    /// Returns the message type number.
    #[must_use]
    pub fn msg_type(&self) -> u16 {
        match self {
            Self::Warning(_) => msg_type::WARNING,
            Self::Init(_) => msg_type::INIT,
            Self::Error(_) => msg_type::ERROR,
            Self::Ping(_) => msg_type::PING,
            Self::Pong(_) => msg_type::PONG,
            Self::OpenChannel(_) => msg_type::OPEN_CHANNEL,
            Self::FundingCreated(_) => msg_type::FUNDING_CREATED,
            Self::ChannelAnnouncement(_) => msg_type::CHANNEL_ANNOUNCEMENT,
            Self::ChannelUpdate(_) => msg_type::CHANNEL_UPDATE,
            Self::QueryChannelRange(_) => msg_type::QUERY_CHANNEL_RANGE,
            Self::ReplyChannelRange(_) => msg_type::REPLY_CHANNEL_RANGE,
            Self::Unknown { msg_type, .. } => *msg_type,
        }
    }

    /// Encodes to wire format (with 2-byte message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.msg_type().write(&mut out);
        match self {
            Self::Warning(m) => out.extend(m.encode()),
            Self::Init(m) => out.extend(m.encode()),
            Self::Error(m) => out.extend(m.encode()),
            Self::Ping(m) => out.extend(m.encode()),
            Self::Pong(m) => out.extend(m.encode()),
            Self::OpenChannel(m) => out.extend(m.encode()),
            Self::FundingCreated(m) => out.extend(m.encode()),
            Self::ChannelAnnouncement(m) => out.extend(m.encode()),
            Self::ChannelUpdate(m) => out.extend(m.encode()),
            Self::QueryChannelRange(m) => out.extend(m.encode()),
            Self::ReplyChannelRange(m) => out.extend(m.encode()),
            Self::Unknown { payload, .. } => out.extend(payload),
        }
        out
    }

    /// Decodes from wire format (with 2-byte message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `BoltError` if the data is truncated, or an unknown even type is encountered.
    pub fn decode(data: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = data;
        let msg_type = u16::read(&mut cursor)?;

        match msg_type {
            msg_type::WARNING => Ok(Self::Warning(Warning::decode(cursor)?)),
            msg_type::INIT => Ok(Self::Init(Init::decode(cursor)?)),
            msg_type::ERROR => Ok(Self::Error(Error::decode(cursor)?)),
            msg_type::PING => Ok(Self::Ping(Ping::decode(cursor)?)),
            msg_type::PONG => Ok(Self::Pong(Pong::decode(cursor)?)),
            msg_type::OPEN_CHANNEL => Ok(Self::OpenChannel(Box::new(OpenChannel::decode(cursor)?))),
            msg_type::FUNDING_CREATED => Ok(Self::FundingCreated(Box::new(
                FundingCreated::decode(cursor)?,
            ))),
            msg_type::CHANNEL_ANNOUNCEMENT => Ok(Self::ChannelAnnouncement(Box::new(
                ChannelAnnouncement::decode(cursor)?,
            ))),
            msg_type::CHANNEL_UPDATE => Ok(Self::ChannelUpdate(Box::new(ChannelUpdate::decode(
                cursor,
            )?))),
            msg_type::QUERY_CHANNEL_RANGE => {
                Ok(Self::QueryChannelRange(QueryChannelRange::decode(cursor)?))
            }
            msg_type::REPLY_CHANNEL_RANGE => Ok(Self::ReplyChannelRange(Box::new(
                ReplyChannelRange::decode(cursor)?,
            ))),
            _ => {
                if msg_type % 2 == 0 {
                    Err(BoltError::UnknownEvenType(msg_type))
                } else {
                    Ok(Self::Unknown {
                        msg_type,
                        payload: cursor.to_vec(),
                    })
                }
            }
        }
    }
}

/// Creates a raw message with the given type and payload.
#[must_use]
pub fn raw_message(msg_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    msg_type.write(&mut out);
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_init_roundtrip() {
        let init = Init::empty();
        let msg = Message::Init(init.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::Init(init));
    }

    #[test]
    fn message_ping_roundtrip() {
        let ping = Ping::new(10);
        let msg = Message::Ping(ping.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::Ping(ping));
    }

    #[test]
    fn message_pong_roundtrip() {
        let pong = Pong::new(5);
        let msg = Message::Pong(pong.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::Pong(pong));
    }

    #[test]
    fn message_open_channel_roundtrip() {
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let key = |b: u8| {
            let sk = SecretKey::from_slice(&[b; 32]).unwrap();
            bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk)
        };
        let open = OpenChannel {
            chain_hash: [0xaa; CHAIN_HASH_SIZE],
            temporary_channel_id: ChannelId::new([0xbb; 32]),
            funding_satoshis: 100_000,
            push_msat: 0,
            dust_limit_satoshis: 546,
            max_htlc_value_in_flight_msat: 100_000_000,
            channel_reserve_satoshis: 10_000,
            htlc_minimum_msat: 1_000,
            feerate_per_kw: 253,
            to_self_delay: 144,
            max_accepted_htlcs: 483,
            funding_pubkey: key(0x11),
            revocation_basepoint: key(0x22),
            payment_basepoint: key(0x33),
            delayed_payment_basepoint: key(0x44),
            htlc_basepoint: key(0x55),
            first_per_commitment_point: key(0x66),
            channel_flags: 0x01,
            tlvs: OpenChannelTlvs::default(),
        };
        let msg = Message::OpenChannel(Box::new(open));
        let encoded = msg.encode();
        assert_eq!(encoded[0..2], msg_type::OPEN_CHANNEL.to_be_bytes());
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn message_funding_created_roundtrip() {
        use bitcoin::hashes::Hash;
        use bitcoin::secp256k1::{Message as SecpMessage, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).unwrap();
        let sig = secp.sign_ecdsa(&SecpMessage::from_digest([0xaa; 32]), &sk);
        let funding = FundingCreated {
            temporary_channel_id: ChannelId::new([0xbb; 32]),
            funding_txid: bitcoin::Txid::from_byte_array([0xcc; 32]),
            funding_output_index: 0,
            signature: sig,
        };
        let msg = Message::FundingCreated(Box::new(funding));
        let encoded = msg.encode();
        assert_eq!(encoded[0..2], msg_type::FUNDING_CREATED.to_be_bytes());
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn message_channel_update_roundtrip() {
        use bitcoin::secp256k1::SecretKey;
        let sk = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let update = ChannelUpdate::new_signed(
            [0xab; 32],
            (539_268 << 40) | (845 << 16) | 1,
            1_715_000_000,
            1,
            0,
            40,
            1,
            1_000,
            1,
            4_294_967_295,
            &sk,
        );
        let msg = Message::ChannelUpdate(Box::new(update));
        let encoded = msg.encode();
        assert_eq!(encoded[0..2], msg_type::CHANNEL_UPDATE.to_be_bytes());
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn message_query_channel_range_roundtrip() {
        let query = QueryChannelRange {
            chain_hash: [0xab; 32],
            first_blocknum: 500_000,
            number_of_blocks: 1_000,
            query_option: Some(query_channel_range::QUERY_OPTION_WANT_TIMESTAMPS),
        };
        let msg = Message::QueryChannelRange(query);
        let encoded = msg.encode();
        assert_eq!(encoded[0..2], msg_type::QUERY_CHANNEL_RANGE.to_be_bytes());
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn message_reply_channel_range_roundtrip() {
        let reply = ReplyChannelRange::from_scids(
            [0xab; 32],
            500_000,
            1_000,
            true,
            &[(500_000 << 40) | (1 << 16)],
        );
        let msg = Message::ReplyChannelRange(Box::new(reply));
        let encoded = msg.encode();
        assert_eq!(encoded[0..2], msg_type::REPLY_CHANNEL_RANGE.to_be_bytes());
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn message_unknown_odd_accepted() {
        let data = raw_message(99, &[0xaa, 0xbb]);
        let msg = Message::decode(&data).unwrap();
        assert_eq!(
            msg,
            Message::Unknown {
                msg_type: 99,
                payload: vec![0xaa, 0xbb]
            }
        );
    }

    #[test]
    fn message_unknown_even_rejected() {
        let data = raw_message(100, &[0xaa, 0xbb]);
        assert_eq!(Message::decode(&data), Err(BoltError::UnknownEvenType(100)));
    }

    #[test]
    fn message_decode_truncated() {
        assert_eq!(
            Message::decode(&[0x00]),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1
            })
        );
    }
}
