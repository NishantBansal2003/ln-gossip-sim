//! BOLT message encoding and decoding.

pub mod error;
pub mod init;
pub mod ping;
pub mod pong;
pub mod tlv;
pub mod types;
pub mod warning;
pub mod wire;

pub use error::Error;
pub use init::{Init, InitTlvs};
pub use ping::Ping;
pub use pong::Pong;
pub use tlv::{TlvRecord, TlvStream};
pub use types::{
    BigSize, CHAIN_HASH_SIZE, CHANNEL_ID_SIZE, COMPACT_SIGNATURE_SIZE, ChannelId, MAX_MESSAGE_SIZE,
    PUBLIC_KEY_SIZE, TXID_SIZE, Txid,
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
}

/// A decoded BOLT message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Warning(Warning),
    Init(Init),
    Error(Error),
    Ping(Ping),
    Pong(Pong),
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
