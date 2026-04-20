//! Async Noise-encrypted TCP connection for Lightning peers.
//!
//! Wraps the sync noise crate primitives with tokio async I/O and
//! handles Init exchange and Ping/Pong keepalive.
//!
//! After the handshake and Init exchange the connection is split into
//! independent [`NoiseWriter`] and [`NoiseReader`] halves so that
//! reading and writing can happen concurrently from different tasks.

use bitcoin::secp256k1::{PublicKey, SecretKey, rand};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use noise::cipher::{ENCRYPTED_LENGTH_SIZE, MAC_SIZE, RecvCipher, SendCipher};
use noise::error::NoiseError;
use noise::handshake::{ACT_TWO_SIZE, NoiseHandshake};

use bolt::{Init, Message, Pong};

/// Write half of a Noise-encrypted connection.
pub struct NoiseWriter {
    stream: OwnedWriteHalf,
    cipher: SendCipher,
}

impl NoiseWriter {
    /// Send a raw wire-encoded message (2-byte type prefix + payload).
    ///
    /// # Errors
    ///
    /// Returns `NoiseError::Io` if writing to the TCP stream fails.
    pub async fn send(&mut self, msg: &[u8]) -> Result<(), NoiseError> {
        let encrypted = self.cipher.encrypt(msg);
        self.stream
            .write_all(&encrypted)
            .await
            .map_err(|e| NoiseError::Io(e.to_string()))
    }
}

/// Read half of a Noise-encrypted connection.
pub struct NoiseReader {
    stream: OwnedReadHalf,
    cipher: RecvCipher,
}

impl NoiseReader {
    /// Receive and decrypt one wire message.
    /// Returns the decrypted body (2-byte type prefix + payload).
    ///
    /// # Errors
    ///
    /// Returns `NoiseError` if reading or decryption fails.
    pub async fn recv(&mut self) -> Result<Vec<u8>, NoiseError> {
        // Read encrypted length header (2 + 16 MAC = 18 bytes).
        let mut len_header = [0u8; ENCRYPTED_LENGTH_SIZE];
        self.stream
            .read_exact(&mut len_header)
            .await
            .map_err(|e| NoiseError::Io(e.to_string()))?;

        let msg_len = self.cipher.decrypt_length(&len_header)?;

        // Read encrypted message body (msg_len + 16 MAC).
        let mut body = vec![0u8; usize::from(msg_len) + MAC_SIZE];
        self.stream
            .read_exact(&mut body)
            .await
            .map_err(|e| NoiseError::Io(e.to_string()))?;

        self.cipher.decrypt_message(&body)
    }

    /// Receive one message, automatically responding to Pings with Pongs.
    /// Skips Pong and Warning messages. Returns the first "real" message.
    ///
    /// Because a Pong reply requires *writing*, this method needs a
    /// reference to the corresponding [`NoiseWriter`].
    ///
    /// # Errors
    ///
    /// Returns `NoiseError` if reading, decryption, or sending a Pong fails.
    pub async fn recv_message(&mut self, writer: &mut NoiseWriter) -> Result<Message, NoiseError> {
        loop {
            let raw = self.recv().await?;
            if raw.len() < 2 {
                return Err(NoiseError::Io("message too short".into()));
            }
            match Message::decode(&raw) {
                Ok(Message::Ping(ping)) => {
                    let resp = Message::Pong(Pong::respond_to(&ping));
                    writer.send(&resp.encode()).await?;
                }
                Ok(Message::Pong(_) | Message::Warning(_)) => {
                    // Silently consume
                }
                Ok(msg) => return Ok(msg),
                Err(_) => {
                    let mt = u16::from_be_bytes([raw[0], raw[1]]);
                    return Ok(Message::Unknown {
                        msg_type: mt,
                        payload: raw[2..].to_vec(),
                    });
                }
            }
        }
    }
}

/// Perform BOLT 8 `Noise_XK` handshake as initiator, exchange Init
/// messages, then split into independent read/write halves.
///
/// # Errors
///
/// Returns `NoiseError` if the handshake, Init exchange, or I/O fails.
pub async fn connect(
    addr: SocketAddr,
    their_node_id: PublicKey,
    our_static: SecretKey,
) -> Result<(NoiseWriter, NoiseReader, PublicKey), NoiseError> {
    let ephemeral = SecretKey::new(&mut rand::thread_rng());
    let mut handshake = NoiseHandshake::new_initiator(our_static, ephemeral, their_node_id);

    let mut stream = TcpStream::connect(addr)
        .await
        .map_err(|e| NoiseError::Io(e.to_string()))?;

    // Act 1: initiator -> responder
    let act_one = handshake.get_act_one()?;
    stream
        .write_all(&act_one)
        .await
        .map_err(|e| NoiseError::Io(e.to_string()))?;

    // Act 2: responder -> initiator
    let mut act_two = [0u8; ACT_TWO_SIZE];
    stream
        .read_exact(&mut act_two)
        .await
        .map_err(|e| NoiseError::Io(e.to_string()))?;

    let act_three = handshake.process_act_two(&act_two)?;

    // Act 3: initiator -> responder
    stream
        .write_all(&act_three)
        .await
        .map_err(|e| NoiseError::Io(e.to_string()))?;

    let cipher = handshake.into_cipher()?;
    log::info!("Noise handshake complete with {their_node_id}");

    // --- Init exchange (needs full cipher before splitting) ---
    let (send_cipher, recv_cipher) = cipher.split();
    let (read_half, write_half) = stream.into_split();

    let mut writer = NoiseWriter {
        stream: write_half,
        cipher: send_cipher,
    };
    let mut reader = NoiseReader {
        stream: read_half,
        cipher: recv_cipher,
    };

    // Receive Init first so we can echo back compatible features.
    let init_resp = reader.recv().await?;
    let received_init = match Message::decode(&init_resp) {
        Ok(Message::Init(init)) => {
            log::info!("Received Init from {their_node_id}");
            init
        }
        Ok(other) => {
            return Err(NoiseError::Io(format!(
                "expected Init (16), got msg type {}",
                other.msg_type()
            )));
        }
        Err(e) => {
            return Err(NoiseError::Io(format!("failed to decode Init: {e}")));
        }
    };

    // Echo the peer's features so we appear compatible with their
    // required feature bits (data-loss-protect, static-remote-key, etc.).
    let reply = Message::Init(Init::echo(&received_init));
    writer.send(&reply.encode()).await?;
    log::info!("Sent Init to {their_node_id}");

    Ok((writer, reader, their_node_id))
}
