/// UDP channel for ML-KEM ciphertext exchange between client and gateway daemons.
///
/// Protocol (single UDP datagram, 1093 bytes):
///   [0]      : version = 0x01
///   [1..4]   : token (u32 LE) — correlates with ZK NEED_PROOF token
///   [5..1093]: ML-KEM-768 ciphertext (1088 bytes)
///
/// The ciphertext fits in a single IPv4/IPv6 UDP datagram (MTU >= 1280 required).
/// No reliability layer — kernel ZK flow retries if PSK is not set in time.

use tokio::net::UdpSocket;
use anyhow::Result;
use crate::mlkem::CT_LEN;

pub const MSG_LEN: usize = 1 + 4 + CT_LEN;  // 1093 bytes
const VERSION: u8 = 0x01;

/// Send ML-KEM ciphertext to the peer daemon.
pub async fn send_ciphertext(
    peer_addr: &str,
    token: u32,
    ct: &[u8; CT_LEN],
) -> Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    let mut buf = [0u8; MSG_LEN];
    buf[0] = VERSION;
    buf[1..5].copy_from_slice(&token.to_le_bytes());
    buf[5..MSG_LEN].copy_from_slice(ct);
    sock.send_to(&buf, peer_addr).await?;
    Ok(())
}

/// Receive one ML-KEM ciphertext message.
/// Returns (token, ciphertext).
pub async fn recv_ciphertext(sock: &UdpSocket) -> Result<(u32, [u8; CT_LEN])> {
    let mut buf = [0u8; MSG_LEN + 16]; // small headroom
    let (n, _src) = sock.recv_from(&mut buf).await?;
    if n < MSG_LEN {
        anyhow::bail!("mlkem_channel: short datagram ({n} < {MSG_LEN})");
    }
    if buf[0] != VERSION {
        anyhow::bail!("mlkem_channel: unknown version {}", buf[0]);
    }
    let token = u32::from_le_bytes(buf[1..5].try_into().unwrap());
    let ct: [u8; CT_LEN] = buf[5..5 + CT_LEN].try_into().unwrap();
    Ok((token, ct))
}

/// Bind a UDP socket on the given port for receiving ciphertexts.
pub async fn bind(port: u16) -> Result<UdpSocket> {
    let sock = UdpSocket::bind(format!("0.0.0.0:{port}")).await?;
    eprintln!("[mlkem_channel] listening on UDP :{port}");
    Ok(sock)
}
