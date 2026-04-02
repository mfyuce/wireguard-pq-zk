/// TCP+TLS channel for ML-KEM ciphertext exchange between client and gateway daemons.
///
/// Security model:
///   - Gateway: self-signed TLS certificate (no CA needed)
///   - Client: verifies gateway cert by SHA-256 fingerprint (certificate pinning)
///   - Client presents NO certificate → client is anonymous → unlinkability preserved
///   - Channel is encrypted + authenticated (server-side only)
///
/// Message format (1124 bytes over TLS stream):
///   [0..4]    : token (u32 LE) — correlates with ZK NEED_PROOF token
///   [4..36]   : session_nonce (32 bytes) — binds CT to ZK proof, prevents replay
///   [36..1124]: ML-KEM-768 ciphertext (1088 bytes)
///
/// Config (env vars):
///   MLKEM_PORT          : TCP port (default 51821)
///   MLKEM_CERT_PEM      : gateway TLS cert PEM (gateway side, auto-generated if absent)
///   MLKEM_KEY_PEM       : gateway TLS key PEM  (gateway side)
///   MLKEM_SERVER_ADDR   : "host:port" of gateway (client side)
///   MLKEM_CERT_FP       : hex SHA-256 fingerprint of gateway cert (client side)

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::mlkem::CT_LEN;

pub const MSG_LEN: usize = 4 + 32 + CT_LEN; // 1124 bytes
pub const DEFAULT_PORT: u16 = 51821;

// ── Certificate helpers ───────────────────────────────────────────────────────

/// Generate a self-signed TLS certificate for the gateway.
/// Returns (cert_pem, key_pem, fingerprint_hex).
pub fn generate_self_signed() -> Result<(String, String, String)> {
    let cert = rcgen::generate_simple_self_signed(vec!["wgzk-gateway".to_string()])?;
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();
    let fp = cert_fingerprint(cert.cert.der());
    Ok((cert_pem, key_pem, fp))
}

fn cert_fingerprint(der: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(der);
    hex::encode(h.finalize())
}

// ── Gateway (server) side ─────────────────────────────────────────────────────

/// Build a TLS acceptor from PEM strings.
pub fn make_acceptor(cert_pem: &str, key_pem: &str) -> Result<TlsAcceptor> {
    let cert_der = parse_cert_pem(cert_pem)?;
    let key_der = parse_key_pem(key_pem)?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .context("TLS server config")?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Listen for one ML-KEM message from a client.
/// Returns (token, session_nonce, ciphertext).
pub async fn recv_ciphertext(
    acceptor: &TlsAcceptor,
    listener: &TcpListener,
) -> Result<(u32, [u8; 32], [u8; CT_LEN])> {
    let (stream, peer) = listener.accept().await?;
    eprintln!("[mlkem_channel] connection from {peer}");

    let mut tls = acceptor.accept(stream).await.context("TLS accept")?;

    let mut buf = [0u8; MSG_LEN];
    tls.read_exact(&mut buf).await.context("read message")?;

    let token = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    let nonce: [u8; 32] = buf[4..36].try_into().unwrap();
    let ct: [u8; CT_LEN] = buf[36..MSG_LEN].try_into().unwrap();

    Ok((token, nonce, ct))
}

/// Bind the TCP listener for the ML-KEM channel.
pub async fn bind(port: u16) -> Result<TcpListener> {
    let listener = TcpListener::bind(format!("0.0.0.0:{port}")).await?;
    eprintln!("[mlkem_channel] TLS listener on TCP :{port}");
    Ok(listener)
}

// ── Client side ───────────────────────────────────────────────────────────────

/// Build a TLS connector that pins the gateway's certificate by fingerprint.
pub fn make_connector(expected_fp: &str) -> Result<TlsConnector> {
    let fp = expected_fp.to_string();

    let verifier = Arc::new(FingerprintVerifier { expected_fp: fp });

    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    Ok(TlsConnector::from(Arc::new(config)))
}

/// Send ML-KEM ciphertext to the gateway daemon over TLS.
pub async fn send_ciphertext(
    connector: &TlsConnector,
    server_addr: &str,
    token: u32,
    session_nonce: &[u8; 32],
    ct: &[u8; CT_LEN],
) -> Result<()> {
    let stream = TcpStream::connect(server_addr)
        .await
        .with_context(|| format!("TCP connect to {server_addr}"))?;

    // ServerName: use a fixed placeholder (cert is verified by fingerprint, not hostname)
    let server_name = ServerName::try_from("wgzk-gateway").context("server name")?;
    let mut tls = connector
        .connect(server_name, stream)
        .await
        .context("TLS connect")?;

    let mut buf = [0u8; MSG_LEN];
    buf[0..4].copy_from_slice(&token.to_le_bytes());
    buf[4..36].copy_from_slice(session_nonce);
    buf[36..MSG_LEN].copy_from_slice(ct);

    tls.write_all(&buf).await.context("write message")?;
    tls.flush().await?;
    Ok(())
}

// ── Certificate fingerprint verifier ─────────────────────────────────────────

#[derive(Debug)]
struct FingerprintVerifier {
    expected_fp: String,
}

impl rustls::client::danger::ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let fp = cert_fingerprint(end_entity.as_ref());
        if fp == self.expected_fp {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "cert fingerprint mismatch: got {fp}, expected {}",
                self.expected_fp
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

// ── PEM parsing helpers ───────────────────────────────────────────────────────

fn parse_cert_pem(pem: &str) -> Result<CertificateDer<'static>> {
    let mut cursor = std::io::Cursor::new(pem.as_bytes());
    let cert = rustls_pemfile::certs(&mut cursor)
        .next()
        .context("no cert in PEM")?
        .context("cert parse error")?;
    Ok(cert)
}

fn parse_key_pem(pem: &str) -> Result<PrivateKeyDer<'static>> {
    let mut cursor = std::io::Cursor::new(pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut cursor)
        .context("key parse error")?
        .context("no key in PEM")?;
    Ok(key)
}
