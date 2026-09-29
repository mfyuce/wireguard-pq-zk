//! Side channel of mode `0x02` (`docs/protocol-r1.md`, Sections 3.2 and 6.1): TLS 1.3 over
//! TCP (default port 51821), client to gateway, one 1124-byte message per connection:
//!
//! ```text
//! [0..4]     token (u32 LE), correlation only
//! [4..36]    session nonce, the key of the gateway's ciphertext buffer
//! [36..1124] ML-KEM-768 ciphertext
//! ```
//!
//! The gateway sends nothing back. Both sides allow TLS 1.3 only; no client certificate, no
//! resumption (the client disables it, the gateway issues no tickets and keeps no session
//! cache), no ALPN, fixed server name `wgzk-gateway`.
//!
//! The client pins the gateway certificate by the SHA-256 fingerprint of its DER encoding,
//! compared in constant time, and verifies the TLS 1.3 handshake signature against that
//! certificate with the algorithms of the installed crypto provider. A server therefore has
//! to hold the private key of the pinned certificate; presenting the certificate is not
//! enough. The TLS 1.2 signature callback always fails.
//!
//! Gateway: [`serve`] accepts connections and spawns one task per connection, at most
//! `WGZK_TLS_MAX_CONN` at a time (further connections are closed at once), with timeouts on
//! the TLS handshake (`WGZK_TLS_HANDSHAKE_MS`) and on the read (`WGZK_TLS_READ_MS`). A task
//! stores the message in the ciphertext buffer and does nothing else: no decapsulation, no
//! key installation.

use anyhow::{anyhow, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{sleep, timeout, Duration};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::ctbuf::CtBuffer;
use crate::mlkem::CT_LEN;

pub const MSG_LEN: usize = 4 + 32 + CT_LEN; // 1124 bytes
pub const DEFAULT_PORT: u16 = 51821;
/// Fixed TLS server name (SNI) of every gateway.
pub const SERVER_NAME: &str = "wgzk-gateway";

static TLS13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

/// The process-wide crypto provider (installed in `main`).
fn installed_provider() -> Result<Arc<CryptoProvider>> {
    CryptoProvider::get_default()
        .cloned()
        .ok_or_else(|| anyhow!("no rustls crypto provider installed"))
}

// ── Message and fingerprint helpers ──────────────────────────────────────────

pub fn encode_message(token: u32, session_nonce: &[u8; 32], ct: &[u8; CT_LEN]) -> [u8; MSG_LEN] {
    let mut buf = [0u8; MSG_LEN];
    buf[0..4].copy_from_slice(&token.to_le_bytes());
    buf[4..36].copy_from_slice(session_nonce);
    buf[36..MSG_LEN].copy_from_slice(ct);
    buf
}

/// Split a received message into (token, nonce, ciphertext).
pub fn decode_message(buf: &[u8; MSG_LEN]) -> Result<(u32, [u8; 32], Arc<[u8; CT_LEN]>)> {
    let (token, rest) = buf.split_at(4);
    let (nonce, ct) = rest.split_at(32);
    let token = u32::from_le_bytes(token.try_into().context("token field")?);
    let nonce: [u8; 32] = nonce.try_into().context("nonce field")?;
    let ct: [u8; CT_LEN] = ct.try_into().context("ciphertext field")?;
    Ok((token, nonce, Arc::new(ct)))
}

/// SHA-256 of a DER certificate.
pub fn cert_fingerprint(der: &[u8]) -> [u8; 32] {
    Sha256::digest(der).into()
}

/// `MLKEM_CERT_FP`: 64 hex digits, either case.
pub fn parse_fingerprint_hex(s: &str) -> Result<[u8; 32]> {
    let b = hex::decode(s.trim()).map_err(|_| anyhow!("fingerprint is not valid hex"))?;
    b.as_slice()
        .try_into()
        .map_err(|_| anyhow!("fingerprint must be 32 bytes (64 hex digits)"))
}

// ── Gateway (server) side ────────────────────────────────────────────────────

/// Build the gateway's TLS acceptor from PEM strings.
pub fn make_acceptor(cert_pem: &str, key_pem: &str) -> Result<TlsAcceptor> {
    let cert_der = parse_cert_pem(cert_pem)?;
    let key_der = parse_key_pem(key_pem)?;

    let mut config = rustls::ServerConfig::builder_with_provider(installed_provider()?)
        .with_protocol_versions(TLS13_ONLY)
        .context("TLS 1.3 not supported by the crypto provider")?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .context("TLS server config")?;
    harden_server_config(&mut config);
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// No resumption state, no tickets, no ALPN.
fn harden_server_config(config: &mut rustls::ServerConfig) {
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config.alpn_protocols.clear();
}

/// Bind the TCP listener for the side channel.
pub async fn bind(port: u16) -> Result<TcpListener> {
    let listener = TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .with_context(|| format!("bind TCP :{port}"))?;
    eprintln!("[mlkem_channel] TLS listener on TCP :{port}");
    Ok(listener)
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_conn: usize,
    pub handshake: Duration,
    pub read: Duration,
}

/// Accept loop of the gateway side channel. Never returns.
pub async fn serve(listener: TcpListener, acceptor: TlsAcceptor, ctbuf: Arc<CtBuffer>, limits: Limits) {
    let slots = Arc::new(Semaphore::new(limits.max_conn));
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _peer)) => stream,
            Err(e) => {
                // e.g. EMFILE: do not spin.
                eprintln!("[mlkem_channel] accept error: {e}");
                sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            eprintln!("[mlkem_channel] connection refused: {} connections open", limits.max_conn);
            continue; // dropping the stream closes it
        };
        let (acceptor, ctbuf) = (acceptor.clone(), ctbuf.clone());
        tokio::spawn(async move {
            let _permit = permit;
            match receive_one(&acceptor, stream, &limits).await {
                Ok((token, nonce, ct)) => match ctbuf.insert(nonce, ct, token) {
                    Ok(()) => eprintln!(
                        "[mlkem_channel] ciphertext buffered token={token} nonce_prefix={}",
                        hex::encode(&nonce[..4])
                    ),
                    Err(e) => eprintln!("[mlkem_channel] ciphertext refused token={token}: {e}"),
                },
                Err(e) => eprintln!("[mlkem_channel] connection dropped: {e:#}"),
            }
        });
    }
}

/// TLS handshake and read of one message, each under its own timeout.
async fn receive_one(
    acceptor: &TlsAcceptor,
    stream: TcpStream,
    limits: &Limits,
) -> Result<(u32, [u8; 32], Arc<[u8; CT_LEN]>)> {
    let _ = stream.set_nodelay(true);
    let mut tls = timeout(limits.handshake, acceptor.accept(stream))
        .await
        .map_err(|_| anyhow!("TLS handshake timeout"))?
        .context("TLS accept")?;
    let mut buf = [0u8; MSG_LEN];
    timeout(limits.read, tls.read_exact(&mut buf))
        .await
        .map_err(|_| anyhow!("read timeout"))?
        .context("read message")?;
    decode_message(&buf)
}

// ── Client side ──────────────────────────────────────────────────────────────

/// Build a TLS connector that pins the gateway's certificate by fingerprint.
///
/// Privacy-hardened config:
///   - No client certificate (preserves client anonymity)
///   - Pinned certificate plus verified TLS 1.3 handshake signature
///   - Session resumption disabled (prevents ticket-based cross-session linkability)
///   - No ALPN offered (no protocol fingerprint leaked beyond SNI and cert)
pub fn make_connector(expected_fp: [u8; 32]) -> Result<TlsConnector> {
    let provider = installed_provider()?;
    let verifier = Arc::new(PinnedCertVerifier {
        expected_fp,
        algs: provider.signature_verification_algorithms,
    });

    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(TLS13_ONLY)
        .context("TLS 1.3 not supported by the crypto provider")?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    // Disable resumption: session tickets or IDs from a prior handshake would
    // let a passive observer link successive ML-KEM sessions from the same
    // client, breaking handshake-level unlinkability.
    config.resumption = rustls::client::Resumption::disabled();
    // Intentionally leave alpn_protocols empty — offering e.g. "wgzk/1" would
    // brand the traffic as our protocol in the clear.
    config.alpn_protocols.clear();

    Ok(TlsConnector::from(Arc::new(config)))
}

/// Establish a TCP+TLS connection to the gateway (no message sent yet).
/// Kept apart from [`send_on`] so that the two phases can be timed separately.
pub async fn connect_tls(
    connector: &TlsConnector,
    server_addr: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let stream = TcpStream::connect(server_addr)
        .await
        .with_context(|| format!("TCP connect to {server_addr}"))?;
    // One small message: do not let Nagle hold it back behind the handshake.
    let _ = stream.set_nodelay(true);
    let server_name = ServerName::try_from(SERVER_NAME).context("server name")?;
    let tls = connector
        .connect(server_name, stream)
        .await
        .context("TLS connect")?;
    Ok(tls)
}

/// Write the single side-channel message onto an established TLS stream.
pub async fn send_on(
    tls: &mut tokio_rustls::client::TlsStream<TcpStream>,
    token: u32,
    session_nonce: &[u8; 32],
    ct: &[u8; CT_LEN],
) -> Result<()> {
    let buf = encode_message(token, session_nonce, ct);
    tls.write_all(&buf).await.context("write message")?;
    tls.flush().await.context("flush message")?;
    Ok(())
}

// ── Pinned-certificate verifier ──────────────────────────────────────────────

#[derive(Debug)]
struct PinnedCertVerifier {
    expected_fp: [u8; 32],
    algs: WebPkiSupportedAlgorithms,
}

impl PinnedCertVerifier {
    fn check_pin(&self, cert: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        let fp = cert_fingerprint(cert.as_ref());
        if bool::from(fp.ct_eq(&self.expected_fp)) {
            Ok(())
        } else {
            Err(rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure))
        }
    }
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.check_pin(end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is not allowed on the wgzk side channel".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // The signature must come from the pinned certificate's key, whatever rustls passes.
        self.check_pin(cert)?;
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

// ── PEM parsing helpers ──────────────────────────────────────────────────────

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

#[cfg(test)]
pub mod testing {
    //! Fixtures shared by the TLS tests of this module and the handshake tests elsewhere.
    use super::*;

    /// Install the process default provider, as `main` does (idempotent).
    pub fn ensure_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    /// A self-signed ECDSA P-256 certificate for `wgzk-gateway`: (cert_pem, key_pem, fp).
    pub fn self_signed() -> (String, String, [u8; 32]) {
        let cert = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_string()]).expect("rcgen");
        let fp = cert_fingerprint(cert.cert.der());
        (cert.cert.pem(), cert.key_pair.serialize_pem(), fp)
    }

    pub fn limits() -> Limits {
        Limits { max_conn: 8, handshake: Duration::from_secs(2), read: Duration::from_secs(1) }
    }

    /// Run [`serve`] on an ephemeral loopback port; returns "127.0.0.1:port".
    pub async fn spawn_gateway(cert_pem: &str, key_pem: &str, ctbuf: Arc<CtBuffer>) -> String {
        let acceptor = make_acceptor(cert_pem, key_pem).expect("acceptor");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr").to_string();
        tokio::spawn(serve(listener, acceptor, ctbuf, limits()));
        addr
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use rustls::sign::{CertifiedKey, SingleCertAndKey};

    fn ctbuf() -> Arc<CtBuffer> {
        Arc::new(CtBuffer::new(16, Duration::from_secs(5)))
    }

    fn rustls_error(e: &anyhow::Error) -> Option<&rustls::Error> {
        e.chain()
            .filter_map(|c| c.downcast_ref::<std::io::Error>())
            .find_map(|io| io.get_ref().and_then(|inner| inner.downcast_ref::<rustls::Error>()))
    }

    #[test]
    fn fingerprint_hex_is_case_insensitive() {
        let (_, _, fp) = self_signed();
        let lower = hex::encode(fp);
        assert_eq!(parse_fingerprint_hex(&lower).expect("lower"), fp);
        assert_eq!(parse_fingerprint_hex(&lower.to_uppercase()).expect("upper"), fp);
        assert!(parse_fingerprint_hex(&lower[..62]).is_err());
        assert!(parse_fingerprint_hex("zz").is_err());
    }

    #[test]
    fn message_roundtrip() {
        let ct = [0x5a; CT_LEN];
        let msg = encode_message(0x0102_0304, &[7; 32], &ct);
        assert_eq!(&msg[0..4], &[4, 3, 2, 1], "token is little endian");
        let (token, nonce, ct2) = decode_message(&msg).expect("decode");
        assert_eq!((token, nonce), (0x0102_0304, [7; 32]));
        assert_eq!(*ct2, ct);
    }

    /// (1) Correct certificate and key: the message arrives in the ciphertext buffer.
    #[tokio::test]
    async fn correct_certificate_delivers_message() {
        ensure_provider();
        let (cert, key, fp) = self_signed();
        let buf = ctbuf();
        let addr = spawn_gateway(&cert, &key, buf.clone()).await;

        let connector = make_connector(fp).expect("connector");
        let mut tls = connect_tls(&connector, &addr).await.expect("TLS connect");
        assert_eq!(tls.get_ref().1.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_3));
        send_on(&mut tls, 77, &[3; 32], &[0xc7; CT_LEN]).await.expect("send");

        let e = buf.lookup(&[3; 32], Duration::from_secs(2)).await.expect("message buffered");
        assert_eq!(e.token, 77);
        assert_eq!(*e.ct, [0xc7; CT_LEN]);
    }

    /// Server that presents `cert` but signs the handshake with `key` (no pairing check).
    async fn spawn_raw_server(cert: &str, key: &str) -> (String, tokio::task::JoinHandle<Result<()>>) {
        let provider = installed_provider().expect("provider");
        let signer = provider
            .key_provider
            .load_private_key(parse_key_pem(key).expect("key"))
            .expect("signing key");
        let ck = CertifiedKey::new(vec![parse_cert_pem(cert).expect("cert")], signer);
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(TLS13_ONLY)
            .expect("tls13")
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SingleCertAndKey::from(ck)));
        harden_server_config(&mut config);
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr").to_string();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut tls = acceptor.accept(stream).await?;
            let mut buf = [0u8; MSG_LEN];
            tls.read_exact(&mut buf).await?;
            Ok(())
        });
        (addr, task)
    }

    /// (2) Pinned certificate, but the handshake is signed with another key: the client
    /// must refuse. The same server built with the matching key is accepted (control).
    #[tokio::test]
    async fn pinned_certificate_with_wrong_key_is_refused() {
        ensure_provider();
        let (cert_a, key_a, fp_a) = self_signed();
        let (_cert_b, key_b, _) = self_signed();
        let connector = make_connector(fp_a).expect("connector");

        let (addr, _server) = spawn_raw_server(&cert_a, &key_b).await;
        let err = connect_tls(&connector, &addr).await.expect_err("wrong key must fail");
        assert_eq!(
            rustls_error(&err),
            Some(&rustls::Error::InvalidCertificate(CertificateError::BadSignature)),
            "failed for the wrong reason: {err:#}"
        );

        let (addr, server) = spawn_raw_server(&cert_a, &key_a).await;
        let mut tls = connect_tls(&connector, &addr).await.expect("control: matching key");
        send_on(&mut tls, 1, &[1; 32], &[1; CT_LEN]).await.expect("send");
        server.await.expect("join").expect("control server");
    }

    /// (3) A server with a different certificate: the client must refuse.
    #[tokio::test]
    async fn different_certificate_is_refused() {
        ensure_provider();
        let (_cert_a, _key_a, fp_a) = self_signed();
        let (cert_b, key_b, _) = self_signed();
        let buf = ctbuf();
        let addr = spawn_gateway(&cert_b, &key_b, buf.clone()).await;

        let connector = make_connector(fp_a).expect("connector");
        let err = connect_tls(&connector, &addr).await.expect_err("other certificate must fail");
        assert_eq!(
            rustls_error(&err),
            Some(&rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)),
            "failed for the wrong reason: {err:#}"
        );
        assert!(buf.lookup(&[0; 32], Duration::from_millis(100)).await.is_none());
    }

    /// (4) A client that offers only TLS 1.2 is refused by the acceptor.
    #[tokio::test]
    async fn tls12_only_client_is_refused() {
        ensure_provider();
        let (cert, key, fp) = self_signed();
        let acceptor = make_acceptor(&cert, &key).expect("acceptor");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            acceptor.accept(stream).await
        });

        let provider = installed_provider().expect("provider");
        let verifier = Arc::new(PinnedCertVerifier { expected_fp: fp, algs: provider.signature_verification_algorithms });
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS12])
            .expect("tls12")
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));
        let stream = TcpStream::connect(addr).await.expect("tcp");
        let name = ServerName::try_from(SERVER_NAME).expect("name");
        assert!(connector.connect(name, stream).await.is_err(), "client must not get a session");

        let server_err = server.await.expect("join").expect_err("acceptor must refuse TLS 1.2");
        let inner = server_err.get_ref().and_then(|e| e.downcast_ref::<rustls::Error>());
        assert!(
            matches!(
                inner,
                Some(rustls::Error::PeerIncompatible(
                    rustls::PeerIncompatible::SupportedVersionsExtensionRequired
                        | rustls::PeerIncompatible::Tls12NotOfferedOrEnabled
                ))
            ),
            "refused for the wrong reason: {server_err}"
        );
    }

    /// Even if a TLS 1.2 session were negotiated (here: TLS 1.2-only server holding the
    /// pinned certificate and its key), the verifier's TLS 1.2 callback refuses it.
    #[tokio::test]
    async fn tls12_signature_callback_fails() {
        ensure_provider();
        let (cert, key, fp) = self_signed();
        let provider = installed_provider().expect("provider");
        let server_cfg = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS12])
            .expect("tls12")
            .with_no_client_auth()
            .with_single_cert(vec![parse_cert_pem(&cert).expect("cert")], parse_key_pem(&key).expect("key"))
            .expect("server config");
        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let _ = acceptor.accept(stream).await;
            }
        });

        let verifier = Arc::new(PinnedCertVerifier { expected_fp: fp, algs: provider.signature_verification_algorithms });
        assert!(!verifier.supported_verify_schemes().is_empty());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS12])
            .expect("tls12")
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        let stream = TcpStream::connect(addr).await.expect("tcp");
        let name = ServerName::try_from(SERVER_NAME).expect("name");
        let err = TlsConnector::from(Arc::new(config))
            .connect(name, stream)
            .await
            .expect_err("TLS 1.2 must be refused by the verifier");
        let inner = err.get_ref().and_then(|e| e.downcast_ref::<rustls::Error>());
        assert!(
            matches!(inner, Some(rustls::Error::General(m)) if m.contains("TLS 1.2")),
            "refused for the wrong reason: {err}"
        );
    }
}
