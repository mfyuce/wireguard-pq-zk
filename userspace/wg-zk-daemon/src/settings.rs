//! Configuration from the environment (after `.env` is loaded); `.env.example` lists every
//! variable. A variable that is set but cannot be parsed is a startup error, never a silent
//! default; unset or empty variables take the documented default. Error messages never
//! contain the value of a key.
//!
//! Mode rule, both roles: `WGZK_DISABLE_MLKEM=1` selects ZK-only (`0x01`). Otherwise
//! (unset or `0`) the ML-KEM configuration of the role must be complete and the mode is
//! ZK+PQ (`0x02`); an incomplete one is a startup error, so a daemon never runs without the
//! post-quantum key by accident.
//!
//! `WGZK_INSTALLER` selects how WireGuard peers are changed, in both roles: `netlink` (the
//! default, WireGuard's generic netlink family, no child process) or `tool` (the `wg` tool).
//!
//! `WGZK_FAULT` selects a client fault in a build with the cargo feature `fault-injection`
//! (module `fault`). Wherever no fault can be injected (every role of a normal build, the
//! gateway role of a fault-injection build) a non-empty `WGZK_FAULT` is a startup error, so
//! that a test run never believes that a fault was injected when it was not.

use anyhow::{anyhow, bail, Context, Result};
use curve25519_dalek::scalar::Scalar;
use std::collections::HashMap;
use std::fmt::Display;
use std::str::FromStr;
use tokio::time::Duration;

use crate::addr;
use crate::mlkem::{EK_LEN, SEED_LEN};
use crate::mlkem_channel;
use crate::zk::{self, Mode};

/// Source of configuration values.
pub trait Env {
    /// The trimmed value of `name`; `None` when unset or empty.
    fn var(&self, name: &str) -> Result<Option<String>>;
}

pub struct ProcessEnv;

impl Env for ProcessEnv {
    fn var(&self, name: &str) -> Result<Option<String>> {
        match std::env::var(name) {
            Ok(v) if v.trim().is_empty() => Ok(None),
            Ok(v) => Ok(Some(v.trim().to_string())),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => bail!("{name} is not valid UTF-8"),
        }
    }
}

impl Env for HashMap<&str, &str> {
    fn var(&self, name: &str) -> Result<Option<String>> {
        Ok(self.get(name).map(|v| v.trim().to_string()).filter(|v| !v.is_empty()))
    }
}

/// A number with a default and a lower bound. The value is not secret, so it is echoed.
fn num<T>(env: &dyn Env, name: &str, default: T, min: T) -> Result<T>
where
    T: FromStr + PartialOrd + Display + Copy,
    T::Err: Display,
{
    let Some(v) = env.var(name)? else { return Ok(default) };
    let n: T = v.parse().map_err(|e| anyhow!("{name}={v:?}: {e}"))?;
    if n < min {
        bail!("{name}={n}: must be at least {min}");
    }
    Ok(n)
}

fn millis(env: &dyn Env, name: &str, default: u64, min: u64) -> Result<Duration> {
    num(env, name, default, min).map(Duration::from_millis)
}

/// A fixed-length hex value that may be secret: errors never show it.
fn hex_fixed<const N: usize>(name: &str, v: &str) -> Result<Box<[u8; N]>> {
    let b = hex::decode(v).map_err(|_| anyhow!("{name}: not valid hex"))?;
    let len = b.len();
    let arr: [u8; N] = b.try_into().map_err(|_| anyhow!("{name}: {len} bytes, expected {N}"))?;
    Ok(Box::new(arr))
}

/// Bounds and timeouts of Section 7.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bounds {
    pub ct_buffer_max: usize,
    pub ct_ttl: Duration,
    pub tls_max_conn: usize,
    pub tls_handshake: Duration,
    pub tls_read: Duration,
    pub ct_wait: Duration,
    /// Decisions on NEED_VERIFY events in progress at one time.
    pub verify_max: usize,
    pub replay_max: usize,
    pub peer_max: usize,
    pub peer_idle: Duration,
}

impl Bounds {
    pub fn from_env(env: &dyn Env) -> Result<Self> {
        Ok(Bounds {
            ct_buffer_max: num(env, "WGZK_CT_BUFFER_MAX", 1024, 1)?,
            ct_ttl: millis(env, "WGZK_CT_TTL_MS", 5000, 1)?,
            tls_max_conn: num(env, "WGZK_TLS_MAX_CONN", 256, 1)?,
            tls_handshake: millis(env, "WGZK_TLS_HANDSHAKE_MS", 2000, 1)?,
            tls_read: millis(env, "WGZK_TLS_READ_MS", 1000, 1)?,
            ct_wait: millis(env, "WGZK_CT_WAIT_MS", 250, 0)?,
            verify_max: num(env, "WGZK_VERIFY_MAX", 1024, 1)?,
            replay_max: num(env, "WGZK_REPLAY_MAX", 1_048_576, 1)?,
            peer_max: num(env, "WGZK_PEER_MAX", 4096, 1)?,
            peer_idle: num(env, "WGZK_PEER_IDLE_SECS", 300u64, 1).map(Duration::from_secs)?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Client,
    Gateway,
}

/// `WGZK_MODE`: `client` or `gateway`; unset means client, as before.
pub fn role(env: &dyn Env) -> Result<Role> {
    match env.var("WGZK_MODE")? {
        None => {
            eprintln!("[wgzk] WGZK_MODE not set; defaulting to 'client'. Set WGZK_MODE=gateway on the gateway daemon.");
            Ok(Role::Client)
        }
        Some(m) if m.eq_ignore_ascii_case("client") => Ok(Role::Client),
        Some(m) if m.eq_ignore_ascii_case("gateway") => Ok(Role::Gateway),
        Some(m) => bail!("WGZK_MODE={m:?}: expected 'client' or 'gateway'"),
    }
}

/// A `0`/`1` switch with a default.
fn flag(env: &dyn Env, name: &str, default: bool) -> Result<bool> {
    match env.var(name)?.as_deref() {
        None => Ok(default),
        Some("0") => Ok(false),
        Some("1") => Ok(true),
        Some(v) => bail!("{name}={v:?}: expected 0 or 1"),
    }
}

/// `WGZK_DISABLE_MLKEM`: `1` disables ML-KEM, `0` or unset requires it.
fn mlkem_disabled(env: &dyn Env) -> Result<bool> {
    flag(env, "WGZK_DISABLE_MLKEM", false)
}

/// Refuse `WGZK_FAULT` where no fault can be injected.
fn refuse_fault(env: &dyn Env) -> Result<()> {
    if env.var("WGZK_FAULT")?.is_some() {
        #[cfg(not(feature = "fault-injection"))]
        bail!("WGZK_FAULT is set, but this build contains no fault injection (it needs cargo --features fault-injection)");
        #[cfg(feature = "fault-injection")]
        bail!("WGZK_FAULT is set, but faults can be injected in the client role only");
    }
    Ok(())
}

/// How the daemon changes WireGuard peers (`WGZK_INSTALLER`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Installer {
    /// WireGuard's generic netlink family, in process.
    Netlink,
    /// The `wg` tool, one child process per change.
    Tool,
}

impl Installer {
    pub fn name(self) -> &'static str {
        match self {
            Installer::Netlink => "netlink",
            Installer::Tool => "tool",
        }
    }
}

/// `WGZK_INSTALLER`: `netlink` (default) or `tool`.
fn installer(env: &dyn Env) -> Result<Installer> {
    match env.var("WGZK_INSTALLER")?.as_deref() {
        None | Some("netlink") => Ok(Installer::Netlink),
        Some("tool") => Ok(Installer::Tool),
        Some(v) => bail!("WGZK_INSTALLER={v:?}: expected netlink or tool"),
    }
}

/// `WGZK_ADDR_PREFIX` or the default prefix of Section 3.5.
pub fn addr_prefix(env: &dyn Env) -> Result<[u8; 8]> {
    match env.var("WGZK_ADDR_PREFIX")? {
        None => Ok(addr::DEFAULT_PREFIX),
        Some(p) => addr::parse_prefix(&p).context("WGZK_ADDR_PREFIX"),
    }
}

fn epoch(env: &dyn Env) -> Result<u32> {
    num(env, "WGZK_EPOCH", 0u32, 0)
}

/// Fetch all `names`; if any is missing, the ML-KEM configuration is incomplete.
fn require_all(env: &dyn Env, names: &[&str]) -> Result<Vec<String>> {
    let mut vals = Vec::new();
    let mut missing = Vec::new();
    for n in names {
        match env.var(n)? {
            Some(v) => vals.push(v),
            None => missing.push(*n),
        }
    }
    if !missing.is_empty() {
        bail!(
            "ML-KEM configuration incomplete (missing {}); set it, or set WGZK_DISABLE_MLKEM=1 to run in ZK-only mode",
            missing.join(", ")
        );
    }
    Ok(vals)
}

pub struct GatewayPq {
    pub dk_seed: Box<[u8; SEED_LEN]>,
    pub cert_pem: String,
    pub key_pem: String,
    pub port: u16,
}

pub struct GatewayConfig {
    pub epoch: u32,
    pub pk: [u8; 32],
    /// Credential public key of epoch `epoch - 1`, if still accepted.
    pub pk_prev: Option<[u8; 32]>,
    pub iface: String,
    pub addr_prefix: [u8; 8],
    pub bounds: Bounds,
    /// Adopt the peers `iface` already has at start (`WGZK_ADOPT_PEERS`, default 1).
    pub adopt_peers: bool,
    pub installer: Installer,
    /// Present exactly in mode ZK+PQ.
    pub pq: Option<GatewayPq>,
}

impl GatewayConfig {
    pub fn mode(&self) -> Mode {
        if self.pq.is_some() {
            Mode::ZkPq
        } else {
            Mode::ZkOnly
        }
    }
}

pub fn gateway_config(env: &dyn Env) -> Result<GatewayConfig> {
    refuse_fault(env)?;
    let bounds = Bounds::from_env(env)?;
    let epoch = epoch(env)?;
    let pk_hex = env.var("WGZK_PK_HEX")?.ok_or_else(|| anyhow!("WGZK_PK_HEX missing (gateway)"))?;
    let pk = zk::parse_pk_hex(&pk_hex).context("WGZK_PK_HEX")?;
    let pk_prev = match env.var("WGZK_PK_PREV_HEX")? {
        None => None,
        Some(h) => {
            if epoch == 0 {
                bail!("WGZK_PK_PREV_HEX is set but WGZK_EPOCH is 0, so there is no previous epoch");
            }
            Some(zk::parse_pk_hex(&h).context("WGZK_PK_PREV_HEX")?)
        }
    };
    let iface = env
        .var("WG_IFACE")?
        .ok_or_else(|| anyhow!("WG_IFACE missing: the gateway installs peers on this interface"))?;
    let pq = if mlkem_disabled(env)? {
        None
    } else {
        let v = require_all(env, &["MLKEM_DK_SEED", "MLKEM_CERT_PEM", "MLKEM_KEY_PEM"])?;
        Some(GatewayPq {
            dk_seed: hex_fixed::<SEED_LEN>("MLKEM_DK_SEED", &v[0])?,
            cert_pem: v[1].clone(),
            key_pem: v[2].clone(),
            port: num(env, "MLKEM_PORT", mlkem_channel::DEFAULT_PORT, 1)?,
        })
    };
    Ok(GatewayConfig {
        epoch,
        pk,
        pk_prev,
        iface,
        addr_prefix: addr_prefix(env)?,
        bounds,
        adopt_peers: flag(env, "WGZK_ADOPT_PEERS", true)?,
        installer: installer(env)?,
        pq,
    })
}

pub struct ClientPq {
    pub server_ek: Box<[u8; EK_LEN]>,
    pub server_addr: String,
    pub cert_fp: [u8; 32],
    /// Interface on which the PSK is installed.
    pub iface: String,
}

pub struct ClientConfig {
    pub epoch: u32,
    pub sk: Scalar,
    /// Events of other interfaces are ignored when set; required in ZK+PQ.
    pub iface: Option<String>,
    pub bounds: Bounds,
    pub installer: Installer,
    /// Present exactly in mode ZK+PQ.
    pub pq: Option<ClientPq>,
    /// Fault selected by `WGZK_FAULT`.
    #[cfg(feature = "fault-injection")]
    pub fault: Option<crate::fault::Fault>,
}

impl ClientConfig {
    pub fn mode(&self) -> Mode {
        if self.pq.is_some() {
            Mode::ZkPq
        } else {
            Mode::ZkOnly
        }
    }
}

pub fn client_config(env: &dyn Env) -> Result<ClientConfig> {
    #[cfg(not(feature = "fault-injection"))]
    refuse_fault(env)?;
    let bounds = Bounds::from_env(env)?;
    let epoch = epoch(env)?;
    let sk_hex = env.var("WGZK_SK_HEX")?.ok_or_else(|| anyhow!("WGZK_SK_HEX missing (client)"))?;
    let sk = zk::parse_sk_hex(&sk_hex).context("WGZK_SK_HEX")?;
    let iface = env.var("WG_IFACE")?;
    let pq = if mlkem_disabled(env)? {
        None
    } else {
        let v = require_all(env, &["MLKEM_SERVER_EK", "MLKEM_SERVER_ADDR", "MLKEM_CERT_FP", "WG_IFACE"])?;
        Some(ClientPq {
            server_ek: hex_fixed::<EK_LEN>("MLKEM_SERVER_EK", &v[0])?,
            server_addr: v[1].clone(),
            cert_fp: mlkem_channel::parse_fingerprint_hex(&v[2]).context("MLKEM_CERT_FP")?,
            iface: v[3].clone(),
        })
    };
    #[cfg(feature = "fault-injection")]
    let fault = crate::fault::from_env(env, pq.is_some())?;
    Ok(ClientConfig {
        epoch,
        sk,
        iface,
        bounds,
        installer: installer(env)?,
        pq,
        #[cfg(feature = "fault-injection")]
        fault,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PK: &str = "c866f2598183d9bbc4b3958828184f9e53537da7c4f39d85361124a50e6eb10b";
    const SK: &str = "4731bcefd3f3791c92a34f200ba53d34ec23fba43359c942acc6de359f62c50c";

    fn env(pairs: &[(&'static str, &'static str)]) -> HashMap<&'static str, &'static str> {
        pairs.iter().copied().collect()
    }

    fn err_text<T>(r: Result<T>) -> String {
        match r {
            Ok(_) => panic!("expected an error"),
            Err(e) => format!("{e:#}"),
        }
    }

    #[test]
    fn bounds_defaults_are_those_of_section_7() {
        let b = Bounds::from_env(&env(&[])).expect("defaults");
        assert_eq!(
            b,
            Bounds {
                ct_buffer_max: 1024,
                ct_ttl: Duration::from_secs(5),
                tls_max_conn: 256,
                tls_handshake: Duration::from_secs(2),
                tls_read: Duration::from_secs(1),
                ct_wait: Duration::from_millis(250),
                verify_max: 1024,
                replay_max: 1_048_576,
                peer_max: 4096,
                peer_idle: Duration::from_secs(300),
            }
        );
    }

    #[test]
    fn bounds_parse_errors_are_startup_errors() {
        let b = Bounds::from_env(&env(&[("WGZK_CT_WAIT_MS", "0"), ("WGZK_PEER_MAX", "10")])).expect("ok");
        assert_eq!((b.ct_wait, b.peer_max), (Duration::ZERO, 10));
        assert!(err_text(Bounds::from_env(&env(&[("WGZK_TLS_MAX_CONN", "many")]))).contains("WGZK_TLS_MAX_CONN"));
        assert!(err_text(Bounds::from_env(&env(&[("WGZK_REPLAY_MAX", "0")]))).contains("at least 1"));
        assert!(Bounds::from_env(&env(&[("WGZK_CT_TTL_MS", "-5")])).is_err());
    }

    fn gw_base() -> Vec<(&'static str, &'static str)> {
        vec![("WGZK_PK_HEX", PK), ("WG_IFACE", "wg0")]
    }

    #[test]
    fn gateway_without_mlkem_config_refuses_to_start() {
        let e = err_text(gateway_config(&env(&gw_base())));
        assert!(e.contains("MLKEM_DK_SEED") && e.contains("WGZK_DISABLE_MLKEM=1"), "{e}");
        let mut v = gw_base();
        v.push(("WGZK_DISABLE_MLKEM", "0"));
        assert!(gateway_config(&env(&v)).is_err(), "0 means ML-KEM is required");
    }

    #[test]
    fn gateway_modes() {
        let mut v = gw_base();
        v.push(("WGZK_DISABLE_MLKEM", "1"));
        let c = gateway_config(&env(&v)).expect("zk-only");
        assert_eq!(c.mode(), Mode::ZkOnly);
        assert!(c.pq.is_none());
        assert_eq!(c.addr_prefix, addr::DEFAULT_PREFIX);

        let seed = "11".repeat(64);
        let seed: &'static str = Box::leak(seed.into_boxed_str());
        let mut v = gw_base();
        v.extend([("MLKEM_DK_SEED", seed), ("MLKEM_CERT_PEM", "cert"), ("MLKEM_KEY_PEM", "key")]);
        let c = gateway_config(&env(&v)).expect("zk+pq");
        assert_eq!(c.mode(), Mode::ZkPq);
        assert_eq!(c.pq.as_ref().map(|p| p.port), Some(51821));

        let mut bad = v.clone();
        bad.push(("WGZK_DISABLE_MLKEM", "yes"));
        assert!(err_text(gateway_config(&env(&bad))).contains("expected 0 or 1"));
    }

    #[test]
    fn gateway_epochs() {
        let mut v = gw_base();
        v.extend([("WGZK_DISABLE_MLKEM", "1"), ("WGZK_PK_PREV_HEX", PK)]);
        assert!(err_text(gateway_config(&env(&v))).contains("no previous epoch"));
        v.push(("WGZK_EPOCH", "5"));
        let c = gateway_config(&env(&v)).expect("epoch 5");
        assert_eq!((c.epoch, c.pk_prev.is_some()), (5, true));
    }

    #[test]
    fn secrets_are_not_echoed() {
        let secret = "5ec2e75ec2e75ec2e75ec2e75ec2e75ec2e75ec2e75ec2e75ec2e75ec2e7zz";
        let e = err_text(client_config(&env(&[("WGZK_SK_HEX", secret), ("WGZK_DISABLE_MLKEM", "1")])));
        assert!(!e.contains("5ec2e7"), "{e}");
        let mut v = gw_base();
        v.extend([("MLKEM_DK_SEED", secret), ("MLKEM_CERT_PEM", "c"), ("MLKEM_KEY_PEM", "k")]);
        let e = err_text(gateway_config(&env(&v)));
        assert!(e.contains("MLKEM_DK_SEED") && !e.contains("5ec2e7"), "{e}");
    }

    #[test]
    fn client_modes() {
        let e = err_text(client_config(&env(&[("WGZK_SK_HEX", SK)])));
        assert!(e.contains("MLKEM_SERVER_EK") && e.contains("WG_IFACE"), "{e}");

        let c = client_config(&env(&[("WGZK_SK_HEX", SK), ("WGZK_DISABLE_MLKEM", "1")])).expect("zk-only");
        assert_eq!((c.mode(), c.iface.is_none()), (Mode::ZkOnly, true));

        let ek: &'static str = Box::leak("00".repeat(EK_LEN).into_boxed_str());
        let fp: &'static str = Box::leak("AB".repeat(32).into_boxed_str());
        let c = client_config(&env(&[
            ("WGZK_SK_HEX", SK),
            ("MLKEM_SERVER_EK", ek),
            ("MLKEM_SERVER_ADDR", "192.0.2.1:51821"),
            ("MLKEM_CERT_FP", fp),
            ("WG_IFACE", "wgc0"),
            ("WGZK_EPOCH", "3"),
        ]))
        .expect("zk+pq");
        assert_eq!((c.mode(), c.epoch), (Mode::ZkPq, 3));
        let pq = c.pq.expect("pq");
        assert_eq!((pq.cert_fp, pq.iface.as_str()), ([0xab; 32], "wgc0"));
    }

    #[test]
    fn roles() {
        assert_eq!(role(&env(&[])).expect("default"), Role::Client);
        assert_eq!(role(&env(&[("WGZK_MODE", "Gateway")])).expect("gw"), Role::Gateway);
        assert!(role(&env(&[("WGZK_MODE", "server")])).is_err());
    }

    #[test]
    fn adopt_peers_switch() {
        let mut v = gw_base();
        v.push(("WGZK_DISABLE_MLKEM", "1"));
        assert!(gateway_config(&env(&v)).expect("default").adopt_peers, "adoption is the default");
        let mut off = v.clone();
        off.push(("WGZK_ADOPT_PEERS", "0"));
        assert!(!gateway_config(&env(&off)).expect("0").adopt_peers);
        let mut bad = v.clone();
        bad.push(("WGZK_ADOPT_PEERS", "yes"));
        assert!(err_text(gateway_config(&env(&bad))).contains("WGZK_ADOPT_PEERS"));
    }

    #[test]
    fn installer_selection() {
        let mut g = gw_base();
        g.push(("WGZK_DISABLE_MLKEM", "1"));
        let c = vec![("WGZK_SK_HEX", SK), ("WGZK_DISABLE_MLKEM", "1")];
        for base in [g, c] {
            let with = |v: Option<&'static str>| {
                let mut e = base.clone();
                if let Some(v) = v {
                    e.push(("WGZK_INSTALLER", v));
                }
                let env = env(&e);
                match base.iter().any(|(k, _)| *k == "WGZK_PK_HEX") {
                    true => gateway_config(&env).map(|c| c.installer),
                    false => client_config(&env).map(|c| c.installer),
                }
            };
            assert_eq!(with(None).expect("default"), Installer::Netlink);
            assert_eq!(with(Some("netlink")).expect("netlink"), Installer::Netlink);
            assert_eq!(with(Some("tool")).expect("tool"), Installer::Tool);
            assert_eq!(with(Some("")).expect("empty means default"), Installer::Netlink);
            assert!(err_text(with(Some("wg"))).contains("expected netlink or tool"));
            assert!(with(Some("Netlink")).is_err(), "exact names only");
        }
    }

    /// Mode 0x02 client settings, for the fault tests.
    fn pq_client_env() -> Vec<(&'static str, &'static str)> {
        let ek: &'static str = Box::leak("00".repeat(EK_LEN).into_boxed_str());
        let fp: &'static str = Box::leak("ab".repeat(32).into_boxed_str());
        vec![
            ("WGZK_SK_HEX", SK),
            ("MLKEM_SERVER_EK", ek),
            ("MLKEM_SERVER_ADDR", "192.0.2.1:51821"),
            ("MLKEM_CERT_FP", fp),
            ("WG_IFACE", "wgc0"),
        ]
    }

    #[cfg(not(feature = "fault-injection"))]
    #[test]
    fn fault_refused_in_a_normal_build() {
        let mut c = pq_client_env();
        c.push(("WGZK_FAULT", "bad_proof"));
        assert!(err_text(client_config(&env(&c))).contains("this build contains no fault injection"));
        let mut g = gw_base();
        g.extend([("WGZK_DISABLE_MLKEM", "1"), ("WGZK_FAULT", "skip_ct")]);
        assert!(err_text(gateway_config(&env(&g))).contains("this build contains no fault injection"));
        // Empty means unset.
        let mut c = pq_client_env();
        c.push(("WGZK_FAULT", ""));
        assert!(client_config(&env(&c)).is_ok());
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn fault_selection_in_a_fault_build() {
        use crate::fault::Fault;
        let with = |base: Vec<(&'static str, &'static str)>, fault: &'static str| {
            let mut v = base;
            v.push(("WGZK_FAULT", fault));
            client_config(&env(&v))
        };
        let zk_only = vec![("WGZK_SK_HEX", SK), ("WGZK_DISABLE_MLKEM", "1")];
        for f in Fault::ALL {
            let c = with(pq_client_env(), f.name()).expect("every fault in mode 0x02");
            assert_eq!(c.fault, Some(f));
        }
        assert_eq!(client_config(&env(&pq_client_env())).expect("unset").fault, None);
        assert_eq!(with(pq_client_env(), "").expect("empty").fault, None);
        assert!(err_text(with(pq_client_env(), "drop_everything")).contains("unknown fault"));
        for f in ["skip_ct", "other_nonce_ct", "flip_ct", "no_psk"] {
            assert!(err_text(with(zk_only.clone(), f)).contains("needs mode 0x02"), "{f}");
        }
        for f in ["bad_proof", "other_key", "other_gw", "other_epoch"] {
            assert!(with(zk_only.clone(), f).expect("any mode").fault.is_some(), "{f}");
        }
        let mut g = gw_base();
        g.extend([("WGZK_DISABLE_MLKEM", "1"), ("WGZK_FAULT", "bad_proof")]);
        assert!(err_text(gateway_config(&env(&g))).contains("client role only"));
    }
}
