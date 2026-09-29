//! WireGuard's own generic netlink interface as a [`PeerInstaller`] (`WGZK_INSTALLER=netlink`,
//! the default): family `wireguard`, version 1, `uapi/linux/wireguard.h`. It takes the `wg`
//! child process out of the handshake path; `new-connection` still uses the tools.
//!
//! ```text
//! set_peer     SET_DEVICE  IFNAME, PEERS { 0 { PUBLIC_KEY, [PRESHARED_KEY],
//!                          [FLAGS=REPLACE_ALLOWEDIPS, ALLOWEDIPS { 0 { FAMILY=AF_INET6, IPADDR, CIDR_MASK=128 } }] } }
//! remove_peer  SET_DEVICE  IFNAME, PEERS { 0 { PUBLIC_KEY, FLAGS=REMOVE_ME } }
//! list_peers   GET_DEVICE  IFNAME (NLM_F_DUMP); the public keys of all reply messages, each once
//! ```
//!
//! These are the requests of `wg set <iface> peer <key> [preshared-key ..] [allowed-ips
//! <addr>/128]`, `wg set .. remove` and `wg show <iface> peers`: attributes in the order of
//! wireguard-tools, NLA_F_NESTED on every nested attribute, list entries of type 0. Without an
//! allowed IP the peer's allowed IPs and endpoint stay untouched; without a PSK the PSK stays
//! untouched. Removing a peer that does not exist succeeds, as with the tool.
//!
//! One socket per installer. Requests are serialised through a mutex and each waits for its
//! acknowledgement (or the NLMSG_DONE of a dump) within [`TOOL_TIMEOUT`]. A kernel error becomes
//! an error naming the operation, the interface and the errno, never a key. A socket error or a
//! timeout drops the socket; the next request reconnects. An interrupted dump (NLM_F_DUMP_INTR)
//! is repeated, at most three times in all.
//!
//! Key material: request and reply payloads live in [`Wiped`], which zeroes its bytes on drop;
//! a request is built in one allocation that never grows, so no stale copy is left by a
//! reallocation. Out of reach from here: the temporary buffer into which neli serialises each
//! request inside `send`, and neli's receive pool, which keeps the last datagram (a reply to a
//! failed request echoes the request, PSK included) until the next receive overwrites it.

use anyhow::{anyhow, bail, Result};
use futures::future::BoxFuture;
use neli::{
    attr::Attribute,
    consts::{
        nl::{NlmF, Nlmsg, NlmsgerrAttr},
        socket::NlFamily,
    },
    err::{DeError, SerError},
    nl::{NlPayload, Nlmsghdr, NlmsghdrBuilder},
    socket::asynchronous::NlSocketHandle,
    types::{Buffer, GenlBuffer},
    utils::Groups,
    FromBytesWithInput, Size, ToBytes,
};
use std::collections::HashSet;
use std::io::{Cursor, Read, Write};
use tokio::sync::Mutex;
use tokio::time::timeout;
use zeroize::Zeroize;

use crate::peers::{PeerInstaller, PeerUpdate};
use crate::tool::TOOL_TIMEOUT;

const WG_GENL_NAME: &str = "wireguard";
const WG_GENL_VERSION: u8 = 1;
const WG_CMD_GET_DEVICE: u8 = 0;
const WG_CMD_SET_DEVICE: u8 = 1;
const WGDEVICE_A_IFNAME: u16 = 2;
const WGDEVICE_A_PEERS: u16 = 8;
const WGPEER_A_PUBLIC_KEY: u16 = 1;
const WGPEER_A_PRESHARED_KEY: u16 = 2;
const WGPEER_A_FLAGS: u16 = 3;
const WGPEER_A_ALLOWEDIPS: u16 = 9;
const WGPEER_F_REMOVE_ME: u32 = 1;
const WGPEER_F_REPLACE_ALLOWEDIPS: u32 = 2;
const WGALLOWEDIP_A_FAMILY: u16 = 1;
const WGALLOWEDIP_A_IPADDR: u16 = 2;
const WGALLOWEDIP_A_CIDR_MASK: u16 = 3;
const AF_INET6: u16 = 10;
const NLA_F_NESTED: u16 = 0x8000;
/// Attribute type without NLA_F_NESTED and NLA_F_NET_BYTEORDER.
const NLA_TYPE_MASK: u16 = 0x3fff;
const GENL_HDRLEN: usize = 4;
const IFNAMSIZ: usize = 16;
/// Enough for the largest request (156 bytes), so a request buffer never reallocates.
const REQUEST_CAPACITY: usize = 256;
const DUMP_ATTEMPTS: usize = 3;

// ── Payload buffer that is wiped on drop ──────────────────────────────────────

/// Bytes that are zeroed when dropped. Used for every request and reply payload.
pub struct Wiped(Vec<u8>);

impl Drop for Wiped {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for Wiped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Wiped({} bytes)", self.0.len())
    }
}

impl Size for Wiped {
    fn unpadded_size(&self) -> usize {
        self.0.len()
    }
}

impl ToBytes for Wiped {
    fn to_bytes(&self, buffer: &mut Cursor<Vec<u8>>) -> Result<(), SerError> {
        buffer.write_all(&self.0)?;
        Ok(())
    }
}

impl FromBytesWithInput for Wiped {
    type Input = usize;

    fn from_bytes_with_input(buffer: &mut Cursor<impl AsRef<[u8]>>, input: usize) -> Result<Self, DeError> {
        if buffer.position() as usize + input > buffer.get_ref().as_ref().len() {
            return Err(DeError::InvalidInput(input));
        }
        let mut bytes = Wiped(vec![0u8; input]);
        buffer.read_exact(&mut bytes.0)?;
        Ok(bytes)
    }
}

// ── Requests ──────────────────────────────────────────────────────────────────

/// Writes a generic netlink payload: header, then attributes aligned to 4 bytes. The second
/// field is the capacity the buffer started with; it must not grow (see [`Encoder::finish`]).
struct Encoder(Wiped, usize);

impl Encoder {
    fn new(cmd: u8) -> Self {
        let mut buf = Vec::with_capacity(REQUEST_CAPACITY);
        buf.extend_from_slice(&[cmd, WG_GENL_VERSION, 0, 0]);
        let capacity = buf.capacity();
        Encoder(Wiped(buf), capacity)
    }

    fn header(&mut self, len: u16, ty: u16) {
        self.0 .0.extend_from_slice(&len.to_ne_bytes());
        self.0 .0.extend_from_slice(&ty.to_ne_bytes());
    }

    fn put(&mut self, ty: u16, value: &[u8]) -> Result<()> {
        self.header(u16::try_from(4 + value.len())?, ty);
        self.0 .0.extend_from_slice(value);
        while !self.0 .0.len().is_multiple_of(4) {
            self.0 .0.push(0);
        }
        Ok(())
    }

    /// Start a nested attribute; returns where its header is.
    fn nest(&mut self, ty: u16) -> usize {
        let at = self.0 .0.len();
        self.header(0, ty | NLA_F_NESTED);
        at
    }

    /// Close a nested attribute: its length covers its children and their padding.
    fn end(&mut self, at: usize) -> Result<()> {
        let len = u16::try_from(self.0 .0.len() - at)?;
        self.0 .0[at..at + 2].copy_from_slice(&len.to_ne_bytes());
        Ok(())
    }

    fn ifname(&mut self, iface: &str) -> Result<()> {
        if iface.is_empty() || iface.len() >= IFNAMSIZ || iface.contains('\0') {
            bail!("interface name {iface:?} is not a valid Linux interface name");
        }
        let mut name = Vec::with_capacity(IFNAMSIZ);
        name.extend_from_slice(iface.as_bytes());
        name.push(0);
        self.put(WGDEVICE_A_IFNAME, &name)
    }

    /// A reallocation would have left an unwiped copy of the bytes written so far.
    fn finish(self) -> Wiped {
        debug_assert_eq!(self.0 .0.capacity(), self.1, "a request buffer reallocated");
        self.0
    }
}

/// `wg set <iface> peer <key> [preshared-key ..] [allowed-ips <addr>/128]`.
fn set_peer_payload(u: &PeerUpdate<'_>) -> Result<Wiped> {
    let mut e = Encoder::new(WG_CMD_SET_DEVICE);
    e.ifname(u.iface)?;
    let peers = e.nest(WGDEVICE_A_PEERS);
    let peer = e.nest(0);
    e.put(WGPEER_A_PUBLIC_KEY, &u.key)?;
    if let Some(psk) = &u.psk {
        e.put(WGPEER_A_PRESHARED_KEY, psk)?;
    }
    if let Some(ip) = u.allowed_ip {
        e.put(WGPEER_A_FLAGS, &WGPEER_F_REPLACE_ALLOWEDIPS.to_ne_bytes())?;
        let ips = e.nest(WGPEER_A_ALLOWEDIPS);
        let one = e.nest(0);
        e.put(WGALLOWEDIP_A_FAMILY, &AF_INET6.to_ne_bytes())?;
        e.put(WGALLOWEDIP_A_IPADDR, &ip.octets())?;
        e.put(WGALLOWEDIP_A_CIDR_MASK, &[128])?;
        e.end(one)?;
        e.end(ips)?;
    }
    e.end(peer)?;
    e.end(peers)?;
    Ok(e.finish())
}

/// `wg set <iface> peer <key> remove`.
fn remove_peer_payload(iface: &str, key: &[u8; 32]) -> Result<Wiped> {
    let mut e = Encoder::new(WG_CMD_SET_DEVICE);
    e.ifname(iface)?;
    let peers = e.nest(WGDEVICE_A_PEERS);
    let peer = e.nest(0);
    e.put(WGPEER_A_PUBLIC_KEY, key)?;
    e.put(WGPEER_A_FLAGS, &WGPEER_F_REMOVE_ME.to_ne_bytes())?;
    e.end(peer)?;
    e.end(peers)?;
    Ok(e.finish())
}

/// `wg show <iface> peers`: GET_DEVICE by name.
fn get_device_payload(iface: &str) -> Result<Wiped> {
    let mut e = Encoder::new(WG_CMD_GET_DEVICE);
    e.ifname(iface)?;
    Ok(e.finish())
}

/// The netlink message of a request: NLM_F_REQUEST | NLM_F_ACK, plus NLM_F_DUMP for a dump.
fn message(family_id: u16, seq: u32, kind: Kind, payload: Wiped) -> Result<Nlmsghdr<u16, Wiped>> {
    let flags = match kind {
        Kind::Ack => NlmF::REQUEST | NlmF::ACK,
        Kind::Dump => NlmF::REQUEST | NlmF::ACK | NlmF::DUMP,
    };
    Ok(NlmsghdrBuilder::default()
        .nl_type(family_id)
        .nl_flags(flags)
        .nl_seq(seq)
        .nl_payload(NlPayload::Payload(payload))
        .build()?)
}

// ── Replies ───────────────────────────────────────────────────────────────────

/// Attributes of `buf` as (type without flags, value). A malformed length is an error.
fn attributes(mut buf: &[u8]) -> Result<Vec<(u16, &[u8])>> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        if buf.len() < 4 {
            bail!("truncated attribute header");
        }
        let len = u16::from_ne_bytes([buf[0], buf[1]]) as usize;
        let ty = u16::from_ne_bytes([buf[2], buf[3]]) & NLA_TYPE_MASK;
        if len < 4 || len > buf.len() {
            bail!("attribute length {len} out of range");
        }
        out.push((ty, &buf[4..len]));
        buf = &buf[((len + 3) & !3).min(buf.len())..];
    }
    Ok(out)
}

/// Add the public keys of one GET_DEVICE reply (generic netlink header and attributes) to
/// `keys`, skipping keys seen before: a peer can be split over several messages.
fn collect_peer_keys(payload: &[u8], keys: &mut Vec<[u8; 32]>, seen: &mut HashSet<[u8; 32]>) -> Result<()> {
    let attrs = payload.get(GENL_HDRLEN..).ok_or_else(|| anyhow!("short generic netlink message"))?;
    for (ty, peers) in attributes(attrs)? {
        if ty != WGDEVICE_A_PEERS {
            continue;
        }
        for (_, peer) in attributes(peers)? {
            for (pty, value) in attributes(peer)? {
                if pty == WGPEER_A_PUBLIC_KEY {
                    let key: [u8; 32] = value
                        .try_into()
                        .map_err(|_| anyhow!("peer public key of {} bytes", value.len()))?;
                    if seen.insert(key) {
                        keys.push(key);
                    }
                }
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Ack,
    Dump,
}

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Pending,
    Complete,
}

#[derive(Debug)]
enum Failure {
    /// The kernel answered with an errno; the socket is fine.
    Kernel { errno: i32, detail: Option<String> },
    /// Socket or parse error; the socket is dropped.
    Transport(anyhow::Error),
}

fn ext_ack_message(ext: &GenlBuffer<NlmsgerrAttr, Buffer>) -> Option<String> {
    ext.iter().find(|a| *a.nla_type().nla_type() == NlmsgerrAttr::Msg).map(|a| {
        String::from_utf8_lossy(a.payload().as_ref()).trim_end_matches('\0').to_string()
    })
}

/// The replies to one request, fed message by message.
struct Replies {
    kind: Kind,
    seq: u32,
    family_id: u16,
    keys: Vec<[u8; 32]>,
    seen: HashSet<[u8; 32]>,
    interrupted: bool,
}

impl Replies {
    fn new(kind: Kind, seq: u32, family_id: u16) -> Self {
        Replies { kind, seq, family_id, keys: Vec::new(), seen: HashSet::new(), interrupted: false }
    }

    fn feed(&mut self, m: &Nlmsghdr<u16, Wiped>) -> Result<Outcome, Failure> {
        if *m.nl_seq() != self.seq {
            return Ok(Outcome::Pending); // left over from an earlier request
        }
        let done = u16::from(Nlmsg::Done);
        match m.nl_payload() {
            NlPayload::Ack(_) => Ok(match self.kind {
                Kind::Ack => Outcome::Complete,
                Kind::Dump => Outcome::Pending,
            }),
            NlPayload::Err(e) => {
                Err(Failure::Kernel { errno: e.error().saturating_neg(), detail: ext_ack_message(e.ext_ack()) })
            }
            // NLMSG_DONE of a dump; it carries 0 or a negative errno.
            NlPayload::DumpExtAck(e) => match *e.error() {
                0 => Ok(Outcome::Complete),
                err => Err(Failure::Kernel { errno: err.saturating_neg(), detail: ext_ack_message(e.ext_ack()) }),
            },
            NlPayload::Empty if *m.nl_type() == done => Ok(Outcome::Complete),
            NlPayload::Empty => Ok(Outcome::Pending),
            NlPayload::Payload(p) if *m.nl_type() == done => {
                let err = p.0.get(..4).map_or(0, |b| i32::from_ne_bytes([b[0], b[1], b[2], b[3]]));
                if err < 0 {
                    Err(Failure::Kernel { errno: err.saturating_neg(), detail: None })
                } else {
                    Ok(Outcome::Complete)
                }
            }
            NlPayload::Payload(p) => {
                if self.kind == Kind::Dump && *m.nl_type() == self.family_id {
                    if m.nl_flags().contains(NlmF::DUMP_INTR) {
                        self.interrupted = true;
                    }
                    collect_peer_keys(&p.0, &mut self.keys, &mut self.seen).map_err(Failure::Transport)?;
                }
                Ok(Outcome::Pending)
            }
        }
    }
}

/// The error of a failed request: operation, interface and errno, never a key.
fn request_error(op: &str, iface: &str, failure: Failure) -> anyhow::Error {
    match failure {
        Failure::Kernel { errno, detail } => {
            let detail = detail.map(|d| format!(" ({d})")).unwrap_or_default();
            anyhow!("wireguard netlink {op} on {iface}: {}{detail}", std::io::Error::from_raw_os_error(errno))
        }
        Failure::Transport(e) => anyhow!("wireguard netlink {op} on {iface}: {e:#}"),
    }
}

// ── Transport ─────────────────────────────────────────────────────────────────

struct Conn {
    sock: NlSocketHandle,
    family_id: u16,
    seq: u32,
}

impl Conn {
    async fn open() -> Result<Conn> {
        let sock = NlSocketHandle::connect(NlFamily::Generic, None, Groups::empty())?;
        let family = crate::netlink::resolve_family_and_groups(&sock, WG_GENL_NAME).await?;
        match family.version {
            Some(v) if v == u32::from(WG_GENL_VERSION) => {}
            Some(v) => bail!("kernel family {WG_GENL_NAME} has version {v}, expected {WG_GENL_VERSION}"),
            None => bail!("kernel family {WG_GENL_NAME} reported no version"),
        }
        // Better error messages from the kernel's attribute validation; optional.
        let _ = sock.enable_ext_ack(true);
        Ok(Conn { sock, family_id: family.family_id, seq: 0 })
    }
}

/// Send one request and read until its replies are complete.
async fn exchange(slot: &mut Option<Conn>, payload: Wiped, kind: Kind) -> Result<Replies, Failure> {
    if slot.is_none() {
        *slot = Some(Conn::open().await.map_err(Failure::Transport)?);
    }
    let Some(conn) = slot.as_mut() else {
        return Err(Failure::Transport(anyhow!("no socket")));
    };
    conn.seq = conn.seq.wrapping_add(1);
    let msg = message(conn.family_id, conn.seq, kind, payload).map_err(Failure::Transport)?;
    let sent = conn.sock.send(&msg).await;
    drop(msg); // zeroes the request payload
    sent.map_err(|e| Failure::Transport(e.into()))?;
    let mut replies = Replies::new(kind, conn.seq, conn.family_id);
    loop {
        let (msgs, _) = conn.sock.recv::<u16, Wiped>().await.map_err(|e| Failure::Transport(e.into()))?;
        for m in msgs {
            let m = m.map_err(|e| Failure::Transport(e.into()))?;
            if replies.feed(&m)? == Outcome::Complete {
                return Ok(replies);
            }
        }
    }
}

/// [`PeerInstaller`] over WireGuard's generic netlink family.
pub struct WgNetlink {
    conn: Mutex<Option<Conn>>,
}

impl WgNetlink {
    pub fn new() -> Self {
        WgNetlink { conn: Mutex::new(None) }
    }

    async fn request(&self, op: &str, iface: &str, payload: Wiped, kind: Kind) -> Result<Replies> {
        let mut slot = self.conn.lock().await;
        let failure = match timeout(TOOL_TIMEOUT, exchange(&mut slot, payload, kind)).await {
            Ok(Ok(replies)) => return Ok(replies),
            Ok(Err(f @ Failure::Kernel { .. })) => f,
            Ok(Err(f @ Failure::Transport(_))) => {
                *slot = None;
                f
            }
            Err(_) => {
                *slot = None;
                Failure::Transport(anyhow!("no reply within {TOOL_TIMEOUT:?}"))
            }
        };
        Err(request_error(op, iface, failure))
    }
}

impl Default for WgNetlink {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerInstaller for WgNetlink {
    fn set_peer<'a>(&'a self, u: &'a PeerUpdate<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.request("set peer", u.iface, set_peer_payload(u)?, Kind::Ack).await.map(drop)
        })
    }

    fn remove_peer<'a>(&'a self, iface: &'a str, key: &'a [u8; 32]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.request("remove peer", iface, remove_peer_payload(iface, key)?, Kind::Ack).await.map(drop)
        })
    }

    fn list_peers<'a>(&'a self, iface: &'a str) -> BoxFuture<'a, Result<Vec<[u8; 32]>>> {
        Box::pin(async move {
            for _ in 0..DUMP_ATTEMPTS {
                let replies = self.request("list peers", iface, get_device_payload(iface)?, Kind::Dump).await?;
                if !replies.interrupted {
                    return Ok(replies.keys);
                }
            }
            bail!("wireguard netlink list peers on {iface}: dump interrupted {DUMP_ATTEMPTS} times")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use neli::FromBytes;
    use std::net::Ipv6Addr;

    /// Attribute header: length (without trailing padding) and type, host byte order.
    fn h(len: u16, ty: u16) -> Vec<u8> {
        [len.to_ne_bytes(), ty.to_ne_bytes()].concat()
    }

    fn addr() -> Ipv6Addr {
        "fd57:475a:4b00:0:f24:5b46:5b2e:4672".parse().expect("ip")
    }

    // ── Requests, byte for byte ──────────────────────────────────────────────

    #[test]
    fn gateway_set_with_psk() {
        let u = PeerUpdate { iface: "wg0", key: [0x11; 32], psk: Some([0x22; 32]), allowed_ip: Some(addr()) };
        let expected = [
            vec![1, 1, 0, 0],                         // SET_DEVICE, version 1
            h(8, 2), b"wg0\0".to_vec(),               // IFNAME
            h(132, 0x8008),                           // PEERS | NESTED
            h(128, 0x8000),                           //   peer 0 | NESTED
            h(36, 1), vec![0x11; 32],                 //     PUBLIC_KEY
            h(36, 2), vec![0x22; 32],                 //     PRESHARED_KEY
            h(8, 3), 2u32.to_ne_bytes().to_vec(),     //     FLAGS = REPLACE_ALLOWEDIPS
            h(44, 0x8009),                            //     ALLOWEDIPS | NESTED
            h(40, 0x8000),                            //       allowed IP 0 | NESTED
            h(6, 1), 10u16.to_ne_bytes().to_vec(), vec![0, 0], // FAMILY = AF_INET6, 2 padding
            h(20, 2), addr().octets().to_vec(),       //         IPADDR
            h(5, 3), vec![128, 0, 0, 0],              //         CIDR_MASK = 128, 3 padding
        ]
        .concat();
        assert_eq!(set_peer_payload(&u).expect("encode").0, expected);
    }

    #[test]
    fn gateway_set_without_psk() {
        let u = PeerUpdate { iface: "wg0", key: [0x11; 32], psk: None, allowed_ip: Some(addr()) };
        let expected = [
            vec![1, 1, 0, 0],
            h(8, 2), b"wg0\0".to_vec(),
            h(96, 0x8008),
            h(92, 0x8000),
            h(36, 1), vec![0x11; 32],
            h(8, 3), 2u32.to_ne_bytes().to_vec(),
            h(44, 0x8009),
            h(40, 0x8000),
            h(6, 1), 10u16.to_ne_bytes().to_vec(), vec![0, 0],
            h(20, 2), addr().octets().to_vec(),
            h(5, 3), vec![128, 0, 0, 0],
        ]
        .concat();
        assert_eq!(set_peer_payload(&u).expect("encode").0, expected);
    }

    #[test]
    fn client_psk_only_set() {
        // Interface name of 5 bytes: IFNAME is 10 bytes long, padded to 12.
        let u = PeerUpdate { iface: "wgzk1", key: [0x33; 32], psk: Some([0x44; 32]), allowed_ip: None };
        let expected = [
            vec![1, 1, 0, 0],
            h(10, 2), b"wgzk1\0".to_vec(), vec![0, 0],
            h(80, 0x8008),
            h(76, 0x8000),
            h(36, 1), vec![0x33; 32],
            h(36, 2), vec![0x44; 32],
            // no FLAGS, no ALLOWEDIPS, no ENDPOINT: they stay as they are
        ]
        .concat();
        assert_eq!(set_peer_payload(&u).expect("encode").0, expected);
    }

    #[test]
    fn remove() {
        let expected = [
            vec![1, 1, 0, 0],
            h(8, 2), b"wg0\0".to_vec(),
            h(52, 0x8008),
            h(48, 0x8000),
            h(36, 1), vec![0x55; 32],
            h(8, 3), 1u32.to_ne_bytes().to_vec(), // FLAGS = REMOVE_ME
        ]
        .concat();
        assert_eq!(remove_peer_payload("wg0", &[0x55; 32]).expect("encode").0, expected);
    }

    #[test]
    fn get_device_and_message_header() {
        let expected = [vec![0, 1, 0, 0], h(8, 2), b"wg0\0".to_vec()].concat();
        assert_eq!(get_device_payload("wg0").expect("encode").0, expected);

        // The whole netlink message as neli puts it on the wire.
        let msg = message(0x1d, 7, Kind::Dump, get_device_payload("wg0").expect("encode")).expect("message");
        let mut out = Cursor::new(Vec::new());
        msg.to_bytes(&mut out).expect("serialise");
        let header = [
            28u32.to_ne_bytes().to_vec(),     // nlmsg_len = 16 + 12
            0x1du16.to_ne_bytes().to_vec(),   // family id
            0x0305u16.to_ne_bytes().to_vec(), // REQUEST | ACK | DUMP
            7u32.to_ne_bytes().to_vec(),      // seq
            0u32.to_ne_bytes().to_vec(),      // pid
        ]
        .concat();
        assert_eq!(out.into_inner(), [header, expected].concat());

        let msg = message(0x1d, 8, Kind::Ack, remove_peer_payload("wg0", &[0x55; 32]).expect("encode")).expect("message");
        let mut out = Cursor::new(Vec::new());
        msg.to_bytes(&mut out).expect("serialise");
        let bytes = out.into_inner();
        assert_eq!(&bytes[..4], &(16u32 + 64).to_ne_bytes());
        assert_eq!(&bytes[6..8], &0x0005u16.to_ne_bytes(), "REQUEST | ACK");
    }

    #[test]
    fn interface_names_are_checked() {
        assert!(get_device_payload("").is_err());
        assert!(get_device_payload("a-name-of-16-chr").is_err(), "IFNAMSIZ - 1 is the limit");
        assert!(get_device_payload("wg\0x").is_err());
        assert!(get_device_payload("fifteen-chars-x").is_ok());
    }

    // ── Replies, from hand-built bytes ───────────────────────────────────────

    const FAMILY: u16 = 0x1d;

    fn attr(ty: u16, value: &[u8]) -> Vec<u8> {
        let mut v = h((4 + value.len()) as u16, ty);
        v.extend_from_slice(value);
        while !v.len().is_multiple_of(4) {
            v.push(0);
        }
        v
    }

    fn nest(ty: u16, children: &[Vec<u8>]) -> Vec<u8> {
        let body = children.concat();
        [h((4 + body.len()) as u16, ty | NLA_F_NESTED), body].concat()
    }

    fn nlmsg(ty: u16, flags: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut v = [
            ((16 + payload.len()) as u32).to_ne_bytes().to_vec(),
            ty.to_ne_bytes().to_vec(),
            flags.to_ne_bytes().to_vec(),
            seq.to_ne_bytes().to_vec(),
            0u32.to_ne_bytes().to_vec(),
        ]
        .concat();
        v.extend_from_slice(payload);
        while !v.len().is_multiple_of(4) {
            v.push(0);
        }
        v
    }

    /// A full peer as the kernel dumps it.
    fn peer(key: u8, ips: &[u8]) -> Vec<u8> {
        let allowed: Vec<Vec<u8>> = ips
            .iter()
            .map(|last| {
                let mut ip = [0u8; 16];
                ip[15] = *last;
                nest(0, &[attr(1, &AF_INET6.to_ne_bytes()), attr(2, &ip), attr(3, &[128])])
            })
            .collect();
        nest(
            0,
            &[
                attr(1, &[key; 32]),
                attr(2, &[0xee; 32]), // PRESHARED_KEY
                attr(6, &[0; 16]),    // LAST_HANDSHAKE_TIME
                attr(7, &0u64.to_ne_bytes()),
                attr(8, &0u64.to_ne_bytes()),
                attr(5, &0u16.to_ne_bytes()),
                nest(9, &allowed),
                attr(10, &1u32.to_ne_bytes()),
            ],
        )
    }

    /// A continuation of a split peer: only PUBLIC_KEY and ALLOWEDIPS.
    fn peer_rest(key: u8) -> Vec<u8> {
        nest(0, &[attr(1, &[key; 32]), nest(9, &[nest(0, &[attr(1, &AF_INET6.to_ne_bytes()), attr(2, &[9; 16]), attr(3, &[64])])])])
    }

    /// A GET_DEVICE reply message; `full` adds the device-level attributes of the first one.
    fn device(seq: u32, flags: u16, full: bool, peers: &[Vec<u8>]) -> Vec<u8> {
        let mut attrs = vec![];
        if full {
            attrs.push(attr(1, &5u32.to_ne_bytes())); // IFINDEX
        }
        attrs.push(attr(2, b"wg0\0"));
        if full {
            attrs.push(attr(3, &[0xaa; 32])); // PRIVATE_KEY
            attrs.push(attr(4, &[0xbb; 32])); // PUBLIC_KEY
            attrs.push(attr(6, &51820u16.to_ne_bytes()));
            attrs.push(attr(7, &0u32.to_ne_bytes()));
        }
        if !peers.is_empty() {
            attrs.push(nest(8, peers));
        }
        let payload = [vec![0, 1, 0, 0], attrs.concat()].concat();
        nlmsg(FAMILY, flags | 0x2, seq, &payload) // NLM_F_MULTI
    }

    fn done(seq: u32, err: i32) -> Vec<u8> {
        nlmsg(3, 0x2, seq, &err.to_ne_bytes())
    }

    /// Parse a byte stream of netlink messages as neli does and feed them in order.
    fn run(replies: &mut Replies, datagrams: &[Vec<u8>]) -> Result<Outcome, Failure> {
        let mut outcome = Outcome::Pending;
        for d in datagrams {
            let mut cur = Cursor::new(d.as_slice());
            while (cur.position() as usize) < d.len() {
                let m = Nlmsghdr::<u16, Wiped>::from_bytes(&mut cur).expect("netlink message");
                outcome = replies.feed(&m)?;
                if outcome == Outcome::Complete {
                    return Ok(outcome);
                }
            }
        }
        Ok(outcome)
    }

    fn keys(peers: &[u8]) -> Vec<[u8; 32]> {
        peers.iter().map(|k| [*k; 32]).collect()
    }

    #[test]
    fn dump_one_message() {
        let mut r = Replies::new(Kind::Dump, 4, FAMILY);
        let stream = [device(4, 0, true, &[peer(1, &[1, 2]), peer(2, &[3])]), done(4, 0)].concat();
        assert_eq!(run(&mut r, &[stream]).expect("dump"), Outcome::Complete);
        assert_eq!(r.keys, keys(&[1, 2]));
        assert!(!r.interrupted);
    }

    #[test]
    fn dump_several_messages() {
        let mut r = Replies::new(Kind::Dump, 4, FAMILY);
        let d1 = device(4, 0, true, &[peer(1, &[1]), peer(2, &[2])]);
        let d2 = device(4, 0, false, &[peer(3, &[3])]);
        assert_eq!(run(&mut r, &[d1, [d2, done(4, 0)].concat()]).expect("dump"), Outcome::Complete);
        assert_eq!(r.keys, keys(&[1, 2, 3]));
    }

    #[test]
    fn dump_peer_split_over_two_messages() {
        let mut r = Replies::new(Kind::Dump, 4, FAMILY);
        let d1 = device(4, 0, true, &[peer(1, &[1]), peer(2, &[2, 3, 4])]);
        let d2 = device(4, 0, false, &[peer_rest(2), peer(3, &[5])]);
        assert_eq!(run(&mut r, &[d1, d2, done(4, 0)]).expect("dump"), Outcome::Complete);
        assert_eq!(r.keys, keys(&[1, 2, 3]), "peer 2 counted once");
    }

    #[test]
    fn dump_zero_peers() {
        let mut r = Replies::new(Kind::Dump, 4, FAMILY);
        assert_eq!(run(&mut r, &[[device(4, 0, true, &[]), done(4, 0)].concat()]).expect("dump"), Outcome::Complete);
        assert!(r.keys.is_empty());
    }

    #[test]
    fn dump_interrupted_and_foreign_messages() {
        let mut r = Replies::new(Kind::Dump, 4, FAMILY);
        let stale = device(3, 0, true, &[peer(9, &[1])]); // other seq: ignored
        let intr = device(4, 0x10, true, &[peer(1, &[1])]); // NLM_F_DUMP_INTR
        assert_eq!(run(&mut r, &[stale, intr, done(4, 0)]).expect("dump"), Outcome::Complete);
        assert_eq!(r.keys, keys(&[1]));
        assert!(r.interrupted, "the caller repeats the dump");
    }

    #[test]
    fn dump_errors() {
        // NLMSG_DONE carrying a negative errno.
        let mut r = Replies::new(Kind::Dump, 4, FAMILY);
        match run(&mut r, &[done(4, -19)]) {
            Err(Failure::Kernel { errno: 19, .. }) => {}
            other => panic!("expected ENODEV, got {other:?}"),
        }
        // A malformed peer list is a transport error.
        let mut r = Replies::new(Kind::Dump, 4, FAMILY);
        let bad = nlmsg(FAMILY, 0x2, 4, &[vec![0, 1, 0, 0], h(8, 0x8008), h(40, 0x8000)].concat());
        assert!(matches!(run(&mut r, &[bad]), Err(Failure::Transport(_))));
    }

    /// NLMSG_ERROR answering the request `echo` (seq 8) with `err`, optionally with an
    /// extended-ACK message.
    fn error(err: i32, echo: &[u8], msg: Option<&str>) -> Vec<u8> {
        let mut payload = err.to_ne_bytes().to_vec();
        payload.extend_from_slice(echo);
        let mut flags = 0u16;
        if let Some(m) = msg {
            flags |= 0x200; // NLM_F_ACK_TLVS
            payload.extend(attr(1, format!("{m}\0").as_bytes())); // NLMSGERR_ATTR_MSG
        }
        if err == 0 {
            flags |= 0x100; // NLM_F_CAPPED: only the request header is echoed
        }
        nlmsg(2, flags, 8, &payload)
    }

    fn request_bytes() -> Vec<u8> {
        let u = PeerUpdate { iface: "wg0", key: [0x5a; 32], psk: Some([0x6b; 32]), allowed_ip: Some(addr()) };
        let msg = message(FAMILY, 8, Kind::Ack, set_peer_payload(&u).expect("encode")).expect("message");
        let mut out = Cursor::new(Vec::new());
        msg.to_bytes(&mut out).expect("serialise");
        out.into_inner()
    }

    #[test]
    fn errno_zero_is_success() {
        let mut r = Replies::new(Kind::Ack, 8, FAMILY);
        let ack = error(0, &request_bytes()[..16], None);
        assert_eq!(run(&mut r, &[ack]).expect("ack"), Outcome::Complete);
    }

    #[test]
    fn negative_errno_is_an_error_without_keys() {
        let req = request_bytes();
        let mut r = Replies::new(Kind::Ack, 8, FAMILY);
        let failure = match run(&mut r, &[error(-19, &req, None)]) {
            Err(f @ Failure::Kernel { errno: 19, .. }) => f,
            other => panic!("expected ENODEV, got {other:?}"),
        };
        let text = format!("{:#}", request_error("set peer", "wg0", failure));
        assert!(text.contains("set peer") && text.contains("wg0") && text.contains("No such device"), "{text}");
        for secret in [[0x5au8; 32], [0x6b; 32]] {
            assert!(!text.contains(&hex::encode(secret)));
            use base64::{engine::general_purpose::STANDARD, Engine as _};
            assert!(!text.contains(&STANDARD.encode(secret)));
        }

        // With an extended-ACK message from the kernel's attribute validation.
        let mut r = Replies::new(Kind::Ack, 8, FAMILY);
        let failure = match run(&mut r, &[error(-22, &req, Some("NLA_F_NESTED is missing"))]) {
            Err(f @ Failure::Kernel { errno: 22, .. }) => f,
            other => panic!("expected EINVAL, got {other:?}"),
        };
        let text = format!("{:#}", request_error("set peer", "wg0", failure));
        assert!(text.contains("Invalid argument") && text.contains("NLA_F_NESTED is missing"), "{text}");
    }

    #[test]
    fn replies_of_other_requests_are_ignored() {
        let mut r = Replies::new(Kind::Ack, 9, FAMILY);
        let ack_for_8 = error(0, &request_bytes()[..16], None);
        assert_eq!(run(&mut r, &[ack_for_8]).expect("ignored"), Outcome::Pending);
    }

    #[test]
    fn wiped_does_not_print_its_bytes() {
        let w = Wiped(vec![0x42; 8]);
        assert_eq!(format!("{w:?}"), "Wiped(8 bytes)");
    }
}
