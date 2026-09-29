//! Generic netlink family `wgzk`, version 2 (`docs/protocol-r1.md`, Section 4).
//!
//! Kernel to daemon, multicast group `events`:
//!   NEED_PROOF  (3): IFINDEX, PEER_ID, PEER_PUB (= S_gw), LOCAL_PUB (= S_c), TOKEN
//!   NEED_VERIFY (5): IFINDEX, PENDING_ID, PEER_INDEX, PEER_PUB (= S_c), LOCAL_PUB (= S_gw),
//!                    R, S, SESSION_NONCE
//! Daemon to kernel:
//!   SET_PROOF   (2): PEER_ID, IFINDEX, R, S, SESSION_NONCE, optional TOKEN
//!   SET_VERIFY  (4): PENDING_ID, RESULT
//!
//! Command 1 (legacy VERIFY) no longer exists. The parsers return an error naming the first
//! attribute that is missing, duplicated or of the wrong length; the caller drops the event.
//! TOKEN is optional in NEED_PROOF, every attribute of NEED_VERIFY is required. Unknown
//! attribute ids are ignored. Integers are in host byte order, as everywhere in netlink.
//!
//! Each role uses two sockets: one joined to `events` that only receives
//! ([`connect_events`], [`recv_events`]), and one owned by a single sender task that takes
//! requests from an mpsc channel ([`run_sender`]). Requests go out without NLM_F_ACK; the
//! kernel reports failures anyway, and the sender task logs them. Both sockets refuse to
//! work with a kernel whose family version is not 2.

use anyhow::{anyhow, bail, Context, Result};
use neli::{
    attr::Attribute,
    consts::{
        genl::{CtrlAttr, CtrlAttrMcastGrp, CtrlCmd},
        nl::{GenlId, NlTypeWrapper, NlmF, NlmsgerrAttr},
        socket::NlFamily,
    },
    err::SocketError,
    genl::{AttrType, Genlmsghdr, GenlmsghdrBuilder, Nlattr, NlattrBuilder},
    nl::{NlPayload, Nlmsghdr, NlmsghdrBuilder},
    socket::asynchronous::NlSocketHandle,
    types::{Buffer, GenlBuffer},
    utils::Groups,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout, Duration};

pub const WGZK_FAMILY: &str = "wgzk";
pub const MC_GROUP_NAME: &str = "events";
/// Family version this daemon implements.
pub const WGZK_VERSION: u8 = 2;

const RETRY: Duration = Duration::from_secs(1);
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(2);
/// Receive buffer requested for the event socket (the kernel caps it at rmem_max).
const EVENT_RCVBUF: usize = 1 << 20;

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WgzkCmd {
    SetProof = 2,
    NeedProof = 3,
    SetVerify = 4,
    NeedVerify = 5,
}

#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WgzkAttr {
    PeerIndex = 1,    // u32
    Result = 2,       // u8
    PeerId = 3,       // u64
    R = 4,            // [u8; 32]
    S = 5,            // [u8; 32]
    Ifindex = 6,      // u32
    PeerPub = 7,      // [u8; 32]
    Token = 8,        // u32
    SessionNonce = 9, // [u8; 32]
    PendingId = 10,   // u64
    LocalPub = 11,    // [u8; 32]
}

impl WgzkAttr {
    const ALL: [WgzkAttr; 11] = [
        WgzkAttr::PeerIndex,
        WgzkAttr::Result,
        WgzkAttr::PeerId,
        WgzkAttr::R,
        WgzkAttr::S,
        WgzkAttr::Ifindex,
        WgzkAttr::PeerPub,
        WgzkAttr::Token,
        WgzkAttr::SessionNonce,
        WgzkAttr::PendingId,
        WgzkAttr::LocalPub,
    ];

    fn from_id(id: u16) -> Option<WgzkAttr> {
        Self::ALL.iter().copied().find(|a| *a as u16 == id)
    }

    pub fn name(self) -> &'static str {
        match self {
            WgzkAttr::PeerIndex => "PEER_INDEX",
            WgzkAttr::Result => "RESULT",
            WgzkAttr::PeerId => "PEER_ID",
            WgzkAttr::R => "R",
            WgzkAttr::S => "S",
            WgzkAttr::Ifindex => "IFINDEX",
            WgzkAttr::PeerPub => "PEER_PUB",
            WgzkAttr::Token => "TOKEN",
            WgzkAttr::SessionNonce => "SESSION_NONCE",
            WgzkAttr::PendingId => "PENDING_ID",
            WgzkAttr::LocalPub => "LOCAL_PUB",
        }
    }
}

/* ---------------- event parsing ---------------- */

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    WrongCommand(u8),
    Missing(WgzkAttr),
    BadLength(WgzkAttr, usize),
    Duplicate(WgzkAttr),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::WrongCommand(c) => write!(f, "unexpected command {c}"),
            ParseError::Missing(a) => write!(f, "missing attribute {}", a.name()),
            ParseError::BadLength(a, n) => write!(f, "attribute {} has length {n}", a.name()),
            ParseError::Duplicate(a) => write!(f, "attribute {} appears twice", a.name()),
        }
    }
}

/// The wgzk attributes of one message, by id.
struct Attrs<'a> {
    slots: [Option<&'a [u8]>; 12],
}

impl<'a> Attrs<'a> {
    fn collect(genl: &'a Genlmsghdr<u8, u16>) -> Result<Self, ParseError> {
        let mut slots: [Option<&'a [u8]>; 12] = [None; 12];
        for a in genl.attrs().iter() {
            let Some(id) = WgzkAttr::from_id(*a.nla_type().nla_type()) else { continue };
            let slot = &mut slots[id as usize];
            if slot.is_some() {
                return Err(ParseError::Duplicate(id));
            }
            *slot = Some(a.payload().as_ref());
        }
        Ok(Attrs { slots })
    }

    fn get(&self, id: WgzkAttr) -> Option<&'a [u8]> {
        self.slots[id as usize]
    }

    fn fixed<const N: usize>(&self, id: WgzkAttr) -> Result<[u8; N], ParseError> {
        let b = self.get(id).ok_or(ParseError::Missing(id))?;
        b.try_into().map_err(|_| ParseError::BadLength(id, b.len()))
    }

    fn u32(&self, id: WgzkAttr) -> Result<u32, ParseError> {
        self.fixed::<4>(id).map(u32::from_ne_bytes)
    }

    fn u64(&self, id: WgzkAttr) -> Result<u64, ParseError> {
        self.fixed::<8>(id).map(u64::from_ne_bytes)
    }

    fn opt_u32(&self, id: WgzkAttr) -> Result<Option<u32>, ParseError> {
        match self.get(id) {
            None => Ok(None),
            Some(_) => self.u32(id).map(Some),
        }
    }
}

/// NEED_PROOF: the kernel of a client asks for a proof for one initiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeedProofEvent {
    pub ifindex: u32,
    pub peer_id: u64,
    /// Static public key of the gateway peer, `S_gw`.
    pub peer_pub: [u8; 32],
    /// Static public key of the local interface, the session key `S_c`.
    pub local_pub: [u8; 32],
    pub token: Option<u32>,
}

pub fn parse_need_proof(genl: &Genlmsghdr<u8, u16>) -> Result<NeedProofEvent, ParseError> {
    if *genl.cmd() != WgzkCmd::NeedProof as u8 {
        return Err(ParseError::WrongCommand(*genl.cmd()));
    }
    let a = Attrs::collect(genl)?;
    Ok(NeedProofEvent {
        ifindex: a.u32(WgzkAttr::Ifindex)?,
        peer_id: a.u64(WgzkAttr::PeerId)?,
        peer_pub: a.fixed(WgzkAttr::PeerPub)?,
        local_pub: a.fixed(WgzkAttr::LocalPub)?,
        token: a.opt_u32(WgzkAttr::Token)?,
    })
}

/// NEED_VERIFY: the kernel of the gateway deferred an initiation under `pending_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeedVerifyEvent {
    pub ifindex: u32,
    pub pending_id: u64,
    pub peer_index: u32,
    /// Decrypted static key of the initiator, the session key `S_c`.
    pub peer_pub: [u8; 32],
    /// Static public key of the local interface, `S_gw`.
    pub local_pub: [u8; 32],
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub session_nonce: [u8; 32],
}

pub fn parse_need_verify(genl: &Genlmsghdr<u8, u16>) -> Result<NeedVerifyEvent, ParseError> {
    if *genl.cmd() != WgzkCmd::NeedVerify as u8 {
        return Err(ParseError::WrongCommand(*genl.cmd()));
    }
    let a = Attrs::collect(genl)?;
    Ok(NeedVerifyEvent {
        ifindex: a.u32(WgzkAttr::Ifindex)?,
        pending_id: a.u64(WgzkAttr::PendingId)?,
        peer_index: a.u32(WgzkAttr::PeerIndex)?,
        peer_pub: a.fixed(WgzkAttr::PeerPub)?,
        local_pub: a.fixed(WgzkAttr::LocalPub)?,
        r: a.fixed(WgzkAttr::R)?,
        s: a.fixed(WgzkAttr::S)?,
        session_nonce: a.fixed(WgzkAttr::SessionNonce)?,
    })
}

/* ---------------- requests ---------------- */

/// SET_PROOF: the proof for one NEED_PROOF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetProof {
    pub peer_id: u64,
    pub ifindex: u32,
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub session_nonce: [u8; 32],
    pub token: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    SetProof(SetProof),
    /// SET_VERIFY: verdict for a deferred initiation, 1 accept, 0 reject.
    SetVerify { pending_id: u64, result: u8 },
}

fn nattr(t: WgzkAttr, payload: Vec<u8>) -> Result<Nlattr<u16, Buffer>> {
    Ok(NlattrBuilder::<u16, Buffer>::default()
        .nla_type(AttrType::from(t as u16))
        .nla_payload(Buffer::from(payload))
        .build()?)
}

impl Request {
    fn cmd(&self) -> WgzkCmd {
        match self {
            Request::SetProof(_) => WgzkCmd::SetProof,
            Request::SetVerify { .. } => WgzkCmd::SetVerify,
        }
    }

    /// Generic netlink payload of the request.
    pub fn to_genl(&self) -> Result<Genlmsghdr<u8, u16>> {
        let mut attrs: GenlBuffer<u16, Buffer> = GenlBuffer::new();
        match self {
            Request::SetProof(p) => {
                attrs.push(nattr(WgzkAttr::PeerId, p.peer_id.to_ne_bytes().to_vec())?);
                attrs.push(nattr(WgzkAttr::Ifindex, p.ifindex.to_ne_bytes().to_vec())?);
                attrs.push(nattr(WgzkAttr::R, p.r.to_vec())?);
                attrs.push(nattr(WgzkAttr::S, p.s.to_vec())?);
                attrs.push(nattr(WgzkAttr::SessionNonce, p.session_nonce.to_vec())?);
                if let Some(t) = p.token {
                    attrs.push(nattr(WgzkAttr::Token, t.to_ne_bytes().to_vec())?);
                }
            }
            Request::SetVerify { pending_id, result } => {
                attrs.push(nattr(WgzkAttr::PendingId, pending_id.to_ne_bytes().to_vec())?);
                attrs.push(nattr(WgzkAttr::Result, vec![*result])?);
            }
        }
        Ok(GenlmsghdrBuilder::default()
            .cmd(self.cmd() as u8)
            .version(WGZK_VERSION)
            .attrs(attrs)
            .build()?)
    }
}

async fn send_request(sock: &NlSocketHandle, family_id: u16, seq: u32, req: &Request) -> Result<()> {
    let msg: Nlmsghdr<u16, Genlmsghdr<u8, u16>> = NlmsghdrBuilder::default()
        .nl_type(family_id)
        .nl_flags(NlmF::REQUEST)
        .nl_seq(seq)
        .nl_payload(NlPayload::Payload(req.to_genl()?))
        .build()?;
    sock.send(&msg).await?;
    Ok(())
}

/// Short description of a request echoed in a kernel error, for the log.
fn describe_echoed(genl: &Genlmsghdr<u8, u16>) -> String {
    let what = match *genl.cmd() {
        c if c == WgzkCmd::SetProof as u8 => "SET_PROOF",
        c if c == WgzkCmd::SetVerify as u8 => "SET_VERIFY",
        _ => "request",
    };
    match Attrs::collect(genl) {
        Ok(a) => match (a.u64(WgzkAttr::PendingId), a.u32(WgzkAttr::Token)) {
            (Ok(id), _) => format!("{what} pending_id={id}"),
            (_, Ok(t)) => format!("{what} token={t}"),
            _ => what.to_string(),
        },
        Err(_) => what.to_string(),
    }
}

fn log_reply(tag: &str, msg: &Nlmsghdr<NlTypeWrapper, Genlmsghdr<u8, u16>>) {
    if let NlPayload::Err(e) = msg.nl_payload() {
        let detail = e
            .ext_ack()
            .iter()
            .find(|a| *a.nla_type().nla_type() == NlmsgerrAttr::Msg)
            .map(|a| {
                let s = String::from_utf8_lossy(a.payload().as_ref()).trim_end_matches('\0').to_string();
                format!(" ({s})")
            })
            .unwrap_or_default();
        eprintln!(
            "[{tag}] kernel rejected {}: {}{detail}",
            describe_echoed(e.nlmsg().nl_payload()),
            std::io::Error::from_raw_os_error(-*e.error()),
        );
    }
}

/// The one task that sends requests to the kernel (SET_PROOF on a client, SET_VERIFY on a
/// gateway). Owns its netlink socket, reconnects after errors, returns when every sender of
/// the channel is gone. A request that cannot be sent is lost; the kernel entry it answers
/// then times out, which rejects the handshake.
pub async fn run_sender(mut rx: mpsc::Receiver<Request>, tag: &'static str) {
    loop {
        let (sock, resolved) = match connect_family().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[{tag}] netlink sender: {e:#} (retrying in 1s)");
                sleep(RETRY).await;
                continue;
            }
        };
        if let Err(e) = sock.enable_ext_ack(true) {
            eprintln!("[{tag}] netlink sender: extended ACK unavailable: {e}");
        }
        let family_id = resolved.family_id;
        let mut seq: u32 = 0;
        let err = loop {
            tokio::select! {
                req = rx.recv() => {
                    let Some(req) = req else { return };
                    seq = seq.wrapping_add(1);
                    if let Err(e) = send_request(&sock, family_id, seq, &req).await {
                        break anyhow!("send {:?}: {e:#}", req.cmd());
                    }
                }
                reply = sock.recv::<NlTypeWrapper, Genlmsghdr<u8, u16>>() => {
                    match reply {
                        Ok((msgs, _)) => {
                            for m in msgs {
                                match m {
                                    Ok(m) => log_reply(tag, &m),
                                    Err(e) => eprintln!("[{tag}] unparseable netlink reply: {e}"),
                                }
                            }
                        }
                        Err(e) => break anyhow!("receive: {e}"),
                    }
                }
            }
        };
        eprintln!("[{tag}] netlink sender: {err:#} (reconnecting in 1s)");
        sleep(RETRY).await;
    }
}

/* ---------------- connect / resolve ---------------- */

pub struct GenlResolved {
    pub family_id: u16,
    pub version: Option<u32>,
    pub mcast_groups: HashMap<String, u32>,
}

/// Parse a buffer of netlink attributes into (type, payload) pairs.
/// Handles 4-byte alignment padding per nla_align().
fn parse_nla_pairs(buf: &[u8]) -> Vec<(u16, &[u8])> {
    let mut res = Vec::new();
    let mut off = 0usize;

    while off + 4 <= buf.len() {
        // header
        let len = u16::from_ne_bytes([buf[off], buf[off + 1]]) as usize;
        let typ = u16::from_ne_bytes([buf[off + 2], buf[off + 3]]);
        if len < 4 || off + len > buf.len() {
            break; // malformed or truncated, bail gracefully
        }

        // payload = [off+4 .. off+len)
        let payload = &buf[off + 4..off + len];
        res.push((typ, payload));

        // align to 4
        let aligned = (len + 3) & !3;
        off += aligned;
    }

    res
}

fn nattr_ctrl(t: CtrlAttr, payload: Vec<u8>) -> Result<Nlattr<CtrlAttr, Buffer>> {
    Ok(NlattrBuilder::<CtrlAttr, Buffer>::default()
        .nla_type(AttrType::from(u16::from(t)))
        .nla_payload(Buffer::from(payload))
        .build()?)
}

/// CTRL_CMD_GETFAMILY: family id, version and multicast groups of `name`.
pub async fn resolve_family_and_groups(sock: &NlSocketHandle, name: &str) -> Result<GenlResolved> {
    let mut attrs: GenlBuffer<CtrlAttr, Buffer> = GenlBuffer::new();
    // NUL-terminated family name ("wgzk\0")
    let mut namez = Vec::with_capacity(name.len() + 1);
    namez.extend_from_slice(name.as_bytes());
    namez.push(0);
    attrs.push(nattr_ctrl(CtrlAttr::FamilyName, namez)?);

    let genlhdr = GenlmsghdrBuilder::default()
        .cmd(CtrlCmd::Getfamily)
        .version(2)
        .attrs(attrs)
        .build()?;
    let req: Nlmsghdr<GenlId, Genlmsghdr<CtrlCmd, CtrlAttr>> = NlmsghdrBuilder::default()
        .nl_type(GenlId::Ctrl)
        .nl_flags(NlmF::REQUEST)
        .nl_payload(NlPayload::Payload(genlhdr))
        .build()?;
    sock.send(&req).await.context("send GETFAMILY")?;

    loop {
        let (iter, _grps) = sock.recv::<NlTypeWrapper, Genlmsghdr<CtrlCmd, CtrlAttr>>().await?;
        for msg in iter {
            let msg = msg?;
            let genl = match msg.nl_payload() {
                NlPayload::Err(e) => bail!(
                    "GETFAMILY {name}: {} (is the module loaded?)",
                    std::io::Error::from_raw_os_error(-*e.error())
                ),
                NlPayload::Payload(genl) if u16::from(*msg.nl_type()) == u16::from(GenlId::Ctrl) => genl,
                _ => continue,
            };
            let mut family_id: Option<u16> = None;
            let mut version: Option<u32> = None;
            let mut groups = HashMap::new();
            for attr in genl.attrs().iter() {
                let atype = *attr.nla_type().nla_type();
                let p = attr.payload().as_ref();
                if atype == CtrlAttr::FamilyId {
                    family_id = <[u8; 2]>::try_from(p).ok().map(u16::from_ne_bytes);
                } else if atype == CtrlAttr::Version {
                    version = <[u8; 4]>::try_from(p).ok().map(u32::from_ne_bytes);
                } else if atype == CtrlAttr::McastGroups {
                    // Nested list of groups, each with nested Name/Id attributes.
                    for (_grp_type, grp_payload) in parse_nla_pairs(p) {
                        let mut gname: Option<String> = None;
                        let mut gid: Option<u32> = None;
                        for (t, v) in parse_nla_pairs(grp_payload) {
                            if t == u16::from(CtrlAttrMcastGrp::Name) {
                                // C string; drop the trailing NUL if present.
                                let v = v.strip_suffix(&[0]).unwrap_or(v);
                                gname = String::from_utf8(v.to_vec()).ok();
                            } else if t == u16::from(CtrlAttrMcastGrp::Id) {
                                gid = <[u8; 4]>::try_from(v).ok().map(u32::from_ne_bytes);
                            }
                        }
                        if let (Some(n), Some(i)) = (gname, gid) {
                            groups.insert(n, i);
                        }
                    }
                }
            }
            if let Some(family_id) = family_id {
                return Ok(GenlResolved { family_id, version, mcast_groups: groups });
            }
        }
    }
}

/// Connect a generic netlink socket and resolve the wgzk family; refuses any version but 2.
async fn connect_family() -> Result<(NlSocketHandle, GenlResolved)> {
    let sock = NlSocketHandle::connect(NlFamily::Generic, None, Groups::empty())?;
    let resolved = timeout(RESOLVE_TIMEOUT, resolve_family_and_groups(&sock, WGZK_FAMILY))
        .await
        .map_err(|_| anyhow!("GETFAMILY {WGZK_FAMILY}: no reply"))??;
    match resolved.version {
        Some(v) if v == u32::from(WGZK_VERSION) => Ok((sock, resolved)),
        Some(v) => bail!(
            "kernel family {WGZK_FAMILY} has version {v}; this daemon implements version {WGZK_VERSION}"
        ),
        None => bail!("kernel family {WGZK_FAMILY} reported no version"),
    }
}

/// Socket joined to the `events` group. Returns the socket and the family id.
pub async fn connect_events() -> Result<(NlSocketHandle, u16)> {
    let (sock, resolved) = connect_family().await?;
    let gid = *resolved
        .mcast_groups
        .get(MC_GROUP_NAME)
        .ok_or_else(|| anyhow!("{WGZK_FAMILY}: '{MC_GROUP_NAME}' multicast group missing"))?;
    if gid == 0 {
        bail!("multicast group id is 0 — family may not be registered");
    }
    sock.add_mcast_membership(Groups::new_groups(&[gid]))?;
    if let Err(e) = sock.set_recv_buffer_size(EVENT_RCVBUF) {
        eprintln!("[netlink] could not enlarge the event socket buffer: {e}");
    }
    Ok((sock, resolved.family_id))
}

/// Next batch of wgzk messages from the event socket (usually one). A receive-buffer
/// overrun loses events; it is logged and the socket stays usable. Other errors are
/// returned so that the caller reconnects.
pub async fn recv_events(sock: &NlSocketHandle, family_id: u16) -> Result<Vec<Genlmsghdr<u8, u16>>> {
    loop {
        let (iter, _groups) = match sock.recv::<NlTypeWrapper, Genlmsghdr<u8, u16>>().await {
            Ok(v) => v,
            Err(SocketError::Io(e)) if e.raw_os_error() == Some(libc::ENOBUFS) => {
                eprintln!("[netlink] event socket overrun: events were lost");
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::new();
        for msg in iter {
            let msg = match msg {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("[netlink] unparseable event: {e}");
                    continue;
                }
            };
            if u16::from(*msg.nl_type()) != family_id {
                continue;
            }
            if let NlPayload::Payload(g) = msg.nl_payload() {
                out.push(g.clone());
            }
        }
        if !out.is_empty() {
            return Ok(out);
        }
    }
}

/* ---------------- interface filter ---------------- */

/// Index of the interface `name` in the current network namespace, if it exists.
pub fn ifindex_of(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: `c` is a valid NUL-terminated string that outlives the call;
    // if_nametoindex(3) only reads it.
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    (idx != 0).then_some(idx)
}

/// Accepts only events of one interface (`WG_IFACE`). Events are multicast to every wgzk
/// listener of the namespace; a daemon must not answer for an interface it does not serve.
/// The index is resolved lazily and again on a mismatch, so a recreated interface is found.
pub struct IfaceFilter {
    name: String,
    cached: AtomicU32,
}

impl IfaceFilter {
    pub fn new(name: &str) -> Self {
        IfaceFilter { name: name.to_string(), cached: AtomicU32::new(ifindex_of(name).unwrap_or(0)) }
    }

    pub fn matches(&self, ifindex: u32) -> bool {
        if ifindex != 0 && self.cached.load(Ordering::Relaxed) == ifindex {
            return true;
        }
        let now = ifindex_of(&self.name).unwrap_or(0);
        self.cached.store(now, Ordering::Relaxed);
        now != 0 && now == ifindex
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn genl(cmd: u8, attrs: &[(u16, Vec<u8>)]) -> Genlmsghdr<u8, u16> {
        let mut buf: GenlBuffer<u16, Buffer> = GenlBuffer::new();
        for (t, p) in attrs {
            buf.push(
                NlattrBuilder::<u16, Buffer>::default()
                    .nla_type(AttrType::from(*t))
                    .nla_payload(Buffer::from(p.clone()))
                    .build()
                    .expect("attr"),
            );
        }
        GenlmsghdrBuilder::default().cmd(cmd).version(WGZK_VERSION).attrs(buf).build().expect("genl")
    }

    fn need_verify_attrs() -> Vec<(u16, Vec<u8>)> {
        vec![
            (WgzkAttr::Ifindex as u16, 7u32.to_ne_bytes().to_vec()),
            (WgzkAttr::PendingId as u16, 0x1122_3344_5566_7788u64.to_ne_bytes().to_vec()),
            (WgzkAttr::PeerIndex as u16, 99u32.to_ne_bytes().to_vec()),
            (WgzkAttr::PeerPub as u16, vec![0xc1; 32]),
            (WgzkAttr::LocalPub as u16, vec![0x9a; 32]),
            (WgzkAttr::R as u16, vec![0x01; 32]),
            (WgzkAttr::S as u16, vec![0x02; 32]),
            (WgzkAttr::SessionNonce as u16, vec![0x03; 32]),
        ]
    }

    #[test]
    fn need_verify_parses_all_eight() {
        let ev = parse_need_verify(&genl(WgzkCmd::NeedVerify as u8, &need_verify_attrs())).expect("parse");
        assert_eq!(
            ev,
            NeedVerifyEvent {
                ifindex: 7,
                pending_id: 0x1122_3344_5566_7788,
                peer_index: 99,
                peer_pub: [0xc1; 32],
                local_pub: [0x9a; 32],
                r: [0x01; 32],
                s: [0x02; 32],
                session_nonce: [0x03; 32],
            }
        );
    }

    #[test]
    fn need_verify_names_each_missing_attribute() {
        let all = need_verify_attrs();
        for i in 0..all.len() {
            let mut attrs = all.clone();
            let (missing, _) = attrs.remove(i);
            let err = parse_need_verify(&genl(WgzkCmd::NeedVerify as u8, &attrs)).expect_err("must fail");
            let expected = WgzkAttr::from_id(missing).expect("known id");
            assert_eq!(err, ParseError::Missing(expected));
            assert!(err.to_string().contains(expected.name()), "log names the attribute: {err}");
        }
    }

    #[test]
    fn need_verify_rejects_bad_length_and_duplicates() {
        let mut attrs = need_verify_attrs();
        attrs[5].1.pop(); // R: 31 bytes
        let err = parse_need_verify(&genl(WgzkCmd::NeedVerify as u8, &attrs)).expect_err("short R");
        assert_eq!(err, ParseError::BadLength(WgzkAttr::R, 31));

        let mut attrs = need_verify_attrs();
        attrs.push((WgzkAttr::SessionNonce as u16, vec![0x04; 32]));
        let err = parse_need_verify(&genl(WgzkCmd::NeedVerify as u8, &attrs)).expect_err("duplicate");
        assert_eq!(err, ParseError::Duplicate(WgzkAttr::SessionNonce));
    }

    #[test]
    fn unknown_attributes_are_ignored() {
        let mut attrs = need_verify_attrs();
        attrs.push((12, vec![0; 4])); // e.g. a padding attribute
        attrs.push((200, vec![1, 2, 3]));
        assert!(parse_need_verify(&genl(WgzkCmd::NeedVerify as u8, &attrs)).is_ok());
        let err = parse_need_verify(&genl(WgzkCmd::NeedProof as u8, &attrs)).expect_err("wrong cmd");
        assert_eq!(err, ParseError::WrongCommand(WgzkCmd::NeedProof as u8));
    }

    #[test]
    fn need_proof_requires_both_keys_token_optional() {
        let base = vec![
            (WgzkAttr::Ifindex as u16, 3u32.to_ne_bytes().to_vec()),
            (WgzkAttr::PeerId as u16, 5u64.to_ne_bytes().to_vec()),
            (WgzkAttr::PeerPub as u16, vec![0x9a; 32]),
            (WgzkAttr::LocalPub as u16, vec![0xc1; 32]),
        ];
        let ev = parse_need_proof(&genl(WgzkCmd::NeedProof as u8, &base)).expect("no token");
        assert_eq!(ev.token, None);
        assert_eq!((ev.peer_pub, ev.local_pub), ([0x9a; 32], [0xc1; 32]));

        let mut with_token = base.clone();
        with_token.push((WgzkAttr::Token as u16, 77u32.to_ne_bytes().to_vec()));
        let ev = parse_need_proof(&genl(WgzkCmd::NeedProof as u8, &with_token)).expect("token");
        assert_eq!((ev.ifindex, ev.peer_id, ev.token), (3, 5, Some(77)));

        for (drop_id, name) in [(WgzkAttr::PeerPub, "PEER_PUB"), (WgzkAttr::LocalPub, "LOCAL_PUB")] {
            let attrs: Vec<_> = base.iter().filter(|(t, _)| *t != drop_id as u16).cloned().collect();
            let err = parse_need_proof(&genl(WgzkCmd::NeedProof as u8, &attrs)).expect_err("required");
            assert!(err.to_string().contains(name));
        }
    }

    fn attr_map(g: &Genlmsghdr<u8, u16>) -> HashMap<u16, Vec<u8>> {
        g.attrs().iter().map(|a| (*a.nla_type().nla_type(), a.payload().as_ref().to_vec())).collect()
    }

    #[test]
    fn set_verify_carries_pending_id_and_result_only() {
        let g = Request::SetVerify { pending_id: 0xdead_beef_0000_0001, result: 1 }.to_genl().expect("genl");
        assert_eq!(*g.cmd(), 4);
        assert_eq!(*g.version(), 2);
        let m = attr_map(&g);
        assert_eq!(m.len(), 2);
        assert_eq!(m[&10], 0xdead_beef_0000_0001u64.to_ne_bytes().to_vec());
        assert_eq!(m[&2], vec![1]);
    }

    #[test]
    fn set_proof_attributes() {
        let p = SetProof {
            peer_id: 42,
            ifindex: 6,
            r: [0x04; 32],
            s: [0x05; 32],
            session_nonce: [0x09; 32],
            token: Some(1234),
        };
        let g = Request::SetProof(p.clone()).to_genl().expect("genl");
        assert_eq!((*g.cmd(), *g.version()), (2, 2));
        let m = attr_map(&g);
        assert_eq!(m.len(), 6);
        assert_eq!(m[&3], 42u64.to_ne_bytes().to_vec());
        assert_eq!(m[&6], 6u32.to_ne_bytes().to_vec());
        assert_eq!(m[&4], vec![0x04; 32]);
        assert_eq!(m[&5], vec![0x05; 32]);
        assert_eq!(m[&9], vec![0x09; 32]);
        assert_eq!(m[&8], 1234u32.to_ne_bytes().to_vec());

        let g = Request::SetProof(SetProof { token: None, ..p }).to_genl().expect("genl");
        assert!(!attr_map(&g).contains_key(&8), "TOKEN only when known");
    }

    /// A NEED_VERIFY as the kernel lays it out: nlmsghdr, genlmsghdr, then attributes
    /// padded to 4 bytes (so the u64 PENDING_ID is only 4-byte aligned).
    #[test]
    fn need_verify_from_wire_bytes() {
        use neli::FromBytes;
        let family_id: u16 = 0x1f;
        let mut attrs = Vec::new();
        for (t, p) in need_verify_attrs() {
            attrs.extend_from_slice(&((4 + p.len()) as u16).to_ne_bytes());
            attrs.extend_from_slice(&t.to_ne_bytes());
            attrs.extend_from_slice(&p);
            while attrs.len() % 4 != 0 {
                attrs.push(0);
            }
        }
        let mut msg = Vec::new();
        msg.extend_from_slice(&((16 + 4 + attrs.len()) as u32).to_ne_bytes());
        msg.extend_from_slice(&family_id.to_ne_bytes());
        msg.extend_from_slice(&0u16.to_ne_bytes()); // flags
        msg.extend_from_slice(&0u32.to_ne_bytes()); // seq
        msg.extend_from_slice(&0u32.to_ne_bytes()); // pid
        msg.extend_from_slice(&[WgzkCmd::NeedVerify as u8, WGZK_VERSION, 0, 0]);
        msg.extend_from_slice(&attrs);

        let parsed = Nlmsghdr::<NlTypeWrapper, Genlmsghdr<u8, u16>>::from_bytes(&mut std::io::Cursor::new(&msg))
            .expect("netlink message");
        assert_eq!(u16::from(*parsed.nl_type()), family_id);
        let NlPayload::Payload(g) = parsed.nl_payload() else { panic!("payload expected") };
        let ev = parse_need_verify(g).expect("parse");
        assert_eq!(ev.pending_id, 0x1122_3344_5566_7788);
        assert_eq!((ev.ifindex, ev.peer_index), (7, 99));
        assert_eq!((ev.peer_pub, ev.local_pub, ev.session_nonce), ([0xc1; 32], [0x9a; 32], [0x03; 32]));
    }

    #[test]
    fn filter_rejects_unknown_interface() {
        let f = IfaceFilter::new("wgzk-test-no-such-if0");
        assert!(!f.matches(0));
        assert!(!f.matches(1));
        // The loopback interface exists in every namespace.
        if let Some(lo) = ifindex_of("lo") {
            let f = IfaceFilter::new("lo");
            assert!(f.matches(lo));
            assert!(!f.matches(lo + 1000));
        }
    }
}
