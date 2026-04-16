use anyhow::Context;
use neli::attr::Attribute;
use neli::genl::Nlattr;
use neli::consts::genl::CtrlCmd;
use neli::nl::{Nlmsghdr, NlmsghdrBuilder};
use neli::socket::asynchronous::NlSocketHandle;
use neli::{
    consts::{
        genl::CtrlAttr, // only needed if you parse ctrl replies elsewhere
        nl::{GenlId, NlmF},
        socket::NlFamily,
    },
    genl::{AttrType, Genlmsghdr, GenlmsghdrBuilder, NlattrBuilder},
    nl::NlPayload
    ,
    types::{Buffer, GenlBuffer},
    utils::Groups,
};


use neli::consts::{
    genl::CtrlAttrMcastGrp,
};
use anyhow::{anyhow,  Result};
use std::collections::HashMap;

pub const WGZK_FAMILY: &str = "wgzk";
pub const MC_GROUP_NAME: &str = "events";

#[repr(u8)]
#[derive(Copy, Clone)]
pub enum WgzkCmd {
    Unspec = 0,
    Verify = 1,
    SetProof = 2,
    NeedProof = 3,
    SetVerify = 4,     // new: userspace → kernel result for verify
    NeedVerify = 5,    // new: kernel → userspace ask to verify
}
// pub const WGZK_CMD_NEED_PROOF: u8 = 1;
// pub const WGZK_CMD_SET_PROOF:  u8 = 2;
#[repr(u16)]
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub enum WgzkAttr {
    Unspec        = 0,
    PeerIndex     = 1, // u32
    Result        = 2, // u8
    PeerId        = 3, // u64
    R             = 4, // [u8;32]
    S             = 5, // [u8;32]
    Ifindex       = 6, // u32
    PeerPub       = 7, // [u8;32]
    Token         = 8, // u32
    SessionNonce  = 9, // [u8;32] — Schnorr++ transcript nonce
}
impl From<u16> for WgzkAttr {
    fn from(v: u16) -> Self {
        match v {
            1 => WgzkAttr::PeerIndex,
            2 => WgzkAttr::Result,
            3 => WgzkAttr::PeerId,
            4 => WgzkAttr::R,
            5 => WgzkAttr::S,
            6 => WgzkAttr::Ifindex,
            7 => WgzkAttr::PeerPub,
            8 => WgzkAttr::Token,
            9 => WgzkAttr::SessionNonce,
            _ => WgzkAttr::Unspec,
        }
    }
}
// attr ids must match the kernel
const ATTR_PEER_INDEX: u16 = 1; // (for VERIFY only)
const ATTR_RESULT:     u16 = 2; // (for VERIFY only)
const ATTR_PEER_ID:    u16 = 3; // u64
const ATTR_R:          u16 = 4; // [32]
const ATTR_S:          u16 = 5; // [32]
const ATTR_IFINDEX:    u16 = 6; // u32
// const ATTR_PEER_PUB: u16 = 7; // optional
// const ATTR_TOKEN:    u16 = 8; // server/VERIFY path

pub struct GenlResolved {
    pub family_id: u16,
    pub mcast_groups: HashMap<String, u32>,
}

/* ---------------- helpers ---------------- */

fn nattr_ctrl(t: CtrlAttr, payload: Vec<u8>) -> Result<Nlattr<CtrlAttr, Buffer>> {
    Ok(NlattrBuilder::<CtrlAttr, Buffer>::default()
        .nla_type(AttrType::from(u16::from(t)))
        .nla_payload(Buffer::from(payload))
        .build()?)
}

fn nattr_u16(t: u16, payload: Vec<u8>) -> Result<Nlattr<u16, Buffer>> {
    Ok(NlattrBuilder::<u16, Buffer>::default()
        .nla_type(AttrType::from(t))
        .nla_payload(Buffer::from(payload))
        .build()?)
}

/* ---------------- connect / resolve ---------------- */

pub async fn connect_genl() -> Result<NlSocketHandle> {
    Ok(NlSocketHandle::connect(NlFamily::Generic, None, Groups::empty())?)
}

pub async fn add_mcast(sock: &NlSocketHandle, grp_id: u32) -> Result<()> {
    eprintln!("[wgzk] subscribing to multicast group id={}", grp_id);
    if grp_id == 0 {
        return Err(anyhow!("multicast group id is 0 — family may not be registered"));
    }
    sock.add_mcast_membership(Groups::new_groups(&[grp_id]))?;
    Ok(())
}
/// Parse a buffer of netlink attributes into (type, payload) pairs.
/// Handles 4-byte alignment padding per nla_align().
fn parse_nla_pairs(buf: &[u8]) -> Vec<(u16, &[u8])> {
    let mut res = Vec::new();
    let mut off = 0usize;

    while off + 4 <= buf.len() {
        // header
        let len = u16::from_le_bytes([buf[off], buf[off + 1]]) as usize;
        let typ = u16::from_le_bytes([buf[off + 2], buf[off + 3]]);
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

pub async fn resolve_family_and_groups(
    sock: &mut NlSocketHandle,
    name: &str,
) -> Result<GenlResolved> {
    // GenlBuffer<CtrlAttr, Buffer>
    let mut attrs: GenlBuffer<CtrlAttr, Buffer> = GenlBuffer::new();

    // NUL-terminated family name ("wgzk\0")
    let mut namez = Vec::with_capacity(name.len() + 1);
    namez.extend_from_slice(name.as_bytes());
    namez.push(0);

    attrs.push(nattr_ctrl(CtrlAttr::FamilyName, namez)?);
    //attrs.push(Nlattr::new(None, CtrlAttr::FamilyName, Buffer::from(namez))?);

    // CTRL_CMD_GETFAMILY v2 + ACK
    let genlhdr = GenlmsghdrBuilder::default()
        .cmd(CtrlCmd::Getfamily)
        .version(2)
        .attrs(attrs)
        .build()?;
    let req: Nlmsghdr<GenlId, Genlmsghdr<CtrlCmd, CtrlAttr>> = NlmsghdrBuilder::default()
        .nl_type(GenlId::Ctrl)
        .nl_flags(NlmF::REQUEST )
        .nl_payload(NlPayload::Payload(genlhdr))
        .build()?;

    sock.send(&req).await.context("send GETFAMILY")?;

    // ---- parse responses
    let mut family_id: Option<u16> = None;
    let mut groups = std::collections::HashMap::new();

    loop {
        let (iter, _grps) = sock
            .recv::<neli::consts::nl::NlTypeWrapper, neli::genl::Genlmsghdr<CtrlCmd, CtrlAttr>>()
            .await?;

        for msg in iter {
            let msg = msg?;                           // Nlmsghdr<_, _>
            let nlw = *msg.nl_type();                 // NlTypeWrapper (copy out of &)
            let nl_u16: u16 = nlw.into();             // -> u16

            // If you prefer matching Nlmsg tag:
            // match neli::consts::nl::Nlmsg::from(nl_u16) {
            //     neli::consts::nl::Nlmsg::Error => continue, // or handle error frame
            //     _ => {}
            // }

            if nl_u16 != GenlId::Ctrl.into() {
                continue;
            }

            if let neli::nl::NlPayload::Payload(genl) = msg.nl_payload() {
                for attr in genl.attrs().iter() {
                    let atype = *attr.nla_type().nla_type();

                    if atype == CtrlAttr::from(u16::from(CtrlAttr::FamilyId)) {
                        let b = attr.payload();
                        let slice = b.as_ref();
                        if slice.len() < 2 {
                            eprintln!("[wgzk] CTRL_ATTR_FAMILY_ID payload too short: {} bytes", slice.len());
                            continue;
                        }
                        let bytes: [u8; 2] = [slice[0], slice[1]];
                        family_id = Some(u16::from_le_bytes(bytes));
                    } else if atype == CtrlAttr::from(u16::from(CtrlAttr::McastGroups)) {
                        // The payload is a nested list of "group" attributes, each of which
                        // itself contains nested Name/Id attributes.
                        let level1 = parse_nla_pairs(attr.payload().as_ref());
                        for (_grp_type, grp_payload) in level1 {
                            // Each group payload has Name/Id inside
                            let level2 = parse_nla_pairs(grp_payload);

                            let mut name: Option<String> = None;
                            let mut id: Option<u32> = None;

                            for (t, p) in level2 {
                                if t == u16::from(CtrlAttrMcastGrp::Name) {
                                    // Name is a C-string; kernel usually includes trailing NUL, but
                                    // String::from_utf8 will happily ignore if we don't trim it.
                                    // Trim a single trailing NUL if present.
                                    let mut v = p.to_vec();
                                    if let Some(&0) = v.last() { v.pop(); }
                                    name = Some(String::from_utf8(v)?);
                                } else if t == u16::from(CtrlAttrMcastGrp::Id) {
                                    if p.len() >= 4 {
                                        if let Ok(bytes) = <[u8; 4]>::try_from(&p[..4]) {
                                            id = Some(u32::from_le_bytes(bytes));
                                        }
                                    }
                                }
                            }

                            if let (Some(n), Some(i)) = (name, id) {
                                groups.insert(n, i);
                            }
                        }
                    }
                }
            }
        }

        if family_id.is_some() {
            eprintln!( "[daemon] Family id found" );
            break;
        }
    }


    Ok(GenlResolved {
        family_id: family_id.ok_or_else(|| anyhow!("family id not found for {}", name))?,
        mcast_groups: groups,
    })
}

/* ---------------- senders (Buffer + builders + ACK) ---------------- */

pub async fn send_set_proof(
    sock: &mut NlSocketHandle,
    family_id: u16,
    peer_id: u64,
    token: Option<u32>,
    r: &[u8; 32],
    s: &[u8; 32],
    ifindex: u32,
    session_nonce: &[u8; 32],
) -> Result<()> {
    let mut attrs: GenlBuffer<u16, Buffer> = GenlBuffer::new();
    attrs.push(nattr_u16(WgzkAttr::PeerId as u16, peer_id.to_le_bytes().to_vec())?);
    if let Some(t) = token {
        attrs.push(nattr_u16(WgzkAttr::Token as u16, t.to_le_bytes().to_vec())?);
    }
    attrs.push(nattr_u16(WgzkAttr::R as u16, r.to_vec())?);
    attrs.push(nattr_u16(WgzkAttr::S as u16, s.to_vec())?);
    attrs.push(nattr_u16(WgzkAttr::Ifindex as u16, ifindex.to_le_bytes().to_vec())?);
    // Schnorr++: include session nonce for transcript binding
    attrs.push(nattr_u16(WgzkAttr::SessionNonce as u16, session_nonce.to_vec())?);


    let genlhdr = GenlmsghdrBuilder::default()
        .cmd(WgzkCmd::SetProof as u8)
        .version(1)
        .attrs(attrs)
        .build()?;

    let req: Nlmsghdr<u16, Genlmsghdr<u8, u16>> = NlmsghdrBuilder::default()
        .nl_type(family_id) // generic T = u16
        .nl_flags(NlmF::REQUEST | NlmF::ACK)
        .nl_payload(NlPayload::Payload(genlhdr))
        .build()?;

    sock.send(&req).await?;
    // Fire-and-forget: don't wait for ACK. If the kernel drops this SET_PROOF,
    // it will re-emit NEED_PROOF on the next handshake attempt.
    Ok(())
}
/* ---------------- server: NEED_VERIFY event ---------------- */
pub struct NeedVerifyEvent {
    pub ifindex: u32,
    pub sender_index: u32,
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub token: Option<u32>,
    pub session_nonce: [u8; 32], // Schnorr++: transcript nonce from ZK packet
}

pub fn try_parse_need_verify(genl: &Genlmsghdr<u8, u16>) -> Option<NeedVerifyEvent> {
    if *genl.cmd() != WgzkCmd::NeedVerify as u8 { return None; }
    let mut ifindex: Option<u32> = None;
    let mut sender_index: Option<u32> = None;
    let mut r: Option<[u8; 32]> = None;
    let mut s: Option<[u8; 32]> = None;
    let mut token: Option<u32> = None;
    let mut session_nonce: Option<[u8; 32]> = None;
    for a in genl.attrs().iter() {
        match WgzkAttr::from(*a.nla_type().nla_type()) {
            WgzkAttr::Ifindex => {
                let b = a.payload(); let bytes: [u8;4] = b.as_ref().try_into().ok()?;
                ifindex = Some(u32::from_le_bytes(bytes));
            }
            WgzkAttr::PeerIndex => {
                let b = a.payload(); let bytes: [u8;4] = b.as_ref().try_into().ok()?;
                sender_index = Some(u32::from_le_bytes(bytes));
            }
            WgzkAttr::R => {
                let p = a.payload();
                if p.as_ref().len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(p.as_ref());
                    r = Some(arr);
                }
            }
            WgzkAttr::S => {
                let p = a.payload();
                if p.as_ref().len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(p.as_ref());
                    s = Some(arr);
                }
            }
            WgzkAttr::Token => {
                let b = a.payload(); let bytes: [u8;4] = b.as_ref().try_into().ok()?;
                token = Some(u32::from_le_bytes(bytes));
            }
            WgzkAttr::SessionNonce => {
                let p = a.payload();
                if p.as_ref().len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(p.as_ref());
                    session_nonce = Some(arr);
                }
            }
            _ => {}
        }
    }
    let session_nonce = match session_nonce {
        Some(n) => n,
        None => {
            eprintln!("[wgzk] NEED_VERIFY missing session_nonce attribute; dropping");
            return None;
        }
    };
    Some(NeedVerifyEvent {
        ifindex: ifindex?,
        sender_index: sender_index?,
        r: r?,
        s: s?,
        token,
        session_nonce,
    })
}
pub async fn send_verify(
    sock: &mut NlSocketHandle,
    family_id: u16,
    sender_index: u32,
    result: u8,
) -> Result<()> {
    let mut attrs: GenlBuffer<u16, Buffer> = GenlBuffer::new();
    attrs.push(nattr_u16(WgzkAttr::PeerIndex as u16, sender_index.to_le_bytes().to_vec())?);
    attrs.push(nattr_u16(WgzkAttr::Result as u16, vec![result])?);

    let genlhdr = GenlmsghdrBuilder::default()
        .cmd(WgzkCmd::Verify as u8)
        .version(1)
        .attrs(attrs)
        .build()?;
    let req: Nlmsghdr<u16, Genlmsghdr<u8, u16>> = NlmsghdrBuilder::default()
        .nl_type(family_id) // generic T = u16
        .nl_flags(NlmF::REQUEST | NlmF::ACK)
        .nl_payload(NlPayload::Payload(genlhdr))
        .build()?;

    sock.send(&req).await?;
    Ok(())
}

/// New: SET_VERIFY mirrors VERIFY payload (PeerIndex, Result) but uses a
/// distinct command so kernel can track the “userspace verify” path.
pub async fn send_set_verify(
    sock: &mut NlSocketHandle,
    family_id: u16,
    sender_index: u32,
    result: u8,
) -> Result<()> {
    let mut attrs: GenlBuffer<u16, Buffer> = GenlBuffer::new();
    attrs.push(nattr_u16(WgzkAttr::PeerIndex as u16, sender_index.to_le_bytes().to_vec())?);
    attrs.push(nattr_u16(WgzkAttr::Result as u16, vec![result])?);
    let genlhdr = GenlmsghdrBuilder::default()
        .cmd(WgzkCmd::SetVerify as u8)
        .version(1)
        .attrs(attrs)
        .build()?;
    let req: Nlmsghdr<u16, Genlmsghdr<u8, u16>> = NlmsghdrBuilder::default()
        .nl_type(family_id)
        .nl_flags(NlmF::REQUEST | NlmF::ACK)
        .nl_payload(NlPayload::Payload(genlhdr))
        .build()?;
    sock.send(&req).await?;
    Ok(())
}
/* ---------------- receiver ---------------- */

pub struct NeedProofEvent {
    pub ifindex: u32,
    pub peer_id: u64,
    pub peer_pub: Option<[u8; 32]>,
    pub token: Option<u32>,
    // session_nonce is generated by the daemon (not by kernel), so not parsed from NEED_PROOF
}

pub fn try_parse_need_proof(genl: &Genlmsghdr<u8, u16>) -> Option<NeedProofEvent> {
    if *genl.cmd() != WgzkCmd::NeedProof as u8 {
        eprintln!( "[daemon] not need proof" );
        return None;
    }
    let mut ifindex: Option<u32> = None;
    let mut peer_id: Option<u64> = None;
    let mut peer_pub: Option<[u8; 32]> = None;
    let mut token: Option<u32> = None;

    for a in genl.attrs().iter() {
        eprintln!( "[daemon] recevied sth" );
        match WgzkAttr::from(*a.nla_type().nla_type()) {
            WgzkAttr::Ifindex => {
                eprintln!( "[daemon] recevied ifindex" );
                let b = a.payload();
                let bytes: [u8; 4] = b.as_ref().try_into().ok()?;
                ifindex = Some(u32::from_le_bytes(bytes));
            }
            WgzkAttr::PeerId => {
                eprintln!( "[daemon] recevied PeerId" );
                let b = a.payload();
                let bytes: [u8; 8] = b.as_ref().try_into().ok()?;
                peer_id = Some(u64::from_le_bytes(bytes));
            }
            WgzkAttr::PeerPub => {
                eprintln!( "[daemon] recevied PeerPub" );
                let p = a.payload();
                let s = p.as_ref();
                if s.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(s);
                    peer_pub = Some(arr);
                }
            }
            WgzkAttr::Token => {
                eprintln!( "[daemon] recevied Token" );
                let b = a.payload();
                let bytes: [u8; 4] = b.as_ref().try_into().ok()?;
                token = Some(u32::from_le_bytes(bytes));
            }
            _ => {
                eprintln!( "[daemon] recevied other" );}
        }
    }

    Some(NeedProofEvent {
        ifindex: ifindex?,
        peer_id: peer_id?,
        peer_pub,
        token,
    })
}

pub async fn recv_next(
    sock: &mut neli::socket::asynchronous::NlSocketHandle,
) -> anyhow::Result<(u16, neli::genl::Genlmsghdr<u8, u16>)> {
    use neli::{consts::nl::NlTypeWrapper, nl::NlPayload};

    loop {
        let (iter, _groups) = sock.recv::<NlTypeWrapper, Genlmsghdr<u8, u16>>().await?;

        for msg in iter {
            let msg = msg?;
            let nl_u16: u16 = (*msg.nl_type()).into();

            match msg.nl_payload() {
                NlPayload::Ack(_) => {
                    // ACK from one of our REQUEST|ACK sends — ignore and keep waiting
                    continue;
                }
                NlPayload::Err(e) => {
                    eprintln!("[daemon] netlink error: {}", e);
                    // Treat as non-fatal: log and continue listening
                    continue;
                }
                NlPayload::Payload(g) => {
                    return Ok((nl_u16, g.clone()));
                }
                _ => continue,
            }
        }
        // Iterator exhausted without a payload — loop back and recv again
    }
}

