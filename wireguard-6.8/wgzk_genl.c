// SPDX-License-Identifier: GPL-2.0
/*
 * wgzk: generic netlink family between the kernel module and the daemon.
 * See wgzk_genl.h and docs/protocol-r1.md, sections 4 and 6.
 */

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/netlink.h>
#include <net/genetlink.h>
#include <net/rtnetlink.h>

#include "device.h"
#include "messages.h"
#include "noise.h"
#include "peer.h"
#include "queueing.h"
#include "socket.h"
#include "wgzk_genl.h"
#include "wgzk_stats.h"
#include "zk_pending.h"
#include "zk_proof.h"

static const struct nla_policy wgzk_genl_policy[WGZK_ATTR_MAX + 1] = {
	[WGZK_ATTR_PEER_INDEX]	  = { .type = NLA_U32 },
	[WGZK_ATTR_RESULT]	  = { .type = NLA_U8 },
	[WGZK_ATTR_PEER_ID]	  = { .type = NLA_U64 },
	[WGZK_ATTR_R]		  = NLA_POLICY_EXACT_LEN(32),
	[WGZK_ATTR_S]		  = NLA_POLICY_EXACT_LEN(32),
	[WGZK_ATTR_IFINDEX]	  = { .type = NLA_U32 },
	[WGZK_ATTR_PEER_PUB]	  = NLA_POLICY_EXACT_LEN(32),
	[WGZK_ATTR_TOKEN]	  = { .type = NLA_U32 },
	[WGZK_ATTR_SESSION_NONCE] = NLA_POLICY_EXACT_LEN(32),
	[WGZK_ATTR_PENDING_ID]	  = { .type = NLA_U64 },
	[WGZK_ATTR_LOCAL_PUB]	  = NLA_POLICY_EXACT_LEN(32),
};

enum { WGZK_MCGRP_EVENTS };
static const struct genl_multicast_group wgzk_mcgrps[] = {
	[WGZK_MCGRP_EVENTS] = { .name = "events" },
};

static struct genl_family wgzk_genl_family;

/* Returns the wgzk device with @ifindex in @net, with a reference on the
 * net_device, or NULL. An interface of another driver is refused.
 */
static struct wg_device *wgzk_device_get(struct net *net, u32 ifindex)
{
	struct net_device *dev = dev_get_by_index(net, ifindex);

	if (!dev)
		return NULL;
	if (!dev->rtnl_link_ops || !dev->rtnl_link_ops->kind ||
	    strcmp(dev->rtnl_link_ops->kind, KBUILD_MODNAME)) {
		dev_put(dev);
		return NULL;
	}
	return netdev_priv(dev);
}

/* SET_VERIFY{PENDING_ID, RESULT}: verdict on a deferred initiation. */
static int wgzk_set_verify(struct sk_buff *skb, struct genl_info *info)
{
	struct message_handshake_initiation *msg;
	struct zk_pending_entry *entry;
	struct wg_peer *peer;
	u64 pending_id;
	u8 result;

	if (!info->attrs[WGZK_ATTR_PENDING_ID] ||
	    !info->attrs[WGZK_ATTR_RESULT])
		return -EINVAL;

	pending_id = nla_get_u64(info->attrs[WGZK_ATTR_PENDING_ID]);
	result = nla_get_u8(info->attrs[WGZK_ATTR_RESULT]);

	entry = zk_pending_take(pending_id, genl_info_net(info));
	if (!entry) {
		wgzk_stat_inc(WGZK_STAT_LATE_VERDICT);
		return -ENOENT;
	}

	if (result != 1) {
		wgzk_stat_inc(WGZK_STAT_REJECTED);
		net_dbg_ratelimited("%s: wgzk: initiation %llu rejected\n",
				    entry->wg->dev->name, pending_id);
		goto out;
	}

	/* The stored packet passed the MAC check when it arrived. From here on
	 * it takes the ordinary WireGuard path: the static key must name a
	 * peer by now, the timestamp must be fresh, the rate limit applies.
	 */
	msg = (struct message_handshake_initiation *)&entry->raw;
	msg->header.type = cpu_to_le32(MESSAGE_HANDSHAKE_INITIATION);
	peer = wg_noise_handshake_consume_initiation(msg, entry->wg);
	if (unlikely(!peer)) {
		wgzk_stat_inc(WGZK_STAT_REFUSED_HANDSHAKE);
		net_dbg_ratelimited("%s: wgzk: initiation %llu accepted by the daemon but refused by the handshake\n",
				    entry->wg->dev->name, pending_id);
		goto out;
	}

	wgzk_stat_inc(WGZK_STAT_ACCEPTED);
	wg_packet_zk_initiation_accepted(peer, &entry->endpoint,
					 sizeof(entry->raw));
	wg_peer_put(peer);
out:
	zk_pending_free(entry);
	return 0;
}

/* SET_PROOF{PEER_ID, IFINDEX, R, S, SESSION_NONCE}: proof for the next
 * initiation towards a peer; the initiation is sent at once.
 */
static int wgzk_set_proof(struct sk_buff *skb, struct genl_info *info)
{
	struct wg_device *wg;
	struct wg_peer *peer;
	u64 peer_id;

	if (!info->attrs[WGZK_ATTR_PEER_ID] || !info->attrs[WGZK_ATTR_R] ||
	    !info->attrs[WGZK_ATTR_S] || !info->attrs[WGZK_ATTR_IFINDEX] ||
	    !info->attrs[WGZK_ATTR_SESSION_NONCE])
		return -EINVAL;

	wg = wgzk_device_get(genl_info_net(info),
			     nla_get_u32(info->attrs[WGZK_ATTR_IFINDEX]));
	if (!wg)
		return -ENODEV;

	peer_id = nla_get_u64(info->attrs[WGZK_ATTR_PEER_ID]);
	peer = wg_lookup_peer_by_internal_id(wg, peer_id);
	if (!peer) {
		dev_put(wg->dev);
		return -ENOENT;
	}

	zk_proof_set(peer_id, nla_data(info->attrs[WGZK_ATTR_R]),
		     nla_data(info->attrs[WGZK_ATTR_S]),
		     nla_data(info->attrs[WGZK_ATTR_SESSION_NONCE]));
	wgzk_stat_inc(WGZK_STAT_PROOFS_SET);
	wg_packet_send_queued_handshake_initiation(peer, true);

	wg_peer_put(peer);
	dev_put(wg->dev);
	return 0;
}

static const struct genl_ops wgzk_genl_ops[] = {
	{
		.cmd = WGZK_CMD_SET_VERIFY,
		.doit = wgzk_set_verify,
		.flags = GENL_UNS_ADMIN_PERM,
	},
	{
		.cmd = WGZK_CMD_SET_PROOF,
		.doit = wgzk_set_proof,
		.flags = GENL_UNS_ADMIN_PERM,
	},
};

static struct genl_family wgzk_genl_family __ro_after_init = {
	.name = WGZK_GENL_NAME,
	.version = WGZK_GENL_VERSION,
	.maxattr = WGZK_ATTR_MAX,
	.policy = wgzk_genl_policy,
	.module = THIS_MODULE,
	.netnsok = true,
	.ops = wgzk_genl_ops,
	.n_ops = ARRAY_SIZE(wgzk_genl_ops),
	.resv_start_op = WGZK_CMD_MAX + 1,
	.mcgrps = wgzk_mcgrps,
	.n_mcgrps = ARRAY_SIZE(wgzk_mcgrps),
};

int __init wgzk_genl_init(void)
{
	/* The stored initiation is handed to the WireGuard handshake as it
	 * is, and the proof travels to the daemon in attributes of 32 bytes.
	 */
	BUILD_BUG_ON(sizeof(struct message_handshake_initiation_zk) != 244);
	BUILD_BUG_ON(offsetof(struct message_handshake_initiation_zk, zk_r) !=
		     offsetof(struct message_handshake_initiation, macs));
	BUILD_BUG_ON(WGZK_PROOF_FIELD_LEN != 32);

	return genl_register_family(&wgzk_genl_family);
}

/* Not __exit: also called on the error path of module init. */
void wgzk_genl_exit(void)
{
	genl_unregister_family(&wgzk_genl_family);
}

static struct sk_buff *wgzk_event_new(u8 cmd, void **hdr)
{
	struct sk_buff *skb = genlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);

	if (!skb)
		return NULL;
	*hdr = genlmsg_put(skb, 0, 0, &wgzk_genl_family, 0, cmd);
	if (!*hdr) {
		nlmsg_free(skb);
		return NULL;
	}
	return skb;
}

/* Events go to the network namespace of the device and to no other. */
static void wgzk_event_send(struct net *net, struct sk_buff *skb, void *hdr)
{
	genlmsg_end(skb, hdr);
	genlmsg_multicast_netns(&wgzk_genl_family, net, skb, 0,
				WGZK_MCGRP_EVENTS, GFP_ATOMIC);
}

void wgzk_multicast_need_proof(struct net *net, u32 ifindex, u64 peer_id,
			       const u8 peer_pub[32], const u8 local_pub[32],
			       u32 token)
{
	struct sk_buff *skb;
	void *hdr;

	skb = wgzk_event_new(WGZK_CMD_NEED_PROOF, &hdr);
	if (!skb)
		return;

	if (nla_put_u32(skb, WGZK_ATTR_IFINDEX, ifindex) ||
	    nla_put_u64_64bit(skb, WGZK_ATTR_PEER_ID, peer_id,
			      WGZK_ATTR_UNSPEC) ||
	    nla_put(skb, WGZK_ATTR_PEER_PUB, 32, peer_pub) ||
	    nla_put(skb, WGZK_ATTR_LOCAL_PUB, 32, local_pub) ||
	    nla_put_u32(skb, WGZK_ATTR_TOKEN, token)) {
		nlmsg_free(skb);
		return;
	}
	wgzk_event_send(net, skb, hdr);
}

void wgzk_multicast_need_verify(struct net *net, u32 ifindex, u64 pending_id,
				u32 sender_index, const u8 peer_pub[32],
				const u8 local_pub[32], const u8 r[32],
				const u8 s[32], const u8 nonce[32])
{
	struct sk_buff *skb;
	void *hdr;

	skb = wgzk_event_new(WGZK_CMD_NEED_VERIFY, &hdr);
	if (!skb)
		return;

	if (nla_put_u32(skb, WGZK_ATTR_IFINDEX, ifindex) ||
	    nla_put_u64_64bit(skb, WGZK_ATTR_PENDING_ID, pending_id,
			      WGZK_ATTR_UNSPEC) ||
	    nla_put_u32(skb, WGZK_ATTR_PEER_INDEX, sender_index) ||
	    nla_put(skb, WGZK_ATTR_PEER_PUB, 32, peer_pub) ||
	    nla_put(skb, WGZK_ATTR_LOCAL_PUB, 32, local_pub) ||
	    nla_put(skb, WGZK_ATTR_R, 32, r) ||
	    nla_put(skb, WGZK_ATTR_S, 32, s) ||
	    nla_put(skb, WGZK_ATTR_SESSION_NONCE, 32, nonce)) {
		nlmsg_free(skb);
		return;
	}
	wgzk_event_send(net, skb, hdr);
}
