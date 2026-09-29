/* SPDX-License-Identifier: GPL-2.0 */
/*
 * wgzk: generic netlink family between the kernel module and the daemon.
 * Attribute and command numbers are fixed by docs/protocol-r1.md, section 4.
 */
#ifndef _WGZK_GENL_H
#define _WGZK_GENL_H

#include <linux/types.h>

struct net;

#define WGZK_GENL_NAME "wgzk"
#define WGZK_GENL_VERSION 2

enum {
	WGZK_ATTR_UNSPEC,
	WGZK_ATTR_PEER_INDEX,	 /* u32: sender index, informational */
	WGZK_ATTR_RESULT,	 /* u8: verdict, 1 accepts */
	WGZK_ATTR_PEER_ID,	 /* u64: kernel peer id, initiator side */
	WGZK_ATTR_R,		 /* bin[32]: commitment */
	WGZK_ATTR_S,		 /* bin[32]: response */
	WGZK_ATTR_IFINDEX,	 /* u32 */
	WGZK_ATTR_PEER_PUB,	 /* bin[32]: static public key of the remote party */
	WGZK_ATTR_TOKEN,	 /* u32: correlation token */
	WGZK_ATTR_SESSION_NONCE, /* bin[32] */
	WGZK_ATTR_PENDING_ID,	 /* u64: id of a deferred initiation */
	WGZK_ATTR_LOCAL_PUB,	 /* bin[32]: static public key of this interface */
	__WGZK_ATTR_MAX,
};

#define WGZK_ATTR_MAX (__WGZK_ATTR_MAX - 1)

enum {
	WGZK_CMD_UNSPEC,
	WGZK_CMD_RESERVED_1,  /* was VERIFY, removed in version 2 */
	WGZK_CMD_SET_PROOF,   /* daemon -> kernel */
	WGZK_CMD_NEED_PROOF,  /* kernel -> daemon, multicast */
	WGZK_CMD_SET_VERIFY,  /* daemon -> kernel */
	WGZK_CMD_NEED_VERIFY, /* kernel -> daemon, multicast */
	__WGZK_CMD_MAX,
};

#define WGZK_CMD_MAX (__WGZK_CMD_MAX - 1)

int wgzk_genl_init(void);
void wgzk_genl_exit(void);

/* Initiator side: ask the daemon for a proof. @peer_pub is the static key of
 * the gateway, @local_pub the static key of this interface.
 */
void wgzk_multicast_need_proof(struct net *net, u32 ifindex, u64 peer_id,
			       const u8 peer_pub[32], const u8 local_pub[32],
			       u32 token);

/* Responder side: ask the daemon for a verdict on a deferred initiation.
 * @peer_pub is the static key that the initiation carried, @local_pub the
 * static key of this interface.
 */
void wgzk_multicast_need_verify(struct net *net, u32 ifindex, u64 pending_id,
				u32 sender_index, const u8 peer_pub[32],
				const u8 local_pub[32], const u8 r[32],
				const u8 s[32], const u8 nonce[32]);

#endif /* _WGZK_GENL_H */
