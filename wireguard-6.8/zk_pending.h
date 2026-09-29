/* SPDX-License-Identifier: GPL-2.0 */
/*
 * wgzk: table of initiations that wait for a verdict from user space.
 *
 * An entry is created when a type 0xA1 initiation has passed the MAC check
 * and its static field has been decrypted. It holds a copy of the packet and
 * nothing else of the handshake: no peer, no keys. The verdict handler
 * re-consumes the stored packet through the ordinary WireGuard path.
 *
 * Entries are found by a kernel-assigned id. The sender index of the packet
 * is chosen by the remote side and is therefore not used for lookups.
 */
#ifndef ZK_PENDING_H
#define ZK_PENDING_H

#include <linux/types.h>
#include <linux/hashtable.h>
#include <linux/seq_file.h>
#include "messages.h"
#include "peer.h"

struct wg_device;
struct net;

struct zk_pending_entry {
	u64 id;
	u32 sender_index; /* informational only */
	struct wg_device *wg; /* holds a reference on wg->dev */
	struct message_handshake_initiation_zk raw;
	struct endpoint endpoint;
	u64 created_ns;
	struct hlist_node node;
};

/* Module parameters, defined in zk_pending.c. */
extern unsigned int wgzk_pending_max;
extern unsigned int wgzk_pending_timeout_ms;

int zk_pending_get_count(void);

/* Stores a copy of @msg. Returns 0 and the new id in @id, -ENOSPC if the table
 * is full, -ENOMEM on allocation failure.
 */
int zk_pending_add(struct wg_device *wg,
		   const struct message_handshake_initiation_zk *msg,
		   const struct endpoint *ep, u64 *id);

/* Removes and returns the entry with @id if it belongs to a device in @net and
 * has not expired. The caller owns the entry and must release it with
 * zk_pending_free().
 */
struct zk_pending_entry *zk_pending_take(u64 id, const struct net *net);

void zk_pending_free(struct zk_pending_entry *entry);

/* Drops every entry of @wg. Called when the device goes down. */
void zk_pending_flush_device(const struct wg_device *wg);

void zk_pending_init(void);
void zk_pending_exit(void);

int zk_pending_seq_show(struct seq_file *m, void *v);

#endif /* ZK_PENDING_H */
