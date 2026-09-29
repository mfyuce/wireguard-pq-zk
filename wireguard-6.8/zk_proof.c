// SPDX-License-Identifier: GPL-2.0
/*
 * wgzk: proofs handed down by the client daemon, waiting to be placed into
 * the next initiation towards a peer. See zk_proof.h.
 */

#include <linux/hashtable.h>
#include <linux/ktime.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>

#include "zk_pending.h"
#include "zk_proof.h"

#define ZK_PROOF_BITS 8

struct zk_proof_entry {
	u64 peer_id;
	u64 created_ns;
	u8 r[32];
	u8 s[32];
	u8 nonce[32];
	struct hlist_node node;
};

static DEFINE_HASHTABLE(zk_proof_table, ZK_PROOF_BITS);
static DEFINE_SPINLOCK(zk_proof_lock);

static void zk_proof_fill(struct zk_proof_entry *e, const u8 r[32],
			  const u8 s[32], const u8 nonce[32])
{
	memcpy(e->r, r, 32);
	memcpy(e->s, s, 32);
	memcpy(e->nonce, nonce, 32);
	e->created_ns = ktime_get_coarse_boottime_ns();
}

void zk_proof_set(u64 peer_id, const u8 r[32], const u8 s[32],
		  const u8 nonce[32])
{
	struct zk_proof_entry *e;
	unsigned long flags;

	spin_lock_irqsave(&zk_proof_lock, flags);
	hash_for_each_possible(zk_proof_table, e, node, peer_id) {
		if (e->peer_id == peer_id) {
			zk_proof_fill(e, r, s, nonce);
			goto out;
		}
	}
	e = kmalloc(sizeof(*e), GFP_ATOMIC);
	if (e) {
		e->peer_id = peer_id;
		zk_proof_fill(e, r, s, nonce);
		hash_add(zk_proof_table, &e->node, peer_id);
	}
out:
	spin_unlock_irqrestore(&zk_proof_lock, flags);
}

bool zk_proof_get_and_clear(u64 peer_id, u8 r[32], u8 s[32], u8 nonce[32])
{
	u64 max_age = (u64)READ_ONCE(wgzk_pending_timeout_ms) * NSEC_PER_MSEC;
	u64 now = ktime_get_coarse_boottime_ns();
	struct zk_proof_entry *e, *found = NULL;
	unsigned long flags;
	bool ok = false;

	spin_lock_irqsave(&zk_proof_lock, flags);
	hash_for_each_possible(zk_proof_table, e, node, peer_id) {
		if (e->peer_id == peer_id) {
			hash_del(&e->node);
			found = e;
			break;
		}
	}
	spin_unlock_irqrestore(&zk_proof_lock, flags);

	if (!found)
		return false;
	if ((s64)(now - found->created_ns) <= (s64)max_age) {
		memcpy(r, found->r, 32);
		memcpy(s, found->s, 32);
		memcpy(nonce, found->nonce, 32);
		ok = true;
	}
	kfree_sensitive(found);
	return ok;
}

void zk_proof_clear(u64 peer_id)
{
	struct zk_proof_entry *e, *found = NULL;
	unsigned long flags;

	spin_lock_irqsave(&zk_proof_lock, flags);
	hash_for_each_possible(zk_proof_table, e, node, peer_id) {
		if (e->peer_id == peer_id) {
			hash_del(&e->node);
			found = e;
			break;
		}
	}
	spin_unlock_irqrestore(&zk_proof_lock, flags);
	kfree_sensitive(found);
}

void zk_proof_exit(void)
{
	struct zk_proof_entry *e;
	struct hlist_node *tmp;
	unsigned long flags;
	HLIST_HEAD(gone);
	int bkt;

	spin_lock_irqsave(&zk_proof_lock, flags);
	hash_for_each_safe(zk_proof_table, bkt, tmp, e, node) {
		hash_del(&e->node);
		hlist_add_head(&e->node, &gone);
	}
	spin_unlock_irqrestore(&zk_proof_lock, flags);

	hlist_for_each_entry_safe(e, tmp, &gone, node) {
		hlist_del(&e->node);
		kfree_sensitive(e);
	}
}
