// SPDX-License-Identifier: GPL-2.0
/*
 * wgzk: table of initiations that wait for a verdict from user space.
 * See zk_pending.h and docs/protocol-r1.md, sections 6 and 7.
 */

#include <linux/atomic.h>
#include <linux/hashtable.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <net/net_namespace.h>

#include "device.h"
#include "wgzk_stats.h"
#include "zk_pending.h"

#define ZK_HASH_BITS 8

unsigned int wgzk_pending_max = 1024;
module_param_named(pending_max, wgzk_pending_max, uint, 0644);
MODULE_PARM_DESC(pending_max,
		 "wgzk: initiations that may wait for a verdict at one time");

unsigned int wgzk_pending_timeout_ms = 5000;
module_param_named(pending_timeout_ms, wgzk_pending_timeout_ms, uint, 0644);
MODULE_PARM_DESC(pending_timeout_ms,
		 "wgzk: how long an initiation waits for a verdict");

static DEFINE_HASHTABLE(zk_pending_table, ZK_HASH_BITS);
static DEFINE_SPINLOCK(zk_lock);
static atomic_t zk_pending_count = ATOMIC_INIT(0);
static atomic64_t zk_pending_next_id = ATOMIC64_INIT(0);
static struct timer_list zk_cleanup_timer;

static u64 zk_timeout_ns(void)
{
	return (u64)READ_ONCE(wgzk_pending_timeout_ms) * NSEC_PER_MSEC;
}

static bool zk_entry_expired(const struct zk_pending_entry *entry, u64 now)
{
	return (s64)(now - entry->created_ns) > (s64)zk_timeout_ns();
}

int zk_pending_get_count(void)
{
	return atomic_read(&zk_pending_count);
}

void zk_pending_free(struct zk_pending_entry *entry)
{
	if (!entry)
		return;
	dev_put(entry->wg->dev);
	kfree_sensitive(entry);
}

/* Moves expired entries of the table to @expired. Caller holds zk_lock. */
static void zk_collect_expired(struct hlist_head *expired)
{
	u64 now = ktime_get_coarse_boottime_ns();
	struct zk_pending_entry *entry;
	struct hlist_node *tmp;
	int bkt;

	hash_for_each_safe(zk_pending_table, bkt, tmp, entry, node) {
		if (zk_entry_expired(entry, now)) {
			hash_del(&entry->node);
			atomic_dec(&zk_pending_count);
			wgzk_stat_inc(WGZK_STAT_EXPIRED);
			hlist_add_head(&entry->node, expired);
		}
	}
}

static void zk_free_list(struct hlist_head *list)
{
	struct zk_pending_entry *entry;
	struct hlist_node *tmp;

	hlist_for_each_entry_safe(entry, tmp, list, node) {
		hlist_del(&entry->node);
		zk_pending_free(entry);
	}
}

static void zk_pending_cleanup_expired(void)
{
	HLIST_HEAD(expired);

	spin_lock_bh(&zk_lock);
	zk_collect_expired(&expired);
	spin_unlock_bh(&zk_lock);
	zk_free_list(&expired);
}

int zk_pending_add(struct wg_device *wg,
		   const struct message_handshake_initiation_zk *msg,
		   const struct endpoint *ep, u64 *id)
{
	struct zk_pending_entry *entry;
	HLIST_HEAD(expired);
	int ret = 0;

	entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry)
		return -ENOMEM;

	entry->id = (u64)atomic64_inc_return(&zk_pending_next_id);
	entry->sender_index = le32_to_cpu(msg->sender_index);
	entry->wg = wg;
	entry->raw = *msg;
	entry->endpoint = *ep;
	entry->created_ns = ktime_get_coarse_boottime_ns();
	dev_hold(wg->dev);

	spin_lock_bh(&zk_lock);
	zk_collect_expired(&expired);
	if (atomic_read(&zk_pending_count) >= READ_ONCE(wgzk_pending_max)) {
		ret = -ENOSPC;
	} else {
		hash_add(zk_pending_table, &entry->node, entry->id);
		atomic_inc(&zk_pending_count);
		*id = entry->id;
	}
	spin_unlock_bh(&zk_lock);

	zk_free_list(&expired);
	if (ret)
		zk_pending_free(entry);
	return ret;
}

struct zk_pending_entry *zk_pending_take(u64 id, const struct net *net)
{
	u64 now = ktime_get_coarse_boottime_ns();
	struct zk_pending_entry *entry, *found = NULL;

	spin_lock_bh(&zk_lock);
	hash_for_each_possible(zk_pending_table, entry, node, id) {
		if (entry->id != id)
			continue;
		if (!net_eq(dev_net(entry->wg->dev), net))
			break;
		hash_del(&entry->node);
		atomic_dec(&zk_pending_count);
		found = entry;
		break;
	}
	spin_unlock_bh(&zk_lock);

	if (found && zk_entry_expired(found, now)) {
		wgzk_stat_inc(WGZK_STAT_EXPIRED);
		zk_pending_free(found);
		found = NULL;
	}
	return found;
}

void zk_pending_flush_device(const struct wg_device *wg)
{
	struct zk_pending_entry *entry;
	struct hlist_node *tmp;
	HLIST_HEAD(gone);
	int bkt;

	spin_lock_bh(&zk_lock);
	hash_for_each_safe(zk_pending_table, bkt, tmp, entry, node) {
		if (entry->wg == wg) {
			hash_del(&entry->node);
			atomic_dec(&zk_pending_count);
			hlist_add_head(&entry->node, &gone);
		}
	}
	spin_unlock_bh(&zk_lock);
	zk_free_list(&gone);
}

static void zk_pending_flush_all(void)
{
	struct zk_pending_entry *entry;
	struct hlist_node *tmp;
	HLIST_HEAD(gone);
	int bkt;

	spin_lock_bh(&zk_lock);
	hash_for_each_safe(zk_pending_table, bkt, tmp, entry, node) {
		hash_del(&entry->node);
		atomic_dec(&zk_pending_count);
		hlist_add_head(&entry->node, &gone);
	}
	spin_unlock_bh(&zk_lock);
	zk_free_list(&gone);
}

static void zk_timer_fn(struct timer_list *t)
{
	zk_pending_cleanup_expired();
	mod_timer(&zk_cleanup_timer, jiffies + msecs_to_jiffies(1000));
}

void zk_pending_init(void)
{
	timer_setup(&zk_cleanup_timer, zk_timer_fn, 0);
	mod_timer(&zk_cleanup_timer, jiffies + msecs_to_jiffies(1000));
}

void zk_pending_exit(void)
{
	timer_shutdown_sync(&zk_cleanup_timer);
	zk_pending_flush_all();
}

int zk_pending_seq_show(struct seq_file *m, void *v)
{
	u64 now = ktime_get_coarse_boottime_ns();
	struct zk_pending_entry *entry;
	int bkt;

	seq_printf(m, "Total pending entries: %d\n", zk_pending_get_count());
	seq_puts(m, "Id\tIndex\tAge (ms)\n");

	spin_lock_bh(&zk_lock);
	hash_for_each(zk_pending_table, bkt, entry, node)
		seq_printf(m, "%llu\t%u\t%llu\n", entry->id,
			   entry->sender_index,
			   div_u64(now - entry->created_ns, NSEC_PER_MSEC));
	spin_unlock_bh(&zk_lock);
	return 0;
}
