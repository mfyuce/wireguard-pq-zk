// SPDX-License-Identifier: GPL-2.0
/*
 * wgzk: event counters and the debugfs files that show them. See wgzk_stats.h.
 */

#include <linux/debugfs.h>
#include <linux/seq_file.h>

#include "wgzk_stats.h"
#include "zk_pending.h"

atomic64_t wgzk_stats[__WGZK_STAT_MAX];

static const char *const wgzk_stat_names[__WGZK_STAT_MAX] = {
	[WGZK_STAT_PROOF_REQUESTS]    = "proof_requests",
	[WGZK_STAT_PROOFS_SET]	      = "proofs_set",
	[WGZK_STAT_DEFERRED]	      = "deferred",
	[WGZK_STAT_REFUSED_FULL]      = "refused_full",
	[WGZK_STAT_UNDECRYPTABLE]     = "undecryptable",
	[WGZK_STAT_ACCEPTED]	      = "accepted",
	[WGZK_STAT_REFUSED_HANDSHAKE] = "refused_handshake",
	[WGZK_STAT_REJECTED]	      = "rejected",
	[WGZK_STAT_EXPIRED]	      = "expired",
	[WGZK_STAT_LATE_VERDICT]      = "late_verdict",
	[WGZK_STAT_LEGACY_DROPPED]    = "legacy_dropped",
};

static struct dentry *wgzk_debugfs_dir;

static int wgzk_stats_show(struct seq_file *m, void *v)
{
	int i;

	seq_printf(m, "pending %d\n", zk_pending_get_count());
	for (i = 0; i < __WGZK_STAT_MAX; ++i)
		seq_printf(m, "%s %lld\n", wgzk_stat_names[i],
			   (long long)atomic64_read(&wgzk_stats[i]));
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(wgzk_stats);

static int wgzk_pending_show(struct seq_file *m, void *v)
{
	return zk_pending_seq_show(m, v);
}
DEFINE_SHOW_ATTRIBUTE(wgzk_pending);

void wgzk_debugfs_init(void)
{
	wgzk_debugfs_dir = debugfs_create_dir("wgzk", NULL);
	debugfs_create_file("stats", 0400, wgzk_debugfs_dir, NULL,
			    &wgzk_stats_fops);
	debugfs_create_file("pending", 0400, wgzk_debugfs_dir, NULL,
			    &wgzk_pending_fops);
}

void wgzk_debugfs_exit(void)
{
	debugfs_remove_recursive(wgzk_debugfs_dir);
}
