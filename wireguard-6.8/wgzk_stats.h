/* SPDX-License-Identifier: GPL-2.0 */
/*
 * wgzk: event counters, readable through debugfs (wgzk/stats, wgzk/pending).
 * They exist for tests and measurements and are no interface.
 */

#ifndef _WGZK_STATS_H
#define _WGZK_STATS_H

#include <linux/atomic.h>

enum wgzk_stat {
	WGZK_STAT_PROOF_REQUESTS,    /* NEED_PROOF events */
	WGZK_STAT_PROOFS_SET,	     /* SET_PROOF accepted */
	WGZK_STAT_DEFERRED,	     /* initiations stored, NEED_VERIFY sent */
	WGZK_STAT_REFUSED_FULL,	     /* not stored: table full */
	WGZK_STAT_UNDECRYPTABLE,     /* not stored: static key did not decrypt */
	WGZK_STAT_ACCEPTED,	     /* verdict accept, handshake answered */
	WGZK_STAT_REFUSED_HANDSHAKE, /* verdict accept, refused by the handshake */
	WGZK_STAT_REJECTED,	     /* verdict reject */
	WGZK_STAT_EXPIRED,	     /* no verdict in time */
	WGZK_STAT_LATE_VERDICT,	     /* verdict for an unknown or expired id */
	WGZK_STAT_LEGACY_DROPPED,    /* initiations without proof dropped */
	__WGZK_STAT_MAX
};

extern atomic64_t wgzk_stats[__WGZK_STAT_MAX];

static inline void wgzk_stat_inc(enum wgzk_stat stat)
{
	atomic64_inc(&wgzk_stats[stat]);
}

void wgzk_debugfs_init(void);
void wgzk_debugfs_exit(void);

#endif /* _WGZK_STATS_H */
