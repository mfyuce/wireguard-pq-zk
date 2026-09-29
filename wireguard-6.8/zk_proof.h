/* SPDX-License-Identifier: GPL-2.0 */
/*
 * wgzk: proofs handed down by the client daemon, waiting to be placed into
 * the next initiation towards a peer. One proof per peer, used once.
 */
#ifndef _WGZK_PROOF_H
#define _WGZK_PROOF_H

#include <linux/types.h>

/* Returns false if no proof is stored for @peer_id or the stored one is older
 * than the pending timeout. A stored proof is removed by this call either way.
 */
bool zk_proof_get_and_clear(u64 peer_id, u8 r[32], u8 s[32], u8 nonce[32]);
void zk_proof_set(u64 peer_id, const u8 r[32], const u8 s[32],
		  const u8 nonce[32]);
void zk_proof_clear(u64 peer_id);
void zk_proof_exit(void);

#endif /* _WGZK_PROOF_H */
