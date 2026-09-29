# Acceptance tests, 20260929T200049Z

Commit `f089072b739c7422841d9197b43ab9747e88a6b6`, 0 files changed in the working tree. Test bed: lan-ist.

Artefacts under test:

```
built 2026-09-29T15:17:48Z
commit 9cb23dd03b41dee7cb2a6734be3185acd35eb486 dirty_files=0
kernel 6.8.0-59-generic
rustc rustc 1.93.0 (254b59607 2026-01-19)
ba7792b41a1d4df2ceabed8638a3a341ff92c9ebfa3b9171e896f9ca28d025f5  wireguard.ko
85305b3d70b100d91b5f8a978d7776f426ac77351683cf68e6279ed7fd249465  wg-zk-daemon
ac0d953ada69211ae7aeab051407e70ee1ae8d41c28c9447cf387bcbe3907a97  wg-zk-daemon-fault
dea6db0dc551cdb6b19ee3d23df90adcdd7076c2cd6c79a159beed0f55d1785e  gen-pk
cf337ea17ab75db66fb0da02eff21fcc3542ff4fcae28382a754774dd59ca155  gen-mlkem
```

Passed 30, failed 0, skipped 0.

| Test | Area | Variant | Result | Checks | Claim |
|---|---|---|---|---|---|
| `pos-zkpq` | Positive path | zk-pq | pass | 12/12 | A client with the credential gets a session (with ML-KEM). |
| `pos-tool` | Positive path | zk-pq | pass | 12/12 | The same with the wg tool in place of the netlink interface. |
| `pos-zkonly` | Positive path | zk-only | pass | 12/12 | A client with the credential gets a session (authorization only). |
| `id-connections` | Identity | zk-pq | pass | 9/9 | Two connections of one client show different session keys, addresses and TLS connections. |
| `id-rekey` | Identity | zk-pq | pass | 5/5 | A new handshake inside a connection keeps session key and address. |
| `id-rekey-natural` | Identity | zk-pq | pass | 4/4 | WireGuard's own re-key after two minutes passes through the proof and keeps the peer. |
| `id-idle` | Identity | zk-pq | pass | 6/6 | The gateway removes the peer of a connection that has gone idle. |
| `id-epochs` | Identity | zk-only | pass | 10/10 | While credentials change, the gateway accepts the previous credential and the current one, and no other. |
| `auth-bad-proof` | Authorisation | zk-only | pass | 7/7 | An invalid proof creates no peer. |
| `auth-other-key` | Authorisation | zk-only | pass | 7/7 | A proof computed for another session key creates no peer. |
| `auth-other-gw` | Authorisation | zk-only | pass | 7/7 | A proof computed for another gateway creates no peer. |
| `auth-other-epoch` | Authorisation | zk-only | pass | 7/7 | A proof computed for an epoch that the gateway does not accept creates no peer. |
| `pq-skip-ct` | PQ enforcement | zk-pq | pass | 7/7 | Without a ciphertext there is no session, although the proof is valid. |
| `pq-other-nonce` | PQ enforcement | zk-pq | pass | 7/7 | A ciphertext that arrived for another nonce does not count. |
| `pq-flip-ct` | PQ enforcement | zk-pq | pass | 7/7 | A ciphertext that differs from the one the proof is bound to is refused. |
| `auth-wrong-credential` | Authorisation | zk-only | pass | 7/7 | A client with another group secret creates no peer. |
| `auth-replay` | Authorisation | zk-pq | pass | 8/8 | A recorded initiation that is sent again creates nothing. |
| `auth-transplant` | Authorisation | zk-only | pass | 7/7 | A proof copied from the wire into an initiation with another key creates no peer. |
| `pq-failed-tls` | PQ enforcement | zk-pq | pass | 7/7 | If the ciphertext cannot be delivered, the client sends no initiation. |
| `pq-wrong-pin` | TLS | zk-pq | pass | 8/8 | If the certificate of the gateway does not match the fingerprint, the client sends nothing. |
| `pq-failed-psk` | PQ enforcement | zk-pq | pass | 7/7 | If the client cannot install its key, it sends no initiation. |
| `pq-no-psk` | PQ enforcement | zk-pq | pass | 5/5 | A client that does not use the ML-KEM secret gets no session, although its proof is valid. |
| `tls-12-refused` | TLS | zk-pq | pass | 3/3 | The gateway refuses a client that offers TLS 1.2. |
| `k-unprivileged` | Kernel | zk-only | pass | 7/7 | A process without privileges cannot send a verdict. |
| `k-same-index` | Kernel | zk-only | pass | 7/7 | Two stored initiations with the same sender index each receive their own verdict. |
| `k-locks` | Kernel | zk-pq | pass | 9/9 | After 1,000 stored initiations that time out or are rejected, the gateway can change its key, remove the interface and unload the module. |
| `k-legacy` | Legacy path | zk-only | pass | 7/7 | An initiation without proof is dropped. |
| `b-initiations` | Bounded state | zk-only | pass | 8/8 | 10,000 initiations that cannot be verified leave the table, the memory and the peers bounded. |
| `b-ciphertexts` | Bounded state | zk-pq | pass | 8/8 | 10,000 side-channel messages that no initiation follows leave the memory and the peers bounded. |
| `b-connections` | Bounded state | zk-pq | pass | 3/3 | Connections that send nothing are closed after the handshake timeout. |
