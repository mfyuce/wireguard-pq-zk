# wg-zk-daemon

The user-space half of the wgzk handshake, protocol revision R1. The specification is
[`docs/protocol-r1.md`](../../docs/protocol-r1.md); this file says how to build and run.

## Build and test

```bash
cargo build --release
cargo test                                   # 123 tests
cargo clippy --all-targets -- -D warnings
cargo test --features fault-injection        # 129 tests; see "Fault injection"
```

`bash vagrant/build-artifacts.sh` in the repository root builds the daemon together with the
kernel module and puts both where the machines of the test bed take them from.

## Run

```bash
wg-zk-daemon                  # the daemon; WGZK_MODE selects client or gateway
wg-zk-daemon new-connection --iface wg0      # client: new key, new UDP port, derived address
wg-zk-daemon derive-addr <base64 public key> # the tunnel address of a session key
```

The configuration comes from the environment, or from a file `.env` in the working
directory. [`.env.example`](.env.example) lists every variable with its default. A value
that cannot be parsed stops the daemon; nothing falls back silently. In particular a daemon
without a complete ML-KEM configuration does not start unless `WGZK_DISABLE_MLKEM=1` says that
authorization only is intended.

The daemon needs `CAP_NET_ADMIN`: it answers the kernel module over the netlink family `wgzk`
and writes peers and preshared keys over WireGuard's own netlink interface.

## What it does

| Role | On | The daemon |
|---|---|---|
| client | `NEED_PROOF` | draws a nonce, encapsulates to the ML-KEM key of the gateway, proves, sends the ciphertext over TLS, installs the preshared key, hands the proof to the kernel. If the ciphertext could not be delivered or the key could not be installed, it hands down nothing |
| gateway | a side-channel message | stores the ciphertext under its nonce and does nothing else |
| gateway | `NEED_VERIFY` | replay check, ciphertext for the nonce, proof, decapsulation, peer with session key, preshared key and one address, replay entry, verdict. Any failure is a rejecting verdict with nothing created |
| gateway | every 30 s at most | removes peers that were not verified again within `WGZK_PEER_IDLE_SECS` |

Every handshake writes one line that starts with `[timing]`, on each side. No key, no proof
and no complete nonce is ever logged.

## Source

| File | Content |
|---|---|
| `zk.rs` | Schnorr proof over Ristretto255, challenge of Section 3.3, known-answer vector |
| `mlkem.rs` | ML-KEM-768, derivation of the preshared key |
| `mlkem_channel.rs` | side channel: TLS 1.3, pinned certificate, bounded listener |
| `ctbuf.rs`, `replay.rs`, `keylock.rs` | ciphertext buffer, replay cache, locks per key |
| `peers.rs`, `wgnl.rs`, `tool.rs` | peer table; installers over netlink and over the `wg` tool |
| `addr.rs`, `sessionkey.rs` | tunnel address, `new-connection` |
| `netlink.rs` | family `wgzk`, version 2 |
| `gateway.rs`, `client.rs` | the two roles |
| `settings.rs` | every environment variable |
| `fault.rs` | fault injection, only with the feature |

## Fault injection

`cargo build --release --features fault-injection` builds a client that misbehaves in the one
way that `WGZK_FAULT` names, so that the test bed can show that the gateway refuses
(`bench/acceptance/run.py`). The normal build contains none of that code and refuses to
start when `WGZK_FAULT` is set.
