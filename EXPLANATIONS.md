# Cryptographic Concepts — WireGuard PQ-ZK

Background reading for the cryptographic primitives used in this repository:
**X25519**, **Schnorr++ zero-knowledge proofs over Ristretto255**, **ML-KEM-768**, and
the **hybrid PSK design** that combines them.

---

# X25519

**X25519** is a modern cryptographic key exchange algorithm widely used for its speed, security, and resistance to implementation mistakes.

---

## 🔑 Core Idea

X25519 is a variant of the Diffie-Hellman key exchange protocol.

Compared to classic Diffie-Hellman:
- Uses elliptic curve cryptography (ECC)
- More secure
- Resistant to side-channel attacks

---

## 📐 Which Curve Does It Use?

X25519 operates on:

- Curve25519 (a Montgomery elliptic curve)

This curve was designed for:
- High performance
- Constant-time operations (prevents timing attacks)
- Safe, transparent parameters (no backdoor concerns)

---

## ⚙️ How It Works (Simplified)

Assume two parties:

- Alice generates a private key → `a`
- Bob generates a private key → `b`

They compute:
- Alice public key: `A = a * G`
- Bob public key: `B = b * G`

They exchange public keys and compute:
- Alice computes: `a * B`
- Bob computes: `b * A`

➡️ Both derive the same **shared secret**

An attacker:
- Can see `A` and `B`
- But cannot derive `a` or `b`

---

## 🚀 Why Is It So Popular?

X25519 is widely adopted because:

- Very fast (especially on mobile/embedded systems)
- Easy to implement correctly (low risk of bugs)
- Constant-time execution → resistant to side-channel attacks
- Standardized in RFC 7748

---

## 🔐 Where Is It Used?

X25519 is used in:

- TLS 1.3
- WireGuard (modern VPN protocol)
- Signal (secure messaging app)
- Noise Protocol Framework

---

## 🧠 Advanced Details

Internally, X25519:

- Uses the Montgomery ladder algorithm
- Operates only on the x-coordinate
- Performs scalar multiplication: `k * u`

This results in:
- Less data handling → smaller attack surface
- Faster computation

---

## 🔥 Connection to ZK + VPN Design

In a privacy-preserving VPN architecture:

- X25519 → provides secure key exchange (confidential channel)
- Zero-Knowledge Proofs → provide identity privacy

So:
- X25519 = "secure communication"
- ZK = "authentication without revealing identity"

This combination is very powerful:
- WireGuard already uses X25519
- Adding ZK introduces a strong privacy layer

---

# Zero-Knowledge Proofs (ZK)

A **Zero-Knowledge Proof** lets one party (the *prover*) convince another (the *verifier*)
that they know a secret — **without revealing the secret itself**.

## 🔑 Core Idea

Three fundamental properties:

| Property | Meaning |
|---|---|
| **Completeness** | If the prover *really* knows the secret, an honest verifier will accept |
| **Soundness** | A cheater who doesn't know the secret cannot fool the verifier (except with negligible probability) |
| **Zero-Knowledge** | The verifier learns *nothing* about the secret beyond the fact that it exists |

## 🎯 Why This Matters for VPNs

Classical VPN authentication sends a long-term public key over the wire:

```
Client → Gateway: "I am peer_pk = 0x4a2f..."
```

Every session uses the same public key → **the peer is linkable across sessions**.
A passive network observer can correlate traffic flows, map user locations, or de-anonymize clients.

With a ZK proof, the client says instead:

```
Client → Gateway: "I know the secret for some authorized peer — here's a proof"
```

The gateway verifies the proof but does **not** learn *which* peer the client is.
Each session produces a fresh, statistically independent proof → **unlinkability**.

---

# Schnorr Proofs

The specific ZK scheme used in this repo is a **Schnorr proof of knowledge of a discrete log**.

## 🧮 The Math (Classical Schnorr)

Assume a cyclic group with generator `G` of prime order `q`.
The prover knows a secret scalar `sk` and publishes `pk = sk · G`.

To prove knowledge of `sk` without revealing it:

1. Prover picks random `r ∈ [0, q)`, sends `R = r · G`
2. Verifier picks random challenge `c`
3. Prover sends `s = r + c · sk   (mod q)`
4. Verifier checks: `s · G == R + c · pk`

The verifier gains no info about `sk` because `r` is random → `R` is uniformly distributed and `s` looks random.

## 🔄 Fiat-Shamir Transform (Non-Interactive)

For a VPN handshake we can't do three round-trips, so we make the proof non-interactive:

```
c = H(R ‖ context ‖ session_nonce)
```

The challenge is derived from a hash — the prover can't choose it adversarially.

## 🛡️ Schnorr++ (This Repo's Variant)

"Schnorr++" means several hardening measures layered on top of plain Schnorr:

| # | Measure | What it defends against |
|---|---|---|
| 1 | **Ristretto255 group** | Cofactor/subgroup attacks present in raw Ed25519 |
| 2 | **Transcript-bound challenge** | Replay in different session contexts |
| 3 | **Hedged nonce** `r = HMAC-SHA512(sk, salt ‖ OSRAND)` | RNG failure + fault attacks |
| 4 | **Canonical encodings** | Malleable / non-canonical point injection |
| 5 | **Constant-time verification** | Timing side channels |
| 6 | **Per-session nonce** | Cross-session replay |

---

# Ristretto255

An elliptic curve group designed to eliminate common implementation pitfalls.

## 🧩 The Problem

Raw Ed25519 (Curve25519 in Edwards form) has a **cofactor of 8** — meaning the group has 8 "small" subgroups
alongside the main prime-order subgroup. This creates attack surface:

- Small-subgroup attacks can leak bits of a secret key
- Different encodings of the same logical point exist (malleability)
- Implementers must remember to check and reject malicious points

## ✅ The Ristretto255 Fix

Ristretto255 is a mathematical **wrapper** around Curve25519 that exposes only the prime-order subgroup:

- **No cofactor** — the group order is a prime ≈ 2²⁵²
- **Canonical encodings** — each logical group element has exactly one 32-byte representation
- **No small subgroup** — malicious inputs are rejected at the deserialization layer automatically
- **Same speed** as raw Curve25519 — it's a mathematical abstraction, not extra computation

It's the recommended choice for any new protocol that needs a prime-order group on Curve25519.

---

# The Quantum Threat

## ⚠️ Why "Post-Quantum"?

A sufficiently large **quantum computer** could run **Shor's algorithm** — which solves the discrete
log and integer factorization problems in polynomial time. That would break:

- X25519 (discrete log)
- ECDSA / Ed25519 signatures
- RSA
- Classical Diffie-Hellman
- …basically all of today's public-key crypto

**Symmetric** crypto (AES, SHA-2) is only weakened (key length must double), not broken.

## 🕰️ "Harvest Now, Decrypt Later"

The threat isn't hypothetical in the long term. An adversary today can:

1. Record encrypted VPN traffic and keys in transit (passive network tap)
2. Store it indefinitely
3. Wait for a cryptographically-relevant quantum computer (CRQC)
4. Decrypt everything retroactively

For data with long-term confidentiality requirements (government, medical, trade secrets),
this is a real threat model — even though a CRQC likely doesn't exist yet.

## 🛡️ The Response: Post-Quantum Cryptography (PQC)

NIST ran a multi-year competition (2016–2024) to standardize algorithms that resist
both classical and quantum attacks. In August 2024, NIST published:

| Standard | Purpose | Underlying hard problem |
|---|---|---|
| **FIPS 203 — ML-KEM** (Kyber) | Key encapsulation | Module Learning With Errors (M-LWE) |
| **FIPS 204 — ML-DSA** (Dilithium) | Digital signatures | Module-LWE + Module-SIS |
| **FIPS 205 — SLH-DSA** (SPHINCS+) | Hash-based signatures | Hash function security |

These problems are **conjectured** to be quantum-resistant — no efficient quantum algorithm is known.

---

# ML-KEM-768 (Kyber)

The post-quantum key encapsulation mechanism (KEM) used in this repo.

## 🗝️ What Is a KEM?

A **Key Encapsulation Mechanism** is a simplified public-key primitive:

- `(ek, dk) ← KeyGen()` — generate encapsulation + decapsulation keys
- `(ct, ss) ← Encap(ek)` — encapsulate to a shared secret
- `ss ← Decap(dk, ct)` — recover the shared secret

Anyone with `ek` (public) can produce a ciphertext `ct` and a shared secret `ss`.
Only the holder of `dk` (private) can recover `ss` from `ct`.

## 📏 ML-KEM-768 Sizes (FIPS 203)

| Field | Size |
|---|---|
| Encapsulation key (public) | 1184 bytes |
| Decapsulation key seed | 64 bytes (expanded to ~2400 B) |
| Ciphertext | 1088 bytes |
| Shared secret | 32 bytes |
| Security level | NIST Level 3 (≈ AES-192) |

For comparison: X25519 public keys are 32 bytes. ML-KEM is ~37× larger — which is why
it doesn't fit inline in a WireGuard UDP handshake packet.

## 🏗️ Why Module-LWE?

ML-KEM's security reduces to the **Module Learning With Errors** problem:

> Given `A` (a matrix) and `b = As + e` (with small noise `e`), find `s`.

This is believed to be hard for both classical and quantum computers.
The "module" structure (using polynomial rings) gives much better performance than plain LWE.

## ⚡ Performance

ML-KEM is **fast** — microseconds per operation. The problem isn't compute; it's **message size**.
A 1088-byte ciphertext fragments UDP packets, breaks MTU assumptions, and doesn't fit in
existing handshake framings designed for small keys.

---

# Hybrid KEM Design

## 🎯 Why Hybrid?

PQC algorithms are new (standardized 2024). Cryptographers are **not yet confident**
that ML-KEM won't be broken by a future classical or quantum algorithm.

So modern PQ deployments use a **hybrid** approach:

```
K_session = KDF(K_classical ‖ K_PQ)
```

Security invariant: *as long as **either** K_classical **or** K_PQ is secure, K_session is secure.*

Specifically:
- If quantum computers arrive but ML-KEM holds → still secure (PQ side saves us)
- If ML-KEM is broken by a novel attack but X25519 holds → still secure (classical side saves us)
- Only if **both** break → the tunnel is compromised

## 🧬 How This Repo Combines Them

WireGuard already does X25519 inside the Noise_IK_PSK2 pattern. To add PQ:

1. Client and gateway run **X25519** as normal (Noise IK) → `K_DH` (classical)
2. Side-channel **ML-KEM-768** exchange over TLS → shared secret `ss` (PQ)
3. Derive PSK: `psk = SHA-256("wgzk-mlkem-v1" ‖ ss)`
4. Inject PSK into both endpoints: `wg set peer ... preshared-key`
5. WireGuard mixes it into the session key: `K_session = BLAKE2s(K_DH ‖ psk ‖ transcript)`

Result: same WireGuard tunnel, but now quantum-safe in confidentiality.

---

# Out-of-Band PSK Injection

## 🚫 Why Not In-Band?

The "obvious" approach — put the ML-KEM ciphertext inside the WireGuard handshake packet —
doesn't work:

| | Size |
|---|---|
| Standard WireGuard initiation | 148 bytes |
| With ML-KEM-768 ciphertext | 148 + 1088 = **1236 bytes** |
| Typical Internet MTU | 1500 bytes (but often 1280 for WireGuard) |

1236 bytes works over a single-hop LAN but **fragments** across most real networks
(VPN-over-VPN, mobile carriers, IPv6 tunnels). Fragmented UDP is notoriously unreliable
and often filtered by middleboxes.

## 📞 The Out-of-Band Pattern

Industry deployments converged on a split-channel design:

```
┌─────────────────────────────────────────────────────┐
│ Channel A: WireGuard UDP (unchanged, 148 B)          │
│   Standard Noise_IK_PSK2 handshake                   │
└─────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────┐
│ Channel B: Separate PQ key-exchange transport        │
│   ML-KEM exchange → PSK → injected via wg set       │
└─────────────────────────────────────────────────────┘
```

Both sides independently derive the same PSK from the ML-KEM shared secret and inject it
into WireGuard before the handshake completes. WireGuard itself sees only a normal PSK.

## 🏢 Who Uses This Pattern?

- **Rosenpass** (rosenpass.eu) — dedicated UDP daemon for PQ keys, feeds WireGuard
- **Mullvad VPN** — PQ-safe tunneling via Rosenpass
- **NordVPN "NordWhisper"** — PQ hybrid VPN
- **Cloudflare** — post-quantum TLS using hybrid key exchange
- **This repo** — ML-KEM exchange over TLS/TCP:51821, PSK injection via `wg set`

---

# QKD vs. PQC (Quick Note)

You'll occasionally see **QKD** (Quantum Key Distribution) mentioned alongside PQC.
They're different things:

| | QKD | PQC |
|---|---|---|
| **Method** | Physical quantum channel (photons) | Mathematical hard problems on classical hardware |
| **Dependency** | Special hardware (fiber, satellite) | Software only |
| **Output** | Raw symmetric key material | KEM / signature keypairs |
| **Standard** | ETSI GS QKD 014 (REST API for KMS) | NIST FIPS 203 / 204 / 205 |
| **Scales?** | Point-to-point links, hard to mesh | Runs anywhere |

Both can feed into WireGuard as a PSK. QKD-from-a-KMS is actually *easier* to integrate
than ML-KEM — you just call `get_key()` on the QKD REST API and inject the result via
`wg set peer ... preshared-key`.

This repo's ML-KEM integration point is designed so it can be **swapped for a QKD key source**
with minimal changes: replace the `mlkem_channel` module with an ETSI 014 REST client.

---

# Putting It All Together

The full hybrid PQ-ZK handshake in this repo:

```
┌───────────────────────────────────────────────────────────────────────┐
│                                                                        │
│  1. CLIENT proves identity without revealing it                       │
│     → Schnorr++ over Ristretto255 (96 bytes, single-use per session)  │
│                                                                        │
│  2. CLIENT & GATEWAY derive a quantum-safe shared secret              │
│     → ML-KEM-768 over a side TLS channel (1088-byte ciphertext)       │
│                                                                        │
│  3. Shared secret becomes WireGuard PSK                               │
│     → psk = SHA-256("wgzk-mlkem-v1" ‖ ss), injected on both sides     │
│                                                                        │
│  4. WireGuard runs standard Noise_IK_PSK2 handshake                   │
│     → K_session = BLAKE2s(K_DH ‖ psk ‖ transcript)                    │
│                                                                        │
│  5. Data flows through the established tunnel                         │
│     → ChaCha20-Poly1305, as in vanilla WireGuard                      │
│                                                                        │
└───────────────────────────────────────────────────────────────────────┘
```

**Security properties:**
- **Unlinkability**: no long-term identifier on the wire (from ZK)
- **PQ confidentiality**: session key safe against quantum attacks (from ML-KEM)
- **Forward secrecy**: per-session ephemeral keys (from WireGuard)
- **Hybrid security**: safe unless *both* X25519 and ML-KEM break
- **Authentication**: proven via Schnorr++ (classical — a future upgrade target)

---

## 📚 Further Reading

- [FIPS 203 (ML-KEM)](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf) — the ML-KEM standard
- [RFC 9180 (HPKE)](https://datatracker.ietf.org/doc/rfc9180/) — modern KEM design patterns
- [Ristretto255 spec](https://ristretto.group/) — the safe prime-order group
- [Rosenpass whitepaper](https://rosenpass.eu/whitepaper.pdf) — PQ PSK daemon design
- [Schnorr signatures (Schnorr 1991)](https://link.springer.com/article/10.1007/BF00196725) — original paper
- [Fiat-Shamir transform](https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic) — interactive → non-interactive
- [WireGuard paper (Donenfeld 2017)](https://www.wireguard.com/papers/wireguard.pdf) — the base protocol
- [Hülsing et al. PQ-WireGuard](https://eprint.iacr.org/2020/379) — inline PQ WireGuard (large packets)