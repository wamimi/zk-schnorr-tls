# Zero-Knowledge Schnorr Protocol in Rust

A working implementation of the Schnorr identification scheme which is a cryptographic protocol that lets you prove you know a secret without revealing it.

## What This Project Does

**The Goal**: Build a practical Zero-Knowledge proof system where:
- A **Prover** can prove they know a secret key
- A **Verifier** can confirm the proof is valid  
- The secret is **never revealed** during the process

## What's Working Now

- **Complete Schnorr Protocol**: 3-round interactive proof (commit → challenge → response)
- **Secure Cryptography**: Uses Curve25519 elliptic curve operations
- **Network Communication**: Real-time TCP networking between prover and verifier
- **Mathematical Verification**: Verifies the equation `s*G = R + c*X`
- **Multiple Rounds**: Can run the protocol multiple times

## Planned Features (Not Yet Implemented)

- TLS encryption (currently uses plain TCP)
- Command-line interface with options
- Secure key storage
- Multi-round repetition in single session
- Simulator component

## Prerequisites

You need **Rust** installed on your computer. Get it from [rustup.rs](https://rustup.rs/)

To verify Rust is installed:
```bash
rustc --version
cargo --version
```

## How to Run

### 1. Clone and Navigate
```bash
git clone https://github.com/wamimi/zk-schnorr-tls.git
cd zk-schnorr-tls
```

### 2. Start the Verifier (Server)
In your first terminal:
```bash
cargo run --bin verifier
```
You should see: `(Verifier) Starting server on 127.0.0.1:4000`

### 3. Run the Prover (Client)  
In a second terminal:
```bash
cargo run --bin prover
```

### 4. Watch the Protocol in Action

You'll see the complete protocol exchange:

![Protocol Demo](./demo-screenshot.png)

```
(Prover) Public key X: 363f097bc9f0264e6b780e1a983927fd794179655df7b29af599d107bb95c043
(Verifier) Accepted connection from: 127.0.0.1:50412
(Prover) Sent commit R: 9cf75959bf392f7f5435f14f214638405c0a6202ed9a1659f4e004a9ad3b2d03
(Verifier) Expected public key X: 363f097bc9f0264e6b780e1a983927fd794179655df7b29af599d107bb95c043
(Verifier) Received commitment R: 9cf75959bf392f7f5435f14f214638405c0a6202ed9a1659f4e004a9ad3b2d03
(Verifier) Sent challenge c: 1d25645ff921051a1a842c6a365cf6f835e0feabb9bb100a5f2f2b9d788a8206
(Prover) Received challenge c: 1d25645ff921051a1a842c6a365cf6f835e0feabb9bb100a5f2f2b9d788a8206
(Prover) Sent response s: a647c69f43e04c2cdcd362f9f33c26488994e6ae2ed7434c72a0b748022adb09
(Verifier) Received response s: a647c69f43e04c2cdcd362f9f33c26488994e6ae2ed7434c72a0b748022adb09
                                                                                                                                  
(Verifier) ✅ PROOF VERIFIED! The prover knows the secret x.
(Verifier) Verification equation: s*G = R + c*X ✓
```

## Why Interactive Proofs Are Not Transferable

This log demonstrates a crucial property of interactive zero-knowledge proofs: **they are not transferable**.

Imagine you showed this log file to a skeptical third party named Tammy. She can see all the values (X, R, c, s) and can even perform the final verification herself by calculating `s*G` and `R + c*X` to see if they match.

But she would still have a critical question: **"How do I know the Verifier didn't cheat?"**

The security of this entire proof relies on the fact that the Verifier generated the challenge `c` randomly and **after** seeing the Prover's commitment `R`. Looking at this static log, Tammy has no way to be certain of that. 

For all she knows, the Prover and Verifier could have colluded. They could have:
1. Chosen `c` and `s` first
2. Calculated `R` backwards to make the final equation work
3. Done this even without the Prover knowing the secret

You, as the person running both programs, know the interaction was honest. But the transcript alone doesn't prove that to an outsider.

## How It Works

The Schnorr protocol follows these steps:

1. **Commitment**: Prover generates a random commitment `R = k*G`
2. **Challenge**: Verifier sends a random challenge `c`  
3. **Response**: Prover responds with `s = k + c*x` (where `x` is the secret)
4. **Verification**: Verifier checks if `s*G = R + c*X` (where `X` is the public key)

The math works out if and only if the prover knows the secret `x`!


- **Curve25519-dalek**: Elliptic curve cryptography
- **Tokio**: Async networking runtime
- **Serde**: JSON serialization
- **Anyhow**: Error handling



