A Rust-based implementation of an interactive zero-knowledge proof (ZKP) using Schnorr’s identification scheme, secured with TLS via Tokio and Rustls. It is designed to demonstrate how cryptographic protocols can be built for secure, live authentication without revealing any secret information.

The system models a prover and verifier engaging in a Schnorr identification protocol over a secure TLS channel. The verifier issues fresh, random challenges (nonces), and the prover responds with mathematically valid proofs derived from a secret key. The verifier checks each proof’s validity without learning the secret itself.

Key aspects:

Interactive Zero-Knowledge Proof — The protocol runs in multiple rounds, with the prover and verifier exchanging challenge–response messages to demonstrate knowledge of a secret.

Schnorr Identification Scheme — Built on elliptic curve cryptography (Curve25519), leveraging strong, modern primitives.

TLS-Encrypted Communication — Uses Tokio + Rustls to ensure confidentiality, integrity, and authenticity of all protocol messages in transit.

Multi-Round Repetition — Supports repeated challenge–response cycles to exponentially decrease soundness error.

CLI-Based Prover & Verifier — Both participants can be run as command-line tools, simulating real-world peer-to-peer authentication scenarios.

Secure Secret Handling — Secrets are stored and managed securely, with in-memory zeroization and encrypted persistence.

Simulation Mode — Optional simulator to model and test protocol runs without requiring two live participants.

This repository serves as a practical, end-to-end example of building a cryptographic interactive protocol from scratch in Rust, bridging the gap between theoretical concepts in zero-knowledge proofs and real-world secure networked implementations.