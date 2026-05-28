# Crypto Custody Engine

The Crypto Custody Engine is a zero-dependency, production-grade security utility demonstrating enterprise key management, data provenance, and decentralized trust orchestration.

Built with TypeScript and the Node.js native crypto primitives, the engine models how a security team can safeguard sensitive data against tampering, collusion, and single-point-of-failure risks.

## Table of Contents

- [Security Architecture](#security-architecture)
- [Core Security Pillars](#core-security-pillars)
- [Architectural Compliance Profile](#architectural-compliance-profile)
- [Installation & Usage](#installation--usage)
- [License](#license)

## Security Architecture

The platform is engineered around three decoupled cryptographic vectors to provide layered defenses.

```mermaid
graph LR
    A[Data Payload] --> B[Confidentiality & Integrity]
    A --> C[Identity Provenance]
    A --> D[Dual-Control Recovery]

    B --> B1[AES-256-GCM (AEAD)]
    C --> C1[Ed25519 Signatures]
    D --> D1[Shamir's Secret Sharing]
```

## Core Security Pillars

### 1. Authenticated Confidentiality at Rest (AES-256-GCM)

Implements Authenticated Encryption with Associated Data (AEAD). The engine generates cryptographically isolated 12-byte initialization vectors (IVs) and validates a 16-byte Galois authentication tag on every read. Any tampering of the stored ciphertext causes authentication to fail and the read operation is rejected.

### 2. Non-Repudiation & Identity Provenance (Ed25519)

Protects against insider asset-swapping and forgery. Even if an actor possesses the symmetric storage key, they cannot forge Ed25519 signatures without the security officer's isolated private key, preserving an auditable chain of custody.

### 3. Split-Knowledge Dual-Control Governance (M-of-N Threshold)

Eliminates root-key single points of failure. The master data-encryption key is split into N polynomial shares; reconstruction requires a threshold of M shares during a key ceremony. This enforces dual-control governance and prevents unilateral administrative overrides.

## Architectural Compliance Profile

- **Language:** Pure TypeScript compiled as ECMAScript Modules (ESM / NodeNext).
- **Regulatory alignment:** Modeled against NSM and NIST key lifecycle guidance.
- **Memory sanitization:** Implements zeroization patterns (see `utils/zeroizer.ts`) across sensitive buffers.
- **Zero-dependency policy:** Uses only Node.js native `crypto` and `buffer` modules to reduce SBOM complexity.
- **Deterministic rotation:** `utils/rotator.ts` ensures atomic key lifecycle transitions.
- **Mathematical hardening:** Shamir's Secret Sharing uses GF(2^8) with a fixed primitive polynomial to avoid entropy bottlenecks.

## Installation & Usage

### Prerequisites

- Node.js v20.x or higher
- npm

### Setup

Clone the repository and install dependencies, then compile the TypeScript source:

```bash
# Install dependencies
npm install

# Compile the source
npx tsc
```

### Execution

Run the compiled engine to initiate the cryptographic lifecycle ceremony:

```bash
node dist/index.js
```
