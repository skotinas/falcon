<p align="center">
  <img src="crates/falcon-cli/assets/favicon.svg" width="76" height="76" alt="Falcon Emblem" />
</p>

<h1 align="center">FALCON</h1>

<p align="center">
  <strong>Cross-Platform COMSEC Disk, Encrypted Volume &amp; Post-Quantum Sealed-Drop Controller</strong>
</p>

<p align="center">
  <code>v0.4.0</code> &middot;
  <code>Rust 2021</code> &middot;
  <code>AES-256-XTS / Serpent-256</code> &middot;
  <code>ML-KEM-1024 (FIPS 203)</code> &middot;
  <code>BLAKE3-256</code> &middot;
  <code>Ed25519</code> &middot;
  <code>MIT / Apache-2.0</code>
</p>

---

## Overview

**Falcon** is a self-contained, zero-telemetry cryptographic storage and secure-transfer workstation written in Rust. It provides authenticated sector-level encrypted containers (and raw block devices), post-quantum hybrid key derivation, plausible-deniability hidden volumes, tamper-evident Ed25519 chains of custody, and asymmetric post-quantum **Sealed Drops** (`.flcpack`) — accessible via both a scriptable CLI and an air-gapped, loopback-only tactical web console (`127.0.0.1`).

> **Zero Telemetry / Air-Gap First**: Falcon never phones home automatically. Software update checks (`falcon update` / UI **Get Update**) execute strictly on explicit operator action.

---

## Cryptographic Architecture

| Layer | Primitive / Standard | Implementation |
|---|---|---|
| **Sector Encryption** | AES-256-XTS (4096B sectors, IEEE P1619, `K1 != K2` enforced) | `falcon-crypto::xts` |
| **Cascade Mode (`--cascade`)** | AES-256-XTS + Serpent-256-XTS (independent 512-bit subkeys each) | `falcon-crypto::xts` |
| **Password KDF** | Argon2id (RFC 9106, 256-bit salt, up to 512 MiB Paranoid) + HKDF-SHA512 | `falcon-crypto::kdf` |
| **Post-Quantum Hybrid** | FIPS 203 **ML-KEM-1024** (CNSA 2.0) combined with Argon2id via HKDF-SHA512 | `falcon-crypto::pq` |
| **Integrity (Encrypt-then-MAC)** | Per-sector & full-header **BLAKE3-256** bound to `(domain, uuid, sector, ct)` | `falcon-crypto::integrity` |
| **Key Slot Wrapping** | AES-256-GCM (NIST SP 800-38D) with AAD over version, flags, UUID, KDF & PQ hash | `falcon-crypto::wrap` |
| **Tactical Sealed Drops** | **ML-KEM-1024** + **AES-256-GCM** + **Ed25519** verify-before-decrypt (`.flcpack`) | `falcon-crypto::seal` |
| **Chain-of-Custody** | Append-only BLAKE3 hash-chained & **Ed25519-signed** internal audit log | `falcon-crypto::custody` |
| **Threshold Key Recovery** | Constant-time `GF(256)` Shamir M-of-N + BLAKE3 share checksums + QR keycards | `falcon-crypto::shamir`, `qr` |
| **Startup Self-Test (POST)** | Fail-closed FIPS 140-3 style 7-check KAT & pairwise verification (~4 ms) | `falcon-crypto::post` |
| **Memory & Process Hardening** | `mlock`/`VirtualLock`, `zeroize` on drop, `RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0` | `falcon-crypto::memory` |

---

## Key Capabilities

- **Plausible Deniability Hidden Volumes**: Provisions an independent inner volume inside the free upper half of an outer decoy container with a BLAKE3-XOF obfuscated header (zero magic bytes on disk) and synchronized outer MACs so decoy integrity checks remain 100% clean.
- **Coercion & Capture Defenses**:
  - **Silent Duress / Panic Slot**: Indistinguishable on disk from an active key slot; entering it silently performs 3-pass CSPRNG header crypto-shredding and returns a normal authentication error.
  - **Dead-Man's Switch (`--max-attempts N`)**: Permanently shreds primary, backup, and detached headers after *N* consecutive failed unlock attempts.
  - **Mission TTL (`--ttl-hours H`)**: Enforces volume expiration timestamps.
  - **USB Physical Kill-Switch (`--usb-watch <PATH>`)**: 250ms background watchdog that immediately locks the session and zeroizes RAM keys if the watched physical token disappears.
- **Detached Stealth Headers (`--header`)**: Separates the 16 KiB header (`.fhdr`) from the volume payload so the container exhibits ~7.999 bits/byte Shannon entropy with zero visible magic signature.
- **OPSEC Metadata Sanitizer (`--sanitize`)**: Losslessly strips JPEG EXIF/GPS/COM and PNG ancillary metadata chunks without re-encoding image data, and zeroes internal timestamps.
- **Tactical Localhost Console (`falcon ui` / `Falcon.app`)**:
  - Strictly bound to `127.0.0.1` with a 256-bit per-session token (constant-time comparison), strict `Host` header validation, CSP (`frame-ancestors 'none'`), and idle auto-lock.
  - Full-viewport MIL-STD workstation UI with **Entry Gate**, **Day/Night mode**, **6 languages** (`EN`, `EL`, `DE`, `FR`, `ES`, `IT`), Sector Integrity Matrix, live Session Audit Log, **Get Update**, and OPSEC-safe **Report Bug**.
- **Self-Contained macOS Desktop App (`Falcon.app`)**: One-click launcher that runs fail-closed `falcon post`, reuses active sessions, auto-falls back across loopback ports `7842..7852`, and opens the tokenized console.

---

## Workspace Structure

```text
falcon/
├── Cargo.toml
├── LICENSE
├── docs/
│   └── THREAT_MODEL.md         # Security boundaries & operational caveats
├── scripts/
│   └── build_macos_app.sh      # Builds self-contained macOS Falcon.app bundle
└── crates/
    ├── falcon-crypto/          # XTS, Cascade Serpent, Argon2id, ML-KEM-1024, BLAKE3,
    │                           # Ed25519 custody, Sealed Drops, Shamir, QR, Sanitizer, POST
    ├── falcon-volume/          # 16 KiB v3 headers, 4 key slots, hidden volumes, duress,
    │                           # strike counter, TTL, backup failover, OS disk guard
    ├── falcon-fs/              # Sector-backed encrypted filesystem (extent chains, SHA-256,
    │                           # wipe-on-delete, internal Ed25519 custody log)
    └── falcon-cli/             # CLI, hardened localhost UI server, embedded console,
                                # E2E integration tests & parser fuzzing/hardening suite
```

---

## Build & Installation

### Prerequisites
- Rust toolchain (`1.78+`, `cargo`)
- macOS, Linux, or Windows

### Compile & Verify

```bash
git clone https://github.com/skotinas/falcon.git
cd falcon

# Build optimized release binary (~2.0 MB)
cargo build --release

# Run FIPS 140-3 Power-On Self-Test (7/7 checks)
./target/release/falcon post

# Launch the local tactical workstation console
./target/release/falcon ui --open
```

### Build macOS Desktop App (`Falcon.app`)

```bash
./scripts/build_macos_app.sh ~/Desktop/Falcon.app
```

---

## CLI Usage

### 1. Provision & Operate an Encrypted Volume

```bash
# Generate a 2FA keyfile and a FIPS 203 ML-KEM-1024 post-quantum keypair
falcon keygen mission.key
falcon pq-keygen mission.pqkey

# Create a Cascade AES+Serpent stealth volume with Mission TTL & Dead-Man's Switch
falcon create payload.bin --size 64M --cascade \
  --header mission.fhdr --keyfile mission.key --pq-key mission.pqkey \
  --ttl-hours 72 --max-attempts 5

# Store a file with OPSEC EXIF/GPS stripping & zeroed inode timestamps
falcon put payload.bin recon.jpg ops/recon.jpg --sanitize \
  --header mission.fhdr --keyfile mission.key --pq-key mission.pqkey

# Verify headers, every 4 KiB sector MAC, and the Ed25519 Chain-of-Custody
falcon verify payload.bin --header mission.fhdr --keyfile mission.key --pq-key mission.pqkey
falcon custody verify payload.bin --header mission.fhdr --keyfile mission.key --pq-key mission.pqkey
```

### 2. Plausible Deniability Hidden Volume

```bash
# Provision an inner hidden volume inside the unallocated upper half of an outer decoy volume
falcon hidden create decoy.flc --cascade

# Open the hidden volume (outer decoy verify remains 100% clean)
falcon ls decoy.flc --hidden
```

### 3. Tactical Sealed Drops (`.flcpack`)

Encrypt and sign files directly to another operator's public bundle — no shared passphrase required:

```bash
# Generate operator identities (.flcid mode 0600 private, .flcpub shareable public)
falcon identity generate alpha.flcid --pub-out alpha.flcpub --callsign ALPHA-1
falcon identity generate bravo.flcid --pub-out bravo.flcpub --callsign BRAVO-2

# Alpha seals & signs a file for Bravo with OPSEC metadata stripping
falcon seal sitrep.jpg --to bravo.flcpub --from alpha.flcid --out drop.flcpack --sanitize

# Bravo verifies Alpha's pinned Ed25519 signature before ML-KEM-1024 + AES-GCM decryption
falcon unseal drop.flcpack --identity bravo.flcid --expect-sender alpha.flcpub --out clean.jpg
```

### 4. Shamir M-of-N Recovery & Air-Gapped QR Keycards

```bash
# Split a fresh 32-byte key into 3-of-5 shares + printable SVG keycards (mode 0600)
falcon shamir split --threshold 3 --shares 5 --out-keyfile master.key --qr --qr-dir ./keycards

# Reconstruct from any 3 shares
falcon shamir combine --out recovered.key FLCN-S1-01-... FLCN-S1-03-... FLCN-S1-05-...
```

### 5. Duress, Diagnostics, Shred & Manual Update Check

```bash
falcon duress vault.flc --label backup-ops          # Arm indistinguishable silent duress slot
falcon diag vault.flc                               # Hardware cipher benchmark & Shannon entropy
falcon shred vault.flc --yes-destroy-forever        # 3-pass CSPRNG header destruction
falcon update                                       # Manual GitHub Releases check (never automatic)
```

---

## Testing & Hardening

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The workspace test suite (**40 tests**) covers:
- **Known-Answer & Crypto Tests (22)**: IEEE P1619 AES-256-XTS Vector 10, Cascade Serpent, Argon2id, ML-KEM-1024, BLAKE3 MAC, AES-GCM wrap/duress, Ed25519 custody, Shamir GF(256), Sealed Drops, OPSEC JPEG/PNG sanitizer, and 7-check POST.
- **Volume & Filesystem Tests (7)**: Backup failover, Mission TTL expiration, Dead-Man's Switch auto-shred, hidden volume outer-MAC preservation, extent chains, and wipe-on-delete.
- **End-to-End CLI Tests (4)**: Full lifecycle across v1–v4 features.
- **Parser Fuzzing & Overflow Hardening (`fuzz_hardening.rs`, 6)**: ~7,000+ mutated, truncated, bit-flipped, and `u64::MAX` overflow inputs across volume headers, superblocks/inodes/extents, `.flcpack`/`.flcid`/`.flcpub`, Shamir shares, JPEG/PNG sanitizers, and custody JSONL — asserting zero panics and strict rejection.

---

## Security & Bug Reporting

- Review [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full threat model and out-of-scope caveats (compromised live OS, offline disk-image rollback, SSD wear-leveling, unsigned local macOS builds).
- To report a bug, use the built-in **Report Bug** button in the console (which generates an OPSEC-sanitized diagnostic summary with zero keys or paths) or open an issue via [GitHub Issues](https://github.com/skotinas/falcon/issues/new?template=bug_report.md).

---

## License

Dual-licensed under **MIT** ([LICENSE](LICENSE)) or **Apache-2.0**.
