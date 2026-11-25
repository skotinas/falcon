# Falcon v0.4.0 (COMSEC / Tactical Field Edition)

Cross-platform block-level disk, sealed drop, and encrypted volume controller written in Rust.

## Core Capabilities

- **FIPS 140-3 Power-On Self-Test (`falcon post`)**: Runs 7 fail-closed Known-Answer & pairwise self-tests (`AES-256-XTS Vector 10`, `Cascade Serpent`, `BLAKE3 MAC`, `AES-256-GCM`, `ML-KEM-1024`, `Shamir + Ed25519`, `Sealed Drop`) in ~4 ms before touching any keys or storage.
- **Tactical Sealed Drops (`falcon identity` / `falcon seal` / `falcon unseal`)**: Post-quantum asymmetric encrypted & signed file packages (`.flcpack`) between operators without any shared passphrase — encapsulates to recipient's **ML-KEM-1024** public bundle (`.flcpub`), encrypts with **AES-256-GCM** + HKDF-SHA512, and verifies sender's **Ed25519** signature before decryption (with optional sender pinning and `--sanitize` OPSEC stripping).
- **AES-256-XTS & Cascading Serpent-256-XTS (`--cascade`)**: 4096-byte sectors with independent 512/1024-bit subkeys (`K1 != K2` enforced on both ciphers).
- **Post-Quantum Hybrid (`--pq-key`)**: **FIPS 203 ML-KEM-1024** (CNSA 2.0) combined with Argon2id via HKDF-SHA512.
- **Plausible Deniability Hidden Volume (`falcon hidden create` / `--hidden`)**: Independent encrypted inner volume inside the unallocated upper half of an outer decoy volume, with BLAKE3-XOF obfuscated header (zero `FLCNDSK1` bytes in data area) and refreshed outer MACs so decoy verification stays 100% clean.
- **Dead-Man's Switch & Mission TTL**:
  - **Auto-Shred Strike Counter (`--max-attempts N`)**: Permanently shreds headers after *N* consecutive failed unlock attempts.
  - **Mission TTL (`--ttl-hours H`)**: Enforces volume expiration timestamp.
  - **USB Kill-Switch Watchdog (`falcon ui --usb-watch <PATH>`)**: 250ms background watcher that immediately locks and zeroizes RAM keys if the physical USB token is pulled.
- **Silent Duress / Panic Password (`falcon duress`)**: Indistinguishable from an active slot on disk; triggers silent 3-pass CSPRNG crypto-shredding on entry.
- **Tamper-Evident Chain-of-Custody (`falcon custody verify`)**: Append-only BLAKE3 hash-chained & **Ed25519-signed** audit trail stored inside the encrypted volume.
- **Shamir M-of-N + Air-Gapped QR Keycards (`falcon shamir split --qr --qr-dir ...`)**: Constant-time `GF(256)` threshold sharing with terminal Unicode QR codes and printable SVG keycards.
- **OPSEC Metadata Sanitizer (`falcon put --sanitize`, `falcon seal --sanitize`)**: Losslessly strips JPEG EXIF/GPS/COM and PNG ancillary metadata chunks and zeroes timestamps.
- **Parser Fuzzing & Hardening Suite (`tests/fuzz_hardening.rs`)**: Thousands of deterministic mutated, truncated, bit-flipped, and integer-overflow inputs across every untrusted binary/text parser — verified zero panics and strict rejection.
- **macOS Desktop Launcher (`Falcon.app`)**: One-click self-contained bundle built via `./scripts/build_macos_app.sh` (runs fail-closed POST, auto-fallback loopback port `7842..7852`, reuses running instance).
- **Local Tactical Console (`falcon ui`)**: Loopback-only (`127.0.0.1`) with 256-bit per-session token, strict `Host` validation, CSP, Day/Night mode, and 6 languages (`EN`, `EL`, `DE`, `FR`, `ES`, `IT`).

## Build & Run

```bash
cargo build --release
./target/release/falcon post
./target/release/falcon ui --open

# Rebuild macOS desktop app bundle
./scripts/build_macos_app.sh /Users/spiros/Desktop/Falcon.app

# Manually check GitHub Releases for updates (never phones home automatically)
./target/release/falcon update
```

## Updates & Bug Reports

- **Air-gap compliant**: Falcon never connects to the internet automatically. Checking for updates (`falcon update` or **GET UPDATE** in the console) runs strictly on manual operator request against [GitHub Releases](https://github.com/skotinas/falcon/releases).
- **OPSEC-safe Bug Reports**: Use **REPORT BUG** in the console (or open an issue at [GitHub Issues](https://github.com/skotinas/falcon/issues/new?template=bug_report.md)) — auto-generated diagnostics exclude all keys, passphrases, volume UUIDs, and file paths.

## Sealed Drops Quick Example

```bash
./target/release/falcon identity generate alpha.flcid --pub-out alpha.flcpub --callsign ALPHA-1
./target/release/falcon identity generate bravo.flcid --pub-out bravo.flcpub --callsign BRAVO-2
./target/release/falcon seal recon.jpg --to bravo.flcpub --from alpha.flcid --out drop.flcpack --sanitize
./target/release/falcon unseal drop.flcpack --identity bravo.flcid --expect-sender alpha.flcpub --out clean.jpg
```
