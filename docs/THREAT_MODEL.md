# Falcon v0.4.0 — Threat Model

## In Scope

- **Offline theft / forensic imaging**: Every 4 KiB sector is encrypted with AES-256-XTS (or cascading AES-256-XTS + Serpent-256-XTS via `--cascade`), with FIPS 140-3 `K1 != K2` enforcement and unique sector tweaks. Free sectors are initialized with valid ciphertext rather than zeros.
- **Harvest-Now, Decrypt-Later (quantum adversary)**: Optional FIPS 203 **ML-KEM-1024** hybrid KDF (`--pq-key`) and asymmetric **Tactical Sealed Drops** (`.flcpack`, ML-KEM-1024 + AES-256-GCM + Ed25519 verify-before-decrypt).
- **Offline brute-force**: Argon2id (RFC 9106) with 256-bit per-slot salts (256 MiB standard, 512 MiB paranoid), optional 2FA keyfile mixing via HKDF-SHA512, and **Dead-Man's Switch** (`--max-attempts N`) auto-shredding.
- **Coercion / hostile capture**:
  - **Plausible Deniability Hidden Volume**: Independent inner volume inside the free upper half of a decoy volume with BLAKE3-XOF obfuscated header (zero magic signature) and synchronized outer MACs.
  - **Silent Duress / Panic Slot**: Indistinguishable from an active slot on disk; silently overwrites all headers with 3-pass CSPRNG and returns a normal auth failure.
  - **USB Kill-Switch Watchdog**: 250ms background monitor that immediately locks and zeroizes RAM keys when the watched physical token disappears.
  - **Mission TTL**: Enforces expiration timestamps on field-deployed volumes.
- **Tampering & evil-maid bit-flips**: Encrypt-then-MAC using keyed BLAKE3-256 tags bound to `(domain, volume_uuid, sector_index, ciphertext)`, full 16 KiB header MAC + mirrored backup header, and append-only **Ed25519-signed Chain-of-Custody** audit log.
- **Startup integrity**: Fail-closed FIPS 140-3 style **Power-On Self-Test (POST)** runs 7 KAT/pairwise checks before touching keys or storage.
- **OPSEC leakage**: Lossless JPEG EXIF/GPS/COM and PNG ancillary metadata stripping (`--sanitize`), optional zeroed inode/drop timestamps, and detached stealth headers (`.fhdr`).
- **Memory, swap & parser hardening**: Core dumps disabled (`RLIMIT_CORE = 0`, Linux `PR_SET_DUMPABLE = 0`), heap-pinned `mlock`/`VirtualLock` + `zeroize` on drop, loopback-only UI (`127.0.0.1`, per-session 256-bit token, strict `Host` check, CSP), and fuzz-tested overflow-safe binary parsers.
- **Accidental OS disk wipe**: Raw block devices require `--raw-device`, UI blocks raw devices outright, and primary OS boot drives are blocked.

## Out of Scope / Operational Caveats

- **Compromised live OS / hardware implant**: A keylogger, rootkit, or DMA/cold-boot attack while a volume is unlocked can capture credentials or RAM contents.
- **Whole-image rollback & offline strike-counter reset**: An adversary with a disk copy can snapshot and restore an older volume image (resetting the unauthenticated Dead-Man's Switch strike counter or rolling back the custody log). Defending against whole-disk rollback requires external monotonic hardware (TPM/HSM).
- **SSD / Flash wear-leveling**: Flash FTLs may retain previous physical blocks until trimmed or ATA/NVMe secure-erased. Always encrypt flash media before writing sensitive plaintext.
- **Clock manipulation on Mission TTL**: Mission TTL checks local system UTC time; an offline adversary who sets the system clock backward can bypass an expired TTL.
- **Weak passphrases**: Security degrades if low-entropy passphrases are used without a CSPRNG keyfile or PQ keypair.
- **macOS Gatekeeper / Code Signing**: `Falcon.app` is built locally and unsigned (not Apple-notarized); distributing it to other Macs requires ad-hoc/Developer ID signing or removing the quarantine attribute (`xattr -cr`).
