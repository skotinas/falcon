mod ui;
mod update;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use falcon_crypto::{
    analyze_entropy, combine_shares, harden_process, hash_keyfile, random_bytes,
    render_keycard_svg, render_terminal_qr, run_crypto_benchmark, run_power_on_self_test,
    sanitize_file_bytes, seal_package, split_secret, unseal_package, CipherMode, KdfProfile,
    OperatorIdentity, OperatorPublicBundle, PqKeypair, SecureArray, SecureBytes, Share,
    SECTOR_SIZE,
};
use falcon_fs::FalconFs;
use falcon_volume::{
    is_protected_system_disk, is_raw_device_path, AuthMaterial, CreateOptions, FileBlockDevice,
    Volume, VolumeLayout,
};
use indicatif::{ProgressBar, ProgressStyle};
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs::{self, File, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

#[derive(Parser)]
#[command(
    name = "falcon",
    version,
    about = "Falcon v0.4 — COMSEC disk, sealed drop & encrypted volume controller (AES-256-XTS / Serpent Cascade / ML-KEM-1024 / BLAKE3 / Ed25519 / POST)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, ValueEnum)]
enum ProfileArg {
    FastTest,
    Interactive,
    Standard,
    Paranoid,
}

impl From<ProfileArg> for KdfProfile {
    fn from(value: ProfileArg) -> Self {
        match value {
            ProfileArg::FastTest => KdfProfile::FastTest,
            ProfileArg::Interactive => KdfProfile::Interactive,
            ProfileArg::Standard => KdfProfile::Standard,
            ProfileArg::Paranoid => KdfProfile::Paranoid,
        }
    }
}

#[derive(Args, Clone)]
struct AuthArgs {
    /// External 2FA keyfile bound to the passphrase
    #[arg(long)]
    keyfile: Option<PathBuf>,

    /// Post-quantum ML-KEM-1024 hybrid keypair file (FIPS 203)
    #[arg(long)]
    pq_key: Option<PathBuf>,

    /// Detached stealth header file (.fhdr)
    #[arg(long)]
    header: Option<PathBuf>,

    /// Open a Plausible Deniability Hidden Volume inside an outer decoy container
    #[arg(long, default_value_t = false)]
    hidden: bool,

    /// Read passphrase from an env var (for scripts/CI)
    #[arg(long)]
    passphrase_env: Option<String>,

    /// Allow operating on a raw block device (/dev/diskX, /dev/sdX, etc.)
    #[arg(long, default_value_t = false)]
    raw_device: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Run FIPS 140-3 Power-On Self-Test (POST) and display verification table
    Post,

    /// Create a new encrypted volume
    Create {
        volume: PathBuf,
        /// Usable data size (e.g. 16M, 512M, 4G)
        #[arg(long)]
        size: String,
        #[arg(long, value_enum, default_value_t = ProfileArg::Standard)]
        profile: ProfileArg,
        #[arg(long, default_value = "primary")]
        label: String,
        /// Enable cascading AES-256-XTS + Serpent-256-XTS sector encryption
        #[arg(long, default_value_t = false)]
        cascade: bool,
        /// Mission TTL: volume expires after N hours (0 = never)
        #[arg(long, default_value_t = 0)]
        ttl_hours: u64,
        /// Dead-Man's Switch: auto-shred after N consecutive failed unlock attempts (0 = disabled)
        #[arg(long, default_value_t = 0)]
        max_attempts: u32,
        /// Disable per-sector BLAKE3 MACs (pure XTS only)
        #[arg(long, default_value_t = false)]
        no_integrity: bool,
        #[command(flatten)]
        auth: AuthArgs,
    },

    /// Provision a Plausible Deniability Hidden Volume inside an existing outer decoy volume
    Hidden {
        #[command(subcommand)]
        action: HiddenAction,
    },

    /// Show volume header metadata, policies, and key slots
    Info {
        volume: PathBuf,
        #[arg(long)]
        header: Option<PathBuf>,
    },

    /// List files in the volume
    Ls {
        volume: PathBuf,
        #[command(flatten)]
        auth: AuthArgs,
    },

    /// Copy a local file into the volume (supports --sanitize for OPSEC EXIF/GPS/timestamp strip)
    Put {
        volume: PathBuf,
        local_file: PathBuf,
        vault_path: Option<String>,
        /// Strip JPEG EXIF/GPS & PNG metadata and zero internal inode timestamps
        #[arg(long, default_value_t = false)]
        sanitize: bool,
        #[command(flatten)]
        auth: AuthArgs,
    },

    /// Extract and verify a file from the volume
    Get {
        volume: PathBuf,
        vault_path: String,
        local_dest: PathBuf,
        #[command(flatten)]
        auth: AuthArgs,
    },

    /// Delete a file and overwrite its sectors
    Rm {
        volume: PathBuf,
        vault_path: String,
        #[command(flatten)]
        auth: AuthArgs,
    },

    /// Verify headers and every sector MAC
    Verify {
        volume: PathBuf,
        #[command(flatten)]
        auth: AuthArgs,
    },

    /// Inspect or verify the Ed25519 hash-chained Chain-of-Custody log
    Custody {
        #[command(subcommand)]
        action: CustodyAction,
    },

    /// Rotate passphrase/keyfile on a key slot
    Passwd {
        volume: PathBuf,
        #[arg(long)]
        slot: Option<usize>,
        #[arg(long)]
        new_keyfile: Option<PathBuf>,
        #[arg(long)]
        new_pq_key: Option<PathBuf>,
        #[arg(long)]
        new_passphrase_env: Option<String>,
        #[arg(long, value_enum)]
        new_profile: Option<ProfileArg>,
        #[command(flatten)]
        auth: AuthArgs,
    },

    /// Add or remove key slots
    Keyslot {
        #[command(subcommand)]
        action: KeyslotAction,
    },

    /// Configure an indistinguishable duress / panic password (silently shreds volume on use)
    Duress {
        volume: PathBuf,
        #[arg(long)]
        slot: Option<usize>,
        #[arg(long, default_value = "backup")]
        label: String,
        #[arg(long, value_enum, default_value_t = ProfileArg::Standard)]
        profile: ProfileArg,
        #[arg(long)]
        duress_passphrase_env: Option<String>,
        #[command(flatten)]
        auth: AuthArgs,
    },

    /// Shamir's Secret Sharing (M-of-N split & combine + Air-Gapped QR Keycards)
    Shamir {
        #[command(subcommand)]
        action: ShamirAction,
    },

    /// Backup, restore, or repair volume headers
    Header {
        #[command(subcommand)]
        action: HeaderAction,
    },

    /// Generate a random 2FA keyfile
    Keygen {
        output: PathBuf,
        #[arg(long, default_value_t = 64)]
        bytes: usize,
    },

    /// Generate or inspect ML-KEM-1024 + Ed25519 Operator Identities for Tactical Sealed Drops
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
    },

    /// Seal a file to a recipient's public bundle (ML-KEM-1024 + AES-256-GCM + Ed25519 signature)
    Seal {
        input: PathBuf,
        /// Recipient public bundle (.flcpub)
        #[arg(long)]
        to: PathBuf,
        /// Sender private operator identity (.flcid)
        #[arg(long)]
        from: PathBuf,
        /// Output sealed drop package (.flcpack)
        #[arg(long)]
        out: PathBuf,
        /// Strip JPEG EXIF/GPS & PNG metadata and zero drop timestamp before sealing
        #[arg(long, default_value_t = false)]
        sanitize: bool,
    },

    /// Verify Ed25519 signature and unseal a post-quantum .flcpack drop
    Unseal {
        package: PathBuf,
        /// Recipient private operator identity (.flcid)
        #[arg(long)]
        identity: PathBuf,
        /// Optional pinned sender public bundle (.flcpub) to enforce sender identity
        #[arg(long)]
        expect_sender: Option<PathBuf>,
        /// Output path for decrypted payload
        #[arg(long)]
        out: PathBuf,
    },

    /// Generate a FIPS 203 ML-KEM-1024 post-quantum hybrid keypair file
    PqKeygen { output: PathBuf },

    /// Run crypto throughput benchmark and optional volume Shannon entropy analysis
    Diag {
        volume: Option<PathBuf>,
        #[arg(long, default_value_t = 2048)]
        sectors: usize,
    },

    /// Destroy primary & backup (or detached) headers permanently
    Shred {
        volume: PathBuf,
        #[arg(long)]
        header: Option<PathBuf>,
        #[arg(long)]
        yes_destroy_forever: bool,
        #[arg(long, default_value_t = false)]
        raw_device: bool,
    },

    /// Manually check GitHub Releases for a newer Falcon version (never phones home automatically)
    Update,

    /// Launch the local localhost-only workstation console (index.html)
    Ui {
        #[arg(long, default_value_t = 7842)]
        port: u16,
        #[arg(long, default_value_t = 15)]
        auto_lock_mins: u64,
        /// Optional physical USB token / mount path for 250ms Kill-Switch Watchdog
        #[arg(long)]
        usb_watch: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        open: bool,
    },
}

#[derive(Subcommand)]
enum HiddenAction {
    /// Provision a hidden volume inside the free upper half of an unlocked outer decoy volume
    Create {
        outer_volume: PathBuf,
        #[arg(long, value_enum, default_value_t = ProfileArg::Standard)]
        profile: ProfileArg,
        #[arg(long, default_value_t = false)]
        cascade: bool,
        #[arg(long, default_value = "inner")]
        label: String,
        #[arg(long)]
        hidden_passphrase_env: Option<String>,
        #[arg(long)]
        hidden_keyfile: Option<PathBuf>,
        #[arg(long)]
        hidden_pq_key: Option<PathBuf>,
        #[command(flatten)]
        auth: AuthArgs,
    },
}

#[derive(Subcommand)]
enum CustodyAction {
    /// Show and cryptographically verify every Ed25519-signed custody entry
    Verify {
        volume: PathBuf,
        #[command(flatten)]
        auth: AuthArgs,
    },
}

#[derive(Subcommand)]
enum KeyslotAction {
    Add {
        volume: PathBuf,
        #[arg(long)]
        slot: Option<usize>,
        #[arg(long, default_value = "recovery")]
        label: String,
        #[arg(long, value_enum, default_value_t = ProfileArg::Standard)]
        profile: ProfileArg,
        #[arg(long)]
        new_keyfile: Option<PathBuf>,
        #[arg(long)]
        new_pq_key: Option<PathBuf>,
        #[arg(long)]
        new_passphrase_env: Option<String>,
        #[command(flatten)]
        auth: AuthArgs,
    },
    Remove {
        volume: PathBuf,
        #[arg(long)]
        slot: usize,
        #[command(flatten)]
        auth: AuthArgs,
    },
}

#[derive(Subcommand)]
enum ShamirAction {
    Split {
        #[arg(long, default_value_t = 3)]
        threshold: u8,
        #[arg(long, default_value_t = 5)]
        shares: u8,
        #[arg(long)]
        in_file: Option<PathBuf>,
        #[arg(long)]
        out_keyfile: Option<PathBuf>,
        /// Print Unicode QR code for each share in the terminal
        #[arg(long, default_value_t = false)]
        qr: bool,
        /// Save printable air-gapped SVG keycards into this directory
        #[arg(long)]
        qr_dir: Option<PathBuf>,
    },
    Combine {
        #[arg(long)]
        out: PathBuf,
        #[arg(required = true)]
        shares: Vec<String>,
    },
}

#[derive(Subcommand)]
enum IdentityAction {
    /// Generate a new ML-KEM-1024 + Ed25519 Operator Identity (.flcid) and Public Bundle (.flcpub)
    Generate {
        /// Private operator identity output path (.flcid, 0600)
        identity_out: PathBuf,
        /// Shareable public bundle output path (.flcpub)
        #[arg(long)]
        pub_out: PathBuf,
        /// Operator callsign (up to 32 bytes)
        #[arg(long, default_value = "OPERATOR")]
        callsign: String,
    },
    /// Inspect an operator identity (.flcid) or public bundle (.flcpub)
    Info { file: PathBuf },
}

#[derive(Subcommand)]
enum HeaderAction {
    Backup {
        volume: PathBuf,
        output: PathBuf,
        #[arg(long)]
        header: Option<PathBuf>,
    },
    Restore {
        volume: PathBuf,
        input: PathBuf,
        #[arg(long)]
        header: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        raw_device: bool,
    },
    Repair {
        volume: PathBuf,
        #[command(flatten)]
        auth: AuthArgs,
    },
}

fn main() -> Result<()> {
    let _ = harden_process();

    // FIPS 140-3 fail-closed Power-On Self-Test before touching any keys or storage.
    let post_report = run_power_on_self_test()
        .context("CRITICAL: FIPS 140-3 Power-On Self-Test (POST) FAILED — halting")?;

    let cli = Cli::parse();
    match cli.command {
        Commands::Post => {
            println!(
                "Falcon FIPS 140-3 Power-On Self-Test (POST): {} ({:.2} ms)",
                if post_report.passed { "PASS" } else { "FAIL" },
                post_report.duration_ms
            );
            for c in &post_report.checks {
                println!(
                    "  [{}] {:<34} ({})",
                    if c.passed { "PASS" } else { "FAIL" },
                    c.name,
                    c.standard
                );
            }
            Ok(())
        }
        Commands::Create {
            volume,
            size,
            profile,
            label,
            cascade,
            ttl_hours,
            max_attempts,
            no_integrity,
            auth,
        } => cmd_create(
            &volume,
            &size,
            profile.into(),
            &label,
            cascade,
            ttl_hours,
            max_attempts,
            !no_integrity,
            &auth,
        ),
        Commands::Hidden { action } => match action {
            HiddenAction::Create {
                outer_volume,
                profile,
                cascade,
                label,
                hidden_passphrase_env,
                hidden_keyfile,
                hidden_pq_key,
                auth,
            } => cmd_hidden_create(
                &outer_volume,
                profile.into(),
                cascade,
                &label,
                hidden_passphrase_env.as_deref(),
                hidden_keyfile.as_deref(),
                hidden_pq_key.as_deref(),
                &auth,
            ),
        },
        Commands::Info { volume, header } => cmd_info(&volume, header.as_deref()),
        Commands::Ls { volume, auth } => cmd_ls(&volume, &auth),
        Commands::Put {
            volume,
            local_file,
            vault_path,
            sanitize,
            auth,
        } => cmd_put(&volume, &local_file, vault_path.as_deref(), sanitize, &auth),
        Commands::Get {
            volume,
            vault_path,
            local_dest,
            auth,
        } => cmd_get(&volume, &vault_path, &local_dest, &auth),
        Commands::Rm {
            volume,
            vault_path,
            auth,
        } => cmd_rm(&volume, &vault_path, &auth),
        Commands::Verify { volume, auth } => cmd_verify(&volume, &auth),
        Commands::Custody { action } => match action {
            CustodyAction::Verify { volume, auth } => cmd_custody_verify(&volume, &auth),
        },
        Commands::Passwd {
            volume,
            slot,
            new_keyfile,
            new_pq_key,
            new_passphrase_env,
            new_profile,
            auth,
        } => cmd_passwd(
            &volume,
            slot,
            new_keyfile.as_deref(),
            new_pq_key.as_deref(),
            new_passphrase_env.as_deref(),
            new_profile.map(Into::into),
            &auth,
        ),
        Commands::Keyslot { action } => match action {
            KeyslotAction::Add {
                volume,
                slot,
                label,
                profile,
                new_keyfile,
                new_pq_key,
                new_passphrase_env,
                auth,
            } => cmd_keyslot_add(
                &volume,
                slot,
                &label,
                profile.into(),
                new_keyfile.as_deref(),
                new_pq_key.as_deref(),
                new_passphrase_env.as_deref(),
                &auth,
            ),
            KeyslotAction::Remove { volume, slot, auth } => {
                cmd_keyslot_remove(&volume, slot, &auth)
            }
        },
        Commands::Duress {
            volume,
            slot,
            label,
            profile,
            duress_passphrase_env,
            auth,
        } => cmd_duress_add(
            &volume,
            slot,
            &label,
            profile.into(),
            duress_passphrase_env.as_deref(),
            &auth,
        ),
        Commands::Shamir { action } => match action {
            ShamirAction::Split {
                threshold,
                shares,
                in_file,
                out_keyfile,
                qr,
                qr_dir,
            } => cmd_shamir_split(
                threshold,
                shares,
                in_file.as_deref(),
                out_keyfile.as_deref(),
                qr,
                qr_dir.as_deref(),
            ),
            ShamirAction::Combine { out, shares } => cmd_shamir_combine(&out, &shares),
        },
        Commands::Header { action } => match action {
            HeaderAction::Backup {
                volume,
                output,
                header,
            } => cmd_header_backup(&volume, &output, header.as_deref()),
            HeaderAction::Restore {
                volume,
                input,
                header,
                raw_device,
            } => cmd_header_restore(&volume, &input, header.as_deref(), raw_device),
            HeaderAction::Repair { volume, auth } => cmd_header_repair(&volume, &auth),
        },
        Commands::Keygen { output, bytes } => cmd_keygen(&output, bytes),
        Commands::Identity { action } => match action {
            IdentityAction::Generate {
                identity_out,
                pub_out,
                callsign,
            } => cmd_identity_generate(&identity_out, &pub_out, &callsign),
            IdentityAction::Info { file } => cmd_identity_info(&file),
        },
        Commands::Seal {
            input,
            to,
            from,
            out,
            sanitize,
        } => cmd_seal(&input, &to, &from, &out, sanitize),
        Commands::Unseal {
            package,
            identity,
            expect_sender,
            out,
        } => cmd_unseal(&package, &identity, expect_sender.as_deref(), &out),
        Commands::PqKeygen { output } => cmd_pq_keygen(&output),
        Commands::Diag { volume, sectors } => cmd_diag(volume.as_deref(), sectors),
        Commands::Shred {
            volume,
            header,
            yes_destroy_forever,
            raw_device,
        } => cmd_shred(&volume, header.as_deref(), yes_destroy_forever, raw_device),
        Commands::Update => {
            let res = update::check_for_updates();
            println!("Falcon Update Check ({})", update::GITHUB_REPO);
            println!("  Installed: v{}", res.current_version);
            if let Some(ref latest) = res.latest_version {
                println!("  Latest:    v{latest}");
            }
            println!("  Status:    {}", res.message);
            println!("  Releases:  {}", res.release_url);
            println!("  Issues:    {}", update::ISSUES_URL);
            Ok(())
        }
        Commands::Ui {
            port,
            auto_lock_mins,
            usb_watch,
            open,
        } => ui::run_ui(port, auto_lock_mins, usb_watch, open, post_report),
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_create(
    volume_path: &Path,
    size_str: &str,
    profile: KdfProfile,
    label: &str,
    cascade: bool,
    ttl_hours: u64,
    max_attempts: u32,
    integrity_enabled: bool,
    auth: &AuthArgs,
) -> Result<()> {
    let data_bytes = parse_size(size_str)?;
    let detached = auth.header.is_some();
    let layout = VolumeLayout::compute(data_bytes, integrity_enabled, detached)?;
    let kdf_params = profile.params();
    let cipher_mode = if cascade {
        CipherMode::CascadeAesSerpentXts
    } else {
        CipherMode::Aes256Xts
    };

    let expires_at_unix = if ttl_hours > 0 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            .saturating_add(ttl_hours.saturating_mul(3600))
    } else {
        0
    };

    let passphrase = read_new_passphrase(auth.passphrase_env.as_deref(), "New passphrase")?;
    let keyfile_hash = load_optional_keyfile(auth.keyfile.as_deref())?;
    let pq_kp = load_optional_pq_keypair(auth.pq_key.as_deref())?;

    let device = FileBlockDevice::create(volume_path, layout.total_bytes, auth.raw_device)?;

    let pb = make_progress_bar(layout.data_sector_count, "Initializing");
    let opts = CreateOptions {
        data_bytes,
        kdf_params,
        integrity_enabled,
        cipher_mode,
        detached_header_path: auth.header.clone(),
        expires_at_unix,
        max_failed_attempts: max_attempts,
        label: label.to_string(),
    };
    let material = AuthMaterial {
        passphrase: passphrase.as_slice(),
        keyfile_hash: keyfile_hash.as_ref().map(|k| k.as_array()),
        pq_keypair: pq_kp.as_ref(),
    };

    let vol = Volume::create(device, &opts, &material, |done, _| pb.set_position(done))?;
    pb.finish_and_clear();

    let uuid = vol.header().uuid_hex();
    let sectors = vol.sector_count();
    let custody_pk = vol.custody_pubkey_hex();
    let mut fs = FalconFs::format(vol)?;
    let _ = fs.append_custody_event("CREATE", &format!("cipher={}", cipher_mode.display_name()));

    println!("Created Falcon volume: {}", volume_path.display());
    println!("  UUID:        {uuid}");
    println!(
        "  Cipher:      {} (4096-byte sectors)",
        cipher_mode.display_name()
    );
    println!(
        "  Integrity:   {}",
        if integrity_enabled {
            "BLAKE3-256 (per-sector + header)"
        } else {
            "disabled"
        }
    );
    println!("  Custody Key: Ed25519 {}", &custody_pk[..24]);
    println!(
        "  KDF:         Argon2id ({} MiB, t={}, p={})",
        kdf_params.memory_kib / 1024,
        kdf_params.iterations,
        kdf_params.parallelism
    );
    println!(
        "  Size:        {} usable ({sectors} sectors, {} on disk)",
        format_bytes(sectors * SECTOR_SIZE as u64),
        format_bytes(layout.total_bytes)
    );
    if ttl_hours > 0 {
        println!("  Mission TTL: {ttl_hours}h (expires UNIX {expires_at_unix})");
    }
    if max_attempts > 0 {
        println!("  Dead-Man:    AUTO-SHRED after {max_attempts} failed attempts");
    }
    if let Some(ref h) = auth.header {
        println!("  Stealth:     DETACHED HEADER at '{}'", h.display());
    }
    if auth.pq_key.is_some() {
        println!("  PQ Hybrid:   ML-KEM-1024 (FIPS 203)");
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_hidden_create(
    outer_volume: &Path,
    profile: KdfProfile,
    cascade: bool,
    label: &str,
    hidden_passphrase_env: Option<&str>,
    hidden_keyfile: Option<&Path>,
    hidden_pq_key: Option<&Path>,
    outer_auth: &AuthArgs,
) -> Result<()> {
    let vol = unlock_volume(outer_volume, outer_auth)?;
    let mut outer_fs = FalconFs::mount(vol)?;
    if !outer_fs.is_upper_half_free() {
        bail!("upper half of outer volume is occupied by decoy files; cannot safely create hidden volume");
    }

    let hidden_pass = read_new_passphrase(hidden_passphrase_env, "Hidden volume passphrase")?;
    let hidden_kf = load_optional_keyfile(hidden_keyfile)?;
    let hidden_pq = load_optional_pq_keypair(hidden_pq_key)?;
    let hidden_auth = AuthMaterial {
        passphrase: hidden_pass.as_slice(),
        keyfile_hash: hidden_kf.as_ref().map(|k| k.as_array()),
        pq_keypair: hidden_pq.as_ref(),
    };
    let cipher_mode = if cascade {
        CipherMode::CascadeAesSerpentXts
    } else {
        CipherMode::Aes256Xts
    };

    let (start_sec, hidden_secs) = outer_fs.volume_mut().create_hidden_in_outer(
        &hidden_auth,
        &profile.params(),
        cipher_mode,
        label,
    )?;

    // Format FalconFS inside the newly provisioned hidden volume
    {
        let dev = FileBlockDevice::open_rw(outer_volume, outer_auth.raw_device)?;
        let hidden_vol = Volume::open_hidden(dev, &hidden_auth, outer_auth.header.as_deref())?;
        let mut hidden_fs = FalconFs::format(hidden_vol)?;
        let _ =
            hidden_fs.append_custody_event("CREATE_HIDDEN", "plausible-deniability inner volume");
    }

    // Re-sync outer BLAKE3 MACs after hidden FS metadata was written so outer verify stays clean
    outer_fs.volume_mut().refresh_upper_half_macs()?;

    println!(
        "Created Plausible Deniability Hidden Volume inside '{}'",
        outer_volume.display()
    );
    println!("  Region:  starting at outer sector {start_sec}");
    println!(
        "  Usable:  {} ({hidden_secs} sectors)",
        format_bytes(hidden_secs * SECTOR_SIZE as u64)
    );
    println!("  Cipher:  {}", cipher_mode.display_name());
    println!("  Header:  BLAKE3-XOF obfuscated (zero magic bytes on disk)");
    Ok(())
}

fn cmd_info(volume_path: &Path, detached_header: Option<&Path>) -> Result<()> {
    let mut device = FileBlockDevice::open_ro(volume_path)?;
    let (hdr, from_backup) = Volume::inspect_header(&mut device, detached_header)?;

    println!("Falcon Volume: {}", volume_path.display());
    println!("  Version:     {}", hdr.version);
    println!("  UUID:        {}", hdr.uuid_hex());
    println!(
        "  Header:      {}",
        if detached_header.is_some() {
            "detached (stealth mode)"
        } else if from_backup {
            "BACKUP (primary header damaged)"
        } else {
            "primary"
        }
    );
    println!(
        "  Cipher:      {} ({}-byte sectors)",
        hdr.cipher_mode().display_name(),
        hdr.sector_size
    );
    println!(
        "  Integrity:   {}",
        if hdr.integrity_enabled() {
            "BLAKE3-256 enabled"
        } else {
            "disabled"
        }
    );
    if hdr.expires_at_unix > 0 {
        println!("  Mission TTL: expires UNIX {}", hdr.expires_at_unix);
    }
    if hdr.max_failed_attempts > 0 {
        println!(
            "  Dead-Man:    {}/{} failed attempts before auto-shred",
            hdr.failed_attempts, hdr.max_failed_attempts
        );
    }
    println!(
        "  Capacity:    {} ({} sectors)",
        format_bytes(hdr.data_sector_count * hdr.sector_size as u64),
        hdr.data_sector_count
    );
    println!("  Key slots:   {}/4 active", hdr.active_slot_count());

    for (idx, slot) in hdr.key_slots.iter().enumerate() {
        if slot.active {
            println!(
                "    [{idx}] active  label=\"{}\"  Argon2id({} MiB, t={}, p={})  keyfile={}  pq={}",
                slot.label,
                slot.kdf_params.memory_kib / 1024,
                slot.kdf_params.iterations,
                slot.kdf_params.parallelism,
                if slot.requires_keyfile { "yes" } else { "no" },
                if slot.pq_hybrid { "ML-KEM-1024" } else { "no" }
            );
        } else {
            println!("    [{idx}] empty");
        }
    }

    Ok(())
}

fn cmd_ls(volume_path: &Path, auth: &AuthArgs) -> Result<()> {
    let vol = unlock_volume(volume_path, auth)?;
    let mut fs = FalconFs::mount(vol)?;
    let files = fs.list_files()?;
    let stats = fs.stats()?;

    if files.is_empty() {
        println!("(empty)");
    } else {
        println!("{:<12}  {:<16}  PATH", "SIZE", "SHA-256");
        println!("{}", "-".repeat(60));
        for f in &files {
            println!(
                "{:<12}  {:<16}  {}",
                format_bytes(f.size),
                &hex::encode(f.sha256)[..16],
                f.path
            );
        }
    }

    println!(
        "\n{}/{} sectors used ({} free) | {}/{} files",
        stats.used_sectors,
        stats.total_sectors,
        format_bytes(stats.free_sectors * SECTOR_SIZE as u64),
        stats.file_count,
        stats.max_files
    );

    Ok(())
}

fn cmd_put(
    volume_path: &Path,
    local_file: &Path,
    vault_path: Option<&str>,
    sanitize: bool,
    auth: &AuthArgs,
) -> Result<()> {
    let target_name = match vault_path {
        Some(p) => p.to_string(),
        None => local_file
            .file_name()
            .and_then(|n| n.to_str())
            .context("could not infer filename; pass an explicit vault path")?
            .to_string(),
    };

    let vol = unlock_volume(volume_path, auth)?;
    let mut fs = FalconFs::mount(vol)?;

    let entry = if sanitize {
        let mut raw = Vec::new();
        File::open(local_file)
            .with_context(|| format!("failed to open '{}'", local_file.display()))?
            .read_to_end(&mut raw)?;
        let (mut clean, rep) = sanitize_file_bytes(&raw);
        raw.zeroize();
        let entry = fs.put_file_opts(&target_name, Cursor::new(&clean), true)?;
        clean.zeroize();
        let _ = fs.append_custody_event(
            "PUT_SANITIZED",
            &format!(
                "{} ({}B, fmt={}, stripped={} segs/{}B)",
                entry.path, entry.size, rep.format, rep.segments_stripped, rep.bytes_removed
            ),
        );
        println!(
            "OPSEC sanitized ({}: stripped {} segment(s), {} bytes removed, inode timestamps zeroed)",
            rep.format, rep.segments_stripped, rep.bytes_removed
        );
        entry
    } else {
        let file = File::open(local_file)
            .with_context(|| format!("failed to open '{}'", local_file.display()))?;
        let entry = fs.put_file(&target_name, file)?;
        let _ = fs.append_custody_event("PUT", &format!("{} ({}B)", entry.path, entry.size));
        entry
    };

    println!(
        "Stored '{}' ({}) sha256={}",
        entry.path,
        format_bytes(entry.size),
        hex::encode(entry.sha256)
    );
    Ok(())
}

fn cmd_get(volume_path: &Path, vault_path: &str, local_dest: &Path, auth: &AuthArgs) -> Result<()> {
    let vol = unlock_volume(volume_path, auth)?;
    let mut fs = FalconFs::mount(vol)?;

    let out_file = File::create(local_dest)
        .with_context(|| format!("failed to create '{}'", local_dest.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = out_file.set_permissions(std::fs::Permissions::from_mode(0o600));
    }

    let entry = match fs.get_file(vault_path, out_file) {
        Ok(e) => e,
        Err(e) => {
            // Never leave unverified or tampered plaintext on disk if integrity check fails.
            let _ = fs::remove_file(local_dest);
            return Err(e.into());
        }
    };
    let _ = fs.append_custody_event("GET", &entry.path);
    println!(
        "Extracted '{}' -> '{}' ({}) sha256={}",
        entry.path,
        local_dest.display(),
        format_bytes(entry.size),
        hex::encode(entry.sha256)
    );
    Ok(())
}

fn cmd_rm(volume_path: &Path, vault_path: &str, auth: &AuthArgs) -> Result<()> {
    let vol = unlock_volume(volume_path, auth)?;
    let mut fs = FalconFs::mount(vol)?;
    fs.remove_file(vault_path)?;
    let _ = fs.append_custody_event("RM_WIPE", vault_path);
    println!("Removed '{vault_path}' and wiped freed sectors.");
    Ok(())
}

fn cmd_verify(volume_path: &Path, auth: &AuthArgs) -> Result<()> {
    let mut vol = unlock_volume(volume_path, auth)?;
    let total = vol.sector_count();
    let pb = make_progress_bar(total, "Verifying");
    let report = vol.verify_all_sectors(|done, _| pb.set_position(done))?;
    pb.finish_and_clear();

    println!("Falcon Integrity Check");
    println!(
        "  Primary header: {}",
        if report.primary_header_ok {
            "OK"
        } else {
            "FAILED"
        }
    );
    if report.hidden_volume {
        println!("  Header mode:    hidden (BLAKE3-XOF obfuscated)");
    } else if report.detached_header {
        println!("  Header mode:    detached (stealth)");
    } else {
        println!(
            "  Backup header:  {}",
            if report.backup_header_ok {
                "OK"
            } else {
                "FAILED"
            }
        );
        println!(
            "  Headers synced: {}",
            if report.headers_identical {
                "yes"
            } else {
                "no"
            }
        );
    }
    println!(
        "  Data sectors:   {}/{} OK",
        report.verified_sectors, report.total_sectors
    );

    if report.is_clean() {
        println!("OK: no tampering detected.");
        Ok(())
    } else {
        if !report.corrupted_sectors.is_empty() {
            println!(
                "TAMPERING DETECTED in {} sector(s): {:?}",
                report.corrupted_sectors.len(),
                &report.corrupted_sectors[..report.corrupted_sectors.len().min(20)]
            );
        }
        bail!("integrity verification failed");
    }
}

fn cmd_custody_verify(volume_path: &Path, auth: &AuthArgs) -> Result<()> {
    let vol = unlock_volume(volume_path, auth)?;
    let mut fs = FalconFs::mount(vol)?;
    let entries = fs.read_custody_log()?;
    let report = fs.verify_custody_log()?;

    println!("Falcon Ed25519 Chain-of-Custody Audit");
    println!("  Verifying Key: {}", report.pubkey_hex);
    println!("  Entries:       {}", report.entry_count);
    println!("  Chain Head:    {}", report.head_hash);
    println!(
        "  Verification:  {}",
        if report.valid {
            "VALID (Ed25519 + BLAKE3 chain intact)"
        } else {
            "BROKEN / TAMPERED"
        }
    );
    if let Some(reason) = &report.reason {
        println!("  Failure:       seq {:?} ({reason})", report.broken_at_seq);
    }

    for e in &entries {
        println!(
            "  #{:03}  t={}  slot={}  {:<14}  {}  sig={}",
            e.seq,
            e.timestamp_utc,
            e.slot,
            e.event,
            e.detail,
            &e.signature[..16]
        );
    }

    if !report.valid {
        bail!("custody log verification failed");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_passwd(
    volume_path: &Path,
    slot: Option<usize>,
    new_keyfile: Option<&Path>,
    new_pq_key: Option<&Path>,
    new_passphrase_env: Option<&str>,
    new_profile: Option<KdfProfile>,
    auth: &AuthArgs,
) -> Result<()> {
    let mut vol = unlock_volume(volume_path, auth)?;
    let target_slot = slot.unwrap_or_else(|| vol.unlocked_slot());

    let new_pass = read_new_passphrase(new_passphrase_env, "New passphrase")?;
    let new_kf = load_optional_keyfile(new_keyfile)?;
    let new_pq = load_optional_pq_keypair(new_pq_key)?;
    let new_params = new_profile.map(|p| p.params());

    let new_auth = AuthMaterial {
        passphrase: new_pass.as_slice(),
        keyfile_hash: new_kf.as_ref().map(|k| k.as_array()),
        pq_keypair: new_pq.as_ref(),
    };
    vol.change_slot_passphrase(target_slot, &new_auth, new_params.as_ref())?;

    println!("Updated key slot {target_slot}.");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_keyslot_add(
    volume_path: &Path,
    slot: Option<usize>,
    label: &str,
    profile: KdfProfile,
    new_keyfile: Option<&Path>,
    new_pq_key: Option<&Path>,
    new_passphrase_env: Option<&str>,
    auth: &AuthArgs,
) -> Result<()> {
    let mut vol = unlock_volume(volume_path, auth)?;
    let new_pass = read_new_passphrase(new_passphrase_env, "Passphrase for new slot")?;
    let new_kf = load_optional_keyfile(new_keyfile)?;
    let new_pq = load_optional_pq_keypair(new_pq_key)?;

    let new_auth = AuthMaterial {
        passphrase: new_pass.as_slice(),
        keyfile_hash: new_kf.as_ref().map(|k| k.as_array()),
        pq_keypair: new_pq.as_ref(),
    };
    let idx = vol.add_keyslot(slot, &new_auth, &profile.params(), label)?;

    println!("Added key slot {idx} (label: \"{label}\").");
    Ok(())
}

fn cmd_keyslot_remove(volume_path: &Path, slot: usize, auth: &AuthArgs) -> Result<()> {
    let mut vol = unlock_volume(volume_path, auth)?;
    vol.remove_keyslot(slot)?;
    println!("Removed key slot {slot}.");
    Ok(())
}

fn cmd_duress_add(
    volume_path: &Path,
    slot: Option<usize>,
    decoy_label: &str,
    profile: KdfProfile,
    duress_passphrase_env: Option<&str>,
    auth: &AuthArgs,
) -> Result<()> {
    let mut vol = unlock_volume(volume_path, auth)?;
    let duress_pass = read_new_passphrase(duress_passphrase_env, "Duress / Panic passphrase")?;
    let duress_auth = AuthMaterial::password_only(duress_pass.as_slice());

    let idx = vol.add_duress_slot(slot, &duress_auth, &profile.params(), decoy_label)?;
    println!(
        "Configured duress slot {idx} (decoy label: \"{decoy_label}\"). Entering this passphrase at unlock will silently crypto-shred the volume."
    );
    Ok(())
}

fn cmd_shamir_split(
    threshold: u8,
    total: u8,
    in_file: Option<&Path>,
    out_keyfile: Option<&Path>,
    print_qr: bool,
    qr_dir: Option<&Path>,
) -> Result<()> {
    let mut secret = if let Some(p) = in_file {
        let mut buf = Vec::new();
        File::open(p)?.read_to_end(&mut buf)?;
        if buf.is_empty() || buf.len() > 256 {
            buf.zeroize();
            bail!("input file for Shamir split must be 1..=256 bytes");
        }
        buf
    } else {
        random_bytes::<32>().to_vec()
    };

    if let Some(out) = out_keyfile {
        write_secret_file(out, &secret)?;
        println!("Saved master keyfile to '{}'.", out.display());
    }

    let shares = split_secret(&secret, threshold, total)?;
    secret.zeroize();

    if let Some(dir) = qr_dir {
        fs::create_dir_all(dir)?;
    }

    println!("Shamir Secret Sharing ({threshold}-of-{total}) — distribute each share separately:");
    for s in &shares {
        let encoded = s.encode();
        println!("  Share {:02}: {encoded}", s.index);
        if print_qr {
            let qr = render_terminal_qr(&encoded)?;
            println!("{qr}");
        }
        if let Some(dir) = qr_dir {
            let svg = render_keycard_svg(
                &format!("SHARE {:02} OF {:02}", s.index, total),
                &format!("THRESHOLD {threshold}"),
                &encoded,
            )?;
            let card_path = dir.join(format!("falcon-share-{:02}.svg", s.index));
            write_secret_file(&card_path, svg.as_bytes())?;
            println!(
                "    -> Saved printable SVG keycard: {}",
                card_path.display()
            );
        }
    }
    Ok(())
}

fn cmd_shamir_combine(out: &Path, encoded_shares: &[String]) -> Result<()> {
    let mut parsed = Vec::with_capacity(encoded_shares.len());
    for raw in encoded_shares {
        parsed.push(Share::parse(raw)?);
    }
    let mut recovered = combine_shares(&parsed)?;
    write_secret_file(out, &recovered)?;
    let len = recovered.len();
    recovered.zeroize();
    println!("Reconstructed {len}-byte keyfile at '{}'.", out.display());
    Ok(())
}

fn cmd_header_backup(
    volume_path: &Path,
    output: &Path,
    detached_header: Option<&Path>,
) -> Result<()> {
    let mut dev = FileBlockDevice::open_ro(volume_path)?;
    let raw = Volume::export_header(&mut dev, detached_header)?;
    write_secret_file(output, &raw)?;
    println!("Backed up 16 KiB header to '{}'.", output.display());
    Ok(())
}

fn cmd_header_restore(
    volume_path: &Path,
    input: &Path,
    detached_header: Option<&Path>,
    raw_device: bool,
) -> Result<()> {
    let mut buf = Vec::new();
    File::open(input)?.read_to_end(&mut buf)?;
    let mut dev = FileBlockDevice::open_rw(volume_path, raw_device)?;
    Volume::restore_header(&mut dev, &buf, detached_header)?;
    println!("Restored header.");
    Ok(())
}

fn cmd_header_repair(volume_path: &Path, auth: &AuthArgs) -> Result<()> {
    let mut vol = unlock_volume(volume_path, auth)?;
    vol.persist_headers()?;
    println!("Repaired and synced headers.");
    Ok(())
}

fn cmd_keygen(output: &Path, bytes: usize) -> Result<()> {
    if bytes < 32 {
        bail!("keyfile must be at least 32 bytes");
    }
    let mut buf = vec![0u8; bytes];
    OsRng.fill_bytes(&mut buf);
    write_secret_file(output, &buf)?;
    buf.zeroize();
    println!("Wrote {bytes}-byte keyfile to '{}'.", output.display());
    Ok(())
}

fn cmd_identity_generate(identity_out: &Path, pub_out: &Path, callsign: &str) -> Result<()> {
    let id = OperatorIdentity::generate(callsign);
    let pub_bundle = id.public_bundle();

    let mut id_bytes = id.to_bytes();
    write_secret_file(identity_out, &id_bytes)?;
    id_bytes.zeroize();

    let pub_bytes = pub_bundle.to_bytes();
    let mut pub_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(pub_out)
        .with_context(|| format!("failed to create '{}'", pub_out.display()))?;
    pub_file.write_all(&pub_bytes)?;
    pub_file.sync_all()?;

    println!("Generated Falcon Operator Identity (ML-KEM-1024 + Ed25519):");
    println!("  Callsign:    {}", pub_bundle.callsign);
    println!("  Fingerprint: {}", pub_bundle.fingerprint_hex());
    println!("  Ed25519 Pub: {}", pub_bundle.ed25519_hex());
    println!(
        "  Private ID:  {} ({} bytes, mode 0600 — KEEP SECRET)",
        identity_out.display(),
        falcon_crypto::IDENTITY_SIZE
    );
    println!(
        "  Public Key:  {} ({} bytes — safe to distribute)",
        pub_out.display(),
        falcon_crypto::PUB_BUNDLE_SIZE
    );
    Ok(())
}

fn cmd_identity_info(file: &Path) -> Result<()> {
    let mut raw = Vec::new();
    File::open(file)
        .with_context(|| format!("failed to open '{}'", file.display()))?
        .read_to_end(&mut raw)?;

    if let Ok(id) = OperatorIdentity::from_bytes(&raw) {
        raw.zeroize();
        let pb = id.public_bundle();
        println!("Falcon Operator Identity (PRIVATE): {}", file.display());
        println!("  Callsign:    {}", pb.callsign);
        println!("  Fingerprint: {}", pb.fingerprint_hex());
        println!("  Ed25519 Pub: {}", pb.ed25519_hex());
        println!("  Algorithms:  ML-KEM-1024 (FIPS 203) + Ed25519 (RFC 8032)");
        return Ok(());
    }
    if let Ok(pb) = OperatorPublicBundle::from_bytes(&raw) {
        raw.zeroize();
        println!("Falcon Operator Public Bundle: {}", file.display());
        println!("  Callsign:    {}", pb.callsign);
        println!("  Fingerprint: {}", pb.fingerprint_hex());
        println!("  Ed25519 Pub: {}", pb.ed25519_hex());
        println!("  Algorithms:  ML-KEM-1024 (FIPS 203) + Ed25519 (RFC 8032)");
        return Ok(());
    }
    raw.zeroize();
    bail!(
        "'{}' is not a valid Falcon identity (.flcid) or public bundle (.flcpub)",
        file.display()
    );
}

fn cmd_seal(
    input: &Path,
    to_pub: &Path,
    from_id: &Path,
    out_path: &Path,
    sanitize: bool,
) -> Result<()> {
    let mut sender_raw = Vec::new();
    File::open(from_id)
        .with_context(|| format!("failed to open sender identity '{}'", from_id.display()))?
        .read_to_end(&mut sender_raw)?;
    let sender = OperatorIdentity::from_bytes(&sender_raw);
    sender_raw.zeroize();
    let sender = sender?;

    let recip_raw = fs::read(to_pub).with_context(|| {
        format!(
            "failed to open recipient public bundle '{}'",
            to_pub.display()
        )
    })?;
    let recipient = OperatorPublicBundle::from_bytes(&recip_raw)?;

    let mut plaintext = fs::read(input)
        .with_context(|| format!("failed to read input file '{}'", input.display()))?;
    let fname = input
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("drop.bin");

    let (pkg, meta, san_rep) = seal_package(&sender, &recipient, fname, &plaintext, sanitize)?;
    plaintext.zeroize();

    let mut out_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(out_path)
        .with_context(|| format!("failed to write '{}'", out_path.display()))?;
    out_file.write_all(&pkg)?;
    out_file.sync_all()?;

    if let Some(rep) = san_rep {
        println!(
            "OPSEC sanitized ({}: stripped {} segment(s), {} bytes removed, timestamp zeroed)",
            rep.format, rep.segments_stripped, rep.bytes_removed
        );
    }
    println!("Sealed Drop created: {}", out_path.display());
    println!(
        "  From:        {} (Ed25519 {})",
        sender.callsign,
        &meta.sender_ed25519_hex[..24]
    );
    println!(
        "  To:          {} (FP {})",
        recipient.callsign, meta.recipient_fingerprint
    );
    println!(
        "  Payload:     {} ({})",
        meta.filename,
        format_bytes(meta.payload_bytes as u64)
    );
    println!(
        "  Package:     {} (ML-KEM-1024 + AES-256-GCM + Ed25519)",
        format_bytes(meta.package_bytes as u64)
    );
    Ok(())
}

fn cmd_unseal(
    package_path: &Path,
    identity_path: &Path,
    expect_sender_path: Option<&Path>,
    out_path: &Path,
) -> Result<()> {
    let mut recip_raw = Vec::new();
    File::open(identity_path)
        .with_context(|| {
            format!(
                "failed to open recipient identity '{}'",
                identity_path.display()
            )
        })?
        .read_to_end(&mut recip_raw)?;
    let recipient = OperatorIdentity::from_bytes(&recip_raw);
    recip_raw.zeroize();
    let recipient = recipient?;

    let expected_sender = match expect_sender_path {
        Some(p) => {
            let raw = fs::read(p).with_context(|| {
                format!("failed to open expected sender bundle '{}'", p.display())
            })?;
            Some(OperatorPublicBundle::from_bytes(&raw)?)
        }
        None => None,
    };

    let pkg = fs::read(package_path)
        .with_context(|| format!("failed to read sealed drop '{}'", package_path.display()))?;
    let drop = unseal_package(&recipient, expected_sender.as_ref(), &pkg)?;

    let mut out_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(out_path)
        .with_context(|| format!("failed to write '{}'", out_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = out_file.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    out_file.write_all(&drop.plaintext)?;
    out_file.sync_all()?;

    println!(
        "Unsealed Drop verified & decrypted -> {}",
        out_path.display()
    );
    println!("  Filename:    {}", drop.meta.filename);
    println!(
        "  Size:        {}",
        format_bytes(drop.meta.payload_bytes as u64)
    );
    println!(
        "  Sender Sig:  Ed25519 {} [VERIFIED]",
        &drop.meta.sender_ed25519_hex[..24]
    );
    if let Some(exp) = expected_sender {
        println!("  Pinned ID:   MATCHED ({})", exp.callsign);
    }
    println!(
        "  OPSEC Strip: {}",
        if drop.meta.opsec_sanitized {
            "YES"
        } else {
            "NO"
        }
    );
    Ok(())
}

fn cmd_pq_keygen(output: &Path) -> Result<()> {
    let kp = PqKeypair::generate();
    let mut bytes = kp.to_bytes();
    write_secret_file(output, &bytes)?;
    bytes.zeroize();
    println!(
        "Wrote FIPS 203 ML-KEM-1024 keypair ({} bytes) to '{}'.",
        falcon_crypto::PQ_KEYFILE_SIZE,
        output.display()
    );
    Ok(())
}

fn cmd_diag(volume: Option<&Path>, sectors: usize) -> Result<()> {
    println!("Running Falcon crypto benchmark ({sectors} x 4 KiB sectors)...");
    let bench = run_crypto_benchmark(sectors)?;
    println!(
        "  AES-256-XTS:               {:>8.1} MiB/s",
        bench.aes_xts_mib_s
    );
    println!(
        "  Cascade AES+Serpent-XTS:   {:>8.1} MiB/s",
        bench.cascade_xts_mib_s
    );
    println!(
        "  BLAKE3-256 Sector MAC:     {:>8.1} MiB/s",
        bench.blake3_mac_mib_s
    );

    if let Some(vol_path) = volume {
        let f = File::open(vol_path)?;
        let mut sample = Vec::new();
        f.take(4 * 1024 * 1024).read_to_end(&mut sample)?;
        let ent = analyze_entropy(&sample);
        println!("\nEntropy & Stealth Analysis ({})", vol_path.display());
        println!(
            "  Sampled bytes:   {}",
            format_bytes(ent.sampled_bytes as u64)
        );
        println!(
            "  Shannon entropy: {:.5} / 8.00000 bits/byte",
            ent.shannon_bits_per_byte
        );
        println!("  Byte mean:       {:.2} (ideal: 127.50)", ent.byte_mean);
        println!(
            "  Bucket spread:   {:.3}x .. {:.3}x",
            ent.min_bucket_ratio, ent.max_bucket_ratio
        );
        println!(
            "  Visible magic:   {}",
            if ent.has_visible_magic {
                "YES (standard attached header)"
            } else {
                "NO (stealth / detached or pure noise)"
            }
        );
    }
    Ok(())
}

fn cmd_shred(
    volume_path: &Path,
    detached_header: Option<&Path>,
    confirmed: bool,
    raw_device: bool,
) -> Result<()> {
    if !confirmed {
        bail!("pass --yes-destroy-forever to confirm permanent destruction");
    }
    if is_raw_device_path(volume_path) && is_protected_system_disk(volume_path) {
        bail!("refusing to shred system disk '{}'", volume_path.display());
    }

    let mut dev = FileBlockDevice::open_rw(volume_path, raw_device)?;
    Volume::crypto_shred(&mut dev, detached_header)?;
    println!(
        "Shredded '{}': headers overwritten with 3 passes of CSPRNG bytes. Volume is permanently unrecoverable.",
        volume_path.display()
    );
    Ok(())
}

fn unlock_volume(volume_path: &Path, auth: &AuthArgs) -> Result<Volume<FileBlockDevice>> {
    let device = FileBlockDevice::open_rw(volume_path, auth.raw_device)?;
    let passphrase = read_existing_passphrase(auth.passphrase_env.as_deref())?;
    let keyfile_hash = load_optional_keyfile(auth.keyfile.as_deref())?;
    let pq_kp = load_optional_pq_keypair(auth.pq_key.as_deref())?;

    let material = AuthMaterial {
        passphrase: passphrase.as_slice(),
        keyfile_hash: keyfile_hash.as_ref().map(|k| k.as_array()),
        pq_keypair: pq_kp.as_ref(),
    };

    let vol = if auth.hidden {
        Volume::open_hidden(device, &material, auth.header.as_deref())?
    } else {
        Volume::open(device, &material, auth.header.as_deref())?
    };

    if vol.recovered_from_backup() {
        eprintln!(
            "WARNING: primary header failed verification; opened via backup header. Run `falcon header repair` and `falcon verify`."
        );
    }

    Ok(vol)
}

fn write_secret_file(path: &Path, data: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("failed to create '{}'", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
    }

    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}

fn read_existing_passphrase(env_var: Option<&str>) -> Result<SecureBytes> {
    if let Some(var) = env_var {
        let val = std::env::var(var).with_context(|| format!("env var '{var}' is not set"))?;
        return Ok(SecureBytes::from_string(val));
    }
    let pw = rpassword::prompt_password("Passphrase: ")?;
    Ok(SecureBytes::from_string(pw))
}

fn read_new_passphrase(env_var: Option<&str>, prompt: &str) -> Result<SecureBytes> {
    if let Some(var) = env_var {
        let val = std::env::var(var).with_context(|| format!("env var '{var}' is not set"))?;
        if val.is_empty() {
            bail!("passphrase cannot be empty");
        }
        return Ok(SecureBytes::from_string(val));
    }
    let p1 = rpassword::prompt_password(format!("{prompt}: "))?;
    if p1.is_empty() {
        bail!("passphrase cannot be empty");
    }
    let p2 = rpassword::prompt_password("Confirm passphrase: ")?;
    let s1 = SecureBytes::from_string(p1);
    let s2 = SecureBytes::from_string(p2);
    if s1.as_slice() != s2.as_slice() {
        bail!("passphrases do not match");
    }
    Ok(s1)
}

fn load_optional_keyfile(path: Option<&Path>) -> Result<Option<SecureArray<32>>> {
    match path {
        Some(p) => {
            let f = File::open(p)
                .with_context(|| format!("failed to open keyfile '{}'", p.display()))?;
            Ok(Some(hash_keyfile(f)?))
        }
        None => Ok(None),
    }
}

fn load_optional_pq_keypair(path: Option<&Path>) -> Result<Option<PqKeypair>> {
    match path {
        Some(p) => {
            let mut raw = Vec::new();
            File::open(p)
                .with_context(|| format!("failed to open PQ keyfile '{}'", p.display()))?
                .read_to_end(&mut raw)?;
            let res = PqKeypair::from_bytes(&raw);
            raw.zeroize();
            Ok(Some(res?))
        }
        None => Ok(None),
    }
}

fn make_progress_bar(total: u64, msg: &str) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::with_template("{msg} [{bar:36.cyan/blue}] {pos}/{len} sectors ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );
    pb.set_message(msg.to_string());
    pb
}

pub(crate) fn parse_size(s: &str) -> Result<u64> {
    let trimmed = s.trim().to_uppercase();
    let (num_part, mult): (&str, u64) = if let Some(v) = trimmed
        .strip_suffix("GIB")
        .or_else(|| trimmed.strip_suffix("GB"))
        .or_else(|| trimmed.strip_suffix('G'))
    {
        (v, 1024 * 1024 * 1024)
    } else if let Some(v) = trimmed
        .strip_suffix("MIB")
        .or_else(|| trimmed.strip_suffix("MB"))
        .or_else(|| trimmed.strip_suffix('M'))
    {
        (v, 1024 * 1024)
    } else if let Some(v) = trimmed
        .strip_suffix("KIB")
        .or_else(|| trimmed.strip_suffix("KB"))
        .or_else(|| trimmed.strip_suffix('K'))
    {
        (v, 1024)
    } else if let Some(v) = trimmed.strip_suffix('B') {
        (v, 1)
    } else {
        (trimmed.as_str(), 1)
    };

    let base: u64 = num_part
        .trim()
        .parse()
        .with_context(|| format!("invalid size: '{s}'"))?;
    base.checked_mul(mult).context("size overflow")
}

fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    let b = bytes as f64;
    if b >= GIB {
        format!("{:.2} GiB", b / GIB)
    } else if b >= MIB {
        format!("{:.2} MiB", b / MIB)
    } else if b >= KIB {
        format!("{:.2} KiB", b / KIB)
    } else {
        format!("{bytes} B")
    }
}
