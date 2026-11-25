use anyhow::{anyhow, bail, Context, Result};
use falcon_crypto::{
    analyze_entropy, combine_shares, hash_keyfile, random_bytes, render_keycard_svg,
    run_crypto_benchmark, run_power_on_self_test, sanitize_file_bytes, seal_package, split_secret,
    unseal_package, CipherMode, KdfProfile, OperatorIdentity, OperatorPublicBundle, PostReport,
    PqKeypair, SecureArray, Share,
};
use falcon_fs::FalconFs;
use falcon_volume::{
    is_protected_system_disk, is_raw_device_path, AuthMaterial, CreateOptions, FileBlockDevice,
    Volume, VolumeLayout,
};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};
use zeroize::Zeroize;

const INDEX_HTML: &str = include_str!("../assets/index.html");
const FAVICON_PNG: &[u8] = include_bytes!("../assets/favicon.png");
const FAVICON_ICO: &[u8] = include_bytes!("../assets/favicon.ico");
const APPLE_TOUCH_ICON_PNG: &[u8] = include_bytes!("../assets/apple-touch-icon.png");
const FAVICON_SVG: &str = include_str!("../assets/favicon.svg");
const MAX_JSON_BODY: usize = 512 * 1024;
const MAX_UPLOAD_BODY: usize = 512 * 1024 * 1024;

struct UnlockedSession {
    path: PathBuf,
    detached_header: Option<PathBuf>,
    fs: FalconFs<FileBlockDevice>,
    last_activity: Instant,
}

struct AppState {
    session: Option<UnlockedSession>,
    auto_lock: Duration,
    usb_watch_path: Option<PathBuf>,
    kill_switch_tripped: bool,
    post_report: PostReport,
}

impl AppState {
    fn check_idle(&mut self) {
        if let Some(s) = &self.session {
            if s.last_activity.elapsed() > self.auto_lock {
                self.session = None;
            }
        }
    }

    fn active_mut(&mut self) -> Result<&mut UnlockedSession> {
        self.check_idle();
        let s = self
            .session
            .as_mut()
            .ok_or_else(|| anyhow!("no volume unlocked"))?;
        s.last_activity = Instant::now();
        Ok(s)
    }
}

#[derive(Serialize)]
struct SlotView {
    active: bool,
    label: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    requires_keyfile: bool,
    pq_hybrid: bool,
}

#[derive(Serialize)]
struct StatusResponse {
    unlocked: bool,
    hidden: bool,
    path: Option<String>,
    detached_header: Option<String>,
    uuid: Option<String>,
    cipher_mode: String,
    integrity: bool,
    unlocked_slot: Option<usize>,
    recovered_from_backup: bool,
    expires_at_unix: u64,
    max_failed_attempts: u32,
    custody_pubkey: Option<String>,
    total_sectors: u64,
    used_sectors: u64,
    free_sectors: u64,
    file_count: usize,
    key_slots: Vec<SlotView>,
    usb_watch: Option<String>,
    kill_switch_tripped: bool,
    post_passed: bool,
    post_report: PostReport,
    app_version: String,
    platform: String,
    repo_url: String,
    releases_url: String,
    issues_url: String,
}

#[derive(Deserialize)]
struct InfoReq {
    path: String,
    detached_header_path: Option<String>,
}

#[derive(Deserialize)]
struct UnlockReq {
    path: String,
    passphrase: String,
    keyfile_path: Option<String>,
    pq_key_path: Option<String>,
    detached_header_path: Option<String>,
    hidden: Option<bool>,
    usb_watch_path: Option<String>,
}

#[derive(Deserialize)]
struct CreateReq {
    path: String,
    size: String,
    profile: String,
    label: Option<String>,
    cascade: Option<bool>,
    ttl_hours: Option<u64>,
    max_attempts: Option<u32>,
    passphrase: String,
    keyfile_path: Option<String>,
    pq_key_path: Option<String>,
    detached_header_path: Option<String>,
}

#[derive(Deserialize)]
struct HiddenCreateReq {
    profile: String,
    cascade: Option<bool>,
    label: Option<String>,
    passphrase: String,
    keyfile_path: Option<String>,
    pq_key_path: Option<String>,
}

#[derive(Deserialize)]
struct KeygenReq {
    path: String,
    bytes: Option<usize>,
}

#[derive(Deserialize)]
struct PqKeygenReq {
    path: String,
}

#[derive(Deserialize)]
struct DeleteFileReq {
    path: String,
}

#[derive(Deserialize)]
struct AddSlotReq {
    label: String,
    profile: String,
    passphrase: String,
    keyfile_path: Option<String>,
    pq_key_path: Option<String>,
}

#[derive(Deserialize)]
struct AddDuressReq {
    label: String,
    profile: String,
    passphrase: String,
}

#[derive(Deserialize)]
struct RemoveSlotReq {
    slot: usize,
}

#[derive(Deserialize)]
struct PasswdReq {
    slot: Option<usize>,
    new_passphrase: String,
    new_keyfile_path: Option<String>,
    new_pq_key_path: Option<String>,
    new_profile: Option<String>,
}

#[derive(Deserialize)]
struct ShredReq {
    path: String,
    detached_header_path: Option<String>,
    confirm: String,
}

#[derive(Deserialize)]
struct ShamirSplitReq {
    threshold: u8,
    shares: u8,
    in_keyfile_path: Option<String>,
    out_keyfile_path: Option<String>,
}

#[derive(Deserialize)]
struct ShamirCombineReq {
    shares: Vec<String>,
    out_keyfile_path: String,
}

#[derive(Deserialize)]
struct BenchReq {
    sectors: Option<usize>,
}

#[derive(Deserialize)]
struct EntropyReq {
    path: String,
}

#[derive(Deserialize)]
struct IdentityGenReq {
    identity_path: String,
    pub_path: String,
    callsign: Option<String>,
}

#[derive(Deserialize)]
struct SealReq {
    input_path: String,
    to_pub_path: String,
    from_id_path: String,
    out_path: String,
    sanitize: Option<bool>,
}

#[derive(Deserialize)]
struct UnsealReq {
    package_path: String,
    identity_path: String,
    expect_sender_path: Option<String>,
    out_path: String,
}

pub fn run_ui(
    port: u16,
    auto_lock_mins: u64,
    usb_watch: Option<PathBuf>,
    open_browser: bool,
    post_report: PostReport,
) -> Result<()> {
    let bind_addr = format!("127.0.0.1:{port}");
    let server = Server::http(&bind_addr)
        .map_err(|e| anyhow!("failed to bind {bind_addr}: {e}"))?;

    let token = hex::encode(random_bytes::<32>());
    let url = format!("http://{bind_addr}/?token={token}");

    println!("Falcon v0.4 COMSEC controller listening on http://{bind_addr} (loopback only)");
    println!(
        "FIPS 140-3 POST: PASS ({:.2} ms) | Auto-lock: {auto_lock_mins} min",
        post_report.duration_ms
    );
    if let Some(ref p) = usb_watch {
        println!("USB Kill-Switch Watchdog armed on '{}'", p.display());
    }
    println!("Open URL: {url}");
    println!("Press Ctrl+C to stop and zeroize active keys.");

    if open_browser {
        launch_browser(&url);
    }

    let state = Arc::new(Mutex::new(AppState {
        session: None,
        auto_lock: Duration::from_secs(auto_lock_mins.saturating_mul(60)),
        usb_watch_path: usb_watch,
        kill_switch_tripped: false,
        post_report,
    }));

    // 250ms USB Physical Kill-Switch Watchdog thread:
    // If the watched USB token / keyfile path vanishes while unlocked, drop & zeroize immediately.
    let watchdog_state = Arc::clone(&state);
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(250));
        let mut guard = watchdog_state.lock().unwrap();
        if guard.session.is_some() {
            let missing = guard
                .usb_watch_path
                .as_ref()
                .filter(|p| !p.exists())
                .cloned();
            if let Some(watch_path) = missing {
                guard.session = None;
                guard.kill_switch_tripped = true;
                eprintln!(
                    "[KILL-SWITCH] Watched token '{}' removed — session locked and RAM keys zeroized!",
                    watch_path.display()
                );
            }
        }
    });

    for req in server.incoming_requests() {
        if !check_host_header(&req, port) {
            let _ = req.respond(json_error(403, "invalid Host header"));
            continue;
        }
        if let Err(err) = handle_request(req, &token, &state) {
            eprintln!("ui request error: {err}");
        }
    }

    Ok(())
}

fn handle_request(mut req: Request, token: &str, state: &Arc<Mutex<AppState>>) -> Result<()> {
    let full_url = req.url().to_string();
    let (path, query) = match full_url.split_once('?') {
        Some((p, q)) => (p, q),
        None => (full_url.as_str(), ""),
    };

    if *req.method() == Method::Get {
        let static_icon: Option<(&[u8], &str)> = match path {
            "/favicon.ico" => Some((FAVICON_ICO, "image/x-icon")),
            "/favicon.png" => Some((FAVICON_PNG, "image/png")),
            "/apple-touch-icon.png" | "/apple-touch-icon-precomposed.png" => {
                Some((APPLE_TOUCH_ICON_PNG, "image/png"))
            }
            "/favicon.svg" => Some((FAVICON_SVG.as_bytes(), "image/svg+xml; charset=utf-8")),
            _ => None,
        };
        if let Some((bytes, ct)) = static_icon {
            let resp = Response::from_data(bytes.to_vec())
                .with_status_code(StatusCode(200))
                .with_header(header("Content-Type", ct))
                .with_header(header("Cache-Control", "public, max-age=86400"))
                .with_header(header("X-Content-Type-Options", "nosniff"));
            req.respond(resp)?;
            return Ok(());
        }
    }

    if *req.method() == Method::Get && path == "/" {
        let q_token = query_param(query, "token").unwrap_or_default();
        if !ct_str_eq(&q_token, token) {
            req.respond(text_response(
                401,
                "text/plain; charset=utf-8",
                "Unauthorized: open the tokenized URL printed by `falcon ui`.",
            ))?;
            return Ok(());
        }

        let html = INDEX_HTML.replace("__FALCON_SESSION_TOKEN__", token);
        let mut resp = Response::from_string(html)
            .with_status_code(StatusCode(200))
            .with_header(header("Content-Type", "text/html; charset=utf-8"))
            .with_header(header(
                "Content-Security-Policy",
                "default-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data: blob:; frame-ancestors 'none'",
            ));
        add_security_headers(&mut resp);
        req.respond(resp)?;
        return Ok(());
    }

    if path.starts_with("/api/") {
        let supplied = req
            .headers()
            .iter()
            .find(|h| h.field.equiv("X-Falcon-Token"))
            .map(|h| h.value.as_str())
            .unwrap_or("");
        if !ct_str_eq(supplied, token) {
            req.respond(json_error(401, "missing or invalid session token"))?;
            return Ok(());
        }
    } else {
        req.respond(json_error(404, "not found"))?;
        return Ok(());
    }

    let method = req.method().clone();
    let result: Result<Response<Cursor<Vec<u8>>>> = match (method, path) {
        (Method::Get, "/api/status") => api_status(state),
        (Method::Get, "/api/files") => api_files(state),
        (Method::Get, "/api/files/download") => api_download(query, state),
        (Method::Get, "/api/custody") => api_custody(state),
        (Method::Get, "/api/browse") => api_browse(query),
        (Method::Post, "/api/info") => api_info(&mut req),
        (Method::Post, "/api/create") => api_create(&mut req, state),
        (Method::Post, "/api/hidden/create") => api_hidden_create(&mut req, state),
        (Method::Post, "/api/keygen") => api_keygen(&mut req),
        (Method::Post, "/api/pq-keygen") => api_pq_keygen(&mut req),
        (Method::Post, "/api/unlock") => api_unlock(&mut req, state),
        (Method::Post, "/api/lock") => api_lock(state),
        (Method::Post, "/api/files/upload") => api_upload(&mut req, state),
        (Method::Post, "/api/files/delete") => api_delete(&mut req, state),
        (Method::Post, "/api/verify") => api_verify(state),
        (Method::Post, "/api/keyslot/add") => api_keyslot_add(&mut req, state),
        (Method::Post, "/api/duress/add") => api_duress_add(&mut req, state),
        (Method::Post, "/api/keyslot/remove") => api_keyslot_remove(&mut req, state),
        (Method::Post, "/api/passwd") => api_passwd(&mut req, state),
        (Method::Post, "/api/header/repair") => api_header_repair(state),
        (Method::Post, "/api/shred") => api_shred(&mut req, state),
        (Method::Post, "/api/shamir/split") => api_shamir_split(&mut req),
        (Method::Post, "/api/shamir/combine") => api_shamir_combine(&mut req),
        (Method::Post, "/api/diag/benchmark") => api_diag_benchmark(&mut req),
        (Method::Post, "/api/diag/entropy") => api_diag_entropy(&mut req),
        (Method::Post, "/api/diag/post") => api_diag_post(state),
        (Method::Post, "/api/identity/generate") => api_identity_generate(&mut req),
        (Method::Post, "/api/seal") => api_seal(&mut req),
        (Method::Post, "/api/unseal") => api_unseal(&mut req),
        (Method::Post, "/api/update/check") => api_update_check(),
        _ => Ok(json_error(404, "unknown endpoint")),
    };

    let resp = match result {
        Ok(r) => r,
        Err(e) => json_error(400, &e.to_string()),
    };
    req.respond(resp)?;
    Ok(())
}

fn api_status(state: &Arc<Mutex<AppState>>) -> Result<Response<Cursor<Vec<u8>>>> {
    let mut guard = state.lock().unwrap();
    guard.check_idle();

    let usb_watch = guard
        .usb_watch_path
        .as_ref()
        .map(|p| p.display().to_string());
    let kill_switch_tripped = guard.kill_switch_tripped;
    let post_report = guard.post_report.clone();

    if let Some(s) = guard.session.as_mut() {
        let stats = s.fs.stats()?;
        let vol = s.fs.volume();
        let hdr = vol.header();
        let slots = hdr
            .key_slots
            .iter()
            .map(|k| SlotView {
                active: k.active,
                label: k.label.clone(),
                memory_kib: k.kdf_params.memory_kib,
                iterations: k.kdf_params.iterations,
                parallelism: k.kdf_params.parallelism,
                requires_keyfile: k.requires_keyfile,
                pq_hybrid: k.pq_hybrid,
            })
            .collect();

        return Ok(json_ok(&StatusResponse {
            unlocked: true,
            hidden: vol.is_hidden(),
            path: Some(s.path.display().to_string()),
            detached_header: s.detached_header.as_ref().map(|p| p.display().to_string()),
            uuid: Some(hdr.uuid_hex()),
            cipher_mode: hdr.cipher_mode().display_name().to_string(),
            integrity: hdr.integrity_enabled(),
            unlocked_slot: Some(vol.unlocked_slot()),
            recovered_from_backup: vol.recovered_from_backup(),
            expires_at_unix: hdr.expires_at_unix,
            max_failed_attempts: hdr.max_failed_attempts,
            custody_pubkey: Some(vol.custody_pubkey_hex()),
            total_sectors: stats.total_sectors,
            used_sectors: stats.used_sectors,
            free_sectors: stats.free_sectors,
            file_count: stats.file_count,
            key_slots: slots,
            usb_watch,
            kill_switch_tripped,
            post_passed: post_report.passed,
            post_report,
            app_version: crate::update::current_version().to_string(),
            platform: crate::update::system_platform(),
            repo_url: crate::update::REPO_URL.to_string(),
            releases_url: crate::update::RELEASES_URL.to_string(),
            issues_url: crate::update::ISSUES_URL.to_string(),
        }));
    }

    Ok(json_ok(&StatusResponse {
        unlocked: false,
        hidden: false,
        path: None,
        detached_header: None,
        uuid: None,
        cipher_mode: String::new(),
        integrity: false,
        unlocked_slot: None,
        recovered_from_backup: false,
        expires_at_unix: 0,
        max_failed_attempts: 0,
        custody_pubkey: None,
        total_sectors: 0,
        used_sectors: 0,
        free_sectors: 0,
        file_count: 0,
        key_slots: Vec::new(),
        usb_watch,
        kill_switch_tripped,
        post_passed: post_report.passed,
        post_report,
        app_version: crate::update::current_version().to_string(),
        platform: crate::update::system_platform(),
        repo_url: crate::update::REPO_URL.to_string(),
        releases_url: crate::update::RELEASES_URL.to_string(),
        issues_url: crate::update::ISSUES_URL.to_string(),
    }))
}

fn api_info(req: &mut Request) -> Result<Response<Cursor<Vec<u8>>>> {
    let body: InfoReq = read_json(req)?;
    let detached = clean_opt_path(body.detached_header_path.as_deref());
    let mut dev = FileBlockDevice::open_ro(Path::new(&body.path))?;
    let (hdr, from_backup) = Volume::inspect_header(&mut dev, detached.as_deref())?;
    let slots: Vec<SlotView> = hdr
        .key_slots
        .iter()
        .map(|k| SlotView {
            active: k.active,
            label: k.label.clone(),
            memory_kib: k.kdf_params.memory_kib,
            iterations: k.kdf_params.iterations,
            parallelism: k.kdf_params.parallelism,
            requires_keyfile: k.requires_keyfile,
            pq_hybrid: k.pq_hybrid,
        })
        .collect();

    Ok(json_ok(&serde_json::json!({
        "uuid": hdr.uuid_hex(),
        "version": hdr.version,
        "from_backup": from_backup,
        "detached": hdr.is_detached(),
        "cipher_mode": hdr.cipher_mode().display_name(),
        "sector_size": hdr.sector_size,
        "data_sectors": hdr.data_sector_count,
        "integrity": hdr.integrity_enabled(),
        "expires_at_unix": hdr.expires_at_unix,
        "max_failed_attempts": hdr.max_failed_attempts,
        "failed_attempts": hdr.failed_attempts,
        "key_slots": slots,
    })))
}

fn api_create(
    req: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Result<Response<Cursor<Vec<u8>>>> {
    let mut body: CreateReq = read_json(req)?;
    if body.passphrase.is_empty() {
        bail!("passphrase cannot be empty");
    }

    let vol_path = PathBuf::from(&body.path);
    if is_raw_device_path(&vol_path) {
        body.passphrase.zeroize();
        bail!("raw block devices must be formatted via CLI (--raw-device)");
    }
    ensure_parent_dir(&vol_path)?;

    let detached = clean_opt_path(body.detached_header_path.as_deref());
    if let Some(ref hp) = detached {
        ensure_parent_dir(hp)?;
    }

    let data_bytes = crate::parse_size(&body.size)?;
    let profile = parse_profile(&body.profile)?;
    let layout = VolumeLayout::compute(data_bytes, true, detached.is_some())?;
    let kf_hash = load_keyfile(body.keyfile_path.as_deref())?;
    let pq_kp = load_pq_keypair(body.pq_key_path.as_deref())?;
    let cipher_mode = if body.cascade.unwrap_or(false) {
        CipherMode::CascadeAesSerpentXts
    } else {
        CipherMode::Aes256Xts
    };

    let ttl_hours = body.ttl_hours.unwrap_or(0);
    let expires_at_unix = if ttl_hours > 0 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            .saturating_add(ttl_hours.saturating_mul(3600))
    } else {
        0
    };

    let dev = FileBlockDevice::create(&vol_path, layout.total_bytes, false)?;
    let opts = CreateOptions {
        data_bytes,
        kdf_params: profile.params(),
        integrity_enabled: true,
        cipher_mode,
        detached_header_path: detached.clone(),
        expires_at_unix,
        max_failed_attempts: body.max_attempts.unwrap_or(0),
        label: body.label.unwrap_or_else(|| "primary".to_string()),
    };
    let material = AuthMaterial {
        passphrase: body.passphrase.as_bytes(),
        keyfile_hash: kf_hash.as_ref().map(|k| k.as_array()),
        pq_keypair: pq_kp.as_ref(),
    };

    let vol_res = Volume::create(dev, &opts, &material, |_, _| {});
    body.passphrase.zeroize();
    let vol = vol_res?;
    let mut fs = FalconFs::format(vol)?;
    let _ = fs.append_custody_event("CREATE", cipher_mode.display_name());

    let mut guard = state.lock().unwrap();
    guard.kill_switch_tripped = false;
    guard.session = Some(UnlockedSession {
        path: vol_path,
        detached_header: detached,
        fs,
        last_activity: Instant::now(),
    });

    Ok(json_ok(&serde_json::json!({ "ok": true })))
}

fn api_hidden_create(
    req: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Result<Response<Cursor<Vec<u8>>>> {
    let mut body: HiddenCreateReq = read_json(req)?;
    if body.passphrase.is_empty() {
        bail!("hidden passphrase cannot be empty");
    }
    let profile = parse_profile(&body.profile)?;
    let kf_hash = load_keyfile(body.keyfile_path.as_deref())?;
    let pq_kp = load_pq_keypair(body.pq_key_path.as_deref())?;
    let cipher_mode = if body.cascade.unwrap_or(false) {
        CipherMode::CascadeAesSerpentXts
    } else {
        CipherMode::Aes256Xts
    };
    let label = body.label.unwrap_or_else(|| "inner".to_string());

    let (outer_path, outer_detached, start_sector, hidden_sectors) = {
        let mut guard = state.lock().unwrap();
        let s = guard.active_mut()?;
        if !s.fs.is_upper_half_free() {
            body.passphrase.zeroize();
            bail!("upper half of outer volume is occupied by decoy files");
        }
        let hidden_auth = AuthMaterial {
            passphrase: body.passphrase.as_bytes(),
            keyfile_hash: kf_hash.as_ref().map(|k| k.as_array()),
            pq_keypair: pq_kp.as_ref(),
        };
        let (st, secs) = s.fs.volume_mut().create_hidden_in_outer(
            &hidden_auth,
            &profile.params(),
            cipher_mode,
            &label,
        )?;
        (s.path.clone(), s.detached_header.clone(), st, secs)
    };

    // Format FalconFS inside the newly created hidden volume
    {
        let dev = FileBlockDevice::open_rw(&outer_path, false)?;
        let hidden_auth = AuthMaterial {
            passphrase: body.passphrase.as_bytes(),
            keyfile_hash: kf_hash.as_ref().map(|k| k.as_array()),
            pq_keypair: pq_kp.as_ref(),
        };
        let hvol = Volume::open_hidden(dev, &hidden_auth, outer_detached.as_deref());
        body.passphrase.zeroize();
        let hvol = hvol?;
        let mut hfs = FalconFs::format(hvol)?;
        let _ = hfs.append_custody_event("CREATE_HIDDEN", cipher_mode.display_name());
    }

    // Re-sync outer BLAKE3 MACs so outer decoy verify stays 100% clean
    {
        let mut guard = state.lock().unwrap();
        if let Ok(s) = guard.active_mut() {
            s.fs.volume_mut().refresh_upper_half_macs()?;
        }
    }

    Ok(json_ok(&serde_json::json!({
        "ok": true,
        "start_sector": start_sector,
        "hidden_sectors": hidden_sectors,
        "cipher_mode": cipher_mode.display_name(),
    })))
}

fn api_keygen(req: &mut Request) -> Result<Response<Cursor<Vec<u8>>>> {
    let body: KeygenReq = read_json(req)?;
    let bytes = body.bytes.unwrap_or(64);
    if !(32..=4096).contains(&bytes) {
        bail!("keyfile length must be 32..=4096 bytes");
    }
    let out_path = PathBuf::from(&body.path);
    ensure_parent_dir(&out_path)?;

    let mut buf = vec![0u8; bytes];
    OsRng.fill_bytes(&mut buf);
    write_secret_0600(&out_path, &buf)?;
    buf.zeroize();

    Ok(json_ok(&serde_json::json!({ "ok": true, "path": body.path })))
}

fn api_pq_keygen(req: &mut Request) -> Result<Response<Cursor<Vec<u8>>>> {
    let body: PqKeygenReq = read_json(req)?;
    let out_path = PathBuf::from(&body.path);
    ensure_parent_dir(&out_path)?;

    let kp = PqKeypair::generate();
    let mut raw = kp.to_bytes();
    write_secret_0600(&out_path, &raw)?;
    raw.zeroize();

    Ok(json_ok(&serde_json::json!({
        "ok": true,
        "path": body.path,
        "algorithm": "ML-KEM-1024 (FIPS 203)",
        "bytes": falcon_crypto::PQ_KEYFILE_SIZE
    })))
}

fn api_unlock(
    req: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Result<Response<Cursor<Vec<u8>>>> {
    let mut body: UnlockReq = read_json(req)?;
    let vol_path = PathBuf::from(&body.path);
    if is_raw_device_path(&vol_path) {
        body.passphrase.zeroize();
        bail!("raw block devices are CLI-only (--raw-device)");
    }

    let detached = clean_opt_path(body.detached_header_path.as_deref());
    let usb_watch = clean_opt_path(body.usb_watch_path.as_deref());
    if let Some(ref wp) = usb_watch {
        if !wp.exists() {
            body.passphrase.zeroize();
            bail!("USB Kill-Switch path '{}' does not currently exist", wp.display());
        }
    }

    let dev = FileBlockDevice::open_rw(&vol_path, false)?;
    let kf_hash = load_keyfile(body.keyfile_path.as_deref())?;
    let pq_kp = load_pq_keypair(body.pq_key_path.as_deref())?;
    let material = AuthMaterial {
        passphrase: body.passphrase.as_bytes(),
        keyfile_hash: kf_hash.as_ref().map(|k| k.as_array()),
        pq_keypair: pq_kp.as_ref(),
    };

    let vol_res = if body.hidden.unwrap_or(false) {
        Volume::open_hidden(dev, &material, detached.as_deref())
    } else {
        Volume::open(dev, &material, detached.as_deref())
    };
    body.passphrase.zeroize();
    let vol = vol_res?;
    let mut fs = FalconFs::mount(vol)?;
    let _ = fs.append_custody_event(
        if fs.volume().is_hidden() {
            "UNLOCK_HIDDEN"
        } else {
            "UNLOCK"
        },
        "localhost console",
    );

    let mut guard = state.lock().unwrap();
    guard.kill_switch_tripped = false;
    if usb_watch.is_some() {
        guard.usb_watch_path = usb_watch;
    }
    guard.session = Some(UnlockedSession {
        path: vol_path,
        detached_header: detached,
        fs,
        last_activity: Instant::now(),
    });

    Ok(json_ok(&serde_json::json!({ "ok": true })))
}

fn api_lock(state: &Arc<Mutex<AppState>>) -> Result<Response<Cursor<Vec<u8>>>> {
    let mut guard = state.lock().unwrap();
    guard.session = None;
    Ok(json_ok(&serde_json::json!({ "ok": true })))
}

fn api_files(state: &Arc<Mutex<AppState>>) -> Result<Response<Cursor<Vec<u8>>>> {
    let mut guard = state.lock().unwrap();
    let s = guard.active_mut()?;
    let files = s.fs.list_files()?;
    let stats = s.fs.stats()?;

    let items: Vec<_> = files
        .into_iter()
        .map(|f| {
            serde_json::json!({
                "path": f.path,
                "size": f.size,
                "created_at": f.created_at,
                "modified_at": f.modified_at,
                "sha256": hex::encode(f.sha256),
            })
        })
        .collect();

    Ok(json_ok(&serde_json::json!({
        "files": items,
        "stats": {
            "total_sectors": stats.total_sectors,
            "used_sectors": stats.used_sectors,
            "free_sectors": stats.free_sectors,
            "file_count": stats.file_count,
            "max_files": stats.max_files,
        }
    })))
}

fn api_upload(
    req: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Result<Response<Cursor<Vec<u8>>>> {
    let raw_path = req
        .headers()
        .iter()
        .find(|h| h.field.equiv("X-Vault-Path"))
        .map(|h| h.value.as_str().to_string())
        .ok_or_else(|| anyhow!("missing X-Vault-Path header"))?;
    let vault_path = percent_decode(&raw_path);

    let sanitize = req
        .headers()
        .iter()
        .find(|h| h.field.equiv("X-Opsec-Sanitize"))
        .map(|h| h.value.as_str() == "1")
        .unwrap_or(false);

    if let Some(len) = req.body_length() {
        if len > MAX_UPLOAD_BODY {
            bail!("file exceeds 512 MiB UI upload limit");
        }
    }

    let mut data = Vec::new();
    req.as_reader()
        .take((MAX_UPLOAD_BODY + 1) as u64)
        .read_to_end(&mut data)?;
    if data.len() > MAX_UPLOAD_BODY {
        data.zeroize();
        bail!("file exceeds 512 MiB UI upload limit");
    }

    let mut guard = state.lock().unwrap();
    let s = guard.active_mut()?;

    let (entry, san_info) = if sanitize {
        let (mut clean, rep) = sanitize_file_bytes(&data);
        data.zeroize();
        let entry = s.fs.put_file_opts(&vault_path, Cursor::new(&clean), true)?;
        clean.zeroize();
        let _ = s.fs.append_custody_event(
            "PUT_SANITIZED",
            &format!(
                "{} ({}B, fmt={}, stripped={}B)",
                entry.path, entry.size, rep.format, rep.bytes_removed
            ),
        );
        (
            entry,
            Some(serde_json::json!({
                "format": rep.format,
                "bytes_removed": rep.bytes_removed,
                "segments_stripped": rep.segments_stripped,
            })),
        )
    } else {
        let entry = s.fs.put_file(&vault_path, Cursor::new(&data))?;
        data.zeroize();
        let _ = s
            .fs
            .append_custody_event("PUT", &format!("{} ({}B)", entry.path, entry.size));
        (entry, None)
    };

    Ok(json_ok(&serde_json::json!({
        "path": entry.path,
        "size": entry.size,
        "sha256": hex::encode(entry.sha256),
        "sanitized": san_info,
    })))
}

fn api_download(
    query: &str,
    state: &Arc<Mutex<AppState>>,
) -> Result<Response<Cursor<Vec<u8>>>> {
    let path = query_param(query, "path").ok_or_else(|| anyhow!("missing path param"))?;
    let mut guard = state.lock().unwrap();
    let s = guard.active_mut()?;

    let mut out = Vec::new();
    let entry = s.fs.get_file(&path, &mut out)?;
    let _ = s.fs.append_custody_event("GET", &entry.path);
    let raw_name = entry.path.rsplit('/').next().unwrap_or("download");
    let filename: String = raw_name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ' ') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let safe_filename = if filename.trim().is_empty() {
        "download".to_string()
    } else {
        filename
    };

    let mut resp = Response::from_data(out)
        .with_status_code(StatusCode(200))
        .with_header(header("Content-Type", "application/octet-stream"))
        .with_header(header(
            "Content-Disposition",
            &format!("attachment; filename=\"{safe_filename}\""),
        ));
    add_security_headers(&mut resp);
    Ok(resp)
}

fn api_delete(
    req: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Result<Response<Cursor<Vec<u8>>>> {
    let body: DeleteFileReq = read_json(req)?;
    let mut guard = state.lock().unwrap();
    let s = guard.active_mut()?;
    s.fs.remove_file(&body.path)?;
    let _ = s.fs.append_custody_event("RM_WIPE", &body.path);
    Ok(json_ok(&serde_json::json!({ "ok": true })))
}

fn api_verify(state: &Arc<Mutex<AppState>>) -> Result<Response<Cursor<Vec<u8>>>> {
    let mut guard = state.lock().unwrap();
    let s = guard.active_mut()?;
    let r = s.fs.volume_mut().verify_all_sectors(|_, _| {})?;
    let uuid = s.fs.volume().header().uuid_hex();
    let cipher = s.fs.volume().header().cipher_mode().display_name();
    let _ = s.fs.append_custody_event(
        "VERIFY",
        if r.is_clean() { "PASS" } else { "TAMPER_ALERT" },
    );
    Ok(json_ok(&serde_json::json!({
        "uuid": uuid,
        "cipher_mode": cipher,
        "clean": r.is_clean(),
        "detached_header": r.detached_header,
        "hidden_volume": r.hidden_volume,
        "total_sectors": r.total_sectors,
        "verified_sectors": r.verified_sectors,
        "corrupted_sectors": r.corrupted_sectors,
        "primary_header_ok": r.primary_header_ok,
        "backup_header_ok": r.backup_header_ok,
        "headers_identical": r.headers_identical,
    })))
}

fn api_custody(state: &Arc<Mutex<AppState>>) -> Result<Response<Cursor<Vec<u8>>>> {
    let mut guard = state.lock().unwrap();
    let s = guard.active_mut()?;
    let entries = s.fs.read_custody_log()?;
    let report = s.fs.verify_custody_log()?;
    Ok(json_ok(&serde_json::json!({
        "report": report,
        "entries": entries,
    })))
}

fn api_keyslot_add(
    req: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Result<Response<Cursor<Vec<u8>>>> {
    let mut body: AddSlotReq = read_json(req)?;
    if body.passphrase.is_empty() {
        bail!("passphrase cannot be empty");
    }
    let profile = parse_profile(&body.profile)?;
    let kf_hash = load_keyfile(body.keyfile_path.as_deref())?;
    let pq_kp = load_pq_keypair(body.pq_key_path.as_deref())?;

    let mut guard = state.lock().unwrap();
    let s = guard.active_mut()?;
    let auth = AuthMaterial {
        passphrase: body.passphrase.as_bytes(),
        keyfile_hash: kf_hash.as_ref().map(|k| k.as_array()),
        pq_keypair: pq_kp.as_ref(),
    };
    let res = s
        .fs
        .volume_mut()
        .add_keyslot(None, &auth, &profile.params(), &body.label);
    body.passphrase.zeroize();
    let slot = res?;
    let _ = s
        .fs
        .append_custody_event("KEYSLOT_ADD", &format!("slot={slot} label={}", body.label));
    Ok(json_ok(&serde_json::json!({ "slot": slot })))
}

fn api_duress_add(
    req: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Result<Response<Cursor<Vec<u8>>>> {
    let mut body: AddDuressReq = read_json(req)?;
    if body.passphrase.is_empty() {
        bail!("duress passphrase cannot be empty");
    }
    let profile = parse_profile(&body.profile)?;
    let mut guard = state.lock().unwrap();
    let s = guard.active_mut()?;
    let auth = AuthMaterial::password_only(body.passphrase.as_bytes());
    let res = s
        .fs
        .volume_mut()
        .add_duress_slot(None, &auth, &profile.params(), &body.label);
    body.passphrase.zeroize();
    let slot = res?;
    Ok(json_ok(&serde_json::json!({ "slot": slot })))
}

fn api_keyslot_remove(
    req: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Result<Response<Cursor<Vec<u8>>>> {
    let body: RemoveSlotReq = read_json(req)?;
    let mut guard = state.lock().unwrap();
    let s = guard.active_mut()?;
    s.fs.volume_mut().remove_keyslot(body.slot)?;
    let _ = s
        .fs
        .append_custody_event("KEYSLOT_REVOKE", &format!("slot={}", body.slot));
    Ok(json_ok(&serde_json::json!({ "ok": true })))
}

fn api_passwd(
    req: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Result<Response<Cursor<Vec<u8>>>> {
    let mut body: PasswdReq = read_json(req)?;
    if body.new_passphrase.is_empty() {
        bail!("new passphrase cannot be empty");
    }
    let new_kf = load_keyfile(body.new_keyfile_path.as_deref())?;
    let new_pq = load_pq_keypair(body.new_pq_key_path.as_deref())?;
    let new_params = match body.new_profile.as_deref() {
        Some(p) => Some(parse_profile(p)?.params()),
        None => None,
    };

    let mut guard = state.lock().unwrap();
    let s = guard.active_mut()?;
    let slot = body.slot.unwrap_or_else(|| s.fs.volume().unlocked_slot());
    let auth = AuthMaterial {
        passphrase: body.new_passphrase.as_bytes(),
        keyfile_hash: new_kf.as_ref().map(|k| k.as_array()),
        pq_keypair: new_pq.as_ref(),
    };
    let res = s
        .fs
        .volume_mut()
        .change_slot_passphrase(slot, &auth, new_params.as_ref());
    body.new_passphrase.zeroize();
    res?;
    let _ = s
        .fs
        .append_custody_event("PASSWD_ROTATE", &format!("slot={slot}"));
    Ok(json_ok(&serde_json::json!({ "ok": true, "slot": slot })))
}

fn api_header_repair(state: &Arc<Mutex<AppState>>) -> Result<Response<Cursor<Vec<u8>>>> {
    let mut guard = state.lock().unwrap();
    let s = guard.active_mut()?;
    s.fs.volume_mut().persist_headers()?;
    let _ = s.fs.append_custody_event("HEADER_REPAIR", "re-signed & synced");
    Ok(json_ok(&serde_json::json!({ "ok": true })))
}

fn api_shred(
    req: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Result<Response<Cursor<Vec<u8>>>> {
    let body: ShredReq = read_json(req)?;
    if body.confirm != "SHRED" {
        bail!("confirmation must be 'SHRED'");
    }
    let path = PathBuf::from(&body.path);
    if is_raw_device_path(&path) || is_protected_system_disk(&path) {
        bail!("raw devices cannot be shredded from the web UI");
    }

    let mut detached = clean_opt_path(body.detached_header_path.as_deref());
    {
        let mut guard = state.lock().unwrap();
        if let Some(ref s) = guard.session {
            if s.path == path {
                if detached.is_none() {
                    detached = s.detached_header.clone();
                }
                guard.session = None;
            }
        }
    }

    let mut dev = FileBlockDevice::open_rw(&path, false)?;
    Volume::crypto_shred(&mut dev, detached.as_deref())?;
    Ok(json_ok(&serde_json::json!({ "ok": true })))
}

fn api_shamir_split(req: &mut Request) -> Result<Response<Cursor<Vec<u8>>>> {
    let body: ShamirSplitReq = read_json(req)?;
    let mut secret = if let Some(in_p) = clean_opt_path(body.in_keyfile_path.as_deref()) {
        let mut buf = Vec::new();
        File::open(&in_p)?.read_to_end(&mut buf)?;
        if buf.is_empty() || buf.len() > 256 {
            buf.zeroize();
            bail!("input keyfile must be 1..=256 bytes");
        }
        buf
    } else {
        random_bytes::<32>().to_vec()
    };

    if let Some(out_p) = clean_opt_path(body.out_keyfile_path.as_deref()) {
        ensure_parent_dir(&out_p)?;
        write_secret_0600(&out_p, &secret)?;
    }

    let shares = split_secret(&secret, body.threshold, body.shares)?;
    secret.zeroize();

    let mut encoded = Vec::with_capacity(shares.len());
    let mut keycards_svg = Vec::with_capacity(shares.len());
    for s in &shares {
        let enc = s.encode();
        let svg = render_keycard_svg(
            &format!("SHARE {:02} OF {:02}", s.index, body.shares),
            &format!("THRESHOLD {}", body.threshold),
            &enc,
        )?;
        encoded.push(enc);
        keycards_svg.push(svg);
    }

    Ok(json_ok(&serde_json::json!({
        "threshold": body.threshold,
        "total": body.shares,
        "shares": encoded,
        "keycards_svg": keycards_svg,
    })))
}

fn api_shamir_combine(req: &mut Request) -> Result<Response<Cursor<Vec<u8>>>> {
    let body: ShamirCombineReq = read_json(req)?;
    let mut parsed = Vec::with_capacity(body.shares.len());
    for line in &body.shares {
        if !line.trim().is_empty() {
            parsed.push(Share::parse(line)?);
        }
    }
    let mut recovered = combine_shares(&parsed)?;
    let out_p = PathBuf::from(&body.out_keyfile_path);
    ensure_parent_dir(&out_p)?;
    write_secret_0600(&out_p, &recovered)?;
    let len = recovered.len();
    recovered.zeroize();

    Ok(json_ok(&serde_json::json!({
        "ok": true,
        "path": body.out_keyfile_path,
        "bytes": len,
    })))
}

fn api_diag_benchmark(req: &mut Request) -> Result<Response<Cursor<Vec<u8>>>> {
    let body: BenchReq = read_json(req).unwrap_or(BenchReq { sectors: None });
    let sectors = body.sectors.unwrap_or(2048).clamp(256, 16384);
    let rep = run_crypto_benchmark(sectors)?;
    Ok(json_ok(&serde_json::json!({
        "sample_mib": rep.sample_mib,
        "aes_xts_mib_s": rep.aes_xts_mib_s,
        "cascade_xts_mib_s": rep.cascade_xts_mib_s,
        "blake3_mac_mib_s": rep.blake3_mac_mib_s,
    })))
}

fn api_diag_entropy(req: &mut Request) -> Result<Response<Cursor<Vec<u8>>>> {
    let body: EntropyReq = read_json(req)?;
    let f = File::open(&body.path)
        .with_context(|| format!("failed to open '{}'", body.path))?;
    let mut sample = Vec::new();
    f.take(4 * 1024 * 1024).read_to_end(&mut sample)?;
    let ent = analyze_entropy(&sample);

    Ok(json_ok(&serde_json::json!({
        "path": body.path,
        "sampled_bytes": ent.sampled_bytes,
        "shannon_bits_per_byte": ent.shannon_bits_per_byte,
        "byte_mean": ent.byte_mean,
        "min_bucket_ratio": ent.min_bucket_ratio,
        "max_bucket_ratio": ent.max_bucket_ratio,
        "has_visible_magic": ent.has_visible_magic,
    })))
}

fn api_diag_post(state: &Arc<Mutex<AppState>>) -> Result<Response<Cursor<Vec<u8>>>> {
    let rep = run_power_on_self_test()?;
    let mut guard = state.lock().unwrap();
    guard.post_report = rep.clone();
    Ok(json_ok(&rep))
}

fn api_update_check() -> Result<Response<Cursor<Vec<u8>>>> {
    Ok(json_ok(&crate::update::check_for_updates()))
}

fn api_identity_generate(req: &mut Request) -> Result<Response<Cursor<Vec<u8>>>> {
    let body: IdentityGenReq = read_json(req)?;
    let id_path = PathBuf::from(body.identity_path.trim());
    let pub_path = PathBuf::from(body.pub_path.trim());
    if id_path.as_os_str().is_empty() || pub_path.as_os_str().is_empty() {
        bail!("both identity path and public bundle path are required");
    }
    ensure_parent_dir(&id_path)?;
    ensure_parent_dir(&pub_path)?;

    let callsign = body.callsign.as_deref().unwrap_or("OPERATOR");
    let id = OperatorIdentity::generate(callsign);
    let pub_bundle = id.public_bundle();

    let mut id_bytes = id.to_bytes();
    write_secret_0600(&id_path, &id_bytes)?;
    id_bytes.zeroize();

    let pub_bytes = pub_bundle.to_bytes();
    let mut pf = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pub_path)
        .with_context(|| format!("failed to create '{}'", pub_path.display()))?;
    pf.write_all(&pub_bytes)?;
    pf.sync_all()?;

    Ok(json_ok(&serde_json::json!({
        "ok": true,
        "callsign": pub_bundle.callsign,
        "fingerprint": pub_bundle.fingerprint_hex(),
        "ed25519_pubkey": pub_bundle.ed25519_hex(),
        "identity_path": id_path.display().to_string(),
        "pub_path": pub_path.display().to_string(),
    })))
}

fn api_seal(req: &mut Request) -> Result<Response<Cursor<Vec<u8>>>> {
    let body: SealReq = read_json(req)?;
    let input_path = PathBuf::from(body.input_path.trim());
    let to_pub_path = PathBuf::from(body.to_pub_path.trim());
    let from_id_path = PathBuf::from(body.from_id_path.trim());
    let out_path = PathBuf::from(body.out_path.trim());

    let mut sender_raw = fs::read(&from_id_path)
        .with_context(|| format!("failed to open sender identity '{}'", from_id_path.display()))?;
    let sender = OperatorIdentity::from_bytes(&sender_raw);
    sender_raw.zeroize();
    let sender = sender?;

    let recip_raw = fs::read(&to_pub_path)
        .with_context(|| format!("failed to open recipient bundle '{}'", to_pub_path.display()))?;
    let recipient = OperatorPublicBundle::from_bytes(&recip_raw)?;

    let mut plaintext = fs::read(&input_path)
        .with_context(|| format!("failed to read input file '{}'", input_path.display()))?;
    let fname = input_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("drop.bin");

    let (pkg, meta, san_rep) = seal_package(
        &sender,
        &recipient,
        fname,
        &plaintext,
        body.sanitize.unwrap_or(false),
    )?;
    plaintext.zeroize();

    ensure_parent_dir(&out_path)?;
    let mut of = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&out_path)
        .with_context(|| format!("failed to write '{}'", out_path.display()))?;
    of.write_all(&pkg)?;
    of.sync_all()?;

    Ok(json_ok(&serde_json::json!({
        "ok": true,
        "out_path": out_path.display().to_string(),
        "meta": meta,
        "sanitized": san_rep.map(|r| serde_json::json!({
            "format": r.format,
            "bytes_removed": r.bytes_removed,
            "segments_stripped": r.segments_stripped,
        })),
    })))
}

fn api_unseal(req: &mut Request) -> Result<Response<Cursor<Vec<u8>>>> {
    let body: UnsealReq = read_json(req)?;
    let pkg_path = PathBuf::from(body.package_path.trim());
    let id_path = PathBuf::from(body.identity_path.trim());
    let out_path = PathBuf::from(body.out_path.trim());

    let mut recip_raw = fs::read(&id_path)
        .with_context(|| format!("failed to open recipient identity '{}'", id_path.display()))?;
    let recipient = OperatorIdentity::from_bytes(&recip_raw);
    recip_raw.zeroize();
    let recipient = recipient?;

    let expected_sender = match clean_opt_path(body.expect_sender_path.as_deref()) {
        Some(p) => {
            let raw = fs::read(&p)
                .with_context(|| format!("failed to open expected sender bundle '{}'", p.display()))?;
            Some(OperatorPublicBundle::from_bytes(&raw)?)
        }
        None => None,
    };

    let pkg = fs::read(&pkg_path)
        .with_context(|| format!("failed to read sealed drop '{}'", pkg_path.display()))?;
    let drop = unseal_package(&recipient, expected_sender.as_ref(), &pkg)?;

    ensure_parent_dir(&out_path)?;
    let mut of = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&out_path)
        .with_context(|| format!("failed to write '{}'", out_path.display()))?;
    of.write_all(&drop.plaintext)?;
    of.sync_all()?;

    Ok(json_ok(&serde_json::json!({
        "ok": true,
        "out_path": out_path.display().to_string(),
        "meta": drop.meta,
    })))
}

fn api_browse(query: &str) -> Result<Response<Cursor<Vec<u8>>>> {
    let dir_str = query_param(query, "dir").unwrap_or_default();
    let dir = if dir_str.is_empty() {
        std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")))
    } else {
        PathBuf::from(&dir_str)
    };

    let mut entries = Vec::new();
    for entry in fs::read_dir(&dir)?.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue;
        }
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        entries.push(serde_json::json!({
            "name": name,
            "path": entry.path().display().to_string(),
            "is_dir": meta.is_dir(),
            "size": meta.len(),
        }));
    }

    entries.sort_by(|a, b| {
        let ad = a["is_dir"].as_bool().unwrap_or(false);
        let bd = b["is_dir"].as_bool().unwrap_or(false);
        bd.cmp(&ad)
            .then_with(|| a["name"].as_str().cmp(&b["name"].as_str()))
    });

    let parent = dir.parent().map(|p| p.display().to_string());
    Ok(json_ok(&serde_json::json!({
        "dir": dir.display().to_string(),
        "parent": parent,
        "entries": entries,
    })))
}

fn clean_opt_path(s: Option<&str>) -> Option<PathBuf> {
    s.map(str::trim)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

fn write_secret_0600(path: &Path, data: &[u8]) -> Result<()> {
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

fn parse_profile(s: &str) -> Result<KdfProfile> {
    match s {
        "fast-test" => Ok(KdfProfile::FastTest),
        "interactive" => Ok(KdfProfile::Interactive),
        "standard" => Ok(KdfProfile::Standard),
        "paranoid" => Ok(KdfProfile::Paranoid),
        other => bail!("unknown KDF profile '{other}'"),
    }
}

fn load_keyfile(path: Option<&str>) -> Result<Option<SecureArray<32>>> {
    match clean_opt_path(path) {
        Some(p) => {
            let f = File::open(&p)
                .with_context(|| format!("failed to open keyfile '{}'", p.display()))?;
            Ok(Some(hash_keyfile(f)?))
        }
        None => Ok(None),
    }
}

fn load_pq_keypair(path: Option<&str>) -> Result<Option<PqKeypair>> {
    match clean_opt_path(path) {
        Some(p) => {
            let mut raw = Vec::new();
            File::open(&p)
                .with_context(|| format!("failed to open PQ keyfile '{}'", p.display()))?
                .read_to_end(&mut raw)?;
            let res = PqKeypair::from_bytes(&raw);
            raw.zeroize();
            Ok(Some(res?))
        }
        None => Ok(None),
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(req: &mut Request) -> Result<T> {
    let mut buf = Vec::new();
    req.as_reader()
        .take((MAX_JSON_BODY + 1) as u64)
        .read_to_end(&mut buf)?;
    if buf.len() > MAX_JSON_BODY {
        buf.zeroize();
        bail!("JSON body too large");
    }
    let parsed = serde_json::from_slice(&buf).context("invalid JSON request")?;
    buf.zeroize();
    Ok(parsed)
}

fn check_host_header(req: &Request, port: u16) -> bool {
    let expected_ip = format!("127.0.0.1:{port}");
    let expected_lh = format!("localhost:{port}");
    match req
        .headers()
        .iter()
        .find(|h| h.field.equiv("Host"))
        .map(|h| h.value.as_str())
    {
        Some(h) => h == expected_ip || h == expected_lh,
        None => false,
    }
}

fn ct_str_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

fn query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(percent_decode(v));
            }
        }
    }
    None
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex_str) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(val) = u8::from_str_radix(hex_str, 16) {
                    out.push(val);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).unwrap()
}

fn add_security_headers<R: Read>(resp: &mut Response<R>) {
    resp.add_header(header("Cache-Control", "no-store"));
    resp.add_header(header("X-Content-Type-Options", "nosniff"));
    resp.add_header(header("X-Frame-Options", "DENY"));
    resp.add_header(header("Referrer-Policy", "no-referrer"));
}

fn json_ok<T: Serialize>(value: &T) -> Response<Cursor<Vec<u8>>> {
    let data = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    let mut resp = Response::from_data(data)
        .with_status_code(StatusCode(200))
        .with_header(header("Content-Type", "application/json; charset=utf-8"));
    add_security_headers(&mut resp);
    resp
}

fn json_error(status: u16, msg: &str) -> Response<Cursor<Vec<u8>>> {
    let data = serde_json::to_vec(&serde_json::json!({ "error": msg })).unwrap();
    let mut resp = Response::from_data(data)
        .with_status_code(StatusCode(status))
        .with_header(header("Content-Type", "application/json; charset=utf-8"));
    add_security_headers(&mut resp);
    resp
}

fn text_response(status: u16, ct: &str, body: &str) -> Response<Cursor<Vec<u8>>> {
    let mut resp = Response::from_data(body.as_bytes().to_vec())
        .with_status_code(StatusCode(status))
        .with_header(header("Content-Type", ct));
    add_security_headers(&mut resp);
    resp
}

fn launch_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(url).spawn();

    #[cfg(target_os = "linux")]
    let _ = std::process::Command::new("xdg-open").arg(url).spawn();

    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("cmd")
        .args(["/C", "start", "", url])
        .spawn();
}
