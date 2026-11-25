use serde::Serialize;
use std::process::Command;

pub const GITHUB_REPO: &str = "skotinas/falcon";
pub const REPO_URL: &str = "https://github.com/skotinas/falcon";
pub const RELEASES_URL: &str = "https://github.com/skotinas/falcon/releases";
pub const ISSUES_URL: &str = "https://github.com/skotinas/falcon/issues/new";

#[derive(Debug, Clone, Serialize)]
pub struct UpdateCheckResult {
    pub current_version: String,
    pub latest_version: Option<String>,
    pub update_available: bool,
    pub release_url: String,
    pub releases_url: String,
    pub published_at: Option<String>,
    pub status: String,
    pub message: String,
}

pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub fn system_platform() -> String {
    format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH)
}

/// Strictly manual (user-initiated) update check against GitHub Releases.
/// Never runs automatically so air-gapped workstations stay zero-telemetry.
pub fn check_for_updates() -> UpdateCheckResult {
    let cur = current_version().to_string();
    let api_url = format!("https://api.github.com/repos/{GITHUB_REPO}/releases/latest");
    let ua = format!("Falcon-COMSEC/{cur}");

    let output = Command::new("curl")
        .args([
            "-fsSL",
            "--max-time",
            "6",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            &format!("User-Agent: {ua}"),
            &api_url,
        ])
        .output();

    let out = match output {
        Ok(o) if o.status.success() => o,
        _ => {
            return UpdateCheckResult {
                current_version: cur,
                latest_version: None,
                update_available: false,
                release_url: RELEASES_URL.to_string(),
                releases_url: RELEASES_URL.to_string(),
                published_at: None,
                status: "offline".to_string(),
                message: "Unable to reach GitHub Releases (air-gapped / offline, or no release published yet).".to_string(),
            };
        }
    };

    let parsed: serde_json::Value = match serde_json::from_slice(&out.stdout) {
        Ok(v) => v,
        Err(_) => {
            return UpdateCheckResult {
                current_version: cur,
                latest_version: None,
                update_available: false,
                release_url: RELEASES_URL.to_string(),
                releases_url: RELEASES_URL.to_string(),
                published_at: None,
                status: "error".to_string(),
                message: "Unexpected response from GitHub Releases API.".to_string(),
            };
        }
    };

    let tag = parsed["tag_name"].as_str().unwrap_or("").trim();
    let clean_latest = tag.trim_start_matches(['v', 'V']).to_string();
    if clean_latest.is_empty() {
        return UpdateCheckResult {
            current_version: cur,
            latest_version: None,
            update_available: false,
            release_url: RELEASES_URL.to_string(),
            releases_url: RELEASES_URL.to_string(),
            published_at: None,
            status: "none".to_string(),
            message: "No tagged release found on GitHub yet.".to_string(),
        };
    }

    let html_url = parsed["html_url"]
        .as_str()
        .filter(|u| u.starts_with("https://github.com/"))
        .unwrap_or(RELEASES_URL)
        .to_string();
    let published_at = parsed["published_at"].as_str().map(String::from);

    let newer = is_newer_semver(&clean_latest, &cur);
    let (status, message) = if newer {
        (
            "update_available".to_string(),
            format!("Update available: v{clean_latest} (installed: v{cur})."),
        )
    } else {
        (
            "up_to_date".to_string(),
            format!("Falcon v{cur} is up to date (latest release: v{clean_latest})."),
        )
    };

    UpdateCheckResult {
        current_version: cur,
        latest_version: Some(clean_latest),
        update_available: newer,
        release_url: html_url,
        releases_url: RELEASES_URL.to_string(),
        published_at,
        status,
        message,
    }
}

fn parse_semver(s: &str) -> Option<(u64, u64, u64)> {
    let base = s.split('-').next().unwrap_or(s);
    let mut parts = base.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next().unwrap_or("0").parse().ok()?;
    Some((major, minor, patch))
}

fn is_newer_semver(candidate: &str, current: &str) -> bool {
    match (parse_semver(candidate), parse_semver(current)) {
        (Some(a), Some(b)) => a > b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_comparison_works() {
        assert!(is_newer_semver("0.4.1", "0.4.0"));
        assert!(is_newer_semver("0.5.0", "0.4.9"));
        assert!(is_newer_semver("1.0.0", "0.9.9"));
        assert!(!is_newer_semver("0.4.0", "0.4.0"));
        assert!(!is_newer_semver("0.3.9", "0.4.0"));
    }
}
