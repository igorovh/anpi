//! `anpi update`: replaces the running binary with a release from GitHub.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, bail, ensure};
use http::Method;
use http::header::{ACCEPT, USER_AGENT};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::checks::http::{RequestSpec, send};

pub const REPO: &str = "igorovh/anpi";
pub const CURRENT: &str = env!("CARGO_PKG_VERSION");

/// Release archive suffix for this build; matches the targets in `.github/workflows/release.yml`.
pub const TARGET: Option<&str> = if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
    Some("x86_64-unknown-linux-musl")
} else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
    Some("aarch64-unknown-linux-musl")
} else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
    Some("aarch64-apple-darwin")
} else {
    None
};

#[derive(Debug, Deserialize)]
pub struct Release {
    pub tag_name: String,
    pub html_url: String,
    pub assets: Vec<Asset>,
}

#[derive(Debug, Deserialize)]
pub struct Asset {
    pub name: String,
    pub browser_download_url: String,
}

/// Parses `v1.2.3` or `1.2.3`; pre-release suffixes are ignored.
pub fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let core = v.trim().trim_start_matches('v').split(['-', '+']).next()?;
    let mut it = core.split('.').map(|p| p.parse::<u64>().ok());
    let v = (it.next()??, it.next()??, it.next()??);
    it.next().is_none().then_some(v)
}

impl Release {
    pub fn version(&self) -> anyhow::Result<(u64, u64, u64)> {
        parse_version(&self.tag_name).with_context(|| format!("unexpected release tag {:?}", self.tag_name))
    }

    pub fn archive_for(&self, target: &str) -> Option<(&Asset, &Asset)> {
        let name = format!("anpi-{}-{target}.tar.gz", self.tag_name);
        let archive = self.assets.iter().find(|a| a.name == name)?;
        let sum = self.assets.iter().find(|a| a.name == format!("{name}.sha256"))?;
        Some((archive, sum))
    }
}

pub async fn download(url: &str, accept: &str, max_bytes: usize) -> anyhow::Result<bytes::Bytes> {
    let mut spec = RequestSpec::new(Method::GET, url::Url::parse(url)?)
        .header(USER_AGENT, &format!("anpi/{CURRENT}"))
        .header(ACCEPT, accept);
    spec.timeout = Duration::from_secs(300);
    spec.max_body_bytes = max_bytes;
    let r = send(&spec).await.with_context(|| format!("GET {url}"))?;
    match r.status {
        200 => {}
        404 => bail!("no release found at {url}; the repository must be public and the version must exist"),
        403 | 429 => bail!("GitHub refused the request (HTTP {}), probably a rate limit; try again later", r.status),
        s => bail!("GET {url}: HTTP {s}"),
    }
    ensure!(!r.body_truncated, "{url} is larger than {max_bytes} bytes");
    Ok(r.body)
}

/// The latest release, or the one tagged `v{version}`.
pub async fn fetch_release(version: Option<&str>) -> anyhow::Result<Release> {
    let url = match version {
        Some(v) => format!("https://api.github.com/repos/{REPO}/releases/tags/v{}", v.trim_start_matches('v')),
        None => format!("https://api.github.com/repos/{REPO}/releases/latest"),
    };
    let body = download(&url, "application/vnd.github+json", 4 * 1024 * 1024).await?;
    serde_json::from_slice(&body).context("reading the GitHub release")
}

/// Checks the archive against a `sha256sum`-style line: `<hex>  <file name>`.
pub fn verify_sha256(data: &[u8], sum_file: &str) -> anyhow::Result<()> {
    let expected = sum_file.split_whitespace().next().unwrap_or_default().to_ascii_lowercase();
    ensure!(expected.len() == 64, "the checksum file is malformed");
    let actual = hex::encode(Sha256::digest(data));
    ensure!(actual == expected, "checksum mismatch: expected {expected}, got {actual}");
    Ok(())
}

/// Pulls the `anpi` executable out of a release `.tar.gz`.
pub fn extract_binary(archive: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(archive));
    for entry in tar.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        if entry.header().entry_type().is_file() && path.file_name().is_some_and(|n| n == "anpi") && path.components().count() <= 2 {
            let mut out = Vec::new();
            entry.read_to_end(&mut out)?;
            ensure!(!out.is_empty(), "the archive holds an empty binary");
            return Ok(out);
        }
    }
    bail!("the archive does not contain the anpi binary")
}

pub fn backup_path(exe: &Path) -> PathBuf {
    exe.with_file_name("anpi.old")
}

/// Writes `new` next to `exe`, keeps the old binary as `anpi.old` and swaps atomically.
pub fn replace_binary(exe: &Path, new: &[u8]) -> anyhow::Result<()> {
    let staged = exe.with_file_name(".anpi.new");
    let write = || -> std::io::Result<()> {
        std::fs::write(&staged, new)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))?;
        }
        std::fs::copy(exe, backup_path(exe))?;
        std::fs::rename(&staged, exe)
    };
    write().map_err(|e| {
        let _ = std::fs::remove_file(&staged);
        permission_hint(e, exe)
    })
}

/// Puts `anpi.old` back in place; the replaced binary becomes the new `anpi.old`.
pub fn rollback(exe: &Path) -> anyhow::Result<()> {
    let old = backup_path(exe);
    ensure!(old.exists(), "there is no previous version at {}", old.display());
    let staged = exe.with_file_name(".anpi.new");
    let swap = || -> std::io::Result<()> {
        std::fs::copy(&old, &staged)?;
        std::fs::copy(exe, &old)?;
        std::fs::rename(&staged, exe)
    };
    swap().map_err(|e| permission_hint(e, exe))
}

fn permission_hint(e: std::io::Error, exe: &Path) -> anyhow::Error {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        anyhow::anyhow!("no permission to replace {}; run it with sudo", exe.display())
    } else {
        anyhow::anyhow!("replacing {}: {e}", exe.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(tag: &str, names: &[&str]) -> Release {
        Release {
            tag_name: tag.into(),
            html_url: String::new(),
            assets: names.iter().map(|n| Asset { name: n.to_string(), browser_download_url: format!("https://dl/{n}") }).collect(),
        }
    }

    fn tar_gz(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut b = tar::Builder::new(flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast()));
        for (path, data) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o755);
            h.set_cksum();
            b.append_data(&mut h, path, *data).unwrap();
        }
        b.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn versions_compare_numerically() {
        assert_eq!(parse_version("v0.10.2"), Some((0, 10, 2)));
        assert_eq!(parse_version("1.2.3-rc.1"), Some((1, 2, 3)));
        assert!(parse_version("v0.10.0") > parse_version("0.9.9"), "not a string comparison");
        assert_eq!(parse_version("1.2"), None);
        assert_eq!(parse_version("1.2.3.4"), None);
        assert_eq!(parse_version("latest"), None);
        assert!(parse_version(CURRENT).is_some(), "the crate version itself parses");
    }

    #[test]
    fn picks_the_archive_and_checksum_for_this_target() {
        let r = release("v0.2.0", &[
            "anpi-v0.2.0-x86_64-unknown-linux-musl.tar.gz",
            "anpi-v0.2.0-x86_64-unknown-linux-musl.tar.gz.sha256",
            "anpi-v0.2.0-aarch64-unknown-linux-musl.tar.gz",
        ]);
        let (a, s) = r.archive_for("x86_64-unknown-linux-musl").unwrap();
        assert_eq!(a.name, "anpi-v0.2.0-x86_64-unknown-linux-musl.tar.gz");
        assert!(s.name.ends_with(".sha256"));
        assert!(r.archive_for("aarch64-unknown-linux-musl").is_none(), "no checksum, no update");
        assert!(r.archive_for("riscv64").is_none());
    }

    #[test]
    fn checksum_must_match() {
        let data = b"archive";
        let good = format!("{}  anpi.tar.gz\n", hex::encode(Sha256::digest(data)));
        verify_sha256(data, &good).unwrap();
        verify_sha256(data, &good.to_uppercase()).unwrap();
        assert!(verify_sha256(b"tampered", &good).unwrap_err().to_string().contains("mismatch"));
        assert!(verify_sha256(data, "").is_err());
    }

    #[test]
    fn extracts_only_the_top_level_binary() {
        let archive = tar_gz(&[
            ("anpi-v0.2.0-x/README.md", b"readme"),
            ("anpi-v0.2.0-x/deploy/anpi", b"not this one"),
            ("anpi-v0.2.0-x/anpi", b"\x7fELF new"),
        ]);
        assert_eq!(extract_binary(&archive).unwrap(), b"\x7fELF new");
        assert!(extract_binary(&tar_gz(&[("x/README.md", b"r")])).is_err());
        assert!(extract_binary(b"not gzip").is_err());
    }

    #[test]
    fn replace_keeps_the_old_binary_and_rollback_swaps_back() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("anpi");
        std::fs::write(&exe, b"v1").unwrap();
        assert!(rollback(&exe).is_err(), "nothing to roll back to yet");

        replace_binary(&exe, b"v2").unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"v2");
        assert_eq!(std::fs::read(backup_path(&exe)).unwrap(), b"v1");
        assert!(!dir.path().join(".anpi.new").exists(), "no staging file left behind");

        rollback(&exe).unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"v1");
        assert_eq!(std::fs::read(backup_path(&exe)).unwrap(), b"v2", "rolling back twice returns to the update");
    }
}
