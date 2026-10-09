use std::time::Duration;

use argon2::Argon2;
use tokio::sync::Semaphore;
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};

pub const MIN_LENGTH: usize = 10;

/// Each hash takes ~19 MB and tens of milliseconds, so only a few run at once, off the async workers.
static HASH_PERMITS: Semaphore = Semaphore::const_new(4);
const PERMIT_WAIT: Duration = Duration::from_secs(2);

#[derive(Debug, PartialEq, Eq)]
pub struct Busy;

impl std::fmt::Display for Busy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("password hashing is busy")
    }
}

impl std::error::Error for Busy {}

async fn off_runtime<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> Result<T, Busy> {
    let _permit = tokio::time::timeout(PERMIT_WAIT, HASH_PERMITS.acquire()).await.map_err(|_| Busy)?.map_err(|_| Busy)?;
    tokio::task::spawn_blocking(work).await.map_err(|_| Busy)
}

/// Checks a password without blocking the runtime; `None` runs a dummy check so unknown users take as long.
pub async fn verify_async(password: &str, phc: Option<&str>) -> Result<bool, Busy> {
    let (password, phc) = (password.to_string(), phc.map(str::to_string));
    off_runtime(move || match phc {
        Some(h) => verify(&password, &h),
        None => {
            dummy_verify(&password);
            false
        }
    })
    .await
}

pub async fn hash_async(password: &str) -> anyhow::Result<String> {
    let password = password.to_string();
    off_runtime(move || hash(&password)).await?
}

pub fn hash(password: &str) -> anyhow::Result<String> {
    Argon2::default().hash_password(password.as_bytes()).map(|h| h.to_string()).map_err(|e| anyhow::anyhow!("hashing failed: {e}"))
}

pub fn verify(password: &str, phc: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(parsed) => Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok(),
        Err(_) => false,
    }
}

pub fn check_strength(password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_LENGTH {
        return Err(format!("password must be at least {MIN_LENGTH} characters"));
    }
    Ok(())
}

/// Verifies against a fixed hash so unknown usernames take as long as wrong passwords.
pub fn dummy_verify(password: &str) {
    use std::sync::OnceLock;
    static DUMMY: OnceLock<String> = OnceLock::new();
    let h = DUMMY.get_or_init(|| hash("anpi-dummy-password").unwrap_or_default());
    let _ = verify(password, h);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_roundtrip_and_salting() {
        let a = hash("correct horse battery").unwrap();
        let b = hash("correct horse battery").unwrap();
        assert!(a.starts_with("$argon2id$"));
        assert_ne!(a, b, "salts must differ");
        assert!(verify("correct horse battery", &a));
        assert!(!verify("wrong horse battery", &a));
        assert!(!verify("anything", "not-a-phc-string"));
    }

    #[tokio::test]
    async fn async_variants_match_the_blocking_ones() {
        let h = hash_async("correct horse battery").await.unwrap();
        assert_eq!(verify_async("correct horse battery", Some(&h)).await, Ok(true));
        assert_eq!(verify_async("wrong", Some(&h)).await, Ok(false));
        assert_eq!(verify_async("anything", None).await, Ok(false), "unknown users still fail");
    }

    #[tokio::test]
    async fn hashing_does_not_block_the_runtime() {
        // On this single-threaded runtime the other task can only run if hashing yields to it.
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = ran.clone();
        tokio::spawn(async move { flag.store(true, std::sync::atomic::Ordering::SeqCst) });
        verify_async("x", None).await.unwrap();
        assert!(ran.load(std::sync::atomic::Ordering::SeqCst), "another task ran while the hash was computed");
    }

    #[test]
    fn strength_counts_characters_not_bytes() {
        assert!(check_strength("short").is_err());
        assert!(check_strength("ąęłńóśźżćą").is_ok());
    }
}
