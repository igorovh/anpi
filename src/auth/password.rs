use argon2::Argon2;
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};

pub const MIN_LENGTH: usize = 10;

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

    #[test]
    fn strength_counts_characters_not_bytes() {
        assert!(check_strength("short").is_err());
        assert!(check_strength("ąęłńóśźżćą").is_ok());
    }
}
