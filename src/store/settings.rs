use crate::db::Db;

pub async fn get(db: &Db, key: &str) -> sqlx::Result<Option<String>> {
    sqlx::query_scalar("SELECT value FROM settings WHERE key = ?").bind(key).fetch_optional(db).await
}

pub async fn set(db: &Db, key: &str, value: &str) -> sqlx::Result<()> {
    sqlx::query("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
        .bind(key)
        .bind(value)
        .execute(db)
        .await?;
    Ok(())
}

#[derive(Clone, Debug, PartialEq)]
pub struct AppSettings {
    pub status_title: String,
    pub status_description: String,
    pub raw_retention_hours: i64,
    pub hourly_retention_days: i64,
    pub incident_retention_days: i64,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            status_title: "Service status".into(),
            status_description: String::new(),
            raw_retention_hours: 24,
            hourly_retention_days: 365,
            incident_retention_days: 365,
        }
    }
}

impl AppSettings {
    pub async fn load(db: &Db) -> sqlx::Result<Self> {
        let d = Self::default();
        let num = |v: Option<String>, def: i64| v.and_then(|s| s.parse().ok()).unwrap_or(def);
        Ok(Self {
            status_title: get(db, "status_title").await?.unwrap_or(d.status_title),
            status_description: get(db, "status_description").await?.unwrap_or(d.status_description),
            raw_retention_hours: num(get(db, "raw_retention_hours").await?, d.raw_retention_hours),
            hourly_retention_days: num(get(db, "hourly_retention_days").await?, d.hourly_retention_days),
            incident_retention_days: num(get(db, "incident_retention_days").await?, d.incident_retention_days),
        })
    }

    pub async fn save(&self, db: &Db) -> sqlx::Result<()> {
        set(db, "status_title", &self.status_title).await?;
        set(db, "status_description", &self.status_description).await?;
        set(db, "raw_retention_hours", &self.raw_retention_hours.to_string()).await?;
        set(db, "hourly_retention_days", &self.hourly_retention_days.to_string()).await?;
        set(db, "incident_retention_days", &self.incident_retention_days.to_string()).await
    }
}
