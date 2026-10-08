use std::collections::HashSet;
use std::sync::RwLock;

use crate::db::Db;
use crate::store;

#[derive(Clone, Debug)]
pub struct Window {
    pub starts_at: i64,
    pub ends_at: i64,
    pub all_monitors: bool,
    pub monitors: HashSet<i64>,
}

impl Window {
    pub fn covers(&self, monitor_id: i64, now: i64) -> bool {
        now >= self.starts_at && now < self.ends_at && (self.all_monitors || self.monitors.contains(&monitor_id))
    }
}

#[derive(Default)]
pub struct MaintenanceCache {
    windows: RwLock<Vec<Window>>,
}

impl MaintenanceCache {
    pub async fn reload(&self, db: &Db, now: i64) -> sqlx::Result<()> {
        let windows = store::maintenance::upcoming_with_monitors(db, now)
            .await?
            .into_iter()
            .map(|(m, ids)| Window {
                starts_at: m.starts_at,
                ends_at: m.ends_at,
                all_monitors: m.all_monitors,
                monitors: ids.into_iter().collect(),
            })
            .collect();
        *self.windows.write().expect("maintenance lock") = windows;
        Ok(())
    }

    pub fn active_for(&self, monitor_id: i64, now: i64) -> bool {
        self.windows.read().expect("maintenance lock").iter().any(|w| w.covers(monitor_id, now))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_bounds_are_half_open_and_scoped() {
        let w = Window { starts_at: 100, ends_at: 200, all_monitors: false, monitors: HashSet::from([1]) };
        assert!(!w.covers(1, 99));
        assert!(w.covers(1, 100));
        assert!(w.covers(1, 199));
        assert!(!w.covers(1, 200));
        assert!(!w.covers(2, 150), "other monitors are unaffected");
        let all = Window { all_monitors: true, monitors: HashSet::new(), ..w };
        assert!(all.covers(42, 150));
    }
}
