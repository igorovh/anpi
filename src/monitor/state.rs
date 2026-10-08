use crate::models::Status;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transition {
    None,
    WentDown,
    Recovered,
}

/// Per-monitor state machine. `last` is `None` for a monitor that has never been checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MonitorState {
    pub last: Option<Status>,
    pub consecutive_failures: u32,
}

impl MonitorState {
    pub fn new() -> Self {
        Self { last: None, consecutive_failures: 0 }
    }

    /// Rebuilds state after a restart from the newest heartbeats (newest first).
    pub fn restore(newest_first: &[Status]) -> Self {
        let Some(&last) = newest_first.first() else { return Self::new() };
        let failures = match last {
            Status::Pending => newest_first.iter().take_while(|s| **s == Status::Pending).count() as u32,
            _ => 0,
        };
        // A monitor stuck in Pending was Up before the failures started.
        let last = if last == Status::Pending { Status::Up } else { last };
        Self { last: Some(last), consecutive_failures: failures }
    }

    /// `threshold` is the number of consecutive failures that marks a monitor Down.
    pub fn apply(&mut self, ok: bool, threshold: u32, in_maintenance: bool) -> (Status, Transition) {
        let threshold = threshold.max(1);
        if in_maintenance {
            self.consecutive_failures = 0;
            self.last = Some(Status::Maintenance);
            return (Status::Maintenance, Transition::None);
        }
        if ok {
            self.consecutive_failures = 0;
            let transition = if self.last == Some(Status::Down) { Transition::Recovered } else { Transition::None };
            self.last = Some(Status::Up);
            return (Status::Up, transition);
        }
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.last == Some(Status::Down) {
            return (Status::Down, Transition::None);
        }
        if self.consecutive_failures >= threshold {
            self.last = Some(Status::Down);
            return (Status::Down, Transition::WentDown);
        }
        // `last` stays as it was so a short blip that recovers never sends a notification.
        (Status::Pending, Transition::None)
    }
}

impl Default for MonitorState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Status::*;
    use Transition as T;

    fn run(state: &mut MonitorState, threshold: u32, checks: &[bool]) -> Vec<(Status, Transition)> {
        checks.iter().map(|ok| state.apply(*ok, threshold, false)).collect()
    }

    #[test]
    fn down_only_after_threshold_consecutive_failures() {
        let mut s = MonitorState::new();
        let r = run(&mut s, 3, &[true, false, false, false, false]);
        assert_eq!(r, vec![(Up, T::None), (Pending, T::None), (Pending, T::None), (Down, T::WentDown), (Down, T::None)]);
    }

    #[test]
    fn a_blip_shorter_than_threshold_is_silent() {
        let mut s = MonitorState::new();
        let r = run(&mut s, 3, &[true, false, false, true, false, true]);
        assert!(r.iter().all(|(_, t)| *t == T::None), "{r:?}");
        assert_eq!(s.consecutive_failures, 0);
    }

    #[test]
    fn success_after_down_sends_exactly_one_recovery() {
        let mut s = MonitorState::new();
        run(&mut s, 2, &[false, false]);
        let r = run(&mut s, 2, &[true, true]);
        assert_eq!(r, vec![(Up, T::Recovered), (Up, T::None)]);
    }

    #[test]
    fn threshold_of_one_goes_down_immediately_even_on_first_check() {
        let mut s = MonitorState::new();
        assert_eq!(s.apply(false, 1, false), (Down, T::WentDown));
        let mut s = MonitorState::new();
        assert_eq!(s.apply(false, 0, false), (Down, T::WentDown), "zero is treated as one");
    }

    #[test]
    fn maintenance_suppresses_transitions_and_resets_counter() {
        let mut s = MonitorState::new();
        run(&mut s, 3, &[true, false, false]);
        assert_eq!(s.apply(false, 3, true), (Maintenance, T::None));
        assert_eq!(s.consecutive_failures, 0);
        // Recovering from maintenance is not a "recovered" event.
        assert_eq!(s.apply(true, 3, false), (Up, T::None));
    }

    #[test]
    fn down_during_maintenance_end_is_reported_after_threshold() {
        let mut s = MonitorState::new();
        s.apply(false, 2, true);
        assert_eq!(run(&mut s, 2, &[false, false]), vec![(Pending, T::None), (Down, T::WentDown)]);
    }

    #[test]
    fn restore_after_restart_avoids_duplicate_alerts() {
        let mut s = MonitorState::restore(&[Down, Down, Up]);
        assert_eq!(s.apply(false, 3, false), (Down, T::None), "already-down monitor must not re-alert");
        assert_eq!(s.apply(true, 3, false), (Up, T::Recovered));

        let mut s = MonitorState::restore(&[Pending, Pending, Up]);
        assert_eq!(s.consecutive_failures, 2);
        assert_eq!(s.apply(false, 3, false), (Down, T::WentDown), "pending streak continues across restarts");

        assert_eq!(MonitorState::restore(&[]), MonitorState::new());
    }
}
