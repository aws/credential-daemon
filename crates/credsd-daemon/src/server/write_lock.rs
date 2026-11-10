//! Bounded use of a caller's per-uid write lock.
//!
//! Every write into `callers/<uid>/` serializes on one lock per uid ([`Daemon::bootstrap_lock`]),
//! so each holder's hold time is every other writer's wait time. Two different things need
//! bounding, and a bare `lock().await` bounds neither:
//!
//! - **Wait.** A writer queued behind a holder must give up rather than park indefinitely, because
//!   some writers are on a request path a caller is blocked on.
//! - **Hold.** A holder whose own work can take minutes (an interactive login is the live case —
//!   device-code entry plus token polling) must be cut off, or one slow holder is indistinguishable
//!   from a lock that is never released.
//!
//! [`under`] does both, so a new write path gets both by picking a [`Budget`] instead of
//! re-deciding the policy. Cancelling the operation on its hold budget releases the lock as a
//! side effect of dropping the future, which is why the hold bound needs no cooperation from the
//! operation itself.
//!
//! [`Daemon::bootstrap_lock`]: crate::server::dispatch::Daemon::bootstrap_lock

use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

/// How long a write path may wait for the lock, and how long it may hold it.
#[derive(Clone, Copy)]
pub(crate) struct Budget {
    pub(crate) wait: Duration,
    pub(crate) hold: Duration,
}

/// Which bound a write path ran past. The caller maps this onto its own error type, because the
/// two mean different things to a client: a wait means "try again", a hold means the operation
/// itself did not finish.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Expired {
    Wait,
    Hold,
}

impl Expired {
    /// The bound that was exceeded, for an error message or an audit field.
    pub(crate) fn limit(&self, budget: Budget) -> Duration {
        match self {
            Self::Wait => budget.wait,
            Self::Hold => budget.hold,
        }
    }
}

/// Proof that `uid`'s write lock is held. Borrowed from the guard, so it cannot outlive the hold,
/// and constructible only here, so the shared drift check can demand it rather than trust a
/// comment that says "the caller holds the lock" (drift-detection Requirement 5.8).
#[derive(Clone, Copy)]
pub(crate) struct Held<'g> {
    uid: u32,
    _guard: PhantomData<&'g ()>,
}

impl<'g> Held<'g> {
    fn of<G>(_guard: &'g G, uid: u32) -> Self {
        Self {
            uid,
            _guard: PhantomData,
        }
    }

    /// The uid whose lock this proves held.
    pub(crate) fn uid(&self) -> u32 {
        self.uid
    }
}

/// `uid`'s write lock, held until dropped. For write paths that hold it across several steps
/// rather than around one bounded operation.
pub(crate) struct Guard {
    uid: u32,
    _guard: tokio::sync::OwnedMutexGuard<()>,
}

impl Guard {
    pub(crate) fn held(&self) -> Held<'_> {
        Held::of(self, self.uid)
    }
}

/// Take `uid`'s write lock, `lock`, with no bound on the wait.
pub(crate) async fn acquire(lock: Arc<tokio::sync::Mutex<()>>, uid: u32) -> Guard {
    Guard {
        uid,
        _guard: lock.lock_owned().await,
    }
}

/// Take `uid`'s write lock if it is free, for tests whose bodies run synchronously.
#[cfg(test)]
pub(crate) fn try_acquire(lock: Arc<tokio::sync::Mutex<()>>, uid: u32) -> Option<Guard> {
    lock.try_lock_owned()
        .ok()
        .map(|guard| Guard { uid, _guard: guard })
}

/// Run `op` holding `uid`'s write lock, `lock`, within `budget`. `op` receives the proof of the
/// hold.
///
/// `Err(Expired::Wait)` means the lock was never acquired and `op` never started — nothing was
/// written. `Err(Expired::Hold)` means `op` started and was cancelled at an await point, so it may
/// have written whatever it completed before that point; a write path whose partial state is not
/// recoverable must stage its work rather than rely on this bound.
pub(crate) async fn under<T>(
    lock: &tokio::sync::Mutex<()>,
    uid: u32,
    budget: Budget,
    op: impl AsyncFnOnce(Held<'_>) -> T,
) -> Result<T, Expired> {
    let Ok(guard) = tokio::time::timeout(budget.wait, lock.lock()).await else {
        return Err(Expired::Wait);
    };
    tokio::time::timeout(budget.hold, op(Held::of(&guard, uid)))
        .await
        .map_err(|_| Expired::Hold)
}

#[cfg(test)]
mod tests {
    use super::*;

    const INSTANT: Budget = Budget {
        wait: Duration::from_millis(50),
        hold: Duration::from_millis(50),
    };

    #[tokio::test]
    async fn an_uncontended_operation_runs_and_returns_its_own_value() {
        let lock = tokio::sync::Mutex::new(());
        let got = under(&lock, 1, INSTANT, async |_| 7).await;
        assert_eq!(got, Ok(7));
    }

    /// A wait expiry must not start the operation: the caller reports "nothing was written", and
    /// that is only true if the body never ran.
    #[tokio::test]
    async fn a_wait_expiry_leaves_the_operation_unstarted() {
        let lock = tokio::sync::Mutex::new(());
        let held = lock.lock().await;
        let ran = std::sync::atomic::AtomicBool::new(false);

        let got = under(&lock, 1, INSTANT, async |_| {
            ran.store(true, std::sync::atomic::Ordering::SeqCst);
        })
        .await;

        assert_eq!(got, Err(Expired::Wait));
        assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
        drop(held);
    }

    /// The point of the hold bound: the next writer gets the lock on it, without the slow holder
    /// cooperating. Asserted by taking the lock again after the expiry rather than by inspecting
    /// the guard, since a leaked guard is exactly what this would fail to catch.
    #[tokio::test]
    async fn a_hold_expiry_releases_the_lock_for_the_next_writer() {
        let lock = tokio::sync::Mutex::new(());

        let got = under(&lock, 1, INSTANT, async |_| {
            std::future::pending::<()>().await
        })
        .await;
        assert_eq!(got, Err(Expired::Hold));

        assert!(
            lock.try_lock().is_ok(),
            "the lock stayed held after its hold budget expired"
        );
    }
}
