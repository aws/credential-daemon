//! `CachingCredentialProvider` — an OPTIONAL, opt-in cache over a credential producer.
//!
//! `core` itself stays a stateless signer: `generate_credentials` always does a fresh
//! sign + CreateSession call. This is the one correct place for a LONG-RUNNING host to
//! hold credentials and re-sign only when they are near expiry — analogous to the Go
//! reference's `serve.go`. Note the cadence differs: this provider refreshes 5 minutes
//! before expiry (`DEFAULT_REFRESH_WINDOW`), whereas `serve.go` effectively refreshes 10
//! minutes before expiry because it applies its `RefreshTime` (5 min) twice — once to set
//! the refresh instant and again as the comparison margin. A known, documented divergence
//! (see docs/changes-and-design-choices.md).
//!
//! This is a library PRIMITIVE with no consumer yet — nothing in the repo calls it outside
//! its own tests. It is built ahead of its intended callers (a long-running credential
//! server, or a long-running Python/Go host). It is deliberately NOT always-on and NOT
//! wired into the FFI per-call. Open item for when a real consumer lands: decide whether
//! the cached credentials should be zeroized on refresh/drop.
//!
//! Not everyone would use this even once consumers exist: a caller whose SDK already caches
//! credentials in its own layer (e.g. off the `Expiration` the core emits) bypasses this
//! primitive by design.

use crate::pipeline::{CredentialProcessOutput, PipelineError};
use chrono::{DateTime, Utc};
use std::sync::Mutex;
use std::time::Duration;

/// Refresh this long before expiry, so a cached credential is never handed out when it is
/// about to die mid-request. This is the Go reference's `RefreshTime` (5 min) applied once;
/// `serve.go` applies it twice for an effective 10-min window (see the module doc).
pub const DEFAULT_REFRESH_WINDOW: Duration = Duration::from_secs(300);

/// Caches the credentials produced by `F` and re-signs (calls `F` again) only when the
/// cached credentials are within `refresh_window` of expiry. `F` is typically a closure
/// that calls `generate_credentials(&input)` — the consumer owns the request, so `core`
/// never has to hold a `SignRequestInput`'s lifetime.
///
/// Thread-safety: a single `Mutex` guards the read-decide-refresh sequence, so under
/// concurrent callers the producer fires at most once per refresh window. `F: Fn` is the
/// only bound the single-threaded API needs; sharing an instance across threads (via `Arc`)
/// additionally requires `F: Send + Sync`, which callers add at the sharing site (see the
/// concurrency test) rather than the type carrying an always-on bound it rarely needs.
pub struct CachingCredentialProvider<F>
where
    F: Fn() -> Result<CredentialProcessOutput, PipelineError>,
{
    producer: F,
    refresh_window: Duration,
    /// The last successfully produced credentials and their parsed expiry. `None` until
    /// the first successful fetch.
    cached: Mutex<Option<(CredentialProcessOutput, DateTime<Utc>)>>,
}

impl<F> CachingCredentialProvider<F>
where
    F: Fn() -> Result<CredentialProcessOutput, PipelineError>,
{
    /// Build a provider with the default 5-minute refresh window.
    pub fn new(producer: F) -> Self {
        Self::with_refresh_window(producer, DEFAULT_REFRESH_WINDOW)
    }

    /// Build a provider with an explicit refresh window (mainly for tests).
    pub fn with_refresh_window(producer: F, refresh_window: Duration) -> Self {
        Self {
            producer,
            refresh_window,
            cached: Mutex::new(None),
        }
    }

    /// Return valid credentials — from the cache if still fresh, otherwise by calling the
    /// producer once and caching the result.
    ///
    /// - Cache HIT (`now < expiration - refresh_window`): clone and return the cached creds.
    /// - Cache MISS / near expiry: call the producer. On `Ok`, parse the expiration, store
    ///   `(creds, expiry)`, and return the creds. On `Err`, propagate it unchanged and LEAVE
    ///   any prior cache entry in place (a failed refresh does not evict a good entry).
    /// - Fail-closed: if a fresh fetch returns an expiration we cannot parse, do NOT cache it
    ///   and return `ResponseError` — we never hand out credentials whose lifetime is unknown.
    pub fn credentials(&self) -> Result<CredentialProcessOutput, PipelineError> {
        // One lock spans the whole read-decide-refresh so concurrent callers can't each
        // trigger a redundant refresh. Recover from a poisoned mutex rather than
        // propagating the panic: poisoning means a *prior* producer call panicked while
        // the lock was held (a bug in the producer), but the cached state is always
        // consistent — we only ever assign a complete `(creds, expiry)` after BOTH the
        // producer and the expiry parse succeed (the assignment below), so a panic leaves
        // the previous entry untouched. Propagating via `unwrap()` would let one transient
        // producer panic permanently wedge every future caller of a shared provider;
        // `into_inner()` lets the cache keep serving and refreshing.
        let mut guard = self
            .cached
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if let Some((creds, expiry)) = guard.as_ref() {
            if !Self::needs_refresh(*expiry, self.refresh_window) {
                return Ok(creds.clone()); // cache hit
            }
        }

        // Miss or near-expiry: fetch fresh. Propagate an error without evicting.
        let fresh = (self.producer)()?;
        let expiry = parse_expiration(&fresh.expiration)?; // fail-closed on unparseable
        let to_return = fresh.clone();
        *guard = Some((fresh, expiry));
        Ok(to_return)
    }

    /// True when `now >= expiration - refresh_window` (i.e. we are at or inside the refresh
    /// window). Using `>=` means the exact boundary refreshes — safer than serving a cred
    /// that is precisely at the window edge.
    fn needs_refresh(expiration: DateTime<Utc>, window: Duration) -> bool {
        let window =
            chrono::Duration::from_std(window).unwrap_or_else(|_| chrono::Duration::zero());
        Utc::now() >= expiration - window
    }
}

/// Parse an ISO-8601 / RFC3339 expiration string (e.g. `"2024-01-15T12:00:00Z"`, the format
/// the core emits verbatim from CreateSession) into a UTC instant. `parse_from_rfc3339`
/// yields a `FixedOffset` datetime, so we convert to `Utc`. A parse failure is a
/// `ResponseError` (fail-closed — see `credentials`).
fn parse_expiration(s: &str) -> Result<DateTime<Utc>, PipelineError> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| PipelineError::ResponseError {
            reason: format!("Failed to parse credential expiration '{}': {}", s, e),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A credential with an expiration `secs` from now (RFC3339 Z), and a marker access key
    /// so tests can tell one fetch from the next.
    fn creds_expiring_in(secs: i64, akid: &str) -> CredentialProcessOutput {
        let exp = (Utc::now() + chrono::Duration::seconds(secs))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        CredentialProcessOutput {
            version: 1,
            access_key_id: akid.to_string(),
            secret_access_key: "secret".to_string(),
            session_token: "token".to_string(),
            expiration: exp,
        }
    }

    #[test]
    fn cache_hit_does_not_re_invoke_producer() {
        let calls = AtomicUsize::new(0);
        // Far-future expiry (1 hour) is well outside the 5-min window -> the second call
        // must be served from cache.
        let provider = CachingCredentialProvider::new(|| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(creds_expiring_in(3600, "AKIA_FRESH"))
        });

        let a = provider.credentials().unwrap();
        let b = provider.credentials().unwrap();
        assert_eq!(a.access_key_id, "AKIA_FRESH");
        assert_eq!(b.access_key_id, "AKIA_FRESH");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "producer must fire exactly once"
        );
    }

    #[test]
    fn near_expiry_triggers_refresh() {
        let calls = AtomicUsize::new(0);
        // Expiry 2 min out is INSIDE the 5-min window -> every call refreshes.
        let provider = CachingCredentialProvider::new(|| {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            Ok(creds_expiring_in(
                120,
                if n == 0 { "AKIA_1" } else { "AKIA_2" },
            ))
        });

        let first = provider.credentials().unwrap();
        let second = provider.credentials().unwrap();
        assert_eq!(first.access_key_id, "AKIA_1");
        assert_eq!(
            second.access_key_id, "AKIA_2",
            "near-expiry creds must be refreshed"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn producer_error_propagates_and_does_not_evict() {
        // The cached entry must be NEAR-EXPIRY so the second call takes the refresh path and
        // actually reaches the producer (a far-future entry would be a cache hit and never
        // exercise the error path). Sequence: fetch good (near-expiry) -> refresh errors
        // (error must PROPAGATE, prior entry not evicted) -> refresh recovers.
        let calls = AtomicUsize::new(0);
        let provider = CachingCredentialProvider::new(|| {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            match n {
                0 => Ok(creds_expiring_in(120, "AKIA_GOOD")),
                1 => Err(PipelineError::HttpError {
                    reason: "boom".to_string(),
                }),
                _ => Ok(creds_expiring_in(120, "AKIA_RECOVERED")),
            }
        });

        assert_eq!(provider.credentials().unwrap().access_key_id, "AKIA_GOOD");
        // Near-expiry -> refresh attempted -> producer errors -> the error must propagate.
        assert!(matches!(
            provider.credentials(),
            Err(PipelineError::HttpError { .. })
        ));
        // A later call still refreshes (the prior entry was retained, not poisoned by the
        // failed refresh) and succeeds once the producer recovers.
        assert_eq!(
            provider.credentials().unwrap().access_key_id,
            "AKIA_RECOVERED"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "each call after the first attempts a refresh (near-expiry entry)"
        );
    }

    #[test]
    fn producer_error_on_empty_cache_propagates() {
        // Empty cache (no prior success) + a producer that always errors: the very first
        // credentials() call must propagate the producer's error, because there is no
        // cached entry to fall back on.
        let provider = CachingCredentialProvider::new(|| {
            Err::<CredentialProcessOutput, _>(PipelineError::HttpError {
                reason: "network down".to_string(),
            })
        });
        match provider.credentials() {
            Err(PipelineError::HttpError { reason }) => assert_eq!(reason, "network down"),
            other => panic!("expected HttpError, got {:?}", other),
        }
    }

    #[test]
    fn unparseable_expiration_is_fail_closed_and_not_cached() {
        let calls = AtomicUsize::new(0);
        let provider = CachingCredentialProvider::new(|| {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            let mut c = creds_expiring_in(3600, "AKIA_X");
            if n == 0 {
                c.expiration = "not-a-date".to_string(); // first fetch: unparseable
            }
            Ok(c)
        });

        // First call: unparseable expiration -> ResponseError, and NOT cached.
        match provider.credentials() {
            Err(PipelineError::ResponseError { .. }) => {}
            other => panic!(
                "expected ResponseError for unparseable expiration, got {:?}",
                other
            ),
        }
        // Second call: producer now returns a valid expiration -> succeeds and caches.
        assert_eq!(provider.credentials().unwrap().access_key_id, "AKIA_X");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "the failed fetch must not have cached"
        );
    }

    #[test]
    fn parse_expiration_accepts_z_format_and_rejects_garbage() {
        assert!(parse_expiration("2024-01-15T12:00:00Z").is_ok());
        assert!(parse_expiration("garbage").is_err());
    }

    #[test]
    fn default_refresh_window_is_five_minutes() {
        assert_eq!(DEFAULT_REFRESH_WINDOW, Duration::from_secs(300));
    }

    #[test]
    fn with_refresh_window_honors_a_non_default_window() {
        // Exercise the custom-window constructor (every other test uses ::new()'s 300s), so a
        // regression where with_refresh_window drops/overwrites its argument is caught. A 10s
        // window with a 60s expiry is a cache HIT (60s is outside 10s); the SAME 60s expiry
        // under the default 300s window would refresh — proving the passed window is applied.
        let calls = AtomicUsize::new(0);
        let provider = CachingCredentialProvider::with_refresh_window(
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(creds_expiring_in(60, "AKIA_CUSTOM"))
            },
            Duration::from_secs(10),
        );

        assert_eq!(provider.credentials().unwrap().access_key_id, "AKIA_CUSTOM");
        assert_eq!(provider.credentials().unwrap().access_key_id, "AKIA_CUSTOM");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "60s expiry is outside the 10s window, so the second call must be a cache hit"
        );
    }

    #[test]
    fn concurrent_callers_refresh_at_most_once_per_window() {
        // Share ONE provider across N threads. The first producer call sleeps briefly so
        // the threads genuinely overlap on the lock; the single Mutex must serialize the
        // read-decide-refresh so the producer fires exactly once (all later threads see the
        // fresh, far-future cache entry). Sharing across threads needs Send + Sync on the
        // closure; see the struct doc for why that bound lives at the sharing site, not the type.
        use std::sync::Arc;
        use std::thread;

        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_producer = Arc::clone(&calls);
        let provider = Arc::new(CachingCredentialProvider::new(move || {
            calls_for_producer.fetch_add(1, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(50)); // widen the overlap window
            Ok(creds_expiring_in(3600, "AKIA_SHARED"))
        }));

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let p = Arc::clone(&provider);
                thread::spawn(move || p.credentials().unwrap().access_key_id)
            })
            .collect();
        for h in handles {
            assert_eq!(h.join().unwrap(), "AKIA_SHARED");
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the Mutex must serialize read-decide-refresh so the producer fires once"
        );
    }

    #[test]
    fn poisoned_lock_recovers_and_keeps_serving() {
        // A producer panic happens while the lock is held, which poisons the Mutex. Prove the
        // `unwrap_or_else(into_inner)` recovery: a later call on the SAME provider must still
        // return Ok and re-fire the producer, rather than propagating the poison forever (the
        // behavior `unwrap()` would give — one transient panic wedging every future caller).
        use std::sync::Arc;
        use std::thread;

        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_producer = Arc::clone(&calls);
        let provider = Arc::new(CachingCredentialProvider::new(move || {
            let n = calls_for_producer.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                panic!("simulated producer bug"); // panics while the lock is held -> poisons it
            }
            Ok(creds_expiring_in(3600, "AKIA_AFTER_PANIC"))
        }));

        // First call: the producer panics; catch it in a thread so the test process survives.
        // The join() Err confirms the panic happened (and thus poisoned the Mutex).
        let p1 = Arc::clone(&provider);
        let first = thread::spawn(move || p1.credentials()).join();
        assert!(first.is_err(), "first call must panic and poison the lock");

        // Second call on the same provider must recover from the poison, re-fire the producer,
        // and return the fresh credentials.
        let creds = provider
            .credentials()
            .expect("must recover from the poisoned lock, not propagate the panic");
        assert_eq!(creds.access_key_id, "AKIA_AFTER_PANIC");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "producer must re-fire after recovery (panic attempt + successful retry)"
        );
    }
}
