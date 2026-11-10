//! AWS credential daemon — shared internals (`credsd-core`).
//!
//! Every non-axum piece of the system lives here so the daemon bin (`credsd-daemon`, the
//! UDS server) and the client bin (`credsd`, the CLI) can each depend on it without
//! depending on each other. Axum-bound code — the UDS server and the run-command proxy —
//! stays in the bins, so this crate never pulls axum.

pub mod auth;
pub mod bootstrap;
pub mod config;
pub mod credential_env;
pub mod credential_resolve;
pub mod credential_status;
pub mod credentials;
pub mod encryption;
pub mod error;
pub mod get;
pub mod import;
pub mod log;
pub mod presence;
pub mod projection;
pub mod providers;
pub mod rpc;
pub mod storage;
pub mod wire;
