//! Credential fetch over the daemon's Unix domain socket, in line-delimited JSON-RPC 2.0.
//!
//! The daemon is the only way a CLI invocation obtains credentials. There is no
//! direct-from-provider fallback: it would reach the same material without the caller
//! assessment `serve` performs, which would make the audit record optional and would
//! silently convert a denial into a success.
//!
//! A consumer needs nothing beyond `UnixStream`, `BufReader`, and the shared codec: one
//! request line out, one response line back, decode, map.

#[cfg(unix)]
use crate::credentials::Credentials;
#[cfg(unix)]
use crate::error::{DaemonError, Result};
#[cfg(unix)]
use crate::wire::ClaimedIdentity;

/// Fetch a specific credential resolved under an env's authority. Backs a generated
/// `credential_process` line (`credsd get --env <env> --credential <cred>`), which is the
/// preferred `exec`/SDK delivery path.
///
/// `credential/get` names both the profile (the authorization context that supplies
/// restriction) and the credential it selects within it — the composed atom/group scheme
/// (an env named `work` referencing a credential named `ra-main`) resolves only when the env
/// travels alongside the credential, because the daemon honors a named credential exactly when
/// the profile reaches it (Open Decision 1). Where it does not, the daemon answers
/// `ENVIRONMENT_NOT_FOUND`, surfaced here as [`crate::error::DaemonError::EnvNotFound`].
#[cfg(unix)]
pub async fn fetch_credential_in_env(
    socket_path: &std::path::Path,
    env: &str,
    credential: &str,
    claimed: ClaimedIdentity,
) -> Result<Credentials> {
    fetch_uds(socket_path, env, Some(credential), claimed).await
}

/// Fetch `credential` within `env`, or the env's own default when `credential` is `None`.
///
/// The `None` case is what an ad-hoc selection needs: its credentials are each served under their
/// own name, so the name *is* the env and there is no credential to select within it.
#[cfg(unix)]
pub async fn fetch_credential_in_env_or_default(
    socket_path: &std::path::Path,
    env: &str,
    credential: Option<&str>,
    claimed: ClaimedIdentity,
) -> Result<Credentials> {
    fetch_uds(socket_path, env, credential, claimed).await
}

/// Fetch an env's default credential from the daemon over the Unix domain socket.
#[cfg(unix)]
pub async fn fetch_from_daemon_uds(
    socket_path: &std::path::Path,
    env: &str,
    claimed: ClaimedIdentity,
) -> Result<Credentials> {
    fetch_uds(socket_path, env, None, claimed).await
}

/// Send one `credential/get` for `profile` (optionally selecting `credential` within it) and
/// project the material onto [`Credentials`].
///
/// The caller's authorization root (`callers/<uid>/owner`) is established at bootstrap/login,
/// not here: the read path never provisions. A daemon that denies by absence answers
/// `ENVIRONMENT_NOT_FOUND`, which [`crate::rpc::uds::call`] surfaces as [`crate::error::DaemonError::EnvNotFound`] rather
/// than a silent migration.
#[cfg(unix)]
async fn fetch_uds(
    socket_path: &std::path::Path,
    environment: &str,
    credential: Option<&str>,
    claimed: ClaimedIdentity,
) -> Result<Credentials> {
    use crate::rpc::{uds, Claim, CredentialResult, GetParams, Material, METHOD_CREDENTIAL_GET};

    let params = GetParams {
        environment: environment.to_owned(),
        credential: credential.map(str::to_owned),
        scope: None,
        // Presence is the claim; the daemon only ever uses it to add restriction (Req 8.2).
        claim: (claimed == ClaimedIdentity::Agentic).then_some(Claim::Agentic),
        request_id: None,
    };
    let result: CredentialResult = uds::call(
        socket_path,
        METHOD_CREDENTIAL_GET,
        &params,
        Some(environment),
    )
    .await?;

    let expires_at = result.expires_at;
    match &result.material {
        Material::SessionCredentials {
            access_key_id,
            secret_access_key,
            session_token,
        } => {
            // A null expiry is legitimate for a token with no stated lifetime, never for AWS
            // session credentials: STS always states one. Treat its absence as a malformed
            // response rather than resolving credentials whose lifetime this process would
            // then have to guess.
            let Some(expires_at) = expires_at else {
                return Err(DaemonError::provider(
                    "daemon returned session credentials with no expiry; refusing to use \
                     AWS credentials of unknown lifetime",
                ));
            };
            Ok(Credentials::session(
                access_key_id.clone(),
                secret_access_key.clone(),
                session_token.clone(),
                expires_at,
            ))
        }
        // `token_type` does not survive into the resolved credential: every token credsd issues
        // is a `Bearer`, and the one thing a differing type would change — how a child spells the
        // `Authorization` header — is the child's business, not this cache's.
        Material::AccessToken { token, .. } => {
            Ok(Credentials::access_token(token.clone(), expires_at))
        }
    }
}
