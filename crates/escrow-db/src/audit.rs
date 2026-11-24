// Append-only audit trail. It also serves as the "already sent" memory for
// reminders and announcements.
//
// Rows are hash-chained by the `audit_log_chain` trigger (migration 0008):
// each row stores `seq`, `prev_hash` and `hash`. Use [`verify`] to walk
// the chain.
//
// Transaction relay submissions are recorded through [`log_tx_submit`] so
// successful relays can be attributed to the authenticated API user without
// storing signed transaction payloads or secrets.

use crate::new_id;
use chrono::{DateTime, Utc};
use sqlx::PgExecutor;

/// Records an audit event.
///
/// Audit rows are append-only and hash-chained by the database trigger.
pub async fn log<'e>(
    ex: impl PgExecutor<'e>,
    actor: &str,
    action: &str,
    target: &str,
    data: &serde_json::Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_log (id, actor, action, target, data)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(new_id())
    .bind(actor)
    .bind(action)
    .bind(target)
    .bind(data)
    .execute(ex)
    .await
    .map(|_| ())
}

/// Records a successfully relayed signed transaction.
///
/// `actor` should identify the authenticated API user using the application's
/// existing actor convention.
///
/// `tx_hash` is stored as the audit target. The invoked contract function is
/// stored in the audit metadata.
///
/// This deliberately does not store the signed transaction envelope, secret
/// keys, or other sensitive transaction payload data.
pub async fn log_tx_submit<'e>(
    ex: impl PgExecutor<'e>,
    actor: &str,
    tx_hash: &str,
    function: &str,
) -> Result<(), sqlx::Error> {
    let data = serde_json::json!({
        "function": function,
    });

    log(ex, actor, "tx.submit", tx_hash, &data).await
}

/// Checks whether an audit event with the given action and target already exists.
pub async fn exists<'e>(
    ex: impl PgExecutor<'e>,
    action: &str,
    target: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (
            SELECT 1
            FROM audit_log
            WHERE action = $1 AND target = $2
        )",
    )
    .bind(action)
    .bind(target)
    .fetch_one(ex)
    .await
}

/// Returns recent audit entries, newest first.
pub async fn recent<'e>(
    ex: impl PgExecutor<'e>,
    limit: i64,
) -> Result<Vec<crate::models::AuditEntry>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, actor, action, target, data, created_at
         FROM audit_log
         ORDER BY created_at DESC
         LIMIT $1",
    )
    .bind(limit)
    .fetch_all(ex)
    .await
}

/// Counts `anomaly_detected` audit entries in the last 24 hours.
pub async fn count_anomalies_24h<'e>(
    ex: impl PgExecutor<'e>,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT COUNT(*)
         FROM audit_log
         WHERE action = 'anomaly_detected'
           AND created_at > NOW() - INTERVAL '24 hours'",
    )
    .fetch_one(ex)
    .await
}
}

/// The first row where the chain is broken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokenLink {
    pub seq: i64,
    pub id: String,
    pub reason: String,
}

/// Walks the chain from `from_seq` (1 for the whole table) and returns the
/// first broken link, if any.
///
/// Verification runs inside Postgres via `audit_verify()`, so it needs no
/// hashing crate.
pub async fn verify<'e>(
    ex: impl PgExecutor<'e>,
    from_seq: i64,
) -> Result<Option<BrokenLink>, sqlx::Error> {
    let row: Option<(i64, String, String)> = sqlx::query_as(
        "SELECT broken_seq, broken_id, reason
         FROM audit_verify($1)",
    )
    .bind(from_seq)
    .fetch_optional(ex)
    .await?;

    Ok(row.map(|(seq, id, reason)| BrokenLink { seq, id, reason }))
}
