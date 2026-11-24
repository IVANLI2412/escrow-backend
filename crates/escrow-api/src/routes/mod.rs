pub mod admin;
pub mod auth;
pub mod funding;
pub mod public;
pub mod webhook;

use crate::error::{ApiError, ApiResult};
use chrono::{DateTime, SecondsFormat, Utc};
use escrow_chain::BuiltTx;
use serde_json::{Value, json};

pub(crate) fn prepared_tx(built: BuiltTx, winner: Option<&str>) -> ApiResult<Value> {
    let valid_until = DateTime::<Utc>::from_timestamp(i64::try_from(built.valid_until).unwrap_or(i64::MAX), 0)
        .ok_or_else(ApiError::internal)?
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    let mut body = json!({ "xdr": built.xdr, "validUntil": valid_until });
    if let Some(w) = winner {
        body["winner"] = json!(w);
    }
    Ok(body)
}
