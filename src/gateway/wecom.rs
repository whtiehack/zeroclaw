//! WeCom gateway — thin HTTP relay.
//!
//! All business logic (crypto, stream state, conversation management, LLM calls)
//! lives in `crate::channels::wecom::WeComChannel`. This module only bridges
//! HTTP requests into the channel's mpsc queue and returns the response.

use super::AppState;
use crate::channels::wecom::{WeComCallbackQuery, WeComInboundRequest, WeComInboundResponse};
use axum::{
    body::Bytes,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};

/// GET /wecom — URL verification relay
pub(super) async fn handle_wecom_verify(
    State(state): State<AppState>,
    Query(query): Query<WeComCallbackQuery>,
) -> impl IntoResponse {
    let Some(wecom_tx) = &state.wecom_inbound_tx else {
        return (
            StatusCode::NOT_FOUND,
            "WeCom not configured".to_string(),
        )
            .into_response();
    };

    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let req = WeComInboundRequest {
        query,
        body: Bytes::new(),
        reply_tx,
    };

    if wecom_tx.send(req).await.is_err() {
        tracing::error!("WeCom gateway: channel inbound_rx dropped (verify)");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "WeCom channel unavailable".to_string(),
        )
            .into_response();
    }

    match reply_rx.await {
        Ok(resp) => (StatusCode::from_u16(resp.status_code).unwrap_or(StatusCode::OK), resp.body).into_response(),
        Err(_) => {
            tracing::error!("WeCom gateway: reply_tx dropped before responding (verify)");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()).into_response()
        }
    }
}

/// POST /wecom — encrypted callback relay
pub(super) async fn handle_wecom_callback(
    State(state): State<AppState>,
    Query(query): Query<WeComCallbackQuery>,
    body: Bytes,
) -> impl IntoResponse {
    let Some(wecom_tx) = &state.wecom_inbound_tx else {
        return (
            StatusCode::NOT_FOUND,
            "WeCom not configured".to_string(),
        )
            .into_response();
    };

    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let req = WeComInboundRequest {
        query,
        body,
        reply_tx,
    };

    if wecom_tx.send(req).await.is_err() {
        tracing::error!("WeCom gateway: channel inbound_rx dropped (callback)");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "WeCom channel unavailable".to_string(),
        )
            .into_response();
    }

    match reply_rx.await {
        Ok(resp) => (StatusCode::from_u16(resp.status_code).unwrap_or(StatusCode::OK), resp.body).into_response(),
        Err(_) => {
            tracing::error!("WeCom gateway: reply_tx dropped before responding (callback)");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()).into_response()
        }
    }
}
