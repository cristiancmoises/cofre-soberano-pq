//! # qaudit-portal
//!
//! Read-only HTTP viewer for `.qa` audit logs.
//!
//! Serves a single-page HTML viewer with header info, verification badge, and
//! a paginated entry table. Companion JSON API for tooling.
//!
//! ```text
//!   qaudit-portal --log audit.qa --pk qaudit.pk --listen 127.0.0.1:8080
//! ```
//!
//! ## Routes
//!
//! | Method | Path           | Description                                   |
//! |--------|----------------|-----------------------------------------------|
//! | GET    | `/`            | HTML viewer page                              |
//! | GET    | `/api/info`    | JSON header + verification status             |
//! | GET    | `/api/verify`  | JSON `{ok: true}` or error                    |
//! | GET    | `/api/entries` | JSON entries; supports `?offset=N&limit=M`    |
//! | GET    | `/api/pubkey`  | Raw public key bytes                          |
//! | GET    | `/healthz`     | Liveness probe                                |
//!
//! ## Threat model
//!
//! - Read-only: no append, no key access, no log modification path.
//! - Designed to bind to `127.0.0.1` by default. Public exposure requires a
//!   reverse proxy with mTLS (Sprint 4: QGateway terminates this).

#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]

use anyhow::{Context, Result};
use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
    Json, Router,
};
use clap::Parser;
use qaudit_core::{decode_pubkey_any, AuditLog};
use serde_json::json;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(
    name = "qaudit-portal",
    version,
    about = "Read-only web viewer for qaudit logs — Cofre Soberano PQ."
)]
struct Cli {
    /// Path to the `.qa` log file.
    #[arg(long)]
    log: PathBuf,
    /// Optional independent public key file (must match log header).
    #[arg(long)]
    pk: Option<PathBuf>,
    /// Listen address (default: 127.0.0.1:8080).
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: String,
}

struct AppState {
    log: AuditLog,
    log_path: PathBuf,
    verify_ok: bool,
    verify_error: Option<String>,
}

/// Magic prefix used by `qgateway audit-keygen` for `.audit.pub` files.
///
// Public-key file format auto-detection (raw 2592 B vs. qgateway-framed
// 2600 B with the `AUDITPK0` magic prefix) lives in `qaudit-core` so that
// `qaudit verify --pk` and `qaudit-portal --pk` share the same logic.

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,tower_http=info")),
        )
        .init();

    let cli = Cli::parse();
    let mut log =
        AuditLog::open(&cli.log).with_context(|| format!("opening log {}", cli.log.display()))?;

    if let Some(pk_path) = cli.pk.as_ref() {
        let bytes = std::fs::read(pk_path)
            .with_context(|| format!("reading public key {}", pk_path.display()))?;
        let pk = decode_pubkey_any(&bytes).context("decoding public key")?;
        if pk.as_bytes() != log.header().pubkey.as_bytes() {
            anyhow::bail!("supplied --pk does not match the log's header pubkey");
        }
        log.override_pubkey(pk);
    }

    let (verify_ok, verify_error) = match log.verify() {
        Ok(()) => (true, None),
        Err(e) => (false, Some(e.to_string())),
    };

    tracing::info!(
        log = %cli.log.display(),
        entries = log.len(),
        verify_ok,
        "log loaded"
    );

    let state = Arc::new(AppState {
        log,
        log_path: cli.log.clone(),
        verify_ok,
        verify_error,
    });

    let app = Router::new()
        .route("/", get(index))
        .route("/api/info", get(api_info))
        .route("/api/verify", get(api_verify))
        .route("/api/entries", get(api_entries))
        .route("/api/pubkey", get(api_pubkey))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state)
        .layer(tower_http::trace::TraceLayer::new_for_http());

    let addr: SocketAddr = cli.listen.parse().context("parsing --listen")?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    tracing::info!(%addr, "qaudit-portal listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("axum server")?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("install Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received");
}

// ---------- handlers ----------

async fn index(State(s): State<Arc<AppState>>) -> Html<String> {
    let h = s.log.header();
    let badge = if s.verify_ok {
        r#"<span class="ok">✓ verified</span>"#
    } else {
        r#"<span class="bad">✗ INVALID</span>"#
    };
    let err = s
        .verify_error
        .as_deref()
        .map(|e| {
            format!(
                r#"<div class="err">Verification error: <code>{}</code></div>"#,
                html_escape(e)
            )
        })
        .unwrap_or_default();
    let mut rows = String::new();
    for e in s.log.entries() {
        let mut meta = String::new();
        for (k, v) in &e.event.metadata {
            meta.push_str(&format!(
                "<div><code>{}</code> = {}</div>",
                html_escape(k),
                html_escape(v)
            ));
        }
        if meta.is_empty() {
            meta.push_str("<em>(none)</em>");
        }
        rows.push_str(&format!(
            r#"<tr>
  <td class="num">{idx}</td>
  <td class="mono">{appended_at}</td>
  <td>{actor}</td>
  <td>{action}</td>
  <td class="resource">{resource}</td>
  <td>{outcome}</td>
  <td class="meta">{meta}</td>
  <td class="mono small">{root}</td>
</tr>
"#,
            idx = e.index,
            appended_at = e.appended_at.format("%Y-%m-%d %H:%M:%SZ"),
            actor = html_escape(&e.event.actor),
            action = html_escape(&e.event.action),
            resource = html_escape(&e.event.resource),
            outcome = html_escape(&e.event.outcome),
            meta = meta,
            root = hex::encode(&e.new_root[..8]) + "…",
        ));
    }

    let body = format!(
        r#"<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>qaudit portal — {log_id}</title>
<style>
  :root {{
    --bg: #0d1117;
    --fg: #c9d1d9;
    --fg-dim: #8b949e;
    --accent: #58a6ff;
    --ok: #3fb950;
    --bad: #f85149;
    --panel: #161b22;
    --border: #30363d;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; padding: 0 24px 64px;
    background: var(--bg); color: var(--fg);
    font-family: -apple-system, "Segoe UI", "JetBrains Mono", monospace;
    line-height: 1.45;
  }}
  header {{
    border-bottom: 1px solid var(--border);
    padding: 24px 0 16px; margin-bottom: 16px;
  }}
  header h1 {{ margin: 0; font-size: 18px; font-weight: 600; color: var(--accent); }}
  header .sub {{ color: var(--fg-dim); font-size: 13px; margin-top: 4px; }}
  .grid {{ display: grid; grid-template-columns: 200px 1fr; gap: 6px 16px; margin: 14px 0; font-size: 13px; }}
  .grid dt {{ color: var(--fg-dim); }}
  .grid dd {{ margin: 0; word-break: break-all; }}
  .ok  {{ color: var(--ok); font-weight: 600; }}
  .bad {{ color: var(--bad); font-weight: 600; }}
  .err {{ background: rgba(248,81,73,0.12); border: 1px solid var(--bad); border-radius: 6px; padding: 10px 14px; margin: 10px 0; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 12.5px; margin-top: 18px; }}
  th, td {{ border-bottom: 1px solid var(--border); padding: 8px 10px; text-align: left; vertical-align: top; }}
  th {{ background: var(--panel); color: var(--fg-dim); font-weight: 500; position: sticky; top: 0; }}
  td.num {{ font-variant-numeric: tabular-nums; color: var(--fg-dim); text-align: right; }}
  td.mono, code {{ font-family: "JetBrains Mono", "Menlo", monospace; }}
  td.mono.small {{ font-size: 11.5px; color: var(--fg-dim); }}
  td.resource {{ max-width: 320px; overflow-wrap: anywhere; }}
  td.meta {{ font-size: 11.5px; color: var(--fg-dim); }}
  td.meta div {{ margin-bottom: 2px; }}
  footer {{ margin-top: 32px; color: var(--fg-dim); font-size: 11.5px; }}
  a {{ color: var(--accent); }}
</style>
</head>
<body>
<header>
  <h1>Cofre Soberano PQ · qaudit portal</h1>
  <div class="sub">Read-only auditor view · {entries} entries · {badge}</div>
</header>

{err}

<dl class="grid">
  <dt>log file</dt><dd class="mono">{log_path}</dd>
  <dt>log_id</dt><dd class="mono">{log_id}</dd>
  <dt>suite</dt><dd>{suite}</dd>
  <dt>wire version</dt><dd>{wire_version}</dd>
  <dt>created at</dt><dd class="mono">{created_at}</dd>
  <dt>label</dt><dd>{label}</dd>
  <dt>signature algo</dt><dd>ml-dsa-87 (FIPS 204)</dd>
  <dt>hash algo</dt><dd>blake3-256</dd>
  <dt>pubkey (first 16 B)</dt><dd class="mono">{pk_prefix}…</dd>
  <dt>current root</dt><dd class="mono">{root}</dd>
</dl>

<table>
  <thead>
    <tr>
      <th>#</th><th>appended_at</th><th>actor</th><th>action</th>
      <th>resource</th><th>outcome</th><th>meta</th><th>root (head)</th>
    </tr>
  </thead>
  <tbody>
  {rows}
  </tbody>
</table>

<footer>
  qaudit-portal v{ver} · <a href="/api/entries">JSON API</a> ·
  <a href="/api/verify">verify status</a> ·
  schema <code>https://securityops.co/schemas/qaudit-export-v1</code>
</footer>
</body>
</html>"#,
        log_id = h.log_id,
        log_path = html_escape(&s.log_path.display().to_string()),
        suite = html_escape(&h.suite),
        wire_version = h.wire_version,
        created_at = h.created_at,
        label = html_escape(if h.label.is_empty() {
            "<none>"
        } else {
            h.label.as_str()
        }),
        pk_prefix = hex::encode(&h.pubkey.as_bytes()[..16]),
        root = hex::encode(s.log.current_root()),
        entries = s.log.len(),
        badge = badge,
        err = err,
        rows = rows,
        ver = env!("CARGO_PKG_VERSION"),
    );
    Html(body)
}

async fn api_info(State(s): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let h = s.log.header();
    Json(json!({
        "log_id":        h.log_id.to_hex(),
        "suite":         h.suite,
        "wire_version":  h.wire_version,
        "created_at":    h.created_at,
        "label":         h.label,
        "entries":       s.log.len(),
        "current_root":  hex::encode(s.log.current_root()),
        "pubkey_bytes":  h.pubkey.as_bytes().len(),
        "signature_algorithm": "ml-dsa-87",
        "hash_algorithm":      "blake3-256",
        "verify_ok":           s.verify_ok,
        "verify_error":        s.verify_error,
    }))
}

async fn api_verify(State(s): State<Arc<AppState>>) -> (StatusCode, Json<serde_json::Value>) {
    if s.verify_ok {
        (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "entries": s.log.len(),
                "root": hex::encode(s.log.current_root()),
            })),
        )
    } else {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "ok": false,
                "error": s.verify_error,
            })),
        )
    }
}

#[derive(serde::Deserialize)]
struct Pagination {
    offset: Option<usize>,
    limit: Option<usize>,
}

async fn api_entries(
    State(s): State<Arc<AppState>>,
    Query(p): Query<Pagination>,
) -> Json<serde_json::Value> {
    let offset = p.offset.unwrap_or(0);
    let limit = p.limit.unwrap_or(100).min(1000);
    let entries: Vec<_> = s
        .log
        .entries()
        .iter()
        .skip(offset)
        .take(limit)
        .map(|e| {
            json!({
                "index":        e.index,
                "appended_at":  e.appended_at,
                "actor":        e.event.actor,
                "action":       e.event.action,
                "resource":     e.event.resource,
                "outcome":      e.event.outcome,
                "metadata":     e.event.metadata,
                "prev_root":    hex::encode(e.prev_root),
                "new_root":     hex::encode(e.new_root),
                "signature":    hex::encode(e.signature.as_bytes()),
            })
        })
        .collect();
    Json(json!({
        "offset":   offset,
        "limit":    limit,
        "total":    s.log.len(),
        "returned": entries.len(),
        "entries":  entries,
    }))
}

async fn api_pubkey(State(s): State<Arc<AppState>>) -> Response {
    let bytes = s.log.header().pubkey.as_bytes().to_vec();
    ([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response()
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use qaudit_core::KeyPair;

    #[test]
    fn escape_handles_html_chars() {
        assert_eq!(
            html_escape("<a href=\"x\">&'</a>"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;&lt;/a&gt;"
        );
    }

    #[test]
    fn decode_pubkey_accepts_raw_2592_bytes() {
        let kp = KeyPair::generate().expect("keygen");
        let raw = kp.public().as_bytes().to_vec();
        assert_eq!(raw.len(), 2592);
        let decoded = decode_pubkey_any(&raw).expect("raw must decode");
        assert_eq!(decoded.as_bytes(), kp.public().as_bytes());
    }

    #[test]
    fn decode_pubkey_accepts_qgateway_2600_byte_framed() {
        let kp = KeyPair::generate().expect("keygen");
        let raw = kp.public().as_bytes();
        let mut framed = Vec::with_capacity(2600);
        framed.extend_from_slice(qaudit_core::QGATEWAY_AUDIT_PK_MAGIC);
        framed.extend_from_slice(raw);
        assert_eq!(framed.len(), 2600);

        let decoded = decode_pubkey_any(&framed).expect("framed must decode");
        assert_eq!(decoded.as_bytes(), kp.public().as_bytes());
    }

    #[test]
    fn decode_pubkey_rejects_2600_bytes_without_magic() {
        let bogus = vec![0u8; 2600];
        let err = decode_pubkey_any(&bogus).expect_err("must reject");
        assert!(err.to_string().contains("magic"));
    }

    #[test]
    fn decode_pubkey_rejects_wrong_length() {
        let too_short = vec![0u8; 100];
        let err = decode_pubkey_any(&too_short).expect_err("must reject");
        let msg = err.to_string();
        assert!(msg.contains("2592"));
        assert!(msg.contains("2600"));
    }
}
