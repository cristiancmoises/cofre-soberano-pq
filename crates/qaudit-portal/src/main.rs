//! # qaudit-portal
//!
//! Read-only HTTP viewer for `.qa` audit logs.
//!
//! Serves a single-page HTML viewer with header info, verification badge, and
//! a bounded, paginated entry table. The page supports English and Brazilian
//! Portuguese (`?lang=pt-BR`). Companion JSON API for tooling.
//! The log and verification result are an immutable startup snapshot.
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
//!   authenticated reverse proxy. The portal has no built-in authentication.

#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]

use anyhow::{Context, Result};
use axum::{
    extract::{Query, Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::{self, Next},
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
    independent_key: bool,
}

// Magic prefix (`AUDITPK0`) used by `qgateway audit-keygen` for `.audit.pub`
// files. Public-key file format auto-detection (raw 2592 B vs. qgateway-framed
// 2600 B with that magic prefix) lives in `qaudit-core` so that
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
        independent_key: cli.pk.is_some(),
    });

    let app = Router::new()
        .route("/", get(index))
        .route("/assets/style.css", get(stylesheet))
        .route("/api/info", get(api_info))
        .route("/api/verify", get(api_verify))
        .route("/api/entries", get(api_entries))
        .route("/api/pubkey", get(api_pubkey))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state)
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .layer(middleware::from_fn(security_headers));

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

async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    for (name, value) in [
        (header::CACHE_CONTROL, "no-store"),
        (header::CONTENT_SECURITY_POLICY, "default-src 'none'; style-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::REFERRER_POLICY, "no-referrer"),
    ] {
        response.headers_mut().insert(name, HeaderValue::from_static(value));
    }
    response
}

async fn stylesheet() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("style.css"),
    )
}

#[derive(Default, serde::Deserialize)]
struct ViewOptions {
    offset: Option<usize>,
    limit: Option<usize>,
    lang: Option<String>,
}

impl ViewOptions {
    fn bounds(&self, total: usize) -> (usize, usize) {
        (
            self.offset.unwrap_or(0).min(total),
            self.limit.unwrap_or(50).clamp(1, 200),
        )
    }
}

async fn index(State(s): State<Arc<AppState>>, Query(p): Query<ViewOptions>) -> Html<String> {
    let h = s.log.header();
    let pt = p.lang.as_deref() == Some("pt-BR");
    let tr = |en, br| if pt { br } else { en };
    let lang = tr("en", "pt-BR");
    let total = s.log.entries().len();
    let (offset, limit) = p.bounds(total);
    let end = offset.saturating_add(limit).min(total);
    let badge = if s.verify_ok {
        format!(
            r#"<span class="badge ok">✓ {}</span>"#,
            tr("Signatures verified", "Assinaturas verificadas")
        )
    } else {
        format!(
            r#"<span class="badge bad">✗ {}</span>"#,
            tr("Verification failed", "Falha na verificação")
        )
    };
    let err = s
        .verify_error
        .as_deref()
        .map(|e| {
            format!(
                r#"<div class="err" role="alert">{}: <code>{}</code></div>"#,
                tr("Verification error", "Erro de verificação"),
                html_escape(e)
            )
        })
        .unwrap_or_default();
    let mut rows = String::new();
    for e in s.log.entries().iter().skip(offset).take(limit) {
        let meta: String = e
            .event
            .metadata
            .iter()
            .map(|(k, v)| {
                format!(
                    "<div><code>{}</code> = {}</div>",
                    html_escape(k),
                    html_escape(v)
                )
            })
            .collect();
        rows.push_str(&format!(r#"<tr><td class="num">{idx}</td><td class="mono timestamp">{at}</td><td>{actor}</td><td><code>{action}</code></td><td class="resource">{resource}</td><td>{outcome}</td><td class="meta">{meta}</td><td class="mono root">{root}…</td></tr>"#,
            idx=e.index, at=e.appended_at.format("%Y-%m-%d %H:%M:%SZ"), actor=html_escape(&e.event.actor),
            action=html_escape(&e.event.action), resource=html_escape(&e.event.resource), outcome=html_escape(&e.event.outcome),
            meta=if meta.is_empty() { "—".to_owned() } else { meta }, root=hex::encode(&e.new_root[..8])));
    }
    if rows.is_empty() {
        rows = format!(
            r#"<tr><td colspan="8" class="empty">{}</td></tr>"#,
            tr("No entries on this page.", "Nenhuma entrada nesta página.")
        );
    }
    let mut pagination = String::new();
    if offset > 0 {
        pagination.push_str(&format!(r#"<a class="button" rel="prev" href="/?offset={}&amp;limit={limit}&amp;lang={lang}">← {}</a>"#, offset.saturating_sub(limit), tr("Previous", "Anterior")));
    }
    if end < total {
        pagination.push_str(&format!(r#"<a class="button" rel="next" href="/?offset={end}&amp;limit={limit}&amp;lang={lang}">{} →</a>"#, tr("Next", "Próxima")));
    }
    Html(format!(include_str!("index.html"),
        lang=lang, log_id=h.log_id, ver=env!("CARGO_PKG_VERSION"),
        lang_other=tr("pt-BR", "en"), lang_label=tr("Português (Brasil)", "English"), offset=offset, limit=limit,
        subtitle=tr("Independent evidence. Offline verification.", "Evidências independentes. Verificação offline."),
        viewer=tr("Audit viewer", "Visualizador de auditoria"), badge=badge, err=err,
        label=html_escape(if h.label.is_empty() { tr("Untitled log", "Registro sem título") } else { &h.label }),
        snapshot_title=tr("Startup snapshot", "Retrato da inicialização"),
        snapshot=tr("This page and API show the file as loaded at startup. Restart the portal to load new entries. Verification alone cannot prove the log is complete or current.", "Esta página e a API mostram o arquivo carregado na inicialização. Reinicie o portal para carregar novas entradas. A verificação por si só não comprova que o registro está completo ou atualizado."),
        entries_label=tr("Log entries", "Entradas do registro"), entries=total,
        signature_label=tr("Signature algorithm", "Algoritmo de assinatura"),
        signature_note=tr("FIPS 204 · 2,592-byte public key", "FIPS 204 · chave pública de 2.592 bytes"),
        metadata_note=tr("Header labels/times and appended timestamps are not covered by wire-v1 signatures.", "Rótulos/datas do cabeçalho e horários de anexação não são cobertos pelas assinaturas wire-v1."),
        key_label=tr("Verification key", "Chave de verificação"),
        key_status=if s.independent_key { tr("Independent key supplied", "Chave independente fornecida") } else { tr("Embedded key only", "Somente chave incorporada") },
        key_note=if s.independent_key { tr("Matches the supplied --pk file; establish its provenance separately.", "Corresponde ao arquivo --pk fornecido; confirme a procedência por outro canal.") } else { tr("Use --pk with a trusted key to establish signer identity.", "Use --pk com uma chave confiável para confirmar a identidade do assinante.") },
        details_label=tr("Log details", "Detalhes do registro"), file_label=tr("Snapshot source", "Origem do retrato"),
        log_path=html_escape(&s.log_path.display().to_string()), created_label=tr("Created at", "Criado em"), created_at=h.created_at,
        suite=html_escape(&h.suite), wire_version=h.wire_version,
        pk_label=tr("Public key · first 16 bytes", "Chave pública · primeiros 16 bytes"), pk_prefix=hex::encode(&h.pubkey.as_bytes()[..16]),
        root_label=tr("Current Merkle root", "Raiz Merkle atual"), root=hex::encode(s.log.current_root()),
        table_label=tr("Audit events", "Eventos de auditoria"), from=if offset < end { offset+1 } else { 0 }, to=if offset < end { end } else { 0 },
        of_label=tr("of", "de"), timestamp_label=tr("Appended (UTC)", "Anexado (UTC)"),
        actor_label=tr("Actor", "Ator"), action_label=tr("Action", "Ação"), resource_label=tr("Resource", "Recurso"),
        outcome_label=tr("Outcome", "Resultado"), meta_label=tr("Metadata", "Metadados"), root_head_label=tr("Root · 8 bytes", "Raiz · 8 bytes"),
        rows=rows, pagination=pagination, pagination_label=tr("Event pages", "Páginas de eventos"),
        readonly=tr("Read-only · no signing keys required", "Somente leitura · sem chaves privadas"),
        api_label=tr("Entries API", "API de entradas"), verify_label=tr("Verification API", "API de verificação"),
        pubkey_label=tr("Download public key", "Baixar chave pública"),
    ))
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
        "snapshot":            "startup",
        "independent_key_supplied": s.independent_key,
    }))
}

async fn api_verify(State(s): State<Arc<AppState>>) -> (StatusCode, Json<serde_json::Value>) {
    if s.verify_ok {
        (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "snapshot": "startup",
                "independent_key_supplied": s.independent_key,
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
    fn html_pagination_is_bounded_even_for_extreme_queries() {
        let p = ViewOptions {
            offset: Some(usize::MAX),
            limit: Some(usize::MAX),
            lang: None,
        };
        assert_eq!(p.bounds(10), (10, 200));
        assert_eq!(
            ViewOptions {
                limit: Some(0),
                ..Default::default()
            }
            .bounds(10),
            (0, 1)
        );
    }

    #[tokio::test]
    async fn html_escapes_events_and_discloses_snapshot_and_untrusted_key() {
        let mut log =
            AuditLog::create_with_label(KeyPair::generate().unwrap(), "<script>label</script>")
                .unwrap();
        for i in 0..3 {
            log.append(
                qaudit_core::AuditEvent::builder()
                    .actor("<script>actor</script>")
                    .action(format!("event-{i}"))
                    .build(),
            )
            .unwrap();
        }
        let state = Arc::new(AppState {
            log,
            log_path: "<source>.qa".into(),
            verify_ok: true,
            verify_error: None,
            independent_key: false,
        });
        let Html(html) = index(
            State(state.clone()),
            Query(ViewOptions {
                offset: Some(1),
                limit: Some(1),
                lang: None,
            }),
        )
        .await;
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;actor&lt;/script&gt;"));
        assert!(html.contains("event-1"));
        assert!(!html.contains("event-0"));
        assert!(!html.contains("event-2"));
        assert!(html.contains("Startup snapshot"));
        assert!(html.contains("Embedded key only"));
        assert!(html.contains("rel=\"prev\""));
        assert!(html.contains("rel=\"next\""));
        let Html(pt) = index(
            State(state),
            Query(ViewOptions {
                lang: Some("pt-BR".into()),
                ..Default::default()
            }),
        )
        .await;
        assert!(pt.contains("lang=\"pt-BR\""));
        assert!(pt.contains("Assinaturas verificadas"));
    }

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
