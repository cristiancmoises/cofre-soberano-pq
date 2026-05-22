//! # qgateway-core
//!
//! Substrate for the QGateway daemon (Cofre Soberano PQ, Sprint 4).

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod admission;
pub mod audit;
pub mod auditkey;
pub mod config;
pub mod gateway;
pub mod metrics;
pub mod proxy;
pub mod tls;

pub use admission::{
    AdmissionController, Admit, HotAdmissionController, RateLimitConfig, RejectReason,
};
pub use audit::{AuditChannel, AuditHandle, RotationHandle, RotationMonitor, SignerFactory};
pub use config::RotationPolicy;
pub use config::{
    AuditSignerConfig, Config, Role, ServePqTenant, ServeTcpTenant, TenantId, TlsConfig,
    TlsListenerGroup,
};
pub use gateway::{
    run_serve_pq_tenant, run_serve_tcp_tenant, run_sni_group, HotSniDispatchTable,
    SniDispatchTable, SniTenantContext,
};
pub use metrics::{Metrics, MetricsRegistry};
pub use tls::{build_reloadable_acceptor, build_reloadable_multi_sni_acceptor, TlsReloadTrigger};
