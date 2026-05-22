//! Audit events: the unit of recorded fact.
//!
//! An [`AuditEvent`] captures a single auditable occurrence — an action by some
//! actor on some resource — and is the leaf payload of the Merkle chain.
//!
//! Events are content-addressed via BLAKE3 over their canonical CBOR encoding.
//! The `metadata` map is a `BTreeMap` so key ordering is deterministic and the
//! same event always produces the same hash, regardless of how it was built.

use crate::error::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A single auditable event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Schema version for this event format. Currently 1.
    pub schema: u32,
    /// Wall-clock timestamp (UTC, RFC 3339).
    pub timestamp: DateTime<Utc>,
    /// Who performed the action (e.g. `"user:joao.silva"`, `"svc:qvault"`).
    pub actor: String,
    /// Action verb (e.g. `"object.put"`, `"key.rotate"`, `"login"`).
    pub action: String,
    /// Resource identifier (e.g. `"vault://prod/customers/2026-05/file.pdf"`).
    pub resource: String,
    /// Outcome: `"ok"`, `"denied"`, `"error"`, or product-specific.
    pub outcome: String,
    /// Free-form metadata. Keep small (recommended <4 KB total).
    pub metadata: BTreeMap<String, String>,
}

impl AuditEvent {
    /// Start building an event.
    pub fn builder() -> EventBuilder {
        EventBuilder::default()
    }

    /// Compute the canonical CBOR encoding of this event.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(256);
        ciborium::into_writer(self, &mut buf)?;
        Ok(buf)
    }

    /// Compute the BLAKE3-256 content hash of this event's canonical encoding.
    pub fn content_hash(&self) -> [u8; 32] {
        let buf = self
            .to_canonical_cbor()
            .expect("AuditEvent serialization is infallible for these field types");
        blake3::hash(&buf).into()
    }
}

/// Fluent builder for [`AuditEvent`].
///
/// Sensible defaults: `schema = 1`, `timestamp = Utc::now()`, `outcome = "ok"`,
/// `actor = "unknown"`, `action = "noop"`, empty resource and metadata.
#[derive(Debug, Default)]
pub struct EventBuilder {
    timestamp: Option<DateTime<Utc>>,
    actor: Option<String>,
    action: Option<String>,
    resource: Option<String>,
    outcome: Option<String>,
    metadata: BTreeMap<String, String>,
}

impl EventBuilder {
    /// Set the actor.
    pub fn actor(mut self, a: impl Into<String>) -> Self {
        self.actor = Some(a.into());
        self
    }

    /// Set the action verb.
    pub fn action(mut self, a: impl Into<String>) -> Self {
        self.action = Some(a.into());
        self
    }

    /// Set the resource identifier.
    pub fn resource(mut self, r: impl Into<String>) -> Self {
        self.resource = Some(r.into());
        self
    }

    /// Set the outcome label.
    pub fn outcome(mut self, o: impl Into<String>) -> Self {
        self.outcome = Some(o.into());
        self
    }

    /// Override the timestamp (default is `Utc::now()` at build time).
    pub fn timestamp(mut self, t: DateTime<Utc>) -> Self {
        self.timestamp = Some(t);
        self
    }

    /// Add a metadata key/value pair.
    pub fn meta(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.metadata.insert(k.into(), v.into());
        self
    }

    /// Finalize the builder into an [`AuditEvent`].
    pub fn build(self) -> AuditEvent {
        AuditEvent {
            schema: 1,
            timestamp: self.timestamp.unwrap_or_else(Utc::now),
            actor: self.actor.unwrap_or_else(|| "unknown".into()),
            action: self.action.unwrap_or_else(|| "noop".into()),
            resource: self.resource.unwrap_or_default(),
            outcome: self.outcome.unwrap_or_else(|| "ok".into()),
            metadata: self.metadata,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_event() -> AuditEvent {
        AuditEvent::builder()
            .actor("svc:test")
            .action("test.op")
            .resource("test://x")
            .timestamp(DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap())
            .meta("k", "v")
            .meta("a", "b")
            .build()
    }

    #[test]
    fn content_hash_is_deterministic() {
        let h1 = fixed_event().content_hash();
        let h2 = fixed_event().content_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn content_hash_independent_of_meta_insertion_order() {
        let t = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        let e1 = AuditEvent::builder()
            .actor("svc:test")
            .action("test.op")
            .resource("test://x")
            .timestamp(t)
            .meta("k", "v")
            .meta("a", "b")
            .build();
        let e2 = AuditEvent::builder()
            .meta("a", "b")
            .meta("k", "v")
            .actor("svc:test")
            .resource("test://x")
            .action("test.op")
            .timestamp(t)
            .build();
        assert_eq!(e1.content_hash(), e2.content_hash());
    }

    #[test]
    fn different_events_have_different_hashes() {
        let e1 = AuditEvent::builder().action("a").build();
        let e2 = AuditEvent::builder().action("b").build();
        assert_ne!(e1.content_hash(), e2.content_hash());
    }

    #[test]
    fn cbor_roundtrip() {
        let e = fixed_event();
        let bytes = e.to_canonical_cbor().unwrap();
        let back: AuditEvent = ciborium::from_reader(&bytes[..]).unwrap();
        assert_eq!(e, back);
    }
}
