//! Regulatory export formats.
//!
//! Audit logs are stored in CBOR for compactness and speed; regulators receive
//! them in XML for machine-readable integration with existing audit and
//! compliance pipelines (Bacen, CVM, ANPD, SUSEP).
//!
//! ## Schema overview
//!
//! Namespace: `https://securityops.co/schemas/qaudit-export-v1`.
//!
//! ```xml
//! <AuditLogExport xmlns="https://securityops.co/schemas/qaudit-export-v1">
//!   <Header>
//!     <LogId>...</LogId>
//!     <Suite>cspq-2026</Suite>
//!     <WireVersion>1</WireVersion>
//!     <CreatedAt>2026-05-19T17:00:57Z</CreatedAt>
//!     <Label>qvault-prod-sp</Label>
//!     <SignatureAlgorithm>ml-dsa-87</SignatureAlgorithm>
//!     <HashAlgorithm>blake3-256</HashAlgorithm>
//!     <PublicKey encoding="hex">d163b48985...</PublicKey>
//!   </Header>
//!   <Entries count="N">
//!     <Entry index="0">
//!       <AppendedAt>2026-05-19T17:00:57Z</AppendedAt>
//!       <Event>
//!         <Schema>1</Schema>
//!         <Timestamp>2026-05-19T17:00:57Z</Timestamp>
//!         <Actor>svc:qvault</Actor>
//!         <Action>object.put</Action>
//!         <Resource>vault://prod/x.pdf</Resource>
//!         <Outcome>ok</Outcome>
//!         <Metadata>
//!           <Item key="size_bytes">182734</Item>
//!         </Metadata>
//!       </Event>
//!       <PrevRoot encoding="hex">...</PrevRoot>
//!       <NewRoot encoding="hex">...</NewRoot>
//!       <Signature encoding="hex" algorithm="ml-dsa-87">...</Signature>
//!     </Entry>
//!   </Entries>
//!   <Trailer>
//!     <FinalRoot encoding="hex">...</FinalRoot>
//!     <EntryCount>N</EntryCount>
//!     <ExportedAt>...</ExportedAt>
//!     <ProducerVersion>qaudit X.Y.Z</ProducerVersion>
//!   </Trailer>
//! </AuditLogExport>
//! ```
//!
//! The schema is intentionally simple: any XSLT or XPath toolchain (Bacen's
//! own systems, regulator-side Java/.NET parsers) can ingest it directly.
//! Field semantics are documented in `docs/BACEN-EXPORT-FORMAT.md`.

use crate::error::Result;
use crate::log::AuditLog;
use chrono::{SecondsFormat, Utc};
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event};
use quick_xml::writer::Writer;
use std::io::Cursor;

const NAMESPACE: &str = "https://securityops.co/schemas/qaudit-export-v1";

fn write_text_elem<W: std::io::Write>(
    w: &mut Writer<W>,
    name: &str,
    text: &str,
) -> quick_xml::Result<()> {
    w.write_event(Event::Start(BytesStart::new(name)))?;
    w.write_event(Event::Text(BytesText::new(text)))?;
    w.write_event(Event::End(BytesEnd::new(name)))?;
    Ok(())
}

fn write_hex_elem<W: std::io::Write>(
    w: &mut Writer<W>,
    name: &str,
    bytes: &[u8],
) -> quick_xml::Result<()> {
    let mut start = BytesStart::new(name);
    start.push_attribute(("encoding", "hex"));
    w.write_event(Event::Start(start))?;
    w.write_event(Event::Text(BytesText::new(&hex::encode(bytes))))?;
    w.write_event(Event::End(BytesEnd::new(name)))?;
    Ok(())
}

fn write_signature_elem<W: std::io::Write>(
    w: &mut Writer<W>,
    bytes: &[u8],
) -> quick_xml::Result<()> {
    let mut start = BytesStart::new("Signature");
    start.push_attribute(("encoding", "hex"));
    start.push_attribute(("algorithm", "ml-dsa-87"));
    w.write_event(Event::Start(start))?;
    w.write_event(Event::Text(BytesText::new(&hex::encode(bytes))))?;
    w.write_event(Event::End(BytesEnd::new("Signature")))?;
    Ok(())
}

/// Render an [`AuditLog`] into the regulator-facing XML format.
///
/// The log is NOT re-verified by this function. Callers MUST run
/// [`AuditLog::verify`] before exporting; the export carries the signatures
/// themselves so any consumer can independently verify, but a clean export
/// of a known-bad log would be misleading.
pub fn export_xml(log: &AuditLog) -> Result<String> {
    let mut buf = Cursor::new(Vec::new());
    let mut w = Writer::new_with_indent(&mut buf, b' ', 2);

    w.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))?;

    let mut root = BytesStart::new("AuditLogExport");
    root.push_attribute(("xmlns", NAMESPACE));
    w.write_event(Event::Start(root.clone()))?;

    // <Header>
    w.write_event(Event::Start(BytesStart::new("Header")))?;
    write_text_elem(&mut w, "LogId", &log.header().log_id.to_hex())?;
    write_text_elem(&mut w, "Suite", &log.header().suite)?;
    write_text_elem(
        &mut w,
        "WireVersion",
        &log.header().wire_version.to_string(),
    )?;
    write_text_elem(
        &mut w,
        "CreatedAt",
        &log.header()
            .created_at
            .to_rfc3339_opts(SecondsFormat::Secs, true),
    )?;
    write_text_elem(&mut w, "Label", &log.header().label)?;
    write_text_elem(&mut w, "SignatureAlgorithm", "ml-dsa-87")?;
    write_text_elem(&mut w, "HashAlgorithm", "blake3-256")?;
    write_hex_elem(&mut w, "PublicKey", log.header().pubkey.as_bytes())?;
    w.write_event(Event::End(BytesEnd::new("Header")))?;

    // <Entries count="N">
    let mut entries_start = BytesStart::new("Entries");
    entries_start.push_attribute(("count", log.len().to_string().as_str()));
    w.write_event(Event::Start(entries_start))?;

    for entry in log.entries() {
        let mut e_start = BytesStart::new("Entry");
        e_start.push_attribute(("index", entry.index.to_string().as_str()));
        w.write_event(Event::Start(e_start))?;

        write_text_elem(
            &mut w,
            "AppendedAt",
            &entry
                .appended_at
                .to_rfc3339_opts(SecondsFormat::Millis, true),
        )?;

        // <Event>
        w.write_event(Event::Start(BytesStart::new("Event")))?;
        write_text_elem(&mut w, "Schema", &entry.event.schema.to_string())?;
        write_text_elem(
            &mut w,
            "Timestamp",
            &entry
                .event
                .timestamp
                .to_rfc3339_opts(SecondsFormat::Millis, true),
        )?;
        write_text_elem(&mut w, "Actor", &entry.event.actor)?;
        write_text_elem(&mut w, "Action", &entry.event.action)?;
        write_text_elem(&mut w, "Resource", &entry.event.resource)?;
        write_text_elem(&mut w, "Outcome", &entry.event.outcome)?;

        // <Metadata>
        w.write_event(Event::Start(BytesStart::new("Metadata")))?;
        for (k, v) in &entry.event.metadata {
            let mut item = BytesStart::new("Item");
            item.push_attribute(("key", k.as_str()));
            w.write_event(Event::Start(item))?;
            w.write_event(Event::Text(BytesText::new(v)))?;
            w.write_event(Event::End(BytesEnd::new("Item")))?;
        }
        w.write_event(Event::End(BytesEnd::new("Metadata")))?;

        w.write_event(Event::End(BytesEnd::new("Event")))?;

        write_hex_elem(&mut w, "PrevRoot", &entry.prev_root)?;
        write_hex_elem(&mut w, "NewRoot", &entry.new_root)?;
        write_signature_elem(&mut w, entry.signature.as_bytes())?;

        w.write_event(Event::End(BytesEnd::new("Entry")))?;
    }

    w.write_event(Event::End(BytesEnd::new("Entries")))?;

    // <Trailer>
    w.write_event(Event::Start(BytesStart::new("Trailer")))?;
    write_hex_elem(&mut w, "FinalRoot", &log.current_root())?;
    write_text_elem(&mut w, "EntryCount", &log.len().to_string())?;
    write_text_elem(
        &mut w,
        "ExportedAt",
        &Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    )?;
    write_text_elem(
        &mut w,
        "ProducerVersion",
        &format!("qaudit-core {}", crate::VERSION),
    )?;
    w.write_event(Event::End(BytesEnd::new("Trailer")))?;

    w.write_event(Event::End(BytesEnd::new("AuditLogExport")))?;

    let bytes = buf.into_inner();
    String::from_utf8(bytes).map_err(|e| crate::Error::Internal(format!("XML UTF-8: {e}")))
}

/// Render an [`AuditLog`] as newline-delimited JSON (one entry per line).
///
/// Format mirrors `qaudit inspect --json` and is intended for ingestion by
/// log-aggregation systems (Splunk, Elastic, Wazuh).
pub fn export_jsonl(log: &AuditLog) -> Result<String> {
    let mut out = String::new();
    for e in log.entries() {
        // Construct a small JSON object by hand to keep the dep surface
        // narrow (no serde_json in qaudit-core; only in the CLI).
        let mut s = String::with_capacity(512);
        s.push('{');
        json_field(&mut s, "index", &e.index.to_string(), false);
        s.push(',');
        json_field(
            &mut s,
            "appended_at",
            &json_escape(&e.appended_at.to_rfc3339_opts(SecondsFormat::Millis, true)),
            true,
        );
        s.push(',');
        json_field(&mut s, "actor", &json_escape(&e.event.actor), true);
        s.push(',');
        json_field(&mut s, "action", &json_escape(&e.event.action), true);
        s.push(',');
        json_field(&mut s, "resource", &json_escape(&e.event.resource), true);
        s.push(',');
        json_field(&mut s, "outcome", &json_escape(&e.event.outcome), true);
        s.push(',');
        s.push_str("\"metadata\":{");
        let mut first = true;
        for (k, v) in &e.event.metadata {
            if !first {
                s.push(',');
            }
            s.push('"');
            s.push_str(&json_escape(k));
            s.push_str("\":\"");
            s.push_str(&json_escape(v));
            s.push('"');
            first = false;
        }
        s.push('}');
        s.push(',');
        json_field(&mut s, "prev_root", &hex::encode(e.prev_root), true);
        s.push(',');
        json_field(&mut s, "new_root", &hex::encode(e.new_root), true);
        s.push(',');
        json_field(
            &mut s,
            "signature",
            &hex::encode(e.signature.as_bytes()),
            true,
        );
        s.push('}');
        s.push('\n');
        out.push_str(&s);
    }
    Ok(out)
}

fn json_field(out: &mut String, k: &str, raw_value: &str, quoted: bool) {
    out.push('"');
    out.push_str(k);
    out.push_str("\":");
    if quoted {
        out.push('"');
    }
    out.push_str(raw_value);
    if quoted {
        out.push('"');
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuditEvent, AuditLog, KeyPair};

    fn populated_log() -> AuditLog {
        let kp = KeyPair::generate().unwrap();
        let mut log = AuditLog::create_with_label(kp, "export-test").unwrap();
        log.append(
            AuditEvent::builder()
                .actor("svc:qvault")
                .action("object.put")
                .resource("vault://prod/x.pdf")
                .outcome("ok")
                .meta("size", "182734")
                .meta("tenant", "itau")
                .build(),
        )
        .unwrap();
        log.append(
            AuditEvent::builder()
                .actor("user:joao")
                .action("login")
                .resource("console://admin")
                .outcome("denied")
                .meta("reason", "mfa-fail")
                .build(),
        )
        .unwrap();
        log
    }

    #[test]
    fn xml_export_is_well_formed_and_has_expected_anchors() {
        let log = populated_log();
        let xml = export_xml(&log).unwrap();
        assert!(xml.starts_with("<?xml"));
        assert!(xml.contains("xmlns=\"https://securityops.co/schemas/qaudit-export-v1\""));
        assert!(xml.contains("<LogId>"));
        assert!(xml.contains("<SignatureAlgorithm>ml-dsa-87</SignatureAlgorithm>"));
        assert!(xml.contains("<HashAlgorithm>blake3-256</HashAlgorithm>"));
        assert!(xml.contains("count=\"2\""));
        assert!(xml.contains("<Item key=\"size\">182734</Item>"));
        assert!(xml.contains("<Outcome>denied</Outcome>"));
        assert!(xml.contains("<FinalRoot encoding=\"hex\">"));
        assert!(xml.contains("</AuditLogExport>"));
        // Round-trip parse: ensure quick-xml can read what we produced.
        let mut reader = quick_xml::Reader::from_str(&xml);
        reader.config_mut().trim_text(true);
        let mut depth: i32 = 0;
        loop {
            match reader.read_event().unwrap() {
                quick_xml::events::Event::Start(_) => depth += 1,
                quick_xml::events::Event::End(_) => depth -= 1,
                quick_xml::events::Event::Eof => break,
                _ => {}
            }
        }
        assert_eq!(depth, 0, "XML tags must balance");
    }

    #[test]
    fn xml_escapes_special_characters_in_resource() {
        let kp = KeyPair::generate().unwrap();
        let mut log = AuditLog::create_with_label(kp, "").unwrap();
        log.append(
            AuditEvent::builder()
                .actor("a")
                .action("b")
                .resource("foo<bar>&\"baz\"")
                .build(),
        )
        .unwrap();
        let xml = export_xml(&log).unwrap();
        assert!(xml.contains("foo&lt;bar&gt;&amp;&quot;baz&quot;"));
        assert!(!xml.contains("foo<bar>&\"baz\""));
    }

    #[test]
    fn jsonl_one_line_per_entry() {
        let log = populated_log();
        let s = export_jsonl(&log).unwrap();
        let lines: Vec<_> = s.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in &lines {
            assert!(line.starts_with('{'));
            assert!(line.ends_with('}'));
            assert!(line.contains("\"new_root\""));
            assert!(line.contains("\"signature\""));
        }
    }

    #[test]
    fn jsonl_escapes_quotes_and_control_chars() {
        let kp = KeyPair::generate().unwrap();
        let mut log = AuditLog::create_with_label(kp, "").unwrap();
        log.append(
            AuditEvent::builder()
                .actor("a\"b")
                .action("x\ny")
                .resource("z\\w")
                .build(),
        )
        .unwrap();
        let s = export_jsonl(&log).unwrap();
        assert!(s.contains("\"actor\":\"a\\\"b\""));
        assert!(s.contains("\"action\":\"x\\ny\""));
        assert!(s.contains("\"resource\":\"z\\\\w\""));
    }
}
