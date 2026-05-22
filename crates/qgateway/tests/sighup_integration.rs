//! Sprint 25 — SIGHUP integration test.
//!
//! Spawns the actual qgateway binary, drives a SIGHUP cycle that ADDs then
//! REMOVEs a tenant, and asserts the Sprint 17 Prometheus counters reflect
//! the operations.
//!
//! See `common/mod.rs` for the shared fixture / daemon-guard / metrics-
//! scrape helpers (extracted in Sprint 26 to support a second integration
//! test for audit chain integrity).

mod common;

use std::time::Duration;

use common::*;

#[test]
fn sighup_add_then_remove_tenant_increments_counters() {
    let fx = Fixture::build(&["alice"]);
    let daemon = DaemonGuard::spawn(&fx.config_path);

    assert!(
        wait_for_metrics(fx.metrics_port, Duration::from_secs(15)),
        "daemon /metrics did not come up within 15s"
    );

    let baseline = scrape_metrics(fx.metrics_port).expect("baseline /metrics");
    let added_before = counter_value(&baseline, "qgateway_tenants_added_total");
    let removed_before = counter_value(&baseline, "qgateway_tenants_removed_total");
    let cycles_before = counter_value(&baseline, "qgateway_sighup_cycles_total");

    // Add bob.
    let bob_port = pick_port();
    fx.write_config_with(&[("alice", fx.tenant_ports[0]), ("bob", bob_port)]);
    sighup(daemon.pid());
    std::thread::sleep(Duration::from_secs(2));

    let after_add = scrape_metrics(fx.metrics_port).expect("after-add /metrics");
    let added_after_add = counter_value(&after_add, "qgateway_tenants_added_total");
    let cycles_after_add = counter_value(&after_add, "qgateway_sighup_cycles_total");

    assert!(
        added_after_add > added_before,
        "expected added counter to increase after SIGHUP ADD: before={added_before} after={added_after_add}"
    );
    assert!(
        cycles_after_add > cycles_before,
        "expected sighup_cycles counter to increase: before={cycles_before} after={cycles_after_add}"
    );

    // Remove bob.
    fx.write_config_with(&[("alice", fx.tenant_ports[0])]);
    sighup(daemon.pid());
    std::thread::sleep(Duration::from_secs(2));

    let after_remove = scrape_metrics(fx.metrics_port).expect("after-remove /metrics");
    let removed_after = counter_value(&after_remove, "qgateway_tenants_removed_total");

    assert!(
        removed_after > removed_before,
        "expected removed counter to increase after SIGHUP REMOVE: before={removed_before} after={removed_after}"
    );
}
