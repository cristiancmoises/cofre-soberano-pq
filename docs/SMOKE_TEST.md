# SMOKE TEST — End-to-end production validation

🇧🇷 **Português:** [SMOKE_TEST.pt-BR.md](SMOKE_TEST.pt-BR.md)

This procedure validates that a fresh **Cofre Soberano PQ** deployment
works against real network conditions: two hosts, one TCP port across
the public internet, post-quantum handshake, audit chain verified
cryptographically on both sides.

It is meant to be runnable by **any operator** with two Linux hosts and
about 30 minutes of attention. There is nothing site-specific in this
procedure — pick any two hosts, pick any non-reserved TCP port, follow
the steps.

If this test passes in your environment, your deployment carries the
same cryptographic guarantees as the reference run documented in
`#observed-results` at the bottom.

---

## Prerequisites

### On both hosts (call them `CLIENT` and `SERVER`)

- Linux x86-64 (Debian 12+, Ubuntu 22.04+, Fedora 39+, Arch, Mint)
- Rust toolchain 1.95.0 (pinned via `rust-toolchain.toml`)
- `pkg-config`, `libssl-dev` or equivalent, `build-essential`
- `nc` (`netcat-openbsd` package)
- A port reachable from `CLIENT` to `SERVER`. Default in this guide:
  `3007/tcp`. If your provider has a network firewall (AWS Security
  Groups, IONOS Firewall Policies, GCP Firewall Rules, hcloud
  Firewalls, etc.), open this port **inbound** on `SERVER`.

### Variables used throughout

Set these in your shell before running anything; substitute your own
values:

```bash
export SERVER_IP=203.0.113.10        # public IP of SERVER
export PQ_PORT=3007                  # PQ tunnel port
export LOCAL_PORT=18080              # where the local app connects on CLIENT
export BACKEND_PORT=3008             # where the real app listens on SERVER
export TENANT=alice                  # arbitrary tenant label
```

`LOCAL_PORT=18080` is suggested because it avoids common collisions
(Docker proxies, dev servers, Jenkins, Tomcat). Pick anything free on
your host.

---

## 1. Build and install

On **both** hosts:

```bash
# Get the source
git clone https://git.securityops.co/cristiancmoises/cofre-soberano-pq.git
cd cofre-soberano-pq

# Build release binaries (uses Cargo.lock, no network surprises)
cargo build --release --workspace --locked

# Install
sudo install -m 0755 target/release/qgateway      /usr/local/bin/
sudo install -m 0755 target/release/qaudit        /usr/local/bin/
sudo install -m 0755 target/release/qaudit-portal /usr/local/bin/

# Confirm
qgateway --version    # qgateway 1.0.1
qaudit --version
qaudit-portal --version
```

---

## 2. Generate identities

### On `CLIENT`

```bash
sudo mkdir -p /etc/qgateway/peers/$TENANT
sudo chown -R $USER:$USER /etc/qgateway
sudo mkdir -p /var/log/qgateway
sudo chown $USER:$USER /var/log/qgateway

cd /etc/qgateway

# Transport identity (ML-DSA-87)
qgateway keygen --sk client.skid --pk client.cspqid.pub
chmod 0400 client.skid

# Audit signing identity
qgateway audit-keygen --sk client.audit.skid --pk client.audit.pub
chmod 0400 client.audit.skid
```

### On `SERVER`

```bash
sudo mkdir -p /etc/qgateway/peers/$TENANT
sudo chown -R $USER:$USER /etc/qgateway
sudo mkdir -p /var/log/qgateway
sudo chown $USER:$USER /var/log/qgateway

cd /etc/qgateway

qgateway keygen       --sk server.skid       --pk server.cspqid.pub
qgateway audit-keygen --sk server.audit.skid --pk server.audit.pub
chmod 0400 server.skid server.audit.skid
```

---

## 3. Exchange peer public keys

Each side must have the **other side's transport pubkey** in its
`peers/<tenant>/` directory before any handshake will succeed.

### From `CLIENT` → `SERVER`

On `CLIENT`:
```bash
scp /etc/qgateway/client.cspqid.pub $USER@$SERVER_IP:/tmp/
```

On `SERVER`:
```bash
cp /tmp/client.cspqid.pub /etc/qgateway/peers/$TENANT/
```

### From `SERVER` → `CLIENT`

On `SERVER`:
```bash
scp /etc/qgateway/server.cspqid.pub $USER@$CLIENT_IP:/tmp/
```

On `CLIENT`:
```bash
cp /tmp/server.cspqid.pub /etc/qgateway/peers/$TENANT/
```

### Verify

On both hosts:
```bash
ls /etc/qgateway/peers/$TENANT/
# Each side should show ONE .cspqid.pub file — the peer's, not its own.
```

---

## 4. Write `sidecar.toml`

### `CLIENT`: `/etc/qgateway/sidecar.toml`

```toml
role           = "serve-tcp"
metrics_listen = "127.0.0.1:9101"

identity_key = "/etc/qgateway/client.skid"
identity_pub = "/etc/qgateway/client.cspqid.pub"

[audit_signer]
kind       = "softkey"
secret_key = "/etc/qgateway/client.audit.skid"
public_key = "/etc/qgateway/client.audit.pub"

[[tenants]]
name         = "alice"
listen       = "127.0.0.1:18080"
peer_pq      = "203.0.113.10:3007"
peer_pub_dir = "/etc/qgateway/peers/alice"
audit_log    = "/var/log/qgateway/alice.qa"
```

Replace `203.0.113.10:3007` with your real `$SERVER_IP:$PQ_PORT`.

### `SERVER`: `/etc/qgateway/sidecar.toml`

```toml
role           = "serve-pq"
metrics_listen = "127.0.0.1:9100"

identity_key = "/etc/qgateway/server.skid"
identity_pub = "/etc/qgateway/server.cspqid.pub"

[audit_signer]
kind       = "softkey"
secret_key = "/etc/qgateway/server.audit.skid"
public_key = "/etc/qgateway/server.audit.pub"

[[tenants]]
name         = "alice"
listen       = "0.0.0.0:3007"
backend      = "127.0.0.1:3008"
peer_pub_dir = "/etc/qgateway/peers/alice"
audit_log    = "/var/log/qgateway/alice.qa"
```

### Validate on both sides

```bash
qgateway validate --config /etc/qgateway/sidecar.toml
# Expected: ok: config valid; role=...; tenants=1
```

---

## 5. Bring up the stack

You need **three terminals on SERVER** and **two on CLIENT**. A
`tmux` session per host is convenient.

### SERVER terminal A — echo backend (foreground)

A trivial Python echo server stands in for a real application:

```bash
python3 -c "
import socket, threading
def handle(c):
    while True:
        d = c.recv(4096)
        if not d: break
        c.sendall(d)
    c.close()
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 3008))
s.listen()
print('echo backend listening on 127.0.0.1:3008')
while True:
    c, addr = s.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
"
```

### SERVER terminal B — qgateway (foreground)

```bash
qgateway run --config /etc/qgateway/sidecar.toml
```

Expected log lines:

```
INFO starting qgateway role=ServePq tenants=1
INFO audit log created (fresh chain) tenant="alice" log=/var/log/qgateway/alice.qa
INFO tenant ready tenant=alice
INFO metrics server listening addr=127.0.0.1:9100
INFO serve-pq tenant active tenant=alice listen=0.0.0.0:3007 backend=127.0.0.1:3008
```

### SERVER terminal C — inspection

```bash
sudo ss -tlnp | grep -E "3007|3008|9100"
# Expected three LISTEN lines.
```

### CLIENT terminal A — qgateway (foreground)

```bash
qgateway run --config /etc/qgateway/sidecar.toml
```

Expected log lines:

```
INFO starting qgateway role=ServeTcp tenants=1
INFO tenant ready tenant=alice
INFO metrics server listening addr=127.0.0.1:9101
INFO serve-tcp tenant active tenant=alice listen=127.0.0.1:18080 peer_pq=203.0.113.10:3007
```

---

## 6. Pre-flight checks (CLIENT terminal B)

Run these three before generating traffic. All three must pass:

```bash
# (1) SERVER reachable on the PQ port
timeout 5 nc -zv $SERVER_IP $PQ_PORT
# Expected: "Connection to ... succeeded!"

# (2) Local qgateway accepting connections
timeout 2 nc -zv 127.0.0.1 $LOCAL_PORT
# Expected: "Connection to ... succeeded!"

# (3) Audit log is fresh (no entries yet)
qaudit inspect --log /var/log/qgateway/alice.qa | head -1
# Expected: entries = 0  (or  "no header" if the daemon hasn't initialised it yet — that's OK)
```

If (1) fails: open the port in your **cloud provider's firewall**.
Distribution-level `nftables` rules are not enough on most providers.

---

## 7. Generate 10 sessions (CLIENT terminal B)

```bash
for i in $(seq 1 10); do
    R=$(echo "session $i over PQ tunnel" | timeout 5 nc 127.0.0.1 $LOCAL_PORT)
    if [ "$R" = "session $i over PQ tunnel" ]; then
        echo "  ✓ session $i — echo matches"
    else
        echo "  ✗ session $i — got: '$R'"
    fi
    sleep 1
done
```

Expected: 10 lines, all `✓ echo matches`.

What this does, per session:
1. `nc` opens TCP to `127.0.0.1:18080`
2. CLIENT qgateway accepts, initiates CSPQ handshake to SERVER
3. ML-KEM-1024 key encapsulation + ML-DSA-87 mutual authentication
4. Session key derived; both sides switch to ChaCha20-Poly1305
5. The line is encrypted, sent over the internet, decrypted by SERVER
6. SERVER qgateway forwards plaintext to the echo backend
7. Echo returns; round trip closes; both sides write `session.open` +
   `session.close` to their audit logs

---

## 8. Read metrics

### CLIENT
```bash
curl -s http://127.0.0.1:9101/metrics \
    | grep -E "qgateway_sessions_(opened|closed|failed)_total" \
    | grep alice
```

### SERVER
```bash
curl -s http://127.0.0.1:9100/metrics \
    | grep -E "qgateway_sessions_(opened|closed|failed)_total" \
    | grep alice
```

Expected on both sides:

```
qgateway_sessions_opened_total{tenant="alice"} 10
qgateway_sessions_closed_total{tenant="alice"} 10
qgateway_sessions_failed_total{tenant="alice"} 0
```

If `failed` is non-zero, see `#known-edge-cases` below.

---

## 9. Graceful shutdown — this matters

**Send SIGINT (Ctrl-C) once on each foreground qgateway and wait for the
flush message.** Never `kill -9` during a smoke test; the audit channel
flushes events to disk only during graceful shutdown.

### CLIENT terminal A (qgateway)
Press Ctrl-C. Expect:
```
INFO received signal sig=SIGINT
INFO audit channel flushed events=20
INFO shutdown complete
```

`events=20` is the 10 sessions × 2 events (`session.open` +
`session.close`) per session.

### SERVER terminal B (qgateway)
Press Ctrl-C. Same flush message expected.

### SERVER terminal A (echo backend)
Press Ctrl-C — no flush needed, it's just Python.

---

## 10. Verify the audit chain

On both hosts:

```bash
qaudit inspect --log /var/log/qgateway/alice.qa | head
qaudit verify  --log /var/log/qgateway/alice.qa
```

Expected on both sides:

```
log_id = <hex>   suite = cspq-2026   entries = 20
label  = qgateway/alice
...

ok: 20 entries verified, root = <hex>
```

Each entry carries an ML-DSA-87 signature; each new root is the BLAKE3
hash of the previous root concatenated with the canonical encoding of
the current event. `qaudit verify` walks the chain and rejects on the
first invalid signature or broken link.

---

## 11. View the chain in a browser

On `CLIENT`:

```bash
qaudit-portal --log /var/log/qgateway/alice.qa --listen 127.0.0.1:8123
```

Open `http://127.0.0.1:8123`. You should see:

- Header bar: `20 entries · ✓ verified`
- Table alternating `session.open` and `session.close` rows
- Per-row: timestamp, actor `svc:qgateway`, action, resource
  (`cspq://<session-id>`), metadata (duration, byte counts, peer port),
  and the rolling root hash truncated to 16 bytes

If the header reports anything other than `✓ verified`, the chain is
corrupted — see `#known-edge-cases`.

### Optional — verify with an externally-published audit pubkey

If you want to simulate the regulator scenario (`#sovereignty-proof`),
pass the pubkey on the command line:

```bash
qaudit-portal \
    --log /var/log/qgateway/alice.qa \
    --pk  /etc/qgateway/client.audit.pub \
    --listen 127.0.0.1:8123
```

The portal accepts both the raw 2592-byte ML-DSA-87 format produced by
`qaudit init` **and** the 2600-byte framed format produced by
`qgateway audit-keygen`. The cross-check confirms the pubkey embedded
in the log header matches the one you supplied externally.

---

## 12. Sovereignty proof — cross-host offline verification

This is the auditor scenario. The regulator wants to verify your audit
log **on their own laptop**, without trusting your infrastructure.

On `SERVER`:
```bash
scp /var/log/qgateway/alice.qa     $USER@$CLIENT_IP:/tmp/server-real.qa
scp /etc/qgateway/server.audit.pub $USER@$CLIENT_IP:/tmp/server-real.pub
```

On `CLIENT`, **without** establishing any new connection to `SERVER`:
```bash
qaudit verify --log /tmp/server-real.qa
qaudit inspect --log /tmp/server-real.qa | head
```

Expected: same 20 entries, same root hash that `SERVER` reported in
step 10. The match is the proof — the chain was not modified in
transit, and no operator-side trust is needed.

---

## Known edge cases

### `early eof` failures on the SERVER side

If `sessions_failed_total > 0` on the server, look at the qgateway log:

```
ERROR CSPQ handshake from peer 198.51.100.42:36928 failed: io: early eof
```

This means the client closed TCP before the handshake completed. The
most common cause is a `nc -w 1` timeout that fires before ML-KEM-1024
finishes. Increase the timeout or use a slower loop.

The daemon survives, the failure is counted, and the audit log is not
written. This is correct behaviour — there is no session to log.

### Port collision on CLIENT

If `qgateway run` fails with `Address already in use`, something else
is bound to `LOCAL_PORT`. Common culprits:

- Docker port-publishing (`docker-proxy` process)
- Local dev servers
- Other reverse proxies

Identify with:
```bash
sudo ss -tlnp | grep $LOCAL_PORT
```

Then either stop the conflicting service or change `LOCAL_PORT` in
your `sidecar.toml` and rerun.

### Clock skew between hosts

If `date -u` on the two hosts differs by more than a few seconds,
audit log timestamps will appear out of order to anyone correlating
the two chains. Run on both:

```bash
sudo timedatectl set-ntp on
```

and wait ~30 seconds before resuming the test.

### Cloud provider firewall

Most providers run a firewall at the network layer, separate from your
host's `iptables`/`nftables`. Symptom: `nc -zv $SERVER_IP $PQ_PORT`
hangs silently, then exits without `succeeded` or `refused`. Open the
port in the provider's web console.

### Behind a VPN

If `CLIENT` runs Mullvad, Tailscale, ProtonVPN, or any other VPN, your
egress IP will not be your home IP. The SERVER will see the VPN exit
node. **This does not affect the smoke test** — CSPQ is end-to-end
between the two gateways and is independent of any intermediate
encryption layer. It does, however, mean that any source-IP allowlists
you configure must include the VPN exit range.

---

## Observed results — reference run

These numbers are from a real run between Caxias do Sul, Brazil
(workstation) and Frankfurt, Germany (IONOS VPS), with the CLIENT
behind Mullvad VPN, 2026-05-21.

| Measurement | Value |
|---|---|
| Round-trip TCP latency | ~250 ms |
| Mean PQ handshake | 311 ms |
| Min handshake | 299 ms |
| Max handshake | 324 ms |
| 10/10 sessions echoed correctly | ✓ |
| `sessions_failed_total` (across run) | 1 (pre-test stray `nc` timeout) |
| Mint audit chain entries | 22 (including 1 pre-test session) |
| VPS audit chain entries | 22 |
| Cross-host offline `verify` matches root | ✓ |

For comparison, classical TLS 1.3 over the same path measures around
80–120 ms. The roughly 3× factor is the cost of ML-KEM + ML-DSA over
ECDHE + Ed25519. It is paid **once per session** and is independent of
session length.

If you publish a result from your own environment, please open a PR
adding a row to the table above. We welcome real numbers.

---

## What this test does NOT validate

Honest disclosure:

- **HSM-backed signing.** This test uses softkey signers. To validate
  PKCS#11 backing, see `docs/HSM.md`.
- **Long-running stability.** 10 sessions over ~30 seconds does not
  exercise leak paths, log rotation, or rate-limit edge cases.
- **High concurrency.** Single-client, sequential. Run `wrk` or
  similar against `127.0.0.1:$LOCAL_PORT` if you need throughput
  numbers.
- **Adversarial peers.** The handshake rejection logic is exercised by
  the `crates/qtransport-cspq/tests/` integration suite, not by this
  procedure.

Run the full `cargo test --workspace --release --locked` suite (227+
tests) for coverage of the above.
