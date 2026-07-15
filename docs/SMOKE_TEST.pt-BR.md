# SMOKE TEST — Validação de produção ponta a ponta

*Teste de fumaça de produção (pt-BR). O [SMOKE_TEST.md](SMOKE_TEST.md) em inglês prevalece em caso de divergência.*

Este procedimento valida que uma implantação nova do **Cofre Soberano PQ**
funciona sob condições reais de rede: dois hosts, uma porta TCP através
da internet pública, handshake pós-quântico, cadeia de auditoria verificada
criptograficamente em ambos os lados.

Ele foi feito para ser executável por **qualquer operador** com dois hosts Linux e
cerca de 30 minutos de atenção. Não há nada específico de instalação neste
procedimento — escolha quaisquer dois hosts, escolha qualquer porta TCP não reservada, siga
os passos.

Se este teste passar no seu ambiente, sua implantação carrega as
mesmas garantias criptográficas da execução de referência documentada em
`#observed-results` no final.

---

## Pré-requisitos

### Em ambos os hosts (chame-os de `CLIENT` e `SERVER`)

- Linux x86-64 (Debian 12+, Ubuntu 22.04+, Fedora 39+, Arch, Mint)
- Toolchain Rust 1.95.0 (fixada via `rust-toolchain.toml`)
- `pkg-config`, `libssl-dev` ou equivalente, `build-essential`
- `nc` (pacote `netcat-openbsd`)
- Uma porta acessível de `CLIENT` para `SERVER`. Padrão neste guia:
  `3007/tcp`. Se o seu provedor tem um firewall de rede (AWS Security
  Groups, IONOS Firewall Policies, GCP Firewall Rules, hcloud
  Firewalls, etc.), abra esta porta **de entrada** no `SERVER`.

### Variáveis usadas ao longo do documento

Defina estas no seu shell antes de executar qualquer coisa; substitua pelos seus próprios
valores:

```bash
export SERVER_IP=203.0.113.10        # public IP of SERVER
export PQ_PORT=3007                  # PQ tunnel port
export LOCAL_PORT=18080              # where the local app connects on CLIENT
export BACKEND_PORT=3008             # where the real app listens on SERVER
export TENANT=alice                  # arbitrary tenant label
```

`LOCAL_PORT=18080` é sugerido porque evita colisões comuns
(proxies Docker, servidores de desenvolvimento, Jenkins, Tomcat). Escolha qualquer porta livre no
seu host.

---

## 1. Compilar e instalar

Em **ambos** os hosts:

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

## 2. Gerar identidades

### No `CLIENT`

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

### No `SERVER`

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

## 3. Trocar as chaves públicas dos peers

Cada lado precisa ter a **chave pública de transporte do outro lado** em seu
diretório `peers/<tenant>/` antes que qualquer handshake tenha sucesso.

### De `CLIENT` → `SERVER`

No `CLIENT`:
```bash
scp /etc/qgateway/client.cspqid.pub $USER@$SERVER_IP:/tmp/
```

No `SERVER`:
```bash
cp /tmp/client.cspqid.pub /etc/qgateway/peers/$TENANT/
```

### De `SERVER` → `CLIENT`

No `SERVER`:
```bash
scp /etc/qgateway/server.cspqid.pub $USER@$CLIENT_IP:/tmp/
```

No `CLIENT`:
```bash
cp /tmp/server.cspqid.pub /etc/qgateway/peers/$TENANT/
```

### Verificar

Em ambos os hosts:
```bash
ls /etc/qgateway/peers/$TENANT/
# Each side should show ONE .cspqid.pub file — the peer's, not its own.
```

---

## 4. Escrever `sidecar.toml`

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

Substitua `203.0.113.10:3007` pelo seu `$SERVER_IP:$PQ_PORT` real.

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

### Validar em ambos os lados

```bash
qgateway validate --config /etc/qgateway/sidecar.toml
# Expected: ok: config valid; role=...; tenants=1
```

---

## 5. Subir a stack

Você precisa de **três terminais no SERVER** e **dois no CLIENT**. Uma
sessão `tmux` por host é conveniente.

### SERVER terminal A — backend de echo (primeiro plano)

Um servidor de echo Python trivial faz as vezes de uma aplicação real:

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

### SERVER terminal B — qgateway (primeiro plano)

```bash
qgateway run --config /etc/qgateway/sidecar.toml
```

Linhas de log esperadas:

```
INFO starting qgateway role=ServePq tenants=1
INFO audit log created (fresh chain) tenant="alice" log=/var/log/qgateway/alice.qa
INFO tenant ready tenant=alice
INFO metrics server listening addr=127.0.0.1:9100
INFO serve-pq tenant active tenant=alice listen=0.0.0.0:3007 backend=127.0.0.1:3008
```

### SERVER terminal C — inspeção

```bash
sudo ss -tlnp | grep -E "3007|3008|9100"
# Expected three LISTEN lines.
```

### CLIENT terminal A — qgateway (primeiro plano)

```bash
qgateway run --config /etc/qgateway/sidecar.toml
```

Linhas de log esperadas:

```
INFO starting qgateway role=ServeTcp tenants=1
INFO tenant ready tenant=alice
INFO metrics server listening addr=127.0.0.1:9101
INFO serve-tcp tenant active tenant=alice listen=127.0.0.1:18080 peer_pq=203.0.113.10:3007
```

---

## 6. Verificações preliminares (CLIENT terminal B)

Execute estas três antes de gerar tráfego. Todas as três precisam passar:

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

Se (1) falhar: abra a porta no **firewall do seu provedor de nuvem**.
Regras `nftables` a nível de distribuição não bastam na maioria dos provedores.

---

## 7. Gerar 10 sessões (CLIENT terminal B)

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

Esperado: 10 linhas, todas `✓ echo matches`.

O que isto faz, por sessão:
1. `nc` abre TCP para `127.0.0.1:18080`
2. O qgateway do CLIENT aceita, inicia o handshake CSPQ para o SERVER
3. Encapsulamento de chave ML-KEM-1024 + autenticação mútua ML-DSA-87
4. Chave de sessão derivada; ambos os lados mudam para ChaCha20-Poly1305
5. A linha é criptografada, enviada pela internet, descriptografada pelo SERVER
6. O qgateway do SERVER encaminha o texto claro para o backend de echo
7. O echo retorna; o round trip se encerra; ambos os lados escrevem `session.open` +
   `session.close` em seus registros de auditoria

---

## 8. Ler métricas

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

Esperado em ambos os lados:

```
qgateway_sessions_opened_total{tenant="alice"} 10
qgateway_sessions_closed_total{tenant="alice"} 10
qgateway_sessions_failed_total{tenant="alice"} 0
```

Se `failed` for diferente de zero, veja `#known-edge-cases` abaixo.

---

## 9. Desligamento gracioso — isto importa

**Envie SIGINT (Ctrl-C) uma vez em cada qgateway em primeiro plano e aguarde a
mensagem de flush.** Nunca use `kill -9` durante um teste de fumaça; o canal de auditoria
descarrega os eventos para o disco apenas durante o desligamento gracioso.

### CLIENT terminal A (qgateway)
Pressione Ctrl-C. Espere:
```
INFO received signal sig=SIGINT
INFO audit channel flushed events=20
INFO shutdown complete
```

`events=20` são as 10 sessões × 2 eventos (`session.open` +
`session.close`) por sessão.

### SERVER terminal B (qgateway)
Pressione Ctrl-C. Espera-se a mesma mensagem de flush.

### SERVER terminal A (backend de echo)
Pressione Ctrl-C — nenhum flush necessário, é apenas Python.

---

## 10. Verificar a cadeia de auditoria

Em ambos os hosts:

```bash
qaudit inspect --log /var/log/qgateway/alice.qa | head
qaudit verify  --log /var/log/qgateway/alice.qa
```

Esperado em ambos os lados:

```
log_id = <hex>   suite = cspq-2026   entries = 20
label  = qgateway/alice
...

ok: 20 entries verified, root = <hex>
```

Cada entrada carrega uma assinatura ML-DSA-87; cada nova raiz é o hash
BLAKE3 da raiz anterior concatenada com a codificação canônica do
evento atual. O `qaudit verify` percorre a cadeia e rejeita na
primeira assinatura inválida ou elo quebrado.

---

## 11. Ver a cadeia em um navegador

No `CLIENT`:

```bash
qaudit-portal --log /var/log/qgateway/alice.qa --listen 127.0.0.1:8123
```

Abra `http://127.0.0.1:8123`. Você deve ver:

- Barra de cabeçalho: `20 entries · ✓ verified`
- Tabela alternando linhas `session.open` e `session.close`
- Por linha: timestamp, ator `svc:qgateway`, ação, recurso
  (`cspq://<session-id>`), metadados (duração, contagens de bytes, porta do peer),
  e o hash da raiz progressiva truncado em 16 bytes

Se o cabeçalho relatar qualquer coisa diferente de `✓ verified`, a cadeia está
corrompida — veja `#known-edge-cases`.

### Opcional — verificar com uma chave pública de auditoria publicada externamente

Se você quiser simular o cenário do regulador (`#sovereignty-proof`),
passe a chave pública na linha de comando:

```bash
qaudit-portal \
    --log /var/log/qgateway/alice.qa \
    --pk  /etc/qgateway/client.audit.pub \
    --listen 127.0.0.1:8123
```

O portal aceita tanto o formato ML-DSA-87 bruto de 2592 bytes produzido pelo
`qaudit init` **quanto** o formato encapsulado de 2600 bytes produzido pelo
`qgateway audit-keygen`. A verificação cruzada confirma que a chave pública embutida
no cabeçalho do log corresponde à que você forneceu externamente.

---

## 12. Prova de soberania — verificação offline entre hosts

Este é o cenário do auditor. O regulador quer verificar seu registro de auditoria
**no próprio laptop dele**, sem confiar na sua infraestrutura.

No `SERVER`:
```bash
scp /var/log/qgateway/alice.qa     $USER@$CLIENT_IP:/tmp/server-real.qa
scp /etc/qgateway/server.audit.pub $USER@$CLIENT_IP:/tmp/server-real.pub
```

No `CLIENT`, **sem** estabelecer qualquer nova conexão com o `SERVER`:
```bash
qaudit verify --log /tmp/server-real.qa
qaudit inspect --log /tmp/server-real.qa | head
```

Esperado: as mesmas 20 entradas, o mesmo hash de raiz que o `SERVER` relatou no
passo 10. A correspondência é a prova — a cadeia não foi modificada em
trânsito, e nenhuma confiança do lado do operador é necessária.

---

## Casos limite conhecidos

### Falhas `early eof` no lado do SERVER

Se `sessions_failed_total > 0` no servidor, olhe o log do qgateway:

```
ERROR CSPQ handshake from peer 198.51.100.42:36928 failed: io: early eof
```

Isto significa que o cliente fechou o TCP antes de o handshake ser concluído. A
causa mais comum é um timeout `nc -w 1` que dispara antes de o ML-KEM-1024
terminar. Aumente o timeout ou use um loop mais lento.

O daemon sobrevive, a falha é contabilizada, e o registro de auditoria não é
escrito. Este é o comportamento correto — não há sessão a registrar.

### Colisão de porta no CLIENT

Se `qgateway run` falhar com `Address already in use`, algo mais
está vinculado à `LOCAL_PORT`. Culpados comuns:

- Publicação de portas do Docker (processo `docker-proxy`)
- Servidores de desenvolvimento locais
- Outros proxies reversos

Identifique com:
```bash
sudo ss -tlnp | grep $LOCAL_PORT
```

Então pare o serviço conflitante ou altere `LOCAL_PORT` no
seu `sidecar.toml` e execute novamente.

### Desvio de relógio entre hosts

Se `date -u` nos dois hosts diferir por mais de alguns segundos,
os timestamps do registro de auditoria aparecerão fora de ordem para quem correlacionar
as duas cadeias. Execute em ambos:

```bash
sudo timedatectl set-ntp on
```

e aguarde ~30 segundos antes de retomar o teste.

### Firewall do provedor de nuvem

A maioria dos provedores roda um firewall na camada de rede, separado do
`iptables`/`nftables` do seu host. Sintoma: `nc -zv $SERVER_IP $PQ_PORT`
trava silenciosamente, depois sai sem `succeeded` ou `refused`. Abra a
porta no console web do provedor.

### Atrás de uma VPN

Se o `CLIENT` roda Mullvad, Tailscale, ProtonVPN, ou qualquer outra VPN, seu
IP de saída não será seu IP residencial. O SERVER verá o nó de saída da
VPN. **Isto não afeta o teste de fumaça** — o CSPQ é ponta a ponta
entre os dois gateways e é independente de qualquer camada de criptografia
intermediária. Significa, contudo, que quaisquer allowlists de IP de origem
que você configurar precisam incluir a faixa de saída da VPN.

---

## Resultados observados — execução de referência

Estes números são de uma execução real entre Caxias do Sul, Brasil
(estação de trabalho) e Frankfurt, Alemanha (IONOS VPS), com o CLIENT
atrás da VPN Mullvad, 2026-05-21.

| Medição | Valor |
|---|---|
| Latência TCP de ida e volta | ~250 ms |
| Handshake PQ médio | 311 ms |
| Handshake mínimo | 299 ms |
| Handshake máximo | 324 ms |
| 10/10 sessões ecoadas corretamente | ✓ |
| `sessions_failed_total` (ao longo da execução) | 1 (timeout `nc` avulso pré-teste) |
| Entradas da cadeia de auditoria da estação | 22 (incluindo 1 sessão pré-teste) |
| Entradas da cadeia de auditoria do VPS | 22 |
| `verify` offline entre hosts corresponde à raiz | ✓ |

Para comparação, o TLS 1.3 clássico pelo mesmo caminho mede cerca de
80–120 ms. O fator de aproximadamente 3× é o custo do ML-KEM + ML-DSA sobre
ECDHE + Ed25519. Ele é pago **uma vez por sessão** e é independente do
tamanho da sessão.

Se você publicar um resultado do seu próprio ambiente, por favor abra um PR
adicionando uma linha à tabela acima. Números reais são bem-vindos.

---

## O que este teste NÃO valida

Divulgação honesta:

- **Assinatura respaldada por HSM.** Este teste usa signatários softkey. Para validar
  o respaldo PKCS#11, veja `docs/HSM.md`.
- **Estabilidade em execução prolongada.** 10 sessões em ~30 segundos não
  exercitam caminhos de vazamento, rotação de logs ou casos limite de rate-limit.
- **Alta concorrência.** Cliente único, sequencial. Execute `wrk` ou
  similar contra `127.0.0.1:$LOCAL_PORT` se você precisar de números de
  throughput.
- **Peers adversariais.** A lógica de rejeição de handshake é exercitada pela
  suíte de integração `crates/qtransport-cspq/tests/`, não por este
  procedimento.

Execute a suíte completa `cargo test --workspace --release --locked` (227+
testes) para cobertura do acima.
