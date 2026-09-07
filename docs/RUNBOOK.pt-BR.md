# Cofre Soberano PQ — Manual operacional

*Runbook operacional (pt-BR). O [RUNBOOK.md](RUNBOOK.md) em inglês prevalece em caso de divergência.*

Implantação em produção, operação diária e resolução de problemas para o
sidecar qgateway. Este documento é o complemento **voltado ao operador**
do `SPEC.md` (que é a especificação de projeto). Se você está implantando
ou executando o gateway em produção, leia isto primeiro.

Para custódia de chaves apoiada em HSM, consulte [HSM.pt-BR.md](HSM.pt-BR.md).


## Verificação de auditoria e acesso ao portal

Execute `qaudit verify --log audit.qa --pk audit.pk` com uma chave cuja
procedência foi confirmada fora do arquivo. `qaudit inspect` apenas exibe o
conteúdo; sua saída não comprova integridade. O XML exportado usa o esquema
próprio do projeto, sem aprovação regulatória.

Guarde fora do host assinante a raiz final, o número de entradas e o inventário
ordenado dos segmentos. Entradas completas removidas do final e versões
antigas válidas exigem esses checkpoints para detecção. Rótulos e datas do
cabeçalho e `appended_at` não são autenticados no wire-v1. O horário de um
evento assinado não substitui uma fonte de tempo confiável.

O portal carrega um retrato somente leitura na inicialização; `/api/verify`
verifica esse retrato. Reinicie-o depois de selecionar um novo arquivo ou uma
cópia consistente do registro. `/healthz` indica apenas que o processo atende
HTTP. O portal não tem autenticação: mantenha o endereço de loopback e use
um túnel SSH ou proxy autenticado para acesso remoto.

```bash
qaudit-portal --log audit.qa --pk audit.pk --listen 127.0.0.1:8080
# Interface em português: http://127.0.0.1:8080/?lang=pt-BR
# Paginação HTML: ?lang=pt-BR&offset=0&limit=50 (máximo 200)
# Paginação JSON: /api/entries?offset=0&limit=100 (máximo 1000)
```

![Portal de auditoria em português](../screenshots/portal-pt-BR.png)

Mantenha **um único escritor por arquivo `.qa`**, incluindo CLIs e daemons.
A substituição atômica protege contra gravações parciais; não implementa
exclusão mútua entre processos. Escritores independentes precisam de
serialização operacional para evitar perda de atualizações.

Antes de `qaudit rotate`, pare o escritor do registro e faça backup dos dois
segmentos. A rotação publica o novo arquivo antes de substituir o antigo;
essas duas gravações não formam uma transação única. Em caso de erro, preserve
ambos os arquivos e verifique o encadeamento antes de retomar a escrita.

---

## 1. Público-alvo e escopo

Este runbook presume que o leitor é um operador de sistemas Linux à vontade
com:

- arquivos de unidade systemd
- configuração TOML
- coleta (scraping) do Prometheus
- leitura da saída de `journalctl -u <unit>`
- execução de daemons não privilegiados com capacidades restritas

Ele **não** presume conhecimento em criptografia. As primitivas pós-quânticas
(ML-KEM-1024, ML-DSA-87, ChaCha20-Poly1305) já vêm embutidas no binário;
os operadores interagem apenas com os arquivos de chave `.skid` / `.cspqid.pub` e
com o artefato de auditoria `.audit.pub`.

---

## 2. Implantação em produção

### 2.1 Distribuição do binário

Cada release publica um bundle binário identificado pela plataforma, um
arquivo-fonte, um SBOM, um manifesto legível por máquina, `SHA256SUMS` e
assinaturas destacadas ML-DSA-87 e Sigstore. O bundle canônico GNU/Linux contém:

```
cofre-soberano-pq-vX.Y.Z-<rust-host-triple>/
├── bin/
│   ├── qaudit
│   ├── qaudit-portal
│   ├── qgateway              # build padrão do gateway
│   └── qgateway-pkcs11       # gateway compilado com a feature pkcs11
├── docs/
│   ├── RUNBOOK.md / RUNBOOK.pt-BR.md
│   ├── HSM.md / HSM.pt-BR.md
│   └── SMOKE_TEST.md / SMOKE_TEST.pt-BR.md
├── README.md / README.pt-BR.md
├── LICENSE-AGPL
├── LICENSE-COMMERCIAL
├── NOTICE
├── SPEC.md
└── systemd/
    └── qgateway.service      # reference unit file
```

Antes de extrair ou instalar, verifique cada arquivo baixado contra
`SHA256SUMS` e depois verifique as duas famílias de assinatura destacada com as
chaves públicas previamente confiáveis. As âncoras do projeto estão em
[`release-keys/`](../release-keys/); confirme seus fingerprints por um canal
independente no primeiro uso. Chaves baixadas ao lado do próprio artefato
não estabelecem, sozinhas, sua autenticidade. Confirme
que `release-manifest.json` registra a versão, o commit, o toolchain Rust
1.95.0, o target triple, as features de build, tamanhos e hashes esperados. O
SBOM CycloneDX é `cofre-soberano-pq-vX.Y.Z.cdx.json`. Não instale um artefato
se um hash ou assinatura falhar; checksums, sozinhos, não autenticam uma
release.

Para verificar uma assinatura com OpenSSL 3.5+ (ML-DSA) e Cosign 3.1.3,
ajuste o caminho das âncoras já confiáveis e execute no diretório dos downloads.
Comece por `SHA256SUMS`; repita as duas verificações para cada bundle, arquivo
fonte, SBOM e manifesto antes de instalar.

```bash
COFRE_KEYS=/path/to/trusted/release-keys
COFRE_ASSET=SHA256SUMS
openssl pkeyutl -verify -pubin \
  -inkey "$COFRE_KEYS/release-mldsa87-public.pem" \
  -in "$COFRE_ASSET" -sigfile "$COFRE_ASSET.mldsa87.sig" \
  -pkeyopt context-string:cofre-soberano-pq-release-v1
cosign verify-blob --key "$COFRE_KEYS/release-sigstore-public.pem" \
  --bundle "$COFRE_ASSET.sigstore.json" "$COFRE_ASSET"
sha256sum -c SHA256SUMS
```

O complemento v1.0.3 para FreeBSD 14.4 amd64 contém `qaudit`, `qaudit-portal`
e `qgateway` com PKCS#11 habilitado. Verifique `SHA256SUMS.freebsd` e o arquivo
FreeBSD com os mesmos dois comandos de assinatura acima, ajustando
`COFRE_ASSET` para cada nome. No FreeBSD, confira o digest com o
[utilitário sha256 nativo](https://man.freebsd.org/cgi/man.cgi?query=sha256&sektion=1):

```sh
read -r COFRE_EXPECTED COFRE_ARCHIVE < SHA256SUMS.freebsd
sha256 -c "$COFRE_EXPECTED" "$COFRE_ARCHIVE"
```

O `native-build-metadata.json` incluído registra
Rust 1.97.1 e 278 testes nativos aprovados; o manifesto e o SBOM originais
descrevem o build GNU/Linux. O bundle FreeBSD não inclui arquivos systemd;
os passos de instalação do serviço abaixo se aplicam ao GNU/Linux.

Instale o gateway padrão ou, quando houver necessidade de HSM, instale a
variante PKCS#11 sob o nome operacional `qgateway`:

```bash
# Crie a conta de serviço antes de instalar diretórios com esse proprietário.
id -u qgateway >/dev/null 2>&1 || \
  sudo useradd --system --no-create-home --shell /usr/sbin/nologin qgateway
sudo install -m 0755 bin/qgateway /usr/local/bin/qgateway
# Alternativa para implantação com HSM:
# sudo install -m 0755 bin/qgateway-pkcs11 /usr/local/bin/qgateway
sudo install -m 0644 systemd/qgateway.service /etc/systemd/system/qgateway.service
sudo install -d -o root -g root -m 0755 /etc/qgateway
sudo install -d -o qgateway -g qgateway -m 0750 /var/lib/qgateway
sudo install -d -o qgateway -g qgateway -m 0750 /var/log/qgateway
```

### 2.2 Geração de chaves

Gere a identidade de transporte do daemon (par de chaves ML-DSA-87):

```bash
sudo qgateway keygen \
    --sk /etc/qgateway/daemon.skid \
    --pk /etc/qgateway/daemon.cspqid.pub
sudo chown qgateway:qgateway /etc/qgateway/daemon.skid /etc/qgateway/daemon.cspqid.pub
sudo chmod 0400 /etc/qgateway/daemon.skid
sudo chmod 0444 /etc/qgateway/daemon.cspqid.pub
```

Gere o par de chaves do signatário de auditoria (par de chaves ML-DSA-87 separado, usado para
assinar as entradas do registro de auditoria):

```bash
sudo qgateway audit-keygen \
    --sk /etc/qgateway/audit.skid \
    --pk /etc/qgateway/audit.pub
sudo chown qgateway:qgateway /etc/qgateway/audit.skid /etc/qgateway/audit.pub
sudo chmod 0400 /etc/qgateway/audit.skid
sudo chmod 0444 /etc/qgateway/audit.pub
```

**Crítico**: o arquivo `.audit.pub` é o artefato que você publica para os
auditores. É a chave pública contra a qual eles verificam a cadeia
de auditoria. Trate-o como um contrato publicável — uma vez distribuído, você
não pode rotacioná-lo sem quebrar a verificação histórica.

Para assinatura de auditoria apoiada em HSM (recomendado para produção), consulte `HSM.md`.

### 2.3 Diretório de confiança de peers

Para cada tenant que aceita conexões CSPQ, crie um diretório de
chaves públicas de peers confiáveis:

```bash
sudo install -d -o qgateway -g qgateway -m 0750 /etc/qgateway/peers/alice
# Copy the peer's .cspqid.pub file into the directory:
sudo install -m 0444 alice-peer.cspqid.pub /etc/qgateway/peers/alice/
```

Cada arquivo `*.cspqid.pub` no diretório é tratado como um peer confiável.
Um peer que NÃO esteja neste diretório é rejeitado no handshake com
`Error::UntrustedPeer` (comprovado pelo teste de integração §13.39).

### 2.4 Arquivo de configuração

`/etc/qgateway/sidecar.toml` mínimo:

```toml
role = "serve-pq"
identity_key = "/etc/qgateway/daemon.skid"
identity_pub = "/etc/qgateway/daemon.cspqid.pub"
metrics_listen = "127.0.0.1:9100"
tenant_drain_timeout_secs = 10

[audit_signer]
kind = "softkey"
secret_key = "/etc/qgateway/audit.skid"
public_key = "/etc/qgateway/audit.pub"

[[tenants]]
name = "alice"
listen = "0.0.0.0:8443"
backend = "127.0.0.1:8080"
peer_pub_dir = "/etc/qgateway/peers/alice"
audit_log = "/var/log/qgateway/alice.qa"

  [tenants.limits]
  max_concurrent = 1000

  [tenants.limits.rate_limit_per_source]
  capacity = 100
  refill_per_sec = 50
```

O schema é aplicado por `qgateway-core`, e sua evolução está registrada nos
contratos de sprint do SPEC. Valide o arquivo efetivo com
`qgateway validate --config <caminho>`. Principais parâmetros:

| Campo | Propósito | Orientação de produção |
|---|---|---|
| `role` | `serve-pq` ou `serve-tcp` | Um por daemon; misturar papéis exige daemons separados |
| `metrics_listen` | Endpoint de scrape do Prometheus | Vincule ao loopback ou à VLAN de gerência, NUNCA a uma interface pública |
| `tenant_drain_timeout_secs` | Prazo de dreno no SIGTERM | 10s é sensato; menor para reinícios rápidos, maior para sessões de longa duração |
| `tenants.limits.max_concurrent` | Limite de sessões por tenant | Defina com base na capacidade do backend, não na memória do gateway |
| `tenants.limits.rate_limit_per_source` | Token bucket por IP de origem | `capacity` = burst máximo; `refill_per_sec` = regime permanente |
| `[rotation] max_age_secs` | Auto-rotaciona o log quando mais antigo que N segundos | Defina conforme requisito de conformidade (o Bacen tipicamente espera diário) |
| `[rotation] poll_interval_ms` | Frequência com que o monitor de rotação verifica os limiares (Sprint 35) | Padrão 5000ms; menor para prazos apertados |

### 2.5 Unidade systemd

Instale o arquivo revisado `systemd/qgateway.service` do bundle binário como
mostrado na §2.1. O arquivo versionado e empacotado é a referência normativa;
ele inclui o contrato de reload por SIGHUP, ordenação por network-online,
restrições de sistema de arquivos, hardening do processo e limites de
recursos.

Habilitar + iniciar:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now qgateway.service
sudo systemctl status qgateway.service
```

### 2.6 Verificar a implantação

```bash
# 1. Daemon is running
systemctl is-active qgateway.service

# 2. Metrics endpoint responds
curl -s http://127.0.0.1:9100/metrics | head -20

# 3. Listen port is bound
ss -tlnp | grep qgateway

# 4. Audit log was created (header-only at this point)
sudo -u qgateway test -f /var/log/qgateway/alice.qa && echo "audit log ok"

# 5. Audit chain header parses
sudo -u qgateway qaudit verify \
    --log /var/log/qgateway/alice.qa \
    --pk /etc/qgateway/audit.pub
```

Se qualquer um destes falhar, consulte §6 Resolução de problemas.

---

## 3. Operação diária

### 3.1 Contrato de sinais

| Sinal | Efeito | Relevante para auditoria? |
|---|---|---|
| `SIGTERM` | Desligamento gracioso: drena as sessões em andamento por até `tenant_drain_timeout_secs`, esvazia os canais de auditoria, encerra | Sim — todos os eventos de auditoria pendentes são esvaziados |
| `SIGINT` | Igual ao SIGTERM | Sim |
| `SIGHUP` | Recarrega a configuração: ADICIONA novos tenants, REMOVE tenants ausentes, aplica mudanças a quente em `[tenants.limits]` | Sim — não emite eventos de auditoria por si só, mas os tenants recém-adicionados passam a emitir a partir de suas próprias cadeias |
| `SIGUSR1` | Hot-reload de certificado TLS em todos os tenants com TLS habilitado | Não |
| `SIGUSR2` | Rotação do registro de auditoria em todos os tenants. Os arquivos `.qa` atuais são renomeados para o padrão de arquivamento, e uma nova cabeça de cadeia é aberta | Sim — a entrada final no arquivo marca o ponto de rotação |
| `SIGKILL` | **NÃO USE** — ignora o dreno, pode deixar o canal de auditoria no meio de uma escrita | Sim (de forma ruim) — as últimas entradas podem ser perdidas |

### 3.2 Recarregar a configuração (SIGHUP)

Fluxo de trabalho:

1. Edite `/etc/qgateway/sidecar.toml`
2. Valide offline: `qgateway validate --config /path/to/new.toml`
   (Sprint 37). O subcomando `validate` exercita cada etapa falível
   de inicialização (parse da chave de identidade, diretório de peers
   por tenant, arquivos do signatário de auditoria, PEM TLS, capacidade de escrita
   do diretório-pai do registro de auditoria)
   sem vincular sockets de escuta, criar quaisquer arquivos de registro de auditoria nem
   abrir sessões PKCS#11. É seguro executá-lo contra uma
   configuração de produção em um host onde o daemon já está em execução. O código de saída
   é `0` em caso de sucesso com um resumo de uma linha; diferente de zero com uma
   mensagem de erro concreta identificando o campo problemático em
   caso de falha.
3. Recarregue: `sudo systemctl reload qgateway.service` (envia SIGHUP)
4. Verifique: `curl -s http://127.0.0.1:9100/metrics | grep sighup`

Contadores esperados após um recarregamento bem-sucedido:
- `qgateway_sighup_cycles_total` aumenta em 1
- `qgateway_tenants_added_total` aumenta pelo número de novos tenants
- `qgateway_tenants_removed_total` aumenta pelo número de tenants removidos
- `qgateway_sighup_failed_total` **permanece em 0**

Se `sighup_failed_total` incrementar, a configuração foi rejeitada — verifique
`journalctl -u qgateway` para o erro de validação. A configuração anterior
permanece ativa.

**O que o SIGHUP pode e não pode alterar em tempo de execução** (SPEC §13.x):

| Mudança | Aplicação a quente | Requer reinício |
|---|---|---|
| Adicionar um tenant | ✅ | |
| Remover um tenant | ✅ | |
| Alterar `max_concurrent` | ✅ | |
| Alterar `rate_limit_per_source` | ✅ | |
| Alterar o conteúdo de `peer_pub_dir` (arquivos) | ✅ (carregado no próximo handshake) | |
| Alterar o caminho de `audit_log` | | ✅ |
| Alterar `backend` / `peer_pq` | | ✅ |
| Alterar `[audit_signer]` | | ✅ |
| Alterar `role` | | ✅ |
| Adicionar/alterar o bloco `[tls]` em um tenant existente | | ✅ |

Para tenants com mudanças a frio, REMOVER e depois ADICIONAR em dois ciclos de SIGHUP funciona,
mas a antiga janela de limpeza de sessão se aplica.

### 3.3 Rotacionar certificados TLS (SIGUSR1)

Apenas para tenants com TLS habilitado. Substitua os arquivos de cert/chave em disco e então:

```bash
sudo kill -USR1 $(pidof qgateway)
# or via systemctl:
sudo systemctl kill -s USR1 qgateway.service
```

O recarregamento é atômico: novas conexões usam o novo certificado; as sessões em andamento
usam o snapshot sob o qual foram aceitas. Se o recarregamento falhar (certificado
malformado, incompatibilidade entre chave/certificado), o acceptor anterior é retido e o
erro é registrado. Os operadores devem fazer grep no journalctl pela falha.

### 3.4 Rotacionar registros de auditoria (SIGUSR2)

```bash
sudo systemctl kill -s USR2 qgateway.service
```

Para cada tenant:
1. O `<tenant>.qa` atual é renomeado para `<tenant>-<timestamp>.qa` (ou
   o padrão configurado em `[rotation] archive_pattern`)
2. Uma nova cabeça de cadeia é escrita no novo `<tenant>.qa`
3. O arquivo de arquivamento passa a ser somente-leitura e pode ser movido para
   armazenamento de longo prazo (por exemplo, para um object store compatível com S3) para
   retenção de conformidade

A auto-rotação (configurada via `[rotation] max_age_secs` /
`max_bytes` / `max_entries`) faz a mesma coisa automaticamente. A
tarefa de monitoramento verifica a cada `poll_interval_ms` (padrão 5000ms; ajustável
desde o Sprint 35).

**Retenção de auditoria de longo prazo** (seu responsável de conformidade se importa):
- Mova os arquivos `.qa` arquivados para armazenamento imutável em até 24 horas após a
  rotação
- Retenha pelo período que seu regulador exigir (a Resolução Bacen
  4658 tipicamente espera 5 anos para logs relevantes à segurança)
- Verifique cada arquivo imediatamente após a rotação:
  ```bash
  qaudit verify --log <archive>.qa --pk audit.pub
  ```
  Este é o mesmo comando que um auditor executa para validar a cadeia
  criptograficamente; passá-lo em seu pipeline de retenção detecta
  corrupção de armazenamento imediatamente, em vez de cinco anos depois.

### 3.5 Reinício gracioso

```bash
sudo systemctl restart qgateway.service
```

Equivalente a SIGTERM + start. O dreno prossegue por até
`tenant_drain_timeout_secs` (padrão 10s); quaisquer sessões ainda
em andamento após o prazo são descartadas. Os operadores não devem
reiniciar durante janelas críticas para o negócio sem antes observar
`qgateway_sessions_active`:

```bash
curl -s http://127.0.0.1:9100/metrics | grep sessions_active
```

Se sessions_active > 0 e a carga de trabalho é de longa duração (por exemplo,
streaming), defina `tenant_drain_timeout_secs` mais alto ou agende
o reinício para um período de baixa atividade.

---

## 4. Referência de métricas

Faça o scrape de `/metrics` na porta `metrics_listen` configurada. O formato de métricas
é o de exposição do Prometheus; os contadores por tenant carregam um rótulo
`tenant="<name>"`.

### 4.1 Plano de dados por tenant

| Métrica | Tipo | Significado | Limiar de ação |
|---|---|---|---|
| `qgateway_sessions_opened_total` | counter | Handshakes bem-sucedidos acumulados | Tendência; queda súbita → problema no backend |
| `qgateway_sessions_closed_total` | counter | Fechamentos de sessão acumulados (encerramento normal) | Deve acompanhar _opened_total |
| `qgateway_sessions_failed_total` | counter | Falhas de handshake acumuladas | Taxa > 1% → investigar (peer ruim? atacante?) |
| `qgateway_sessions_active` | gauge | Sessões atualmente abertas | Próximo de `max_concurrent` → escalar |
| `qgateway_bytes_c2s_total` | counter | Bytes cliente→servidor após decifragem CSPQ | Planejamento de capacidade |
| `qgateway_bytes_s2c_total` | counter | Bytes servidor→cliente após cifragem CSPQ | Planejamento de capacidade |
| `qgateway_handshake_seconds_bucket` | histogram | Distribuição de latência de handshake | p99 > 500ms → HSM sob carga |

### 4.2 Auditoria por tenant

| Métrica | Tipo | Significado | Limiar de ação |
|---|---|---|---|
| `qgateway_audit_events_total` | counter | Total de eventos escritos na cadeia | Deve acompanhar 2 × sessions_opened (abertura+fechamento) |
| `qgateway_audit_failures_total` | counter | Descartes por backpressure do canal de auditoria | **>0 = perda de dados** — investigar imediatamente |
| `qgateway_audit_rotations_total` | counter | Rotações disparadas (sinal ou automáticas) | Visibilidade operacional |

### 4.3 Admissão por tenant

| Métrica | Tipo | Significado | Limiar de ação |
|---|---|---|---|
| `qgateway_admission_rejected_quota_total` | counter | Sessões rejeitadas por `max_concurrent` | Persistente > 0 → aumentar a cota ou escalar |
| `qgateway_admission_rejected_rate_total` | counter | Sessões rejeitadas por limite de taxa | Pico → tentativa de DoS ou cliente mal configurado |

### 4.4 HSM (se `[audit_signer] kind = "pkcs11"`)

| Métrica | Significado | Limiar de ação |
|---|---|---|
| `qgateway_hsm_sessions_opened_total` | Sessões HSM abertas | Tendência |
| `qgateway_hsm_sessions_failed_total` | Falhas de abertura de sessão HSM | >0 → HSM inacessível, verificar `HSM.md` |
| `qgateway_hsm_sign_ops_total` | Operações de assinatura tentadas | Deve acompanhar audit_events_total |
| `qgateway_hsm_sign_failures_total` | Falhas de assinatura | **>0 = cadeia de auditoria em risco** — investigar imediatamente |

### 4.5 Nível de daemon (sem rótulo de tenant)

| Métrica | Significado | Limiar de ação |
|---|---|---|
| `qgateway_sighup_cycles_total` | Recarregamentos por SIGHUP que passaram na validação | Visibilidade operacional |
| `qgateway_sighup_failed_total` | Recarregamentos por SIGHUP rejeitados na validação | >0 → verificar journalctl, corrigir a configuração |
| `qgateway_tenants_added_total` | Tenants adicionados em tempo de execução | Visibilidade operacional |
| `qgateway_tenants_add_failed_total` | Tentativas de adição de tenant que falharam | >0 → verificar journalctl |
| `qgateway_tenants_removed_total` | Tenants removidos em tempo de execução | Visibilidade operacional |
| `qgateway_tenants_remove_failed_total` | Tentativas de remoção de tenant que falharam | >0 → verificar journalctl |
| `qgateway_limits_hot_applied_total` | Mudanças aplicadas a quente em `[tenants.limits]` | Visibilidade operacional |
| `qgateway_config_changed_hot_total` | Tenants com diffs aplicáveis a quente no último SIGHUP | Visibilidade operacional |
| `qgateway_config_changed_cold_total` | Tenants que exigem reinício por diffs somente-a-frio | >0 → agendar reinício |

### 4.6 Alertas sugeridos

```yaml
# Prometheus alerting rules
groups:
- name: qgateway
  rules:
  - alert: QgatewayAuditFailures
    expr: increase(qgateway_audit_failures_total[5m]) > 0
    for: 1m
    severity: critical
    annotations:
      summary: "Audit channel dropped events on {{ $labels.tenant }}"
      runbook: "RUNBOOK.md §5.1"

  - alert: QgatewayHsmSignFailures
    expr: increase(qgateway_hsm_sign_failures_total[5m]) > 0
    for: 1m
    severity: critical
    annotations:
      summary: "HSM sign operations failing — audit chain at risk"
      runbook: "HSM.md §4"

  - alert: QgatewayHighHandshakeFailureRate
    expr: |
      rate(qgateway_sessions_failed_total[5m])
      / rate(qgateway_sessions_opened_total[5m]) > 0.05
    for: 5m
    severity: warning
    annotations:
      summary: "Handshake failure rate > 5% on {{ $labels.tenant }}"
      runbook: "RUNBOOK.md §6.2"

  - alert: QgatewaySighupRejected
    expr: increase(qgateway_sighup_failed_total[5m]) > 0
    severity: warning
    annotations:
      summary: "Config reload rejected — old config still active"
      runbook: "RUNBOOK.md §6.3"

  - alert: QgatewayAdmissionQuotaPersistent
    expr: rate(qgateway_admission_rejected_quota_total[10m]) > 0
    for: 10m
    severity: warning
    annotations:
      summary: "Persistent admission rejections on {{ $labels.tenant }} — raise max_concurrent or scale"
```

---

## 5. Conformidade e manuseio da cadeia de auditoria

### 5.1 O que a cadeia de auditoria prova

O arquivo `.qa` de cada tenant é um **registro sequencial de eventos assinado
criptograficamente** onde:

1. Cada entrada contém: timestamp, ator, ação, recurso, metadados
   opcionais e uma assinatura ML-DSA-87
2. A entrada de assinatura de cada entrada inclui o **hash da entrada
   anterior** — qualquer adulteração de uma entrada quebra a cadeia daquele
   ponto em diante
3. A cabeça da cadeia carrega a chave pública de auditoria do daemon, de modo que um
   auditor que recebe o arquivo fora de banda pode verificar sem segredos
   compartilhados além de `audit.pub`

Isso significa que um auditor pode responder **"prove que exatamente esta sequência de
sessões ocorreu"** sem confiar na sua infraestrutura.

### 5.2 Verificação externa

Para verificar uma cadeia offline (o fluxo de trabalho do auditor):

```bash
# Verify against the public key embedded in the chain header
qaudit verify --log /path/to/alice.qa

# Verify against an externally-provided public key (the auditor's
# preferred mode — proves the chain header's pubkey matches the
# pubkey you published)
qaudit verify \
    --log /path/to/alice.qa \
    --pk /path/to/audit.pub
```

Os testes de integração do Sprint 26 + Sprint 30 provam que a cadeia sobrevive
a ciclos de SIGHUP, tráfego de sessão e verificação externa de chave pública
de ponta a ponta dentro do daemon em execução. Consulte SPEC §13.34 e §13.38.

### 5.3 Pipeline de retenção de longo prazo

Fluxo de trabalho sugerido:

1. O daemon auto-rotaciona diariamente (via `[rotation] max_age_secs = 86400`)
   ou por limiar de tamanho
2. Um processo separado (cron, timer do systemd) coleta os arquivos `.qa`
   arquivados de `/var/log/qgateway/` e:
   - Executa `qaudit verify` em cada um (detecta corrupção de armazenamento
     imediatamente)
   - Envia para armazenamento de objetos imutável (S3 Object Lock, MinIO com
     modo de conformidade, etc.)
   - Registra o SHA-256 de cada arquivo em um ledger separado para
     inventário à prova de adulteração
3. Os arquivos locais são excluídos após o upload + verificação serem confirmados
4. O período de retenção no armazenamento imutável corresponde ao requisito do
   seu regulador

### 5.4 Mapeamento Bacen / LGPD

O Cofre Soberano PQ fornece blocos de construção que mapeiam para requisitos
regulatórios brasileiros, mas NÃO constitui conformidade por si só.
O mapeamento completo está fora do escopo deste runbook. Pontos principais:

- **Resolução Bacen 4658/2018** (cibersegurança): a cadeia de auditoria
  satisfaz o requisito de "registro e análise de incidentes de segurança"
  do §IV, desde que seja retida e disponibilizada aos examinadores do BCB
- **LGPD (Lei 13.709/2018)**: a cadeia registra o "ator" (a identidade do peer
  CSPQ) e a "ação" (session.open / session.close); se dados
  pessoais fluem pelo backend proxiado, aplicam-se obrigações adicionais de
  controlador de dados que este gateway não
  aborda
- **Prontidão pós-quântica**: ML-KEM-1024 (FIPS 203) e ML-DSA-87
  (FIPS 204) são algoritmos padronizados pelo NIST, adequados para
  os requisitos de agilidade criptográfica antecipados pelo Bacen

Um documento formal de mapeamento de conformidade é um entregável do Sprint 36+
quando chegarem requisitos concretos de PoC bancária.

---

## 6. Resolução de problemas

### 6.1 Pico de falhas de auditoria (`qgateway_audit_failures_total > 0`)

**O que significa**: o buffer limitado do canal de auditoria transbordou.
O canal descarta a entrada pendente MAIS ANTIGA em caso de backpressure (SPEC
§7.x) — isto é perda de dados para conformidade.

**Causas**:
- Disco cheio ou lento (o escritor de auditoria não consegue fazer fsync rápido o suficiente)
- HSM sob carga (se signatário PKCS#11) — cada evento precisa de uma operação de assinatura
- Rajada patológica de eventos (raro; exigiria >10 K eventos/seg)

**Remédio**:
1. Verifique o disco: `df -h /var/log/qgateway`
2. Verifique a latência de fsync: `iostat -x 1` — procure por `await` alto no
   disco de auditoria
3. Se apoiado em HSM: `curl -s :9100/metrics | grep hsm_sign` — latência
   p99 da operação de assinatura
4. Se sustentado: investigue a origem da rajada de eventos (volume de tráfego
   do proxy, verbosidade dos eventos de auditoria)

### 6.2 Alta taxa de falhas de handshake

**Causas** (ordenadas por probabilidade):
- Um cliente está mal configurado com a identidade CSPQ errada (rejeição de
  peer não confiável — comprovado pelo teste de integração do Sprint 31)
- Um port scanner está atingindo o listener (comprovado pelo Sprint 32:
  o daemon sobrevive, o contador incrementa, nenhum evento de auditoria vaza)
- As identidades dos clientes legítimos não estão em `peer_pub_dir`

**Diagnosticar**:
```bash
journalctl -u qgateway --since "5 minutes ago" | grep -i "handshake\|untrusted"
```

Se o erro for `UntrustedPeer { peer_id: <hex> }`, a identidade do dialer
não está em `peer_pub_dir`. Ou adicione-a (se legítima) ou
ignore (se atacante).

### 6.3 Recarregamento por SIGHUP rejeitado

**Sintoma**: `qgateway_sighup_failed_total` incrementou, a configuração antiga
ainda ativa.

**Diagnosticar**:
```bash
journalctl -u qgateway --since "1 minute ago" | grep -i "config\|sighup"
```

A mensagem de erro identifica o campo problemático. Causas comuns:
- Colisão de nome de tenant (dois blocos `[[tenants]]` com o mesmo nome)
- `peer_pub_dir` ausente (o caminho não existe)
- Endereço `listen` inválido (porta já em uso)
- Incompatibilidade entre certificado TLS e chave

**Remédio**: corrija o arquivo de configuração e faça SIGHUP novamente. O daemon retém
a configuração funcional anterior, de modo que o gateway continua atendendo.

### 6.4 Tenant adicionado em tempo de execução não se comporta corretamente

**Contexto**: Os Sprints 27 e 28 capturaram dois bugs de produção onde
tenants adicionados em tempo de execução (via SIGHUP ADD) não eram totalmente conectados
aos pipelines de rotação e auto-rotação. Ambos foram corrigidos. Se você
observar um tenant adicionado em tempo de execução cujo registro de auditoria nunca rotaciona:

1. Confirme que o daemon foi compilado a partir de um release com tag em ou após
   a v1.0 (que inclui os Sprints 27 + 28)
2. `curl -s :9100/metrics | grep rotation` — confirme que
   `qgateway_audit_rotations_total{tenant="<new>"}` está sendo emitido
3. Se ainda ausente, abra um relatório de bug com:
   - Histórico de ciclos de SIGHUP
   - Diff de configuração no momento do ADD
   - Tamanho do arquivo `.qa` do tenant adicionado em tempo de execução + último mtime

### 6.5 Sessões reportadas como ativas muito depois de os clientes desconectarem

**Sintoma**: `qgateway_sessions_active{tenant=...}` mostra um número
grande, mas nenhum tráfego flui.

**Causas**:
- O backend nunca fecha o seu lado do proxy (TCP de longa duração)
- O keepalive TCP não está disparando porque `net.ipv4.tcp_keepalive_time`
  está alto demais (padrão 7200s no Linux)
- Uma sessão travada no loop do proxy (raro; indicaria um bug do
  daemon)

**Remédio**:
- Reduza o keepalive do kernel: `sysctl net.ipv4.tcp_keepalive_time=300`
- Ajuste o protocolo de aplicação para fechar as sessões de forma limpa
- Se você suspeitar de um bug do daemon, capture: PID, `/proc/<pid>/stack`
  via `cat /proc/<pid>/task/*/stack`, saída do journal, e abra uma
  issue

### 6.6 Erros de PKCS#11 / HSM

Consulte `HSM.md` §4 para resolução de problemas específica de HSM.

### 6.7 Loop de reinício

`sudo systemctl status qgateway.service` mostra `failed (Result: exit-code)` e `Restart=on-failure` continua re-disparando.

**Diagnosticar**: `journalctl -u qgateway --since "5 minutes ago" -p err`

Causas comuns:
- Arquivo de configuração ilegível (permissões)
- Porta de escuta já em uso
- Caminho do registro de auditoria sem permissão de escrita
- Arquivo de chave de identidade/auditoria ausente ou corrompido (os magic bytes não correspondem)

Interrompa o loop de reinício enquanto diagnostica:
```bash
sudo systemctl stop qgateway.service
# fix the issue
sudo systemctl start qgateway.service
```

---

## 7. Procedimento de atualização

O Cofre Soberano PQ NÃO suporta atualização online entre versões
principais. O procedimento para um salto de versão principal:

1. Prepare o novo binário em `/usr/local/bin/qgateway.new`
2. Drene: `sudo systemctl stop qgateway.service` (ou aguarde uma
   janela de manutenção)
3. Troque: `sudo mv /usr/local/bin/qgateway.new /usr/local/bin/qgateway`
4. Reinicie: `sudo systemctl start qgateway.service`
5. Verifique: §2.6

Para saltos compatíveis dentro da mesma versão principal (por exemplo, da
release atual para a próxima release patch),
o mesmo procedimento funciona, mas o tempo de indisponibilidade é menor. O protocolo de fio
(CSPQ v1) é estável ao longo da linha v1.x.

**Migração para um futuro CSPQ v2** (planejado para 2028, conforme SPEC §16): NÃO
é retrocompatível no nível do fio. Uma implantação mista v1↔v2 está
fora do escopo para a v1.x.

---

## 8. Extras de observabilidade

### 8.1 Intervalo de scrape do Prometheus recomendado

15 segundos. Os contadores de nível de sessão (`sessions_opened`, etc.)
incrementam com frequência suficiente para que 60s percam fidelidade; os gauges
por tenant (`sessions_active`) são de amostragem e retenção (sample-and-hold), então intervalos mais longos
perdem transientes.

### 8.2 Painéis de dashboard Grafana recomendados

(Um JSON de dashboard de referência ainda não é fornecido; planejado para o Sprint 36+
se a demanda dos operadores justificar.)

Layout sugerido:

- **Linha 1: Capacidade** — `sessions_active` por tenant (linha), taxa de `bytes_c2s + bytes_s2c` (linha)
- **Linha 2: Qualidade** — handshake p50/p95/p99 (heatmap), taxa de `sessions_failed` (linha)
- **Linha 3: Conformidade** — taxa de `audit_events`, `audit_failures` (elegível a alerta), `audit_rotations` (linhas verticais)
- **Linha 4: Operações** — `sighup_cycles_total` (degrau por dia), `tenants_added/removed` (eventos)
- **Linha 5 (se HSM)** — taxa de `hsm_sign` + falhas, latência p99 do HSM

### 8.3 Agregação de logs

O daemon escreve logs estruturados no stderr via `tracing`. Configuração comum
de produção:

- o systemd captura o stderr para o journal
- Fluentd / Vector / Loki Promtail fazem scrape do journal
- A retenção de armazenamento de log de longo prazo deve corresponder à retenção da cadeia de auditoria
  (5 anos para contextos Bacen)

Campos sensíveis (hashes de identidade de peer, IPs de origem) SÃO registrados. Se
o seu contexto de conformidade restringe o log de IPs (por exemplo, implantações
sensíveis à LGPD), use `RUST_LOG=qgateway=warn` para reduzir a verbosidade.

---

## 9. Resposta a incidentes

Se você suspeitar de um incidente de segurança (chave comprometida, acesso não
autorizado, adulteração da cadeia de auditoria):

1. **Não exclua os arquivos de registro de auditoria.** Eles são evidência.
2. **Não pare o daemon abruptamente**, a menos que a ameaça esteja ativa.
   Um SIGTERM limpo esvazia os eventos pendentes; o SIGKILL pode perdê-los.
3. **Preserve um snapshot** de `/var/log/qgateway/` imediatamente:
   ```bash
   sudo tar -czf /tmp/audit-snapshot-$(date +%Y%m%dT%H%M%S).tar.gz \
       /var/log/qgateway/ /etc/qgateway/audit.pub
   ```
4. **Verifique as cadeias** para detectar adulteração:
   ```bash
   for f in /var/log/qgateway/*.qa; do
       qaudit verify --log "$f" --pk /etc/qgateway/audit.pub
   done
   ```
   Um resultado de `verify failed` em uma cadeia previamente válida é forte
   evidência de adulteração.
5. **Se houver suspeita de que a chave do signatário de auditoria foi comprometida**: todo o
   histórico da cadeia assinado por essa chave é suspeito. Gere um novo
   `audit.skid` / `audit.pub`, reinicie o daemon com as novas chaves,
   e documente o timestamp da rotação. As cadeias históricas permanecem
   verificáveis contra a `audit.pub` antiga, mas o timestamp de corte
   precisa ser registrado no seu relatório de incidente.

---

## 10. Onde este runbook está incompleto

Lista honesta de lacunas para o lançamento da v1.0:

- **Sem JSON de dashboard Grafana de referência.** Painéis sugeridos em §8.2.
- **Sem documento formal de mapeamento de conformidade Bacen / LGPD.** Orientação principal em §5.4.
- **Sem procedimento de backup / recuperação de desastres.** Implícito: os arquivos `.skid` são os segredos insubstituíveis; faça backup deles offline (implantações apoiadas em HSM empurram isso para o HSM).
- **Sem guia de implantação Kubernetes / containerizada.** O `Dockerfile` no repositório é um ponto de partida; um Helm chart seria Sprint 38+ se a demanda dos operadores justificar.

Essas lacunas são documentadas honestamente para que as equipes de implantação saibam o que está
pronto para produção e o que está pendente.
