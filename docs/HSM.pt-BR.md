# Cofre Soberano PQ — Integração HSM PKCS#11

*Guia de HSM (pt-BR). O [HSM.md](HSM.md) em inglês prevalece em caso de divergência.*

Suporte por módulo de segurança de hardware (HSM) para o assinador de
auditoria. Implantações em produção em setores regulados (bancos
brasileiros, governo) normalmente exigem que as chaves de assinatura
nunca deixem uma fronteira de hardware certificada; este documento
percorre a configuração e a postura operacional para esse caminho.

Para implantações sem HSM, o assinador `softkey` (chave secreta
ML-DSA-87 baseada em arquivo) está documentado em `RUNBOOK.md` §2.2.

---

## 1. Por que assinatura de auditoria respaldada por HSM

A cadeia de auditoria é o artefato de conformidade. Se um atacante
obtiver a chave de assinatura de auditoria, ele pode:

- Gerar entradas forjadas indistinguíveis das legítimas
- Retroagir a data da cadeia para fazer sua atividade parecer
  consistente com o estado de auditoria anterior ao incidente
- Convencer um regulador de que o gateway registrou uma sequência de
  eventos que na verdade nunca ocorreu

Colocar a chave em um HSM significa:

- Mesmo com acesso root total ao host do gateway, o atacante não
  consegue exfiltrar os bytes da chave
- Toda operação de assinatura deixa uma trilha de auditoria no próprio
  HSM (independente da cadeia que está assinando)
- Auditores de conformidade obtêm uma atestação de hardware de que a
  chave de assinatura está restrita à fronteira certificada do HSM

O trade-off: uma chamada de assinatura agora exige uma ida e volta ao
HSM (tipicamente pela rede — mesmo HSMs PCIe locais serializam por meio
de um único handle de dispositivo). O trabalho de intervalo de polling
do Sprint 35 e o escritor de auditoria em lote do daemon mitigam o custo
de latência, mas implantações de alto throughput devem fazer benchmark.

---

## 2. Implementações PKCS#11 suportadas

O Cofre Soberano PQ depende de `qaudit-hsm` (crate do workspace) com a
feature `pkcs11`. A implementação é genérica entre fornecedores que
suportam ML-DSA-87 por meio de um mecanismo PKCS#11 definido pelo
fornecedor — este é o estado do padrão na v1.0.

Testado:

| HSM | Status | Notas |
|---|---|---|
| **SoftHSM2** | ✅ Testado em lib | Usado pela CI do qaudit-hsm. ML-DSA-87 emulado em software; não certificado. Útil para dev + CI. |
| **YubiHSM2** (firmware 2.4+) | 🟡 Não testado | Suporte a ML-DSA anunciado; verificação prevista para o Sprint 36+ quando o hardware estiver disponível. |
| **Thales Luna** | 🟡 Não testado | Dependente de firmware; consulte o fornecedor sobre a disponibilidade do mecanismo ML-DSA. |
| **Utimaco SecurityServer** | 🟡 Não testado | Mesma ressalva. |

O mecanismo ML-DSA do padrão PKCS#11 está em fluxo em 2026. Fornecedores
entregam sob diferentes IDs de mecanismo (tipicamente
`CKM_VENDOR_DEFINED + N`). O campo de configuração `mechanism_id`
permite que operadores fixem o ID exato que seu HSM usa sem recompilar.

Se o seu HSM ainda não expõe ML-DSA-87 na camada PKCS#11, o fallback de
softkey é honesto: entregue com chaves baseadas em arquivo com
permissões restritivas (0400, em um sistema de arquivos criptografado se
o seu modelo de ameaças justificar) até que o suporte do fornecedor de
HSM se atualize.

---

## 3. Configuração

### 3.1 Provisionamento da chave do HSM

O par de chaves de assinatura de auditoria deve ser gerado **no HSM**,
não importado. Importar anula o propósito da custódia em HSM (a chave
secreta transitou por um host onde poderia ter sido registrada ou
copiada em backup).

Comandos específicos do fornecedor; exemplo com SoftHSM2 (apenas para
desenvolvimento — não para produção):

```bash
# Initialize a SoftHSM2 token
softhsm2-util --init-token --slot 0 --label "qgateway-audit" \
    --so-pin 1234 --pin 5678

# Generate the ML-DSA-87 keypair via the vendor's tooling.
# SoftHSM2 doesn't natively support ML-DSA at the CLI as of writing;
# use the qaudit-hsm-tool helper (shipped in v1.1+) or vendor SDK.
qaudit-hsm-tool keygen-on-hsm \
    --module /usr/lib/softhsm/libsofthsm2.so \
    --slot 0 \
    --pin 5678 \
    --label "audit-2026"
```

Após o provisionamento, exporte o blob da chave pública para
distribuição aos auditores:

```bash
qaudit-hsm-tool export-pubkey \
    --module /usr/lib/softhsm/libsofthsm2.so \
    --slot 0 \
    --pin-env QGATEWAY_HSM_PIN \
    --label "audit-2026" \
    --out /etc/qgateway/audit.pub
```

O `.audit.pub` exportado tem o mesmo formato de arquivo que o
`.audit.pub` do caminho softkey — auditores verificam da mesma forma
independentemente de o assinador ter sido softkey ou HSM.

### 3.2 Configuração do daemon

`/etc/qgateway/sidecar.toml`, substituindo o bloco `[audit_signer]`:

```toml
[audit_signer]
kind         = "pkcs11"
module       = "/usr/lib/softhsm/libsofthsm2.so"
slot         = 0
pin_env      = "QGATEWAY_HSM_PIN"
key_label    = "audit-2026"
# Optional: separate label if the HSM stores pub and priv distinctly
# pub_label  = "audit-2026-pub"
# Optional: pin the vendor's mechanism ID (defaults to a sensible
# value if your HSM uses a standard ID)
# mechanism_id = 0x80000123
```

### 3.3 Tratamento do PIN

O PIN **nunca** fica no arquivo de configuração. O campo `pin_env`
nomeia uma variável de ambiente da qual o daemon lê o PIN na
inicialização (e após cada SIGHUP que toca o bloco do assinador).

Para o systemd:

```ini
[Service]
EnvironmentFile=/etc/qgateway/hsm.env
```

Onde `/etc/qgateway/hsm.env` (modo 0400, de propriedade de `qgateway`)
contém:

```
QGATEWAY_HSM_PIN=your_actual_pin_here
```

A diretiva `EnvironmentFile` do systemd garante que o PIN seja carregado
no ambiente de processo do daemon, mas não no arquivo de unidade (que
pode ser legível por outros usuários). Operadores NÃO devem passar o PIN
via shell ou pela diretiva `Environment=` do systemd — ambos vazam via
`ps -e` ou `/proc/<pid>/environ` (embora este último normalmente seja
restrito por padrão).

Para chaves PED fornecidas pelo HSM ou desbloqueio por smart-card
(Thales Luna PED) — o mecanismo `pin_env` é ignorado; o operador
autentica o HSM fora de banda antes de iniciar o daemon. O campo pin_env,
neste caso, contém um nome de variável fictício; o que importa é que a
sessão PKCS#11 do daemon herde o estado já autenticado do HSM.

### 3.4 Verifique se o daemon conectou-se ao HSM

Após iniciar:

```bash
curl -s http://127.0.0.1:9100/metrics | grep hsm_

# Expected output (counters at 0 initially, will increment with traffic).
# Every metric carries a per-tenant `tenant="<name>"` label — the exporter
# emits one line per tenant registry:
qgateway_hsm_sessions_opened_total{tenant="alice"} 1
qgateway_hsm_sessions_failed_total{tenant="alice"} 0
qgateway_hsm_sign_ops_total{tenant="alice"} 0
qgateway_hsm_sign_failures_total{tenant="alice"} 0
```

`hsm_sessions_opened_total = 1` confirma que o daemon abriu sua sessão
PKCS#11 na inicialização. `hsm_sessions_failed_total > 0` indica um
problema de conexão — veja §4.

---

## 4. Solução de problemas

### 4.1 `hsm_sessions_failed_total` > 0 na inicialização

Causas comuns (verifique o journal):

| Fragmento de erro | Causa |
|---|---|
| `CKR_TOKEN_NOT_PRESENT` | Número de `slot` incorreto, ou o HSM está desconectado |
| `CKR_PIN_INCORRECT` | PIN incorreto na variável de ambiente `QGATEWAY_HSM_PIN` |
| `CKR_USER_PIN_LOCKED` | Tentativas de PIN falhas em excesso; o administrador do HSM deve desbloquear |
| `CKR_KEY_HANDLE_INVALID` | `key_label` não corresponde a nenhuma chave no HSM |
| `CKR_MECHANISM_INVALID` | `mechanism_id` não suportado por este firmware do HSM |
| Biblioteca não encontrada | O caminho `module` está incorreto |

Diagnostique tentando a ferramenta CLI do fornecedor com os mesmos
parâmetros antes de suspeitar do qgateway. `pkcs11-tool` (do OpenSC):

```bash
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --list-slots
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --slot 0 \
    --list-objects --pin 5678
```

### 4.2 `hsm_sign_failures_total` incrementa sob carga

O daemon falhou em assinar um ou mais eventos de auditoria. **Este é um
incidente crítico** — a integridade da cadeia de auditoria pode estar em
risco.

Causas prováveis:

- **Timeout de sessão do HSM**: alguns HSMs encerram sessões ociosas
  após N minutos de inatividade. A camada de gerenciamento de sessões do
  daemon (qaudit-hsm) reabre em `CKR_SESSION_CLOSED`, mas uma rajada de
  eventos chegando durante a reconexão pode falhar. Mitigação:
  configure o HSM para um tempo de vida de sessão maior, ou envie uma
  operação de assinatura de heartbeat via cron.
- **HSM sob carga**: HSM compartilhado entre múltiplas aplicações;
  a fila de operações de assinatura está saturada. Mitigação: slot
  dedicado ou escalar o HSM.
- **Bug de firmware do HSM**: raro, mas observado em implementações
  iniciais de ML-DSA de fornecedores. Mitigação: abra um chamado com o
  fornecedor; considere o fallback de softkey temporariamente se o
  regulador permitir.

Se `hsm_sign_failures_total > 0` for sustentado:

1. Acione imediatamente o operador de plantão (o alerta do Prometheus em
   `RUNBOOK.md` §4.6 detecta isso)
2. Determine se a cadeia ainda verifica:
   ```bash
   qaudit verify --log /var/log/qgateway/<tenant>.qa \
       --pk /etc/qgateway/audit.pub
   ```
3. Se a verificação falhar, a cadeia tem uma lacuna — inicie a resposta
   a incidentes conforme `RUNBOOK.md` §9

O daemon NÃO ignora silenciosamente operações de assinatura falhas. Uma
falha de assinatura faz o canal de auditoria registrar a falha no
contador `hsm_sign_failures_total` E descartar o evento (em vez de
inserir uma entrada não assinada que invalidaria a cadeia). Este é um
trade-off deliberado: a cadeia permanece criptograficamente válida mas
os operadores devem detectar falhas via métricas.

### 4.3 Latência p99 do handshake aumentou após habilitar o HSM

Cada session.open + session.close emite um evento de auditoria, o que
significa duas operações de assinatura no HSM por sessão. Se o HSM for o
gargalo:

1. Meça: `curl -s :9100/metrics | grep hsm_sign`
2. Calcule a taxa de operações de assinatura: `rate(qgateway_hsm_sign_ops_total[5m])`
3. Compare com a especificação do fornecedor do HSM (operações de assinatura/s)

Se a taxa estiver próxima da especificação do HSM, considere:

- Agrupar múltiplos eventos de auditoria por assinatura (AINDA NÃO
  IMPLEMENTADO; trabalho do Sprint 36+)
- Atualizar o hardware do HSM
- Usar um assinador softkey para tenants não críticos e o HSM apenas
  para tenants críticos de conformidade (cada tenant tem seu próprio
  assinador de auditoria na v1.1+ — atualmente o assinador é global do
  daemon)

### 4.4 Rotação da chave do HSM

Se uma chave precisar de rotação (suspeita de comprometimento, rotação
agendada conforme política organizacional, ou atualização de firmware do
HSM que exija regeneração):

1. Gere um novo par de chaves no HSM com um novo label
   (ex.: `audit-2027`)
2. Exporte a nova chave pública para um novo caminho
   (ex.: `/etc/qgateway/audit-2027.pub`)
3. Distribua a nova chave pública aos auditores fora de banda; marque o
   timestamp de cutover
4. Dispare SIGUSR2 (rotação do registro de auditoria) — as cadeias
   atuais são fechadas sob a chave antiga; novas cadeias começam sob o
   que o daemon conhece no momento
5. Edite a configuração: altere `key_label` para o novo label, altere o
   caminho da chave pública exportada
6. SIGHUP — o daemon adota a nova chave (o assinador de auditoria é um
   dos campos de reinício a frio; o SIGHUP atualmente falha nisso. A
   rotação real de chave exige um reinício completo: `systemctl restart`
   após a conclusão da rotação por SIGUSR2)

Cadeias históricas assinadas pela chave ANTIGA permanecem verificáveis
contra o `.audit.pub` antigo. O timestamp de cutover + o par de chaves
públicas antiga/nova devem ser mantidos no seu livro-razão de
conformidade para que os auditores possam verificar o período histórico
correto contra a chave correta.

---

## 5. Limitações honestas e roadmap

### 5.1 Contra o que a custódia em HSM NÃO protege

- **Injeção de código na camada de aplicação** que roda no processo do
  daemon ainda pode chamar o HSM (o HSM só enxerga requisições de
  assinatura autenticadas; não consegue distinguir se a requisição veio
  do fluxo legítimo de eventos de auditoria ou de código injetado).
  Mitigação: a postura `#![forbid(unsafe_code)]` do daemon + superfície
  mínima de dependências + builds reproduzíveis. Mas, em última análise:
  defesa em profundidade, não uma solução mágica.
- **Ataque físico ao próprio HSM**. A maioria dos HSMs é certificada
  FIPS 140-2 / 140-3 Nível 3 para evidência de adulteração, mas
  adversários determinados de nível estatal com acesso físico prolongado
  já derrotaram historicamente até módulos de alta garantia. Fora do
  escopo deste gateway; o endurecimento do fornecedor do HSM é a sua
  fronteira.
- **Ataques de canal lateral no host**. Se a biblioteca PKCS#11 do HSM
  tiver canais laterais de temporização no processo do host, um atacante
  observando o processo do host pode extrair informações. As
  implementações de ML-DSA-87 ainda estão amadurecendo nesse aspecto;
  específico do fornecedor.

### 5.2 Itens do roadmap (Sprint 36+ se houver demanda)

- Assinadores de auditoria por tenant (atualmente global do daemon;
  planejado para implantações multi-tenant onde cada tenant tem seu
  próprio slot de HSM)
- Agrupamento de operações de assinatura (assinar N eventos com uma
  única ida e volta ao HSM)
- Consciência de cluster de HSM (failover entre HSMs redundantes)
- Fluxo nativo de atestação de chave (prova criptográfica aos auditores
  de que a chave pública em execução do daemon foi gerada no HSM
  certificado)

### 5.3 Checklist recomendado de endurecimento

Antes de entrar em produção com assinatura de auditoria respaldada por
HSM:

- [ ] O HSM está em um rack separadamente protegido com registro de
      acesso físico
- [ ] As credenciais de administrador do HSM e as credenciais de
      operador estão separadas (pessoas diferentes para `--so-pin` e
      `--pin`)
- [ ] O arquivo `audit.pub` foi distribuído aos auditores e seu SHA-256
      foi registrado no seu livro-razão de conformidade
- [ ] Alertas do Prometheus em `hsm_sign_failures_total` e
      `hsm_sessions_failed_total` estão conectados à escala de plantão
- [ ] Existe um procedimento documentado de failover do HSM (o que
      acontece se o HSM ficar inacessível por 10 minutos durante o
      horário comercial)
- [ ] O arquivo de ambiente do PIN está no modo 0400, de propriedade de
      `qgateway`, e NÃO está no controle de versão nem em snapshots de
      backup que operadores sem acesso ao HSM possam ler
- [ ] Um playbook de incidentes (`RUNBOOK.md` §9) foi revisado e a
      equipe de plantão praticou a etapa de verificação da cadeia de
      auditoria
- [ ] Pelo menos uma rotação de HSM foi praticada em um slot fora de
      produção para validar o procedimento de rotação
