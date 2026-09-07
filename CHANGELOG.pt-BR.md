# Changelog

*Registro de alterações (pt-BR). O [CHANGELOG.md](CHANGELOG.md) em inglês é a referência normativa.*

Todas as alterações relevantes deste projeto serão documentadas neste arquivo.

O formato baseia-se livremente em [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
e este projeto adere ao [Versionamento Semântico](https://semver.org/spec/v2.0.0.html).

O **protocolo de fio** e o **formato de registro de auditoria `.qa`** são governados por um
identificador `suite` explícito em cada cabeçalho de cadeia
(`suite = "cspq-2026"` nesta versão). Qualquer alteração que quebre
a compatibilidade de suite exigirá tanto um incremento de versão maior **quanto** um
novo identificador de suite.

---

## [1.0.3] — 2026-09-06

Atualização de segurança, integridade de release e usabilidade bilíngue.
O protocolo de fio, a codificação `.qa` e a suite criptográfica permanecem
inalterados (`cspq-2026`). Logs malformados, EOF sem autenticação, chaves
ambíguas e operações inseguras em arquivos passam a ser rejeitados.

### Adicionado

- **Portal bilíngue.** Interface em inglês e pt-BR, paginação limitada, layout
  responsivo, estado explícito de snapshot/confiança e cabeçalhos HTTP de
  segurança. Capturas reais usam somente dados sintéticos.
- **Empacotamento para distribuições.** Receitas locais Guix e Nix e geração
  de candidatos a pacotes de release. A inclusão nas distribuições depende
  da revisão de cada projeto e da validação nativa de build.
- **Chaves públicas de release.** Chaves ML-DSA-87 e Sigstore rastreadas;
  material privado permanece fora do repositório. A assinatura usa a
  configuração padrão suportada do Cosign 3.1.3 e bundles verificáveis.
- **Gates canônicos de CI.** `.github/workflows/ci.yml` agora tem como alvo o
  branch real `master` e delega formatação, clippy, testes padrão/release,
  builds PKCS#11, builds de release travados e auditoria de dependências ao
  `scripts/ci.sh`. A validação local e a hospedada exigem o toolchain Rust
  `1.95.0` exato declarado por `rust-toolchain.toml`.
- **Empacotamento determinístico de release.** `scripts/release.sh` compila os
  três executáveis (`qaudit`, `qaudit-portal` e `qgateway`) mais a variante
  `qgateway-pkcs11`, arquivos-fonte e binários Linux determinísticos, um SBOM
  CycloneDX 1.5, `release-manifest.json` e `SHA256SUMS`. A saída candidata é
  explicitamente não publicável; o modo final exige adicionalmente uma tag de
  versão anotada em uma árvore limpa e assinaturas ML-DSA-87 e Sigstore
  verificadas. Referências do SBOM são normalizadas para não expor caminhos
  temporários do build. O script nunca gera nem persiste chaves de assinatura.
- **Serviço systemd rastreado.** `systemd/qgateway.service` fornece o contrato
  de hardening e sinais antes mostrado apenas como exemplo no runbook.

### Corrigido

- **Persistência e falhas de assinatura.** Rejeita entradas CBOR parciais e
  cabeçalhos inválidos; verifica o histórico antes de vinculá-lo ao signatário.
  Falhas de assinatura preservam o estado Merkle. A gravação substitui o
  arquivo atomicamente no mesmo diretório, com sincronização. A rotação mantém
  o estado original em falhas de assinatura ou disco e não sobrescreve
  arquivos de rotação existentes; uma falha na substituição do arquivo ativo
  pode deixar um segmento concluído para reconciliação pelo operador.
- **Truncamento do transporte.** Exige marcador EOF autenticado e preserva
  texto descriptografado pendente, quadros em escrita e estado EOF ao dividir
  o fluxo. Desconexões abruptas deixam de ser tratadas como sessões normais.
- **Chaves e arquivos de saída.** Rejeita caminhos equivalentes e links
  simbólicos, impede sobrescrita de chaves do gateway, verifica correspondência
  do par e tamanho exato dos arquivos, e mantém permissões privadas na CLI.
- **Falhas de HSM.** Oculta o PIN no Debug, limpa sua memória na substituição
  ou descarte da configuração, rejeita rótulos duplicados e verifica localmente
  cada assinatura do hardware antes de devolvê-la ao gravador de auditoria.
- **Auditoria de dependências.** Atualiza quick-xml para 0.41, anyhow para
  1.0.104 e cryptoki para 0.12; migra PEM para rustls-pki-types. Remove
  paste/rustls-pemfile sem manutenção e AWS-LC desnecessário ao selecionar
  explicitamente ring no tokio-rustls. Chaves TLS malformadas agora falham
  na validação.

- **O contêiner qaudit agora compila o workspace real.** O Dockerfile copia
  todos os membros do workspace antes da resolução do Cargo, não descreve mais
  seu binário glibc como musl, remove o exemplo obsoleto `0.1.0` e inclui
  versão/revisão/data de build e metadados corretos de licença dupla na imagem.
  O contexto Docker mínimo exclui dados e chaves de execução; a imagem inclui
  os avisos de licença.
- **A documentação de release e de operação agora corresponde ao repositório.**
  Os documentos em inglês e pt-BR concordam sobre Rust `1.95.0`, nomes das
  chaves geradas, suporte atual a signatário por tenant, `qgateway validate`,
  caminho do serviço rastreado, conteúdo do bundle, verificação de SBOM e
  assinaturas e quais itens da cadeia de suprimentos foram implementados ou
  adiados. Alegações obsoletas sobre sprint, árvore do projeto, versão,
  quantidade de testes e estado do QVault foram removidas ou corrigidas.

### Alterado

- **O escopo da licença dupla está preciso.** A opção AGPL permanece completa
  e inalterada; `LICENSE-COMMERCIAL` é explicitamente um aviso de consulta e
  escopo, não uma concessão de licença. `NOTICE` identifica o escopo autoral
  próprio e preserva a licença de cada dependência. Os metadados do Cargo e do
  contêiner usam a expressão SPDX correspondente sem sugerir direitos
  comerciais que não tenham sido assinados separadamente.

### Compatibilidade de fio / formato

Logs e registros de transporte válidos de `1.0.2` e `1.0.3` mantêm a mesma
codificação. As rejeições mais rigorosas acima são intencionais. Detectar a
remoção de entradas finais completas ainda exige checkpoint externo confiável
de contagem/raiz; rótulos do cabeçalho e timestamps de anexação não são
autenticados pela assinatura v1. Esta revisão de manutenção não é certificação
criptográfica independente. O teste ML-DSA em HSM exige hardware compatível real.

---

## [1.0.2] — 2026-07-15

Versão de precisão de documentação e de reforço do HSM. **Sem alteração no
protocolo de fio, no formato de arquivo `.qa` ou na suite de auditoria** —
`1.0.0` ↔ `1.0.1` ↔ `1.0.2` são totalmente compatíveis em ambos os sentidos,
e implantações com versões mistas permanecem seguras (`suite = "cspq-2026"`).

### Corrigido

- **A busca de chave PKCS#11 agora filtra por `CKA_CLASS`.**
  `find_key_by_label` comparava apenas por `CKA_LABEL` e retornava o primeiro
  objeto encontrado. Como a chave de auditoria privada e a pública podem
  compartilhar um rótulo (`pubkey_label` assume por padrão `key_label`), a
  busca podia retornar o handle da chave pública onde era exigido o handle da
  chave privada, fazendo `C_Sign` falhar. A busca agora restringe a pesquisa
  a `CKO_PRIVATE_KEY` / `CKO_PUBLIC_KEY` conforme apropriado.
  (`crates/qaudit-hsm/src/pkcs11.rs`)

- **O requisito de contexto de assinatura no HSM agora está documentado com
  honestidade.** Um comentário de código afirmava que o contexto de separação
  de domínio do ML-DSA era "aplicado pelo qaudit-core antes de chamar sign()".
  Não é: o contexto (`b"cofre-soberano-pq/qaudit/v1"`) é aplicado *dentro* do
  signatário de software via `try_sign(msg, ctx)` do FIPS-204, então um
  mecanismo de HSM que não vincule o mesmo contexto produz assinaturas que
  falham em `qaudit_core::verify`. O comentário agora declara o requisito de
  paridade e direciona os operadores ao teste `live_hsm_sign_verify` que devem
  executar antes de confiar em um HSM em produção.
  (`crates/qaudit-hsm/src/pkcs11.rs`)

- **Os exemplos de `sidecar.toml` em `docs/SMOKE_TEST.md` agora são
  interpretados.** Os exemplos de cliente e servidor usavam chaves que o
  carregador rejeita (`identity_sk`/`identity_pk`, `audit_sk`/`audit_pk` de
  nível superior, `[[tenant]]`, `peer_dir`). Agora usam o esquema real
  (`identity_key`/`identity_pub`, um bloco `[audit_signer]`, `[[tenants]]`,
  `peer_pub_dir`) e foram verificados com `qgateway validate`.

- **Os documentos de runbook/HSM não referenciam mais um subcomando
  inexistente.** `docs/RUNBOOK.md` e `docs/HSM.md` invocavam `qgateway
  audit-verify --pubkey …`, que não existe. Substituído pelo real
  `qaudit verify --pk …` (que aceita o `.audit.pub` emoldurado produzido por
  `qgateway audit-keygen`).

- **Nomes de métricas e amostras da documentação corrigidos.** O módulo de
  admissão documentava uma métrica inexistente
  `qgateway_admission_rejected_total{reason=…}` — o exportador emite
  `qgateway_admission_rejected_quota_total` e
  `qgateway_admission_rejected_rate_total`, cada uma com um rótulo
  `tenant="…"`. A amostra de métricas do HSM em `docs/HSM.md` estava sem esse
  rótulo `tenant="…"` obrigatório. A documentação do emissor de auditoria
  afirmava que a contrapressão "descarta a mais antiga" — `emit()` usa
  `try_send`, então descarta a mais nova (a que chega) e preserva as já
  enfileiradas. O magic de `.audit.pub` / `.audit.skid` em
  `crates/qgateway-core/src/auditkey.rs` estava documentado como
  `AUDITPK01`/`AUDITSK01`; o magic real de 8 bytes é `AUDITPK0`/`AUDITSK0`. O
  exemplo do portal no `README.md` passava `--pk qaudit.pk`; `qaudit init`
  grava `audit.pk`.

- **Documentação do módulo `qaudit-portal` corrigida.** A doc da crate
  descrevia uma "tabela de entradas paginada", mas a visão HTML renderiza a
  tabela completa (a paginação existe apenas no endpoint JSON
  `/api/entries`); e um comentário de doc `///` órfão estava sendo anexado a
  `main()`.

### Adicionado

- **Documentação em português do Brasil (pt-BR).** Traduções fiéis dos
  documentos principais para o público Brasil-primeiro (Bacen, CVM, ANPD,
  SUSEP): `README.pt-BR.md`, `docs/RUNBOOK.pt-BR.md`, `docs/HSM.pt-BR.md`,
  `docs/SMOKE_TEST.pt-BR.md` e `CHANGELOG.pt-BR.md`. Todo código, comandos,
  chaves de configuração, flags e identificadores de criptografia são
  preservados literalmente; os documentos em inglês permanecem normativos
  para os termos de licenciamento.

### Alterado

- Higiene de clippy: dois blocos `else { if … }` sinalizados por
  `clippy::collapsible_else_if` foram colapsados
  (`crates/qgateway-core/src/gateway.rs`,
  `crates/qgateway-core/src/tls.rs`) e um import de teste não usado sob
  `--features pkcs11` foi removido. Sem alteração de comportamento. O
  workspace está limpo no clippy tanto no conjunto de features padrão quanto
  em `--features qaudit-hsm/pkcs11`.

### Compatibilidade de fio / formato

`1.0.1` ↔ `1.0.2`: **totalmente compatível**. Sem alterações no protocolo de
fio, no formato de arquivo `.qa` ou no identificador de suite de auditoria.

---

## [1.0.1] — 2026-05-22

### Corrigido

- **`qaudit inspect` não entra mais em pânico com broken pipe.** Encanar
  `qaudit inspect` para `head`, `less`, ou qualquer consumidor que fecha sua
  stdin cedo costumava manifestar-se como
  `thread 'main' panicked … failed printing to stdout: Broken pipe`.
  A saída agora passa por um handle de stdout travado e o ponto de entrada
  `main` trata `ErrorKind::BrokenPipe` como uma saída limpa (convenção
  Unix). O código de saída é 0 neste caso.
  (`crates/qaudit/src/main.rs`)

- **Todas as flags `--pk` aceitam tanto o formato de chave pública bruto quanto o emoldurado (framed).**
  A v1.0.0 exigia exatamente 2592 bytes de material bruto de chave pública
  ML-DSA-87 em todos os lugares em que recebia uma flag `--pk` (`qaudit verify`,
  `qaudit verify-chain`, `qaudit-portal`), e rejeitava o formato de 2600 bytes
  produzido por `qgateway audit-keygen` (que prefixa 8 bytes de
  magic `AUDITPK0`). O decodificador agora é compartilhado em `qaudit-core` como a
  função pública `decode_pubkey_any`, usada por todos os três pontos de chamada.
  A autodetecção é feita por comprimento, com o magic verificado no caso
  emoldurado; arquivos espúrios de 2600 bytes sem o prefixo magic são rejeitados
  com um diagnóstico claro. Testes de biblioteca em `qaudit-core` mais testes
  de integração da CLI em `qaudit` cobrem tanto os caminhos felizes quanto ambos
  os caminhos de rejeição. (`crates/qaudit-core/src/signing.rs`,
  `crates/qaudit/src/main.rs`,
  `crates/qaudit-portal/src/main.rs`,
  `crates/qaudit/tests/cli_framed_pubkey.rs`)

- **`qaudit init` não sobrescreve mais silenciosamente as chaves do peer quando executado no
  mesmo diretório.** A v1.0.0 usava como padrão `--sk qaudit.sk` /
  `--pk qaudit.pk` independentemente do argumento `--log`, de modo que duas
  invocações de `init` no mesmo diretório destruíam a chave de assinatura do primeiro
  log sem aviso. Os padrões agora são derivados do nome do arquivo de log:
  `--log /var/audit/tenant-a.qa` produz
  `/var/audit/tenant-a.sk` e `/var/audit/tenant-a.pk`. `--sk` / `--pk`
  explícitos continuam a prevalecer. Três testes de integração foram adicionados
  cobrindo os caminhos de padrão-derivado, sobreposição-explícita e recusa-de-sobrescrita.
  (`crates/qaudit/src/main.rs`,
  `crates/qaudit/tests/cli_init_defaults.rs`)

- **`qaudit append` resolve `--sk` e `--pk` a partir do nome do arquivo de log
  por padrão.** A v1.0.0 fixava `qaudit.sk` e `qaudit.pk` em
  `$PWD`, o que significava que `append` só funcionava quando o operador primeiro
  fazia `cd` para o diretório de chaves e nunca tinha mais de um log naquele
  diretório. A v1.0.1 deriva `<log-stem>.sk` e `<log-stem>.pk` ao lado
  do arquivo de log. Um fallback de compatibilidade com a v1.0.0 para os
  legados `qaudit.sk` / `qaudit.pk` em `$PWD` é preservado para que
  implantações existentes não quebrem na atualização. Quatro testes de integração
  da CLI cobrem padrão-derivado, ausência-de-colisão-entre-logs, fallback legado
  e sobreposição explícita. (`crates/qaudit/src/main.rs`,
  `crates/qaudit/tests/cli_append_defaults.rs`)

### Adicionado

- **`docs/SMOKE_TEST.md`** — procedimento de validação de produção fim-a-fim
  agnóstico ao operador. Dois hosts, internet pública, handshake PQ real,
  cadeia de auditoria verificada em cruzamento. Inclui números de referência de uma
  execução Brasil ↔ Alemanha por um ponto de saída VPN.

- **`CHANGELOG.md`** — este arquivo.

### Alterado

- `README.md` documenta o novo comportamento de derivação de chaves de
  `qaudit init` e vincula o guia de smoke-test.

### Compatibilidade de fio / formato

`1.0.0` ↔ `1.0.1`: **totalmente compatível**. Sem alterações no protocolo de
fio, sem alterações no formato de arquivo `.qa`, sem alterações no
identificador de suite de auditoria. Logs escritos sob a 1.0.0 verificam sob a 1.0.1
e vice-versa. Implantações de versões mistas são seguras.

---

## [1.0.0] — 2026-05-20

Primeiro lançamento público estável. Encerra a sequência de sprints da v0.x; a
partir deste ponto em diante, o semver se aplica.

### Destaques

- **QAudit**: registro de auditoria Merkle assinado com PQ (ML-DSA-87 / FIPS 204 +
  MMR BLAKE3), CLI, biblioteca, assinador plugável a HSM, portal web
  somente-leitura para auditores.
- **QTransport CSPQ**: transporte pós-quântico de referência (ML-KEM-1024 /
  FIPS 203 + ML-DSA-87 + ChaCha20-Poly1305 + HKDF-SHA3-256). Sigilo
  futuro (forward secrecy), autenticação mútua, proteção contra repetição (replay).
- **QGateway**: daemon sidecar de proxy reverso. Coloque-o na frente de qualquer
  serviço TCP; os clientes continuam falando TCP puro localmente, e o gateway
  tunela CSPQ até o peer. Multi-tenant, multi-listener, hot-reload
  via SIGHUP, emissão de auditoria por sessão.
- 227 testes sob `--locked`, zero `unsafe` fora de FFI auditada,
  `cargo clippy -- -D warnings` limpo, build reproduzível via `Cargo.lock`
  e `rust-toolchain.toml` fixados.
- Licença de código-fonte AGPL-3.0-only com uma licença comercial paralela
  disponível para organizações que não podem aceitar os termos da AGPL.

Consulte `SPEC.md` e `docs/RUNBOOK.md` para o detalhe completo de projeto e
operações. Consulte o histórico do git para o changelog por sprint da v0.x.
