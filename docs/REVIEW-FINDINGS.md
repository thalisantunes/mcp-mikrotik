# Achados consolidados — revisão multi-modelo (2026-07-09)

Cinco revisões independentes sobre o alicerce: `ta-reviewer` (geral), e o
local-ultrareview em 4 perspectivas (Arquitetura/Opus, Segurança/Opus,
Performance/Sonnet, Edge Cases/Sonnet).

**Veredito geral: nenhum achado de severidade ALTA.** O write-guard foi
confirmado à prova de bypass por 3 revisores independentes: a allowlist é o
único caminho de escrita, `server.py` nunca chama `update/add/remove` direto,
e `allow_write=false` bloqueia antes de qualquer I/O mesmo com `confirm=true`.
As 5 falhas do fork reprovado estão todas corrigidas.

Abaixo, o que corrigir, priorizado.

## Corrigir ANTES do primeiro teste contra hardware real

| # | Sev | Arquivo:linha | Problema | Correção |
|---|---|---|---|---|
| S1 | Médio (3 revisores) | `config.py:37` | `Device.password` e `Settings` sem `repr=False` → um `logger.debug(settings)` vaza as 14 senhas em stderr | `password: str = field(default="", repr=False)` + repr custom em `Settings` |
| N1 | Normal | `client.py:88` | `path/ping/update/add/remove` só capturam `LibRouterosError`; queda de link no meio (OSError/socket.timeout/SSLError) escapa como "Internal error" opaco, sem nome do device | Capturar `(LibRouterosError, OSError)` e envolver em `DeviceCommandError` |
| E1 | Normal | `config.py:94` | YAML malformado → `yaml.YAMLError` não capturado, crash com traceback cru no startup | `try/except yaml.YAMLError` → `ConfigError` |
| E2 | Normal | `config.py:80` | `port` não-numérico no YAML → `ValueError` não capturado, crash no startup | wrap `int(...)` → `ConfigError` com nome do device |
| SSL1 | Médio (3 revisores) | `client.py:58` | `ssl.create_default_context()` valida contra CA do sistema; RouterOS api-ssl usa cert self-signed → todo `use_ssl:true` falha out-of-the-box | opção por-device `tls_verify` (default true) + caminho de CA/fingerprint; documentar trade-off, não afrouxar por padrão |
| T1 | Médio | `client.py:49-66` | `_connect()`/camada SSL nunca exercitada pelos 62 testes (fakes pulam) → passar não prova nada sobre SSL/erro de transporte | teste com monkeypatch de `librouteros.connect` |

## Robustez do coletor (container 256 MB, poll 14 devices/60s)

| # | Sev | Arquivo:linha | Problema | Correção |
|---|---|---|---|---|
| N2 | Normal | `client.py:136`, `server.py:51` | sem pooling: nova conexão TCP+login a cada tool call | cache de `MikrotikClient` por `device_name` |
| N3 | Normal | `server.py:51` | nenhum `close()`: sockets vazam até GC; RouterOS tem limite de sessões → wedge no container | `try/finally` com `close()` ou pooling com evict no shutdown |
| N4 | Nit | `client.py:31` | `DEFAULT_TIMEOUT=10` hardcoded; links lentos (banner 15-40s) podem estourar | timeout configurável por-device + env default |

## Arquitetura / falsa garantia

| # | Sev | Arquivo:linha | Problema | Correção |
|---|---|---|---|---|
| A1 | Normal | `guard.py:99` | `WriteOperation.action` está na allowlist mas é inerte — `set_identity` hardcoda `.update`; a tabela não governa o dispatch de fato | dispatchar via `getattr(client, op.action)` para a allowlist realmente governar |
| A2 | Reforço | `tests/` | invariante "todo write passa pelo guard" é só convenção; nada no CI impede uma PR futura de chamar `client.update()` direto de `server.py` | teste-meta que faz grep em `server.py` barrando `.update(`/`.add(`/`.remove(` |

## Correção / edge de input

| # | Sev | Arquivo:linha | Problema | Correção |
|---|---|---|---|---|
| E3 | Nit | `config.py:78` | `name:` numérico no YAML vira int key → device inalcançável ("Unknown device") | coagir `name`/`host` para str, `ConfigError` se não for |
| E4 | Nit | `server.py:181` | `MIKROTIK_LOG_LEVEL` inválido → `ValueError` no `basicConfig`, crash no startup | validar contra allow-list, fallback INFO |
| R3 | Nit | `server.py:143,154` | `limit`/`count <= 0` clampam pra 1 silenciosamente | `ValidationError` em vez de clamp silencioso |
| R2 | Nit | `server.py:120` | `ip_routes` sem cap de linhas | `limit` opcional |
| R1 | Nit | `server.py:144` | `logs` puxa tabela inteira e corta em Python (ruim sobre link lento) | pedir só as linhas necessárias se a API suportar |
| R4 | Nit | `formatting.py:29` | double `dict(row)` (client.py já materializa) | normalizar num lugar só |

## Documentação

| # | Sev | Arquivo:linha | Problema | Correção |
|---|---|---|---|---|
| D1 | Nit (2 revisores) | `README.md:127` | descreve erro como `{"error":...}` mas o código propaga exceção → `isError` | corrigir descrição |
| D2 | Nit | `server.py:134` | docstring de `logs` diz filtro aplicado após o cap, mas é antes | corrigir comentário |
| D3 | Nit | `guard.py:44` | campo `description` na allowlist nunca é exposto | surface (em `list_write_operations`) ou remover |

## Não são achados (confirmado correto)

- Guard order, read-only gate, confirm/preview: corretos e testados ponta a ponta.
- `ping` address: validado por regex E passado como parâmetro estruturado.
- Compatibilidade ROS6/ROS7: nenhum path assume campo exclusivo do ROS7.
- Validação de hostname com último label numérico rejeitado: intencional (RFC 1123),
  mas revisar se a frota usa sufixo numérico (ex.: `ap.15`).
