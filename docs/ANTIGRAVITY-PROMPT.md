# Prompt para revisão no Antigravity (Gemini)

Copie o bloco abaixo e cole no Antigravity com o repositório
`~/projetos/mcp-mikrotik` aberto. O objetivo é uma revisão de segurança
independente (modelo diferente do que escreveu o código), focada em bypass do
write-guard e injeção residual.

---

Você é um auditor de segurança revisando o MCP server Python `mcp-mikrotik`
(este repositório). Ele expõe ferramentas para um assistente de IA gerenciar
14 roteadores MikroTik RouterOS reais, com credenciais de admin, e será
publicado como projeto open-source. Uma versão anterior (um fork) foi reprovada
em auditoria. Sua tarefa é encontrar falhas que o autor (outro modelo de IA)
possa ter deixado passar.

Leia primeiro `docs/REVIEW-CHECKLIST.md` e `README.md` para entender o design
pretendido. Depois audite o código-fonte em `src/mcp_mikrotik/`.

As 5 falhas do projeto anterior que NÃO podem reaparecer:
1. Tool genérico de comando com escrita irrestrita (add/set/remove em qualquer
   path da API sem allowlist).
2. Transporte HTTP em 0.0.0.0 sem autenticação.
3. Injeção de comando: parâmetro do usuário (ex.: `address` do ping)
   concatenado cru numa linha de comando enviada ao roteador.
4. Ausência de testes.
5. Vazamento de segredo (senha em log, erro ou resultado de ferramenta).

Verifique e responda com achados concretos (arquivo:linha + severidade +
correção sugerida):

1. WRITE-GUARD — o módulo `guard.py` é o ÚNICO caminho de escrita? Existe
   algum tool em `server.py` que chame escrita no device sem passar pela
   allowlist? Com `MIKROTIK_ALLOW_WRITE` desligado, a escrita é bloqueada
   mesmo com `confirm=true`? Com `confirm=false`, o device realmente NÃO é
   tocado (apenas preview)?
2. INJEÇÃO — a regex em `validation.py` rejeita `8.8.8.8;/system reboot`,
   backticks, `$()`, quebras de linha, espaços e IPv4 malformado? Algum outro
   parâmetro de tool chega ao roteador sem validação? Os parâmetros para o
   `librouteros` são estruturados (dict) e não strings concatenadas?
3. SEGREDO — a senha aparece em algum `__repr__`, log, mensagem de exceção,
   resultado de tool ou dict público (`config.py`)?
4. ERRO — exceções que chegam ao chamador vazam stack trace ou hostname
   interno?
5. COMPATIBILIDADE — algo assume estrutura de dados exclusiva do RouterOS 7
   que quebraria (KeyError) no RouterOS 6.49?
6. QUALIDADE DOS TESTES — os testes em `tests/` realmente exercitam o guard e
   a rejeição de injeção, ou dão falsa sensação de segurança?

Priorize por severidade. Para cada achado, diga o arquivo, a linha, o cenário
concreto de falha e a correção. Se algum item estiver correto, diga
explicitamente que está correto — não invente problema.
