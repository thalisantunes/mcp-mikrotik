# Checklist de revisão de segurança — mcp-mikrotik

Este projeto substitui um MCP que foi auditado e reprovado. Toda revisão
(humana, Antigravity/Gemini, ou multi-agente) deve confirmar que NENHUMA das
falhas abaixo reaparece, e que o modelo de segurança é à prova de bypass.

## Falhas do projeto anterior que NÃO podem reaparecer

1. **Escrita irrestrita.** O fork tinha um tool `command()` que aceitava path
   de API + parâmetros arbitrários e fazia add/set/remove conforme a string.
   Aqui NÃO pode existir tool genérico de comando. Toda escrita passa por uma
   operação nomeada na allowlist central (`guard.py`).
2. **HTTP sem auth em 0.0.0.0.** Transporte é stdio. Se um dia houver HTTP,
   bind em 127.0.0.1 + bearer token obrigatório.
3. **Injeção de comando.** O fork concatenava `address` do ping numa linha SSH.
   Aqui usa-se `librouteros` com parâmetros ESTRUTURADOS (dict), e `address` é
   validado por regex (`validation.py`).
4. **Zero testes.** Aqui há suíte pytest cobrindo guard e validação.
5. **Vazamento de segredo.** Senha nunca em log nem em tool result.

## Pontos para o revisor confirmar (arquivo:linha)

- [ ] `guard.py` — a allowlist é o ÚNICO caminho de escrita? Algum tool em
      `server.py` chama `client.update/add/remove` direto, fora do guard?
- [ ] `guard.py` — `allow_write=false` bloqueia mesmo com `confirm=true`?
- [ ] `guard.py` — `confirm=false` realmente NÃO toca o device (só preview)?
- [ ] `validation.py` — a regex de address rejeita `8.8.8.8;/system reboot`,
      backticks, `$()`, espaços, e IPv4 malformado?
- [ ] `client.py` — nenhuma montagem de comando por concatenação de string?
- [ ] `config.py` — a senha fica fora de qualquer `to_public_dict`/repr/log?
- [ ] Erros ao chamador não vazam stack trace nem senha.
- [ ] Nada assume estrutura exclusiva do RouterOS 7 (frota tem ROS 6.49).

## Como rodar

- **Testes:** `pytest` na raiz.
- **Antigravity/Gemini:** abrir o repo e pedir revisão de segurança usando
  este checklist como guia; focar em bypass do guard e injeção residual.
- **local-ultrareview:** revisão multi-perspectiva via agentes (Claude).
