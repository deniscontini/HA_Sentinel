# Changelog

## [Não lançado]
### Segurança
- Serviços `report_event`, `purge_events` e `generate_test_events` passam a exigir usuário
  administrador (automações seguem permitidas). (A trilha de auditoria não pode mais ser apagada
  nem poluída por usuário não-admin.)
- Revalidação de `is_allowed_path` dos arquivos de log em runtime.
- **Syslog (A1):** o receptor recusa iniciar sem allowlist de remetentes e as opções não deixam
  salvar o syslog ativo com a lista vazia (IP de origem UDP é falsificável).
- **Syslog (A2):** o parsing das linhas passou do event loop para o executor (em lotes), evitando
  latência sob flood de mensagens grandes.

## [0.1.0] - 2026-11-10
### Adicionado
- Primeira versão: motor de detecção, fontes (logins do HA, arquivos de log, syslog UDP, `report_event`),
  armazenamento SQLite, sensores, evento de automação, painel em tempo real e testes.
