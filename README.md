# 🛡️ HA Sentinel

Integração personalizada para o **Home Assistant** que detecta tentativas de ataque contra a sua casa
conectada — logins inválidos, força bruta, varreduras de porta, injeção SQL, XSS, path traversal,
Log4Shell, scanners de vulnerabilidade e outros — e exibe tudo num **dashboard em tempo real** com
análise por período.

<img width="1723" height="953" alt="Captura de Tela 2026-11-10 às 15 49 33" src="https://github.com/user-attachments/assets/c193f771-3742-414f-bf6e-14d80e122794" />

## Funcionalidades

| | |
|---|---|
| **Fontes de dados** | Logins inválidos e banimentos do próprio HA · arquivos de log (sshd, nginx/Apache/Caddy/Traefik, UFW/iptables, pfSense/OPNsense, fail2ban) · receptor **syslog UDP** para roteadores, firewalls e NAS · ação `ha_sentinel.report_event` para qualquer outra integração/automação |
| **Detecção** | 15 categorias com severidade (baixa → crítica), decodificação dupla de URL, correlação de **força bruta** (N falhas/IP/janela) e **varredura de portas** (N portas distintas/IP/janela) |
| **Dashboard** | Painel na barra lateral (somente admins): KPIs, linha do tempo por severidade, ataques por tipo, principais IPs de origem, status das fontes, lista paginada com detalhes e linha original, filtros por tipo/severidade/texto, períodos 1 h/24 h/7 d/30 d ou personalizado, zoom clicando no gráfico, atualização ao vivo e exportação CSV |
| **Entidades** | `binary_sensor.ha_sentinel_under_attack`, sensores de ataques (1 h / 24 h), atacantes únicos, altos/críticos, nível de ameaça, último ataque e horário |
| **Automação** | Evento `ha_sentinel_attack_detected` + [blueprint de notificação](blueprints/automation/ha_sentinel/notify_on_attack.yaml) |
| **Armazenamento** | SQLite próprio (`/config/ha_sentinel.db`), separado do recorder, com retenção configurável |

## Instalação

### HACS (repositório personalizado)
1. HACS → ⋮ → *Repositórios personalizados* → URL deste repositório, categoria **Integração**.
2. Instale **HA Sentinel** e reinicie o Home Assistant.

### Manual
Copie `custom_components/ha_sentinel` para `/config/custom_components/` e reinicie.

### Configuração
*Configurações → Dispositivos e serviços → Adicionar integração → HA Sentinel*.
O monitoramento de logins do HA já começa ativo. Fontes extras ficam em **Configurar** (opções):

| Seção | Opções |
|---|---|
| Fontes | logins do HA, arquivos de log (um caminho por linha), intervalo de leitura |
| Syslog (UDP) | ativar, endereço, porta (padrão `5514`), remetentes permitidos (IPs/CIDRs) |
| Detecção | limiares de força bruta e varredura, limiar de "sob ataque", IPs/redes ignorados |
| Geral | retenção (dias), severidade mínima para disparar eventos de automação |

Detalhes de cada fonte e exemplos de encaminhamento de logs: **[docs/FONTES.md](docs/FONTES.md)**.

> Requer Home Assistant **2025.8** ou superior.

## Testando rapidamente
Em *Ferramentas de desenvolvedor → Ações*, execute:

```yaml
action: ha_sentinel.generate_test_events
data:
  count: 300
  hours: 24
```

Abra **Sentinel** na barra lateral. Para remover os dados de teste: `ha_sentinel.purge_events` com
`older_than_days: 0` (apaga tudo).

## Ações (serviços)

| Ação | Uso |
|---|---|
| `ha_sentinel.report_event` | Registra um ataque vindo de outra integração (UniFi, AdGuard, câmeras, IDS…). Campos: `attack_type`, `ip`, `severity`, `source`, `port`, `username`, `target`, `details` |
| `ha_sentinel.purge_events` | Apaga eventos mais antigos que `older_than_days` (0 = tudo) |
| `ha_sentinel.generate_test_events` | Cria eventos sintéticos (IPs de documentação RFC 5737) |

Exemplo — registrar bloqueios de um roteador que já gera eventos no HA:

```yaml
triggers:
  - trigger: event
    event_type: unifi_ips_alert   # exemplo
actions:
  - action: ha_sentinel.report_event
    data:
      attack_type: port_scan
      ip: "{{ trigger.event.data.src_ip }}"
      source: unifi
      details: "{{ trigger.event.data.message }}"
```

## Desenvolvimento

```bash
# Ambiente de testes (instala um Home Assistant compatível)
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements_test.txt
pytest -q            # motor de detecção + testes de integração com HA real
ruff check . && ruff format --check .

# Instância local do HA com a integração montada
docker compose up -d                      # http://localhost:8123
python3 scripts/simulate_attacks.py --loop 10
```

No HA de desenvolvimento, adicione a integração e configure nas opções os arquivos
`/var/log/sentinel/auth.log`, `/var/log/sentinel/access.log`, `/var/log/sentinel/ufw.log` e ative o syslog
na porta `5514`. O simulador escreve nesses arquivos e envia syslog para `127.0.0.1:5514`.
Com `--ha-url http://localhost:8123` ele também faz logins inválidos na instância **local**.

Estrutura e decisões técnicas: **[docs/ARQUITETURA.md](docs/ARQUITETURA.md)**.

## Segurança e privacidade
- Tudo é processado localmente; nenhum dado sai do Home Assistant.
- O painel e a API websocket exigem usuário **administrador**.
- Conteúdo vindo de atacantes (URLs, user-agents, usuários) é sempre escapado no painel e neutralizado
  contra *formula injection* na exportação CSV.
- O receptor syslog deve ser restrito aos IPs dos seus equipamentos (*remetentes permitidos*).

## Licença
[MIT](LICENSE)
