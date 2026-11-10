# Fontes de dados

## 1. Logins do Home Assistant (padrão)
Ativo por padrão. Captura:
- senha errada na tela de login;
- token inválido na API REST, websocket e webhooks autenticados;
- banimentos automáticos (`http: ip_ban_enabled: true`).

Recomendado no `configuration.yaml`:

```yaml
http:
  ip_ban_enabled: true
  login_attempts_threshold: 5
```

Se o HA estiver atrás de um proxy reverso, configure `use_x_forwarded_for` e `trusted_proxies`; caso
contrário todos os ataques aparecerão com o IP do proxy.

## 2. Arquivos de log
Opções → **Fontes → Arquivos de log**, um caminho absoluto por linha. O formato é detectado
automaticamente:

| Conteúdo | Exemplo de caminho | Detecta |
|---|---|---|
| OpenSSH | `/var/log/auth.log` | falhas de senha/chave, usuários inexistentes, sondagens, máximo de tentativas |
| nginx / Apache / Caddy / Traefik (formato *combined*) | `/config/nginx/access.log` | SQLi, XSS, path traversal, injeção de comando, Log4Shell, Shellshock, arquivos sensíveis (`.env`, `.git`, `wp-login.php`…), scanners por User-Agent, requisições malformadas |
| UFW / iptables `LOG` | `/var/log/ufw.log`, `/var/log/kern.log` | bloqueios + correlação de varredura de portas |
| fail2ban | `/var/log/fail2ban.log` | banimentos |

Caminhos fora de `/config` precisam ser liberados:

```yaml
homeassistant:
  allowlist_external_dirs:
    - /var/log/sentinel
```

### Por tipo de instalação
- **Home Assistant OS / Supervised**: o container do HA não vê os logs do host. Use o add-on **NGINX Home
  Assistant SSL proxy** com log de acesso em `/share` ou, melhor, **encaminhe via syslog** (abaixo).
- **Container (Docker)**: monte os logs como volume somente leitura, ex.: `- /var/log:/var/log/host:ro`
  e use `/var/log/host/auth.log`.
- **Core (venv)**: o usuário do HA precisa de permissão de leitura (ex.: grupo `adm` no Debian/Ubuntu).

## 3. Receptor syslog (UDP)
Opções → **Receptor syslog**: ative, mantenha a porta `5514` (portas < 1024 exigem root) e preencha
**remetentes permitidos** com o IP de cada equipamento.

| Equipamento | Como encaminhar |
|---|---|
| Linux (rsyslog) | `/etc/rsyslog.d/90-sentinel.conf`: `auth,authpriv.*;kern.warning @IP_DO_HA:5514` e `systemctl restart rsyslog` |
| pfSense | *Status → System Logs → Settings → Remote Logging*: servidor `IP_DO_HA:5514`, marque *Firewall Events* e *System* |
| OPNsense | *System → Settings → Logging → Remote*: UDP, `IP_DO_HA`, porta `5514`, aplicações `filter`, `audit` |
| OpenWrt | *System → System → Logging*: *External system log server* `IP_DO_HA`, porta `5514`, protocolo UDP |
| MikroTik | `/system logging action add name=sentinel target=remote remote=IP_DO_HA remote-port=5514` e regras para `firewall` e `account` |
| Synology DSM | *Central de Logs → Enviar logs*: servidor `IP_DO_HA`, porta `5514`, UDP, formato BSD |
| UniFi | *Settings → System → Integrations → Activity Logging (SIEM)*: `IP_DO_HA:5514` |

Para que regras de firewall gerem logs, habilite o *log* nas regras de bloqueio (ex.: `ufw logging on`).

## 4. Ação `report_event`
Qualquer automação pode registrar eventos — útil para integrações que já expõem alertas (UniFi
Protect, AdGuard, Frigate, CrowdSec etc.). Veja o exemplo no [README](../README.md#ações-serviços).
