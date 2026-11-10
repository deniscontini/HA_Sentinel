# Roadmap

## ✅ Fase 1 — MVP (v0.1.0)
- [x] Motor de detecção independente do HA (15 categorias, correlação de força bruta e varredura)
- [x] Fontes: logins do HA, arquivos de log, syslog UDP, ação `report_event`
- [x] Armazenamento SQLite com retenção e purga
- [x] Sensores, binary sensor "sob ataque" e evento de automação
- [x] Painel: tempo real, períodos predefinidos/personalizados, gráficos, filtros, CSV
- [x] Config flow + opções com validação; diagnóstico
- [x] Testes (motor + integração com HA real), lint, CI (hassfest, HACS, pytest)

## 🔜 Fase 2 — Validação em campo (próximo passo)
- [ ] Instalar na sua instância e ajustar regras com tráfego real (falsos positivos/negativos)
- [ ] Publicar no GitHub e configurar `codeowners`/URLs no `manifest.json`
- [ ] Ícone/brand (`brand/icon.png`) e release no HACS
- [ ] Capturas de tela do painel no README

## 💡 Fase 3 — Enriquecimento (decisões a confirmar)
| Item | Opções / impacto |
|---|---|
| **GeoIP** (país/ASN no painel + mapa) | (a) base local MaxMind GeoLite2 (requer conta gratuita e download do arquivo) ou (b) API externa (envia IPs a terceiros — opt-in) |
| **Reputação de IP** | AbuseIPDB / CrowdSec CTI com chave do usuário, com cache |
| **Resposta automática** | Banir IP no próprio HA (`ip_bans.yaml`), chamar API do firewall (pfSense/OPNsense/UniFi) ou CrowdSec bouncer — exige confirmação explícita por ser ação ativa |
| **Notificações nativas** | Notificação persistente/mobile configurável pela integração (hoje via blueprint) |
| **Regras personalizadas** | Editor de regex/YAML pelo usuário, com teste ao vivo |

## 🧭 Fase 4 — Escala e alcance
- [ ] Syslog TCP/TLS e formato RFC 5424 estruturado
- [ ] Add-on complementar para HA OS (acesso aos logs do host, sniffing opcional de portas-isca/honeypot)
- [ ] Importar histórico de arquivos com timestamps originais
- [ ] Card Lovelace compacto (resumo + mini linha do tempo) para dashboards existentes
- [ ] Relatório periódico (diário/semanal) por notificação ou e-mail
