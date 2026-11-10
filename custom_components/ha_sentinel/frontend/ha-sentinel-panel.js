/**
 * HA Sentinel dashboard panel.
 *
 * Dependency-free Web Component (no build step, works offline). Talks to the
 * backend through the websocket commands in websocket_api.py:
 *   ha_sentinel/info, ha_sentinel/stats, ha_sentinel/events, ha_sentinel/subscribe
 *
 * SECURITY: every string shown here may come from an attacker (URLs, user
 * agents, usernames). Everything is rendered through esc() — never insert
 * event data as raw HTML.
 */

const SEVERITIES = ["low", "medium", "high", "critical"];

const I18N = {
  pt: {
    title: "HA Sentinel",
    subtitle: "Monitor de tentativas de ataque",
    live: "Ao vivo",
    paused: "Pausado",
    p1h: "1 h",
    p24h: "24 h",
    p7d: "7 dias",
    p30d: "30 dias",
    custom: "Personalizado",
    from: "De",
    to: "Até",
    apply: "Aplicar",
    allTypes: "Todos os tipos",
    search: "Buscar IP, usuário, URL…",
    export: "Exportar CSV",
    refresh: "Atualizar",
    clear: "Limpar filtros",
    total: "Ataques no período",
    uniqueIps: "IPs de origem únicos",
    highCrit: "Alta + crítica",
    topType: "Tipo mais frequente",
    lastEvent: "Último evento",
    timeline: "Ataques ao longo do tempo",
    timelineSub: "por severidade · clique numa coluna para ampliar",
    byType: "Por tipo de ataque",
    byTypeSub: "clique para filtrar",
    topIps: "Principais origens",
    sources: "Fontes de dados",
    events: "Eventos",
    time: "Data/hora",
    severity: "Severidade",
    type: "Tipo",
    ip: "IP de origem",
    user: "Usuário",
    target: "Alvo",
    source: "Fonte",
    count: "Eventos",
    lastSeen: "Visto por último",
    details: "Detalhes",
    raw: "Linha original",
    prev: "Anterior",
    next: "Próxima",
    page: "Página",
    of: "de",
    none: "—",
    lan: "LAN",
    wan: "Internet",
    empty: "Nenhum ataque registrado neste período.",
    emptyHint:
      "Para testar o painel, execute a ação ha_sentinel.generate_test_events em Ferramentas de desenvolvedor → Ações.",
    newEvents: "novos",
    loading: "Carregando…",
    error: "Erro ao consultar o HA Sentinel",
    seen: "eventos",
    noSources: "Nenhuma fonte ativa. Configure nas opções da integração.",
    share: "do total",
    invalidPeriod: "O fim do período deve ser depois do início.",
    sev: { low: "Baixa", medium: "Média", high: "Alta", critical: "Crítica" },
    types: {
      failed_login: "Falha de login",
      brute_force: "Força bruta",
      banned_ip: "IP banido",
      sql_injection: "Injeção SQL",
      xss: "XSS",
      path_traversal: "Path traversal",
      command_injection: "Injeção de comando",
      log4shell: "Log4Shell",
      shellshock: "Shellshock",
      sensitive_file_probe: "Sondagem de arquivos",
      scanner: "Scanner",
      port_scan: "Varredura de portas",
      firewall_block: "Bloqueio de firewall",
      suspicious_request: "Requisição suspeita",
      other: "Outro",
    },
    sourceNames: { home_assistant: "Login do Home Assistant", log_files: "Arquivos de log", syslog: "Syslog" },
  },
  en: {
    title: "HA Sentinel",
    subtitle: "Attack attempt monitor",
    live: "Live",
    paused: "Paused",
    p1h: "1 h",
    p24h: "24 h",
    p7d: "7 days",
    p30d: "30 days",
    custom: "Custom",
    from: "From",
    to: "To",
    apply: "Apply",
    allTypes: "All types",
    search: "Search IP, user, URL…",
    export: "Export CSV",
    refresh: "Refresh",
    clear: "Clear filters",
    total: "Attacks in period",
    uniqueIps: "Unique source IPs",
    highCrit: "High + critical",
    topType: "Most frequent type",
    lastEvent: "Last event",
    timeline: "Attacks over time",
    timelineSub: "by severity · click a column to zoom in",
    byType: "By attack type",
    byTypeSub: "click to filter",
    topIps: "Top sources",
    sources: "Data sources",
    events: "Events",
    time: "Time",
    severity: "Severity",
    type: "Type",
    ip: "Source IP",
    user: "User",
    target: "Target",
    source: "Source",
    count: "Events",
    lastSeen: "Last seen",
    details: "Details",
    raw: "Raw line",
    prev: "Previous",
    next: "Next",
    page: "Page",
    of: "of",
    none: "—",
    lan: "LAN",
    wan: "Internet",
    empty: "No attacks recorded in this period.",
    emptyHint: "To try the dashboard, run the ha_sentinel.generate_test_events action in Developer tools → Actions.",
    newEvents: "new",
    loading: "Loading…",
    error: "Error querying HA Sentinel",
    seen: "events",
    noSources: "No active source. Configure them in the integration options.",
    share: "of total",
    invalidPeriod: "The end of the period must be after the start.",
    sev: { low: "Low", medium: "Medium", high: "High", critical: "Critical" },
    types: {
      failed_login: "Failed login",
      brute_force: "Brute force",
      banned_ip: "Banned IP",
      sql_injection: "SQL injection",
      xss: "XSS",
      path_traversal: "Path traversal",
      command_injection: "Command injection",
      log4shell: "Log4Shell",
      shellshock: "Shellshock",
      sensitive_file_probe: "Sensitive file probe",
      scanner: "Scanner",
      port_scan: "Port scan",
      firewall_block: "Firewall block",
      suspicious_request: "Suspicious request",
      other: "Other",
    },
    sourceNames: { home_assistant: "Home Assistant login", log_files: "Log files", syslog: "Syslog" },
  },
};

const PRESETS = { "1h": 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400 };
const PAGE_SIZE = 50;
const SVG_NS = "http://www.w3.org/2000/svg";

const esc = (value) =>
  String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

const compact = (n) => {
  if (n < 10000) return n.toLocaleString();
  if (n < 1e6) return `${(n / 1000).toFixed(n < 1e5 ? 1 : 0)}K`;
  return `${(n / 1e6).toFixed(1)}M`;
};

const niceMax = (max) => {
  if (max <= 4) return 4;
  const pow = 10 ** Math.floor(Math.log10(max));
  for (const step of [1, 2, 2.5, 5, 10]) {
    if (step * pow * 4 >= max) return step * pow * 4;
  }
  return max;
};

/** Neutralize spreadsheet formula injection in CSV cells. */
const csvCell = (value) => {
  let s = String(value ?? "");
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
};

class HaSentinelPanel extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: "open" });
    this._state = {
      preset: "24h",
      start: null,
      end: null,
      types: [],
      severities: [],
      search: "",
      page: 0,
      live: true,
      expanded: new Set(),
      fresh: new Set(),
      pending: 0,
    };
    this._stats = null;
    this._events = { total: 0, events: [] };
    this._info = null;
    this._error = null;
    this._loading = false;
    this._tips = new Map();
    this._initialized = false;
    this._unsub = null;
    this._refreshTimer = null;
    this._tickTimer = null;
    this._searchTimer = null;
    this._resizeObserver = null;
    this._lastWidth = 0;
  }

  // -- HA lifecycle -----------------------------------------------------------

  set hass(hass) {
    const first = !this._hass;
    this._hass = hass;
    const dark = Boolean(hass?.themes?.darkMode);
    if (dark !== this._dark) {
      this._dark = dark;
      this.toggleAttribute("dark", dark);
    }
    if (first) this._init();
    const menu = this.shadowRoot.querySelector("ha-menu-button");
    if (menu) menu.hass = hass;
  }

  set narrow(narrow) {
    this._narrow = narrow;
    const menu = this.shadowRoot.querySelector("ha-menu-button");
    if (menu) menu.narrow = narrow;
  }

  set panel(panel) {
    this._panel = panel;
  }

  connectedCallback() {
    if (this._hass && !this._initialized) this._init();
  }

  disconnectedCallback() {
    this._teardown();
  }

  get _t() {
    const lang = (this._hass?.locale?.language || this._hass?.language || "en").toLowerCase();
    return lang.startsWith("pt") ? I18N.pt : I18N.en;
  }

  async _init() {
    if (this._initialized || !this.isConnected) return;
    this._initialized = true;
    this._renderShell();
    this._bindEvents();
    this._resizeObserver = new ResizeObserver(() => {
      const w = this.shadowRoot.querySelector(".timeline-body")?.clientWidth || 0;
      if (Math.abs(w - this._lastWidth) > 4) this._renderTimeline();
    });
    this._resizeObserver.observe(this);
    try {
      this._info = await this._ws({ type: "ha_sentinel/info" });
      this._renderFilters();
    } catch (err) {
      this._error = err?.message || String(err);
    }
    await this._subscribe();
    await this._load();
    // Rolling presets move with the clock.
    this._tickTimer = setInterval(() => {
      if (this._state.preset !== "custom" && this._state.live) this._load(true);
    }, 60000);
  }

  _teardown() {
    if (this._unsub) {
      this._unsub.then((unsub) => unsub()).catch(() => {});
      this._unsub = null;
    }
    clearInterval(this._tickTimer);
    clearTimeout(this._refreshTimer);
    this._resizeObserver?.disconnect();
    this._initialized = false;
  }

  _ws(msg) {
    return this._hass.connection.sendMessagePromise(msg);
  }

  async _subscribe() {
    try {
      this._unsub = this._hass.connection.subscribeMessage((msg) => this._onLiveEvents(msg.events || []), {
        type: "ha_sentinel/subscribe",
      });
      await this._unsub;
    } catch (err) {
      this._unsub = null;
      this._error = err?.message || String(err);
    }
  }

  _onLiveEvents(events) {
    const s = this._state;
    const followsNow = s.preset !== "custom";
    if (!s.live || !followsNow || s.page > 0) {
      s.pending += events.length;
      this._renderHeaderStatus();
      return;
    }
    for (const ev of events) if (ev.id != null) s.fresh.add(ev.id);
    clearTimeout(this._refreshTimer);
    this._refreshTimer = setTimeout(() => this._load(true), 1200);
  }

  // -- data -------------------------------------------------------------------

  _period() {
    const s = this._state;
    if (s.preset === "custom" && s.start && s.end) return { start: s.start, end: s.end };
    const end = Date.now() / 1000;
    return { start: end - PRESETS[s.preset], end };
  }

  _filters() {
    const s = this._state;
    const f = {};
    if (s.types.length) f.attack_types = s.types;
    if (s.severities.length) f.severities = s.severities;
    if (s.search) f.search = s.search;
    return f;
  }

  async _load(quiet = false) {
    const { start, end } = this._period();
    const filters = this._filters();
    const seq = (this._seq = (this._seq || 0) + 1);
    if (!quiet) {
      this._loading = true;
      this._renderStatusOnly();
    }
    try {
      const [stats, events] = await Promise.all([
        this._ws({ type: "ha_sentinel/stats", start, end, ...filters }),
        this._ws({
          type: "ha_sentinel/events",
          start,
          end,
          ...filters,
          limit: PAGE_SIZE,
          offset: this._state.page * PAGE_SIZE,
        }),
      ]);
      if (seq !== this._seq) return; // a newer request superseded this one
      this._stats = stats;
      this._events = events;
      this._error = null;
      this._state.pending = 0;
    } catch (err) {
      if (seq !== this._seq) return;
      this._error = err?.message || String(err);
    } finally {
      if (seq === this._seq) {
        this._loading = false;
        this._renderContent();
        setTimeout(() => this._state.fresh.clear(), 2500);
      }
    }
  }

  async _exportCsv() {
    const { start, end } = this._period();
    const res = await this._ws({ type: "ha_sentinel/events", start, end, ...this._filters(), limit: 10000, offset: 0 });
    const header = ["timestamp_iso", "severity", "attack_type", "ip", "is_private", "port", "username", "target", "source", "details", "raw"];
    const rows = res.events.map((e) =>
      [
        new Date(e.timestamp * 1000).toISOString(),
        e.severity,
        e.attack_type,
        e.ip,
        e.is_private,
        e.port,
        e.username,
        e.target,
        e.source,
        e.details,
        e.raw,
      ]
        .map(csvCell)
        .join(","),
    );
    const blob = new Blob([`${header.join(",")}\n${rows.join("\n")}\n`], { type: "text/csv;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `ha-sentinel-${new Date(start * 1000).toISOString().slice(0, 16)}_${new Date(end * 1000)
      .toISOString()
      .slice(0, 16)}.csv`.replace(/:/g, "-");
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 5000);
  }

  // -- formatting ---------------------------------------------------------------

  _fmt(ts, opts) {
    const lang = this._hass?.locale?.language || "en";
    return new Intl.DateTimeFormat(lang, opts).format(new Date(ts * 1000));
  }

  _fmtDateTime(ts) {
    return this._fmt(ts, { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }

  _fmtBucket(ts, bucket) {
    if (bucket >= 86400) return this._fmt(ts, { day: "2-digit", month: "2-digit" });
    if (bucket >= 21600) return this._fmt(ts, { day: "2-digit", month: "2-digit", hour: "2-digit" });
    return this._fmt(ts, { hour: "2-digit", minute: "2-digit" });
  }

  _relative(ts) {
    const lang = this._hass?.locale?.language || "en";
    const rtf = new Intl.RelativeTimeFormat(lang, { numeric: "auto" });
    const diff = ts - Date.now() / 1000;
    const abs = Math.abs(diff);
    if (abs < 60) return rtf.format(Math.round(diff), "second");
    if (abs < 3600) return rtf.format(Math.round(diff / 60), "minute");
    if (abs < 86400) return rtf.format(Math.round(diff / 3600), "hour");
    return rtf.format(Math.round(diff / 86400), "day");
  }

  _typeLabel(type) {
    return this._t.types[type] || type;
  }

  _sevBadge(sev) {
    return `<span class="sev"><span class="dot sev-${esc(sev)}"></span>${esc(this._t.sev[sev] || sev)}</span>`;
  }

  _netBadge(isPrivate) {
    if (isPrivate == null) return "";
    return `<span class="badge ${isPrivate ? "lan" : "wan"}">${isPrivate ? this._t.lan : this._t.wan}</span>`;
  }

  _toLocalInput(ts) {
    const d = new Date(ts * 1000);
    const pad = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

  // -- rendering ------------------------------------------------------------------

  _renderShell() {
    const t = this._t;
    this.shadowRoot.innerHTML = `
      <style>${STYLES}</style>
      <div class="toolbar">
        <ha-menu-button></ha-menu-button>
        <div class="title"><span>${t.title}</span><small>${t.subtitle}</small></div>
        <div class="status" id="status"></div>
      </div>
      <div class="page">
        <div class="filters" id="filters"></div>
        <div id="content"></div>
        <div class="tooltip" id="tooltip" role="tooltip" hidden></div>
      </div>`;
    const menu = this.shadowRoot.querySelector("ha-menu-button");
    menu.hass = this._hass;
    menu.narrow = this._narrow;
    this._renderFilters();
    this._renderHeaderStatus();
  }

  _renderHeaderStatus() {
    const el = this.shadowRoot.getElementById("status");
    if (!el) return;
    const t = this._t;
    const s = this._state;
    el.innerHTML = `
      ${s.pending ? `<button class="chip pending" data-action="refresh">+${s.pending} ${t.newEvents}</button>` : ""}
      <button class="live ${s.live ? "on" : ""}" data-action="toggle-live" aria-pressed="${s.live}">
        <span class="pulse"></span>${s.live ? t.live : t.paused}
      </button>`;
  }

  _renderStatusOnly() {
    const content = this.shadowRoot.getElementById("content");
    if (content && !this._stats) content.innerHTML = `<div class="card muted">${this._t.loading}</div>`;
  }

  _renderFilters() {
    const t = this._t;
    const s = this._state;
    const types = this._info?.attack_types || Object.keys(t.types);
    const { start, end } = this._period();
    const presetBtn = (key, label) =>
      `<button class="seg ${s.preset === key ? "active" : ""}" data-action="preset" data-value="${key}">${label}</button>`;
    this.shadowRoot.getElementById("filters").innerHTML = `
      <div class="row">
        <div class="segmented" role="group">
          ${presetBtn("1h", t.p1h)}${presetBtn("24h", t.p24h)}${presetBtn("7d", t.p7d)}${presetBtn("30d", t.p30d)}
          ${presetBtn("custom", t.custom)}
        </div>
        ${
          s.preset === "custom"
            ? `<label class="dt">${t.from}<input type="datetime-local" id="dt-start" value="${this._toLocalInput(start)}"></label>
               <label class="dt">${t.to}<input type="datetime-local" id="dt-end" value="${this._toLocalInput(end)}"></label>
               <button class="btn primary" data-action="apply-custom">${t.apply}</button>`
            : ""
        }
      </div>
      <div class="row">
        <select id="type-filter" aria-label="${t.type}">
          <option value="">${t.allTypes}</option>
          ${types
            .map((ty) => `<option value="${esc(ty)}" ${s.types[0] === ty ? "selected" : ""}>${esc(this._typeLabel(ty))}</option>`)
            .join("")}
        </select>
        <div class="sev-chips" role="group" aria-label="${t.severity}">
          ${SEVERITIES.map(
            (sev) =>
              `<button class="chip ${s.severities.includes(sev) ? "active" : ""}" data-action="toggle-sev" data-value="${sev}" aria-pressed="${s.severities.includes(sev)}"><span class="dot sev-${sev}"></span>${t.sev[sev]}</button>`,
          ).join("")}
        </div>
        <input type="search" id="search" placeholder="${t.search}" value="${esc(s.search)}">
        <span class="spacer"></span>
        ${
          s.types.length || s.severities.length || s.search
            ? `<button class="btn" data-action="clear">${t.clear}</button>`
            : ""
        }
        <button class="btn" data-action="refresh">${t.refresh}</button>
        <button class="btn" data-action="export">${t.export}</button>
      </div>`;
  }

  _renderContent() {
    const content = this.shadowRoot.getElementById("content");
    if (!content) return;
    const t = this._t;
    this._tips.clear();
    if (this._error && !this._stats) {
      content.innerHTML = `<div class="card error">${t.error}: ${esc(this._error)}</div>`;
      return;
    }
    if (!this._stats) return;
    const st = this._stats;
    content.innerHTML = `
      ${this._error ? `<div class="card error">${t.error}: ${esc(this._error)}</div>` : ""}
      ${this._renderKpis(st)}
      <div class="grid two">
        <section class="card timeline-card">
          <header><h2>${t.timeline}</h2><small>${t.timelineSub}</small></header>
          <div class="legend">${SEVERITIES.map(
            (sev) => `<span><span class="swatch sev-${sev}"></span>${t.sev[sev]}</span>`,
          ).join("")}</div>
          <div class="timeline-body"></div>
        </section>
        <section class="card">
          <header><h2>${t.byType}</h2><small>${t.byTypeSub}</small></header>
          ${this._renderTypeBars(st)}
        </section>
      </div>
      <div class="grid two">
        <section class="card">
          <header><h2>${t.topIps}</h2></header>
          ${this._renderTopIps(st)}
        </section>
        <section class="card">
          <header><h2>${t.sources}</h2></header>
          ${this._renderSources(st)}
        </section>
      </div>
      <section class="card">
        <header><h2>${t.events}</h2><small>${this._events.total.toLocaleString()}</small></header>
        ${this._renderEvents()}
      </section>`;
    this._renderTimeline();
    this._renderHeaderStatus();
  }

  _renderKpis(st) {
    const t = this._t;
    const high = (st.by_severity.high || 0) + (st.by_severity.critical || 0);
    const top = st.by_type[0];
    const last = this._events.events[0];
    const tile = (label, value, extra = "", hero = false) =>
      `<div class="kpi ${hero ? "hero" : ""}"><div class="label">${label}</div><div class="value">${value}</div>${extra}</div>`;
    return `<div class="kpis">
      ${tile(t.total, compact(st.total), "", true)}
      ${tile(t.uniqueIps, compact(st.unique_ips))}
      ${tile(t.highCrit, compact(high), high ? `<div class="sub">${this._sevBadge("critical")} ${compact(st.by_severity.critical || 0)}</div>` : "")}
      ${tile(t.topType, top ? esc(this._typeLabel(top.key)) : t.none, top ? `<div class="sub">${compact(top.count)} ${t.seen}</div>` : "")}
      ${tile(t.lastEvent, last && this._state.page === 0 ? esc(this._relative(last.timestamp)) : t.none, last && this._state.page === 0 ? `<div class="sub">${esc(last.ip || "")}</div>` : "")}
    </div>`;
  }

  _renderTimeline() {
    const host = this.shadowRoot.querySelector(".timeline-body");
    if (!host || !this._stats) return;
    const t = this._t;
    const st = this._stats;
    const buckets = st.timeline;
    const W = Math.max(280, host.clientWidth || 600);
    this._lastWidth = W;
    const H = 220;
    const m = { top: 8, right: 8, bottom: 26, left: 40 };
    const pw = W - m.left - m.right;
    const ph = H - m.top - m.bottom;
    const totals = buckets.map((b) => SEVERITIES.reduce((sum, s) => sum + b[s], 0));
    const max = niceMax(Math.max(0, ...totals));
    const band = pw / buckets.length;
    const barW = Math.max(1, Math.min(24, band - 2));
    const y = (v) => m.top + ph - (v / max) * ph;

    let svg = `<svg xmlns="${SVG_NS}" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(t.timeline)}">`;
    for (let i = 0; i <= 4; i++) {
      const v = (max / 4) * i;
      const yy = Math.round(y(v)) + 0.5;
      svg += `<line class="${i === 0 ? "axis" : "grid"}" x1="${m.left}" x2="${W - m.right}" y1="${yy}" y2="${yy}"/>`;
      svg += `<text class="tick" x="${m.left - 6}" y="${yy + 4}" text-anchor="end">${compact(v)}</text>`;
    }
    const labelEvery = Math.max(1, Math.ceil(buckets.length / Math.max(2, Math.floor(pw / 70))));
    buckets.forEach((b, i) => {
      const x0 = m.left + i * band;
      const cx = x0 + (band - barW) / 2;
      let yCursor = y(0);
      const segments = SEVERITIES.filter((s) => b[s] > 0);
      segments.forEach((sev, idx) => {
        const h = (b[sev] / max) * ph;
        const gap = idx > 0 && h > 3 ? 2 : 0;
        const top = yCursor - h;
        const isTop = idx === segments.length - 1;
        const segH = Math.max(1, h - gap);
        svg += isTop
          ? `<path class="bar sev-${sev}" d="${roundedTop(cx, top, barW, segH, Math.min(4, barW / 2, segH))}"/>`
          : `<rect class="bar sev-${sev}" x="${cx}" y="${top}" width="${barW}" height="${segH}"/>`;
        yCursor = top;
      });
      if (i % labelEvery === 0) {
        svg += `<text class="tick" x="${x0 + band / 2}" y="${H - 8}" text-anchor="middle">${esc(this._fmtBucket(b.start, st.bucket))}</text>`;
      }
      const key = `tl-${i}`;
      const end = Math.min(b.start + st.bucket, st.end);
      this._tips.set(
        key,
        `<div class="tt-title">${esc(this._fmtDateTime(b.start))} – ${esc(this._fmtDateTime(end))}</div>
         ${SEVERITIES.slice()
           .reverse()
           .map((s) => `<div class="tt-row"><span><span class="swatch sev-${s}"></span>${t.sev[s]}</span><b>${b[s].toLocaleString()}</b></div>`)
           .join("")}
         <div class="tt-row total"><span>Total</span><b>${totals[i].toLocaleString()}</b></div>`,
      );
      svg += `<rect class="hit" data-tip="${key}" data-action="zoom" data-start="${b.start}" data-end="${end}" x="${x0}" y="${m.top}" width="${band}" height="${ph}" aria-label="${esc(this._fmtBucket(b.start, st.bucket))}: ${totals[i]}"/>`;
    });
    svg += "</svg>";
    host.innerHTML = svg;
  }

  _renderTypeBars(st) {
    const t = this._t;
    if (!st.by_type.length) return `<div class="muted empty">${t.empty}</div>`;
    const max = Math.max(...st.by_type.map((r) => r.count));
    return `<div class="hbars">${st.by_type
      .map((row) => {
        const pct = st.total ? ((row.count / st.total) * 100).toFixed(1) : "0";
        const key = `ty-${row.key}`;
        this._tips.set(
          key,
          `<div class="tt-title">${esc(this._typeLabel(row.key))}</div><div class="tt-row"><span>${t.count}</span><b>${row.count.toLocaleString()}</b></div><div class="tt-row"><span>${t.share}</span><b>${pct}%</b></div>`,
        );
        const active = this._state.types.includes(row.key);
        return `<button class="hbar ${active ? "active" : ""}" data-action="filter-type" data-value="${esc(row.key)}" data-tip="${key}">
          <span class="hlabel">${esc(this._typeLabel(row.key))}</span>
          <span class="htrack"><span class="hfill" style="width:${Math.max(1, (row.count / max) * 100)}%"></span></span>
          <span class="hvalue">${compact(row.count)}</span>
        </button>`;
      })
      .join("")}</div>`;
  }

  _renderTopIps(st) {
    const t = this._t;
    if (!st.top_ips.length) return `<div class="muted empty">${t.none}</div>`;
    const max = st.top_ips[0].count;
    return `<table class="table compact">
      <thead><tr><th>${t.ip}</th><th class="num">${t.count}</th><th>${t.severity}</th><th>${t.lastSeen}</th></tr></thead>
      <tbody>${st.top_ips
        .map(
          (r) => `<tr class="clickable" data-action="filter-ip" data-value="${esc(r.ip)}" title="${esc(r.types.map((x) => this._typeLabel(x)).join(", "))}">
            <td><span class="mono">${esc(r.ip)}</span> ${this._netBadge(r.is_private)}
              <div class="mini"><span style="width:${(r.count / max) * 100}%"></span></div></td>
            <td class="num">${r.count.toLocaleString()}</td>
            <td>${this._sevBadge(r.max_severity)}</td>
            <td class="muted">${esc(this._relative(r.last_seen))}</td>
          </tr>`,
        )
        .join("")}</tbody></table>`;
  }

  _renderSources(st) {
    const t = this._t;
    const sources = this._info?.status?.sources || [];
    const bySource = st.by_source
      .map((r) => `<div class="tt-row"><span class="mono">${esc(r.key)}</span><b>${r.count.toLocaleString()}</b></div>`)
      .join("");
    const active = sources.length
      ? sources
          .map(
            (s) => `<div class="source ${s.last_error ? "bad" : "ok"}">
              <span class="dot ${s.last_error ? "sev-critical" : "ok"}"></span>
              <div><b>${esc(t.sourceNames[s.name] || s.name)}</b>
              ${s.address ? `<span class="muted mono"> ${esc(s.address)}</span>` : ""}
              ${(s.files || []).map((f) => `<div class="muted mono small">${esc(f.path)}${f.error ? ` — ${esc(f.error)}` : ""}</div>`).join("")}
              ${s.last_error ? `<div class="err small">${esc(s.last_error)}</div>` : ""}</div>
            </div>`,
          )
          .join("")
      : `<div class="muted">${t.noSources}</div>`;
    return `${active}${bySource ? `<div class="by-source">${bySource}</div>` : ""}`;
  }

  _renderEvents() {
    const t = this._t;
    const s = this._state;
    const { events, total } = this._events;
    if (!events.length) {
      return `<div class="empty"><p>${t.empty}</p><p class="muted small">${t.emptyHint}</p></div>`;
    }
    const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
    const rows = events
      .map((e) => {
        const open = s.expanded.has(e.id);
        return `<tr class="clickable ${s.fresh.has(e.id) ? "fresh" : ""}" data-action="expand" data-value="${e.id}" aria-expanded="${open}">
            <td class="nowrap mono">${esc(this._fmtDateTime(e.timestamp))}</td>
            <td>${this._sevBadge(e.severity)}</td>
            <td>${esc(this._typeLabel(e.attack_type))}</td>
            <td class="nowrap"><span class="mono">${esc(e.ip || t.none)}</span> ${this._netBadge(e.is_private)}</td>
            <td class="hide-narrow">${esc(e.username || "")}</td>
            <td class="ellipsis hide-narrow mono" title="${esc(e.target || "")}">${esc(e.target || "")}</td>
            <td class="hide-narrow muted">${esc(e.source)}</td>
          </tr>
          ${
            open
              ? `<tr class="detail"><td colspan="7">
                  <div><b>${t.details}:</b> ${esc(e.details || t.none)}</div>
                  ${e.port != null ? `<div><b>Port:</b> ${esc(e.port)}</div>` : ""}
                  ${e.raw ? `<div><b>${t.raw}:</b><pre>${esc(e.raw)}</pre></div>` : ""}
                </td></tr>`
              : ""
          }`;
      })
      .join("");
    return `<div class="table-wrap"><table class="table">
        <thead><tr><th>${t.time}</th><th>${t.severity}</th><th>${t.type}</th><th>${t.ip}</th>
          <th class="hide-narrow">${t.user}</th><th class="hide-narrow">${t.target}</th><th class="hide-narrow">${t.source}</th></tr></thead>
        <tbody>${rows}</tbody></table></div>
      <div class="pager">
        <button class="btn" data-action="page" data-value="-1" ${s.page === 0 ? "disabled" : ""}>${t.prev}</button>
        <span>${t.page} ${s.page + 1} ${t.of} ${pages}</span>
        <button class="btn" data-action="page" data-value="1" ${s.page + 1 >= pages ? "disabled" : ""}>${t.next}</button>
      </div>`;
  }

  // -- interaction -------------------------------------------------------------------

  _bindEvents() {
    const root = this.shadowRoot;
    root.addEventListener("click", (ev) => {
      const el = ev.target.closest("[data-action]");
      if (el) this._onAction(el.dataset.action, el);
    });
    root.addEventListener("change", (ev) => {
      if (ev.target.id === "type-filter") {
        this._state.types = ev.target.value ? [ev.target.value] : [];
        this._filtersChanged();
      }
    });
    root.addEventListener("input", (ev) => {
      if (ev.target.id !== "search") return;
      clearTimeout(this._searchTimer);
      this._searchTimer = setTimeout(() => {
        this._state.search = ev.target.value.trim();
        this._state.page = 0;
        this._load();
      }, 400);
    });
    root.addEventListener("mousemove", (ev) => this._onHover(ev));
    this.addEventListener("mouseleave", () => this._hideTip());
    root.addEventListener("focusin", (ev) => this._onHover(ev));
  }

  _filtersChanged() {
    this._state.page = 0;
    this._renderFilters();
    this._load();
  }

  _onAction(action, el) {
    const s = this._state;
    switch (action) {
      case "preset":
        if (el.dataset.value === "custom") {
          const { start, end } = this._period();
          Object.assign(s, { preset: "custom", start, end });
          this._renderFilters();
          return;
        }
        Object.assign(s, { preset: el.dataset.value, start: null, end: null, page: 0 });
        this._filtersChanged();
        break;
      case "apply-custom": {
        const start = Date.parse(this.shadowRoot.getElementById("dt-start").value) / 1000;
        const end = Date.parse(this.shadowRoot.getElementById("dt-end").value) / 1000;
        if (!(end > start)) {
          this._error = this._t.invalidPeriod;
          this._renderContent();
          return;
        }
        Object.assign(s, { start, end, page: 0 });
        this._load();
        break;
      }
      case "zoom": {
        const start = Number(el.dataset.start);
        const end = Number(el.dataset.end);
        if (end - start <= 300) return;
        Object.assign(s, { preset: "custom", start, end, page: 0 });
        this._hideTip();
        this._filtersChanged();
        break;
      }
      case "toggle-sev": {
        const v = el.dataset.value;
        s.severities = s.severities.includes(v) ? s.severities.filter((x) => x !== v) : [...s.severities, v];
        this._filtersChanged();
        break;
      }
      case "filter-type": {
        const v = el.dataset.value;
        s.types = s.types[0] === v ? [] : [v];
        this._hideTip();
        this._filtersChanged();
        break;
      }
      case "filter-ip":
        s.search = el.dataset.value;
        this._filtersChanged();
        break;
      case "clear":
        Object.assign(s, { types: [], severities: [], search: "" });
        this._filtersChanged();
        break;
      case "refresh":
        s.pending = 0;
        this._load();
        break;
      case "toggle-live":
        s.live = !s.live;
        this._renderHeaderStatus();
        if (s.live && s.pending) this._load(true);
        break;
      case "export":
        this._exportCsv().catch((err) => {
          this._error = err?.message || String(err);
          this._renderContent();
        });
        break;
      case "page":
        s.page = Math.max(0, s.page + Number(el.dataset.value));
        s.expanded.clear();
        this._load();
        break;
      case "expand": {
        const id = Number(el.dataset.value);
        if (s.expanded.has(id)) s.expanded.delete(id);
        else s.expanded.add(id);
        const section = el.closest("section");
        const wrapper = section?.querySelector(".table-wrap")?.parentElement;
        if (wrapper) {
          const header = wrapper.querySelector("header").outerHTML;
          wrapper.innerHTML = header + this._renderEvents();
        }
        break;
      }
      default:
        break;
    }
  }

  _onHover(ev) {
    const el = ev.target.closest?.("[data-tip]");
    const tip = this.shadowRoot.getElementById("tooltip");
    if (!el || !tip) {
      this._hideTip();
      return;
    }
    const html = this._tips.get(el.dataset.tip);
    if (!html) return;
    this.shadowRoot.querySelectorAll(".hovered").forEach((n) => n.classList.remove("hovered"));
    el.classList.add("hovered");
    tip.innerHTML = html;
    tip.hidden = false;
    const page = this.shadowRoot.querySelector(".page").getBoundingClientRect();
    const rect = el.getBoundingClientRect();
    const x = ev.clientX ?? rect.left + rect.width / 2;
    const yPos = ev.clientY ?? rect.top;
    const tw = tip.offsetWidth;
    let left = x - page.left + 14;
    if (left + tw > page.width - 8) left = x - page.left - tw - 14;
    tip.style.left = `${Math.max(8, left)}px`;
    tip.style.top = `${yPos - page.top + this.shadowRoot.querySelector(".page").scrollTop + 14}px`;
  }

  _hideTip() {
    const tip = this.shadowRoot.getElementById("tooltip");
    if (tip) tip.hidden = true;
    this.shadowRoot.querySelectorAll(".hovered").forEach((n) => n.classList.remove("hovered"));
  }
}

/** Path for a bar with 4px rounded top corners and a square baseline. */
function roundedTop(x, y, w, h, r) {
  return `M${x},${y + h} L${x},${y + r} Q${x},${y} ${x + r},${y} L${x + w - r},${y} Q${x + w},${y} ${x + w},${y + r} L${x + w},${y + h} Z`;
}

const STYLES = `
  :host {
    display: block;
    height: 100%;
    background: var(--primary-background-color, #f9f9f7);
    color: var(--primary-text-color, #0b0b0b);
    font-family: var(--paper-font-body1_-_font-family, system-ui, -apple-system, "Segoe UI", sans-serif);
    --surface: var(--card-background-color, #fcfcfb);
    --text-2: var(--secondary-text-color, #52514e);
    --muted: #898781;
    --line: var(--divider-color, #e1e0d9);
    --sev-low: #2a78d6;
    --sev-medium: #eda100;
    --sev-high: #e34948;
    --sev-critical: #6250d6;
    --ok: #0ca30c;
    --accent: #2a78d6;
    --fresh: rgba(42, 120, 214, 0.12);
  }
  :host([dark]) {
    --sev-low: #3987e5;
    --sev-medium: #c48800;
    --sev-high: #d63d3d;
    --sev-critical: #9085e9;
    --accent: #3987e5;
    --fresh: rgba(57, 135, 229, 0.18);
  }
  * { box-sizing: border-box; }
  .toolbar {
    display: flex; align-items: center; gap: 8px; height: var(--header-height, 56px);
    padding: 0 12px; background: var(--app-header-background-color, var(--primary-color));
    color: var(--app-header-text-color, #fff);
  }
  .toolbar .title { display: flex; flex-direction: column; line-height: 1.15; flex: 1; min-width: 0; }
  .toolbar .title span { font-size: 20px; font-weight: 500; }
  .toolbar .title small { opacity: .8; font-size: 12px; }
  .status { display: flex; gap: 8px; align-items: center; }
  .live { display: inline-flex; align-items: center; gap: 6px; border: 1px solid rgba(255,255,255,.5); background: transparent;
    color: inherit; border-radius: 16px; padding: 4px 10px; cursor: pointer; font: inherit; font-size: 13px; }
  .pulse { width: 8px; height: 8px; border-radius: 50%; background: #9e9e9e; }
  .live.on .pulse { background: var(--ok); animation: pulse 1.6s infinite; }
  @keyframes pulse { 0% { box-shadow: 0 0 0 0 rgba(12,163,12,.6); } 70% { box-shadow: 0 0 0 7px rgba(12,163,12,0); } 100% { box-shadow: 0 0 0 0 rgba(12,163,12,0); } }
  .page { position: relative; padding: 16px; max-width: 1600px; margin: 0 auto; height: calc(100% - var(--header-height, 56px)); overflow-y: auto; }
  .filters { display: flex; flex-direction: column; gap: 8px; margin-bottom: 16px; }
  .row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
  .spacer { flex: 1; }
  .segmented { display: inline-flex; border: 1px solid var(--line); border-radius: 8px; overflow: hidden; background: var(--surface); }
  .seg { border: 0; background: transparent; color: var(--primary-text-color); padding: 7px 12px; cursor: pointer; font: inherit; font-size: 13px; }
  .seg + .seg { border-left: 1px solid var(--line); }
  .seg.active { background: var(--accent); color: #fff; }
  .btn, select, input[type=search], input[type=datetime-local] {
    font: inherit; font-size: 13px; padding: 7px 10px; border-radius: 8px; border: 1px solid var(--line);
    background: var(--surface); color: var(--primary-text-color);
  }
  input[type=search] { min-width: 220px; flex: 1 1 220px; max-width: 360px; }
  .btn { cursor: pointer; }
  .btn:disabled { opacity: .45; cursor: default; }
  .btn.primary { background: var(--accent); color: #fff; border-color: var(--accent); }
  .dt { display: inline-flex; align-items: center; gap: 6px; font-size: 13px; color: var(--text-2); }
  .chip { display: inline-flex; align-items: center; gap: 6px; border: 1px solid var(--line); background: var(--surface);
    color: var(--primary-text-color); border-radius: 16px; padding: 5px 10px; cursor: pointer; font: inherit; font-size: 13px; }
  .chip.active { border-color: var(--accent); box-shadow: inset 0 0 0 1px var(--accent); }
  .chip.pending { background: #fff; color: #0b0b0b; border: 0; font-weight: 600; }
  .sev-chips { display: inline-flex; gap: 6px; flex-wrap: wrap; }
  .dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; flex: none; }
  .dot.ok { background: var(--ok); }
  .swatch { display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 6px; vertical-align: -1px; }
  .sev-low { background: var(--sev-low); fill: var(--sev-low); }
  .sev-medium { background: var(--sev-medium); fill: var(--sev-medium); }
  .sev-high { background: var(--sev-high); fill: var(--sev-high); }
  .sev-critical { background: var(--sev-critical); fill: var(--sev-critical); }
  .sev { display: inline-flex; align-items: center; gap: 6px; white-space: nowrap; }
  .card { background: var(--surface); border-radius: var(--ha-card-border-radius, 12px); padding: 16px;
    border: 1px solid var(--ha-card-border-color, var(--line)); margin-bottom: 16px; min-width: 0; }
  .card header { display: flex; align-items: baseline; gap: 8px; margin-bottom: 12px; }
  .card h2 { font-size: 16px; font-weight: 600; margin: 0; }
  .card header small { color: var(--muted); font-size: 12px; }
  .card.error { border-color: var(--sev-high); color: var(--sev-high); }
  .grid.two { display: grid; grid-template-columns: minmax(0, 2fr) minmax(0, 1fr); gap: 16px; }
  .grid.two > .card { margin-bottom: 16px; }
  @media (max-width: 1000px) { .grid.two { grid-template-columns: minmax(0, 1fr); gap: 0; } }
  .kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 16px; margin-bottom: 16px; }
  .kpi { background: var(--surface); border: 1px solid var(--ha-card-border-color, var(--line)); border-radius: var(--ha-card-border-radius, 12px); padding: 14px 16px; }
  .kpi .label { color: var(--text-2); font-size: 13px; }
  .kpi .value { font-size: 26px; font-weight: 600; margin-top: 4px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .kpi.hero .value { font-size: 48px; line-height: 1.05; }
  .kpi .sub { color: var(--text-2); font-size: 12px; margin-top: 4px; display: flex; gap: 6px; align-items: center; }
  .legend { display: flex; flex-wrap: wrap; gap: 14px; font-size: 12px; color: var(--text-2); margin-bottom: 8px; }
  .timeline-body { width: 100%; min-height: 220px; }
  svg { display: block; overflow: visible; }
  svg .grid { stroke: var(--line); stroke-width: 1; }
  svg .axis { stroke: var(--muted); stroke-width: 1; }
  svg .tick { fill: var(--muted); font-size: 11px; font-variant-numeric: tabular-nums; }
  svg .hit { fill: transparent; cursor: zoom-in; }
  svg .hit.hovered { fill: var(--primary-text-color); fill-opacity: .06; }
  .hbars { display: flex; flex-direction: column; gap: 4px; }
  .hbar { display: grid; grid-template-columns: minmax(90px, 40%) 1fr auto; gap: 10px; align-items: center; border: 0; background: transparent;
    color: var(--primary-text-color); font: inherit; font-size: 13px; padding: 5px 4px; border-radius: 6px; cursor: pointer; text-align: left; }
  .hbar:hover, .hbar.hovered, .hbar:focus-visible { background: color-mix(in srgb, var(--primary-text-color) 6%, transparent); }
  .hbar.active { box-shadow: inset 3px 0 0 var(--accent); }
  .hlabel { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .htrack { height: 12px; }
  .hfill { display: block; height: 12px; background: var(--accent); border-radius: 0 4px 4px 0; }
  .hvalue { font-variant-numeric: tabular-nums; color: var(--text-2); min-width: 3ch; text-align: right; }
  .table-wrap { overflow-x: auto; }
  .table { width: 100%; border-collapse: collapse; font-size: 13px; }
  .table th { text-align: left; font-weight: 500; color: var(--text-2); border-bottom: 1px solid var(--line); padding: 8px; white-space: nowrap; }
  .table td { border-bottom: 1px solid var(--line); padding: 8px; vertical-align: top; font-variant-numeric: tabular-nums; }
  .table.compact td { padding: 6px 8px; }
  .table .num { text-align: right; }
  .clickable { cursor: pointer; }
  .clickable:hover { background: color-mix(in srgb, var(--primary-text-color) 4%, transparent); }
  tr.fresh { animation: fresh 2.5s ease-out; }
  @keyframes fresh { from { background: var(--fresh); } to { background: transparent; } }
  tr.detail td { background: color-mix(in srgb, var(--primary-text-color) 3%, transparent); }
  pre { white-space: pre-wrap; word-break: break-all; font-size: 12px; margin: 4px 0 0; padding: 8px; border-radius: 6px;
    background: color-mix(in srgb, var(--primary-text-color) 6%, transparent); }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
  .nowrap { white-space: nowrap; }
  .ellipsis { max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .muted { color: var(--muted); }
  .small { font-size: 12px; }
  .err { color: var(--sev-high); }
  .badge { font-size: 10px; text-transform: uppercase; letter-spacing: .04em; border-radius: 4px; padding: 1px 5px; border: 1px solid var(--line); color: var(--text-2); }
  .badge.wan { border-color: var(--sev-high); }
  .mini { height: 4px; margin-top: 4px; background: color-mix(in srgb, var(--accent) 15%, transparent); border-radius: 2px; }
  .mini span { display: block; height: 4px; background: var(--accent); border-radius: 2px; }
  .source { display: flex; gap: 10px; align-items: flex-start; padding: 8px 0; border-bottom: 1px solid var(--line); font-size: 13px; }
  .source .dot { margin-top: 4px; }
  .by-source { margin-top: 12px; font-size: 13px; }
  .pager { display: flex; gap: 12px; align-items: center; justify-content: flex-end; margin-top: 12px; font-size: 13px; color: var(--text-2); }
  .empty { padding: 24px 8px; text-align: center; }
  .tooltip { position: absolute; z-index: 10; pointer-events: none; min-width: 180px; max-width: 320px; padding: 8px 10px; border-radius: 8px;
    background: var(--surface); color: var(--primary-text-color); border: 1px solid var(--line);
    box-shadow: 0 4px 16px rgba(0,0,0,.18); font-size: 12px; }
  .tt-title { font-weight: 600; margin-bottom: 6px; }
  .tt-row { display: flex; justify-content: space-between; gap: 16px; padding: 1px 0; font-variant-numeric: tabular-nums; }
  .tt-row.total { border-top: 1px solid var(--line); margin-top: 4px; padding-top: 4px; }
  @media (max-width: 700px) {
    .page { padding: 12px; }
    .hide-narrow { display: none; }
    .kpi.hero .value { font-size: 40px; }
    input[type=search] { max-width: none; }
  }
`;

if (!customElements.get("ha-sentinel-panel")) {
  customElements.define("ha-sentinel-panel", HaSentinelPanel);
}
