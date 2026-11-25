const state = {
  me: null,
  health: { demo: false },
  view: "mission",
  settings: null,
  secrets: [],
  connectors: null,
  catalog: [],
  tools: [],
  audit: [],
  runs: [],
  run: null,
  findings: [],
  report: "",
  log: [],
  banner: null,
  busy: false,
  demoLoaded: false,
  connectorStatus: {},
  mcpOutput: "",
  requestedProvider: "",
};

const app = document.getElementById("app");
let source = null;

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[ch]));
}

function detailOf(data, fallback) {
  if (!data) return fallback;
  if (typeof data.detail === "string") return data.detail;
  if (Array.isArray(data.detail)) {
    return data.detail.map((item) => item.msg || "Check the form.").join(" ");
  }
  return fallback;
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      "X-CYBOT": "1",
      ...(options.headers || {}),
    },
  });
  const text = await response.text();
  let data = null;
  if (text) {
    try { data = JSON.parse(text); } catch { data = { detail: text.slice(0, 180) }; }
  }
  if (response.status === 401 && path !== "/api/login" && path !== "/api/me") {
    state.me = { authed: false, needs_setup: false };
    render();
    throw new Error("Sign in.");
  }
  if (!response.ok) throw new Error(detailOf(data, response.statusText));
  return data;
}

async function boot() {
  state.health = await (await fetch("/api/health")).json();
  const response = await fetch("/api/me");
  if (response.status === 200) {
    state.me = await response.json();
    if (state.me.authed) await loadShell();
  } else {
    state.me = { authed: false, needs_setup: false, demo: state.health.demo };
  }
  render();
}

async function loadShell() {
  const [settings, catalog, tools, audit, runs, connectors] = await Promise.all([
    api("/api/settings"),
    api("/api/catalog"),
    api("/api/tools"),
    api("/api/audit"),
    api("/api/runs"),
    api("/api/connectors"),
  ]);
  state.settings = settings.settings;
  state.secrets = settings.secrets;
  state.catalog = catalog.catalog;
  state.tools = tools.tools;
  state.audit = audit.audit;
  state.runs = runs.runs;
  state.connectors = connectors;
}

function render() {
  if (!state.me) {
    app.innerHTML = `<main class="auth"><p class="eyebrow">CYBOT</p><h1 class="word">Checking the gate</h1></main>`;
    return;
  }
  if (state.me.needs_setup) {
    app.innerHTML = authCard("Set the dashboard password", "setup", "This password locks the dashboard. It is stored as a scrypt hash.");
    return;
  }
  if (!state.me.authed) {
    app.innerHTML = authCard("Sign in", "login", "CYBOT keeps provider keys encrypted. This password only opens the dashboard.");
    return;
  }
  app.innerHTML = shell();
  paintLog();
  const report = document.getElementById("report");
  if (report) report.textContent = state.report || "No report yet. Finish a run and the Markdown report will appear here.";
  if (state.view === "settings") kickConnectorTests();
  if ((state.view === "findings" || state.view === "report") && !state.run && state.runs.length) {
    const latest = state.runs[0].id;
    if (state.loadingRun !== latest && state.runLoadFailed !== latest) openRun(latest);
  }
}

function authCard(title, action, help) {
  return `
    <main class="auth">
      <div class="top auth-top">
        <div class="mark" aria-hidden="true">C</div>
        <div>
          <p class="eyebrow">Scope-gated recon</p>
          <h1 class="word">CYBOT</h1>
        </div>
      </div>
      <section class="card">
        <h2>${esc(title)}</h2>
        <p class="help">${esc(help)}</p>
        <form id="${action}Form">
          <label for="password">Password, at least 10 characters</label>
          <input id="password" name="password" type="password" autocomplete="${action === "setup" ? "new-password" : "current-password"}" data-testid="login-password" required minlength="10" />
          ${action === "setup" ? `<label for="confirm">Type it again</label><input id="confirm" name="confirm" type="password" autocomplete="new-password" required minlength="10" />` : ""}
          <div class="row"><button class="btn primary" type="submit" data-testid="login-submit">${action === "setup" ? "Create password" : "Enter"}</button></div>
        </form>
        ${state.banner ? `<p class="banner bad">${esc(state.banner)}</p>` : ""}
      </section>
    </main>`;
}

function shell() {
  const settings = state.settings || {};
  const page = pageCopy();
  return `
    <div class="shell">
      <aside class="rail">
        <div class="brand">
          <div class="mark" aria-hidden="true">C</div>
          <div>
            <p class="eyebrow">Scope-gated recon</p>
            <p class="word">CYBOT</p>
          </div>
        </div>
        <nav class="nav" aria-label="Sections">
          ${navButton("mission", "Mission")}
          ${navButton("findings", "Findings")}
          ${navButton("report", "Report")}
          ${navButton("terminal", "Terminal")}
          ${navButton("tools", "Tools")}
          ${navButton("settings", "Settings")}
        </nav>
      </aside>
      <div class="workspace">
        <header class="pagehead">
          <h1>${esc(page.title)}</h1>
          <p class="lede">${esc(page.lede)}</p>
        </header>
        ${mockFallback() ? `<div class="banner bad mock-banner" data-testid="mock-banner">This run fell back to Mock. The provider you selected did not answer. Check the key or the connector grant, then run again.</div>` : ""}
        <main class="layout">${view(settings)}</main>
        <footer class="note">Scope is checked before any packet. Out-of-scope hosts are refused. Active-test waits for confirmation.</footer>
      </div>
    </div>`;
}

function pageCopy() {
  const pages = {
    mission: ["Mission", "Set the scope, pick the provider, and start recon."],
    findings: ["Findings", "Notes that share a type are grouped. Explain writes one short paragraph."],
    report: ["Report", "Final status, the provider that answered, and the export."],
    terminal: ["Terminal", "Allowlisted commands only. Each host is checked before the process starts."],
    tools: ["Tools", "What this machine can run, and what CYBOT will not install."],
    settings: ["Settings", "OpenCode is primary. Gemini is the live connector. Ollama Cloud is optional."],
  };
  const pair = pages[state.view] || pages.mission;
  return { title: pair[0], lede: pair[1] };
}

function navButton(id, label) {
  const current = state.view === id ? ' aria-current="page"' : "";
  return `<button type="button" data-action="nav" data-view="${id}"${current}>${label}</button>`;
}

function view(settings) {
  if (state.view === "findings") return findingsView();
  if (state.view === "report") return reportView();
  if (state.view === "terminal") return terminalView();
  if (state.view === "tools") return toolsView();
  if (state.view === "settings") return settingsView(settings);
  return missionView(settings);
}

function draft() {
  return state.draft || {
    program: "",
    include: "",
    exclude: "",
    authorization: "",
    target: "",
    intensity: "passive",
    mode: "passive",
    attestation: "",
    active: false,
    provider: "",
    model: "",
  };
}

function rememberMission(form) {
  if (!form) return;
  const data = Object.fromEntries(new FormData(form).entries());
  state.draft = {
    program: data.program || "",
    include: data.include || "",
    exclude: data.exclude || "",
    authorization: data.authorization || "",
    target: data.target || "",
    intensity: data.intensity || "passive",
    mode: data.mode || "passive",
    attestation: data.attestation || "",
    active: Boolean(form.elements.active_approved && form.elements.active_approved.checked),
    notionYes: Boolean(form.elements.notion_yes && form.elements.notion_yes.checked),
    provider: data.run_provider || "",
    model: data.run_model || "",
  };
}

function missionView(settings) {
  const saved = draft();
  const provider = saved.provider || settings.provider || "opencode";
  const model = saved.model || settings.model || "";
  const demo = state.health.demo
    ? `<button class="btn" type="button" data-action="demo" data-testid="load-demo">Load example.com demo</button>
       <button class="btn" type="button" data-action="local-demo" data-testid="load-local-demo">Load local demo</button>`
    : "";
  const answered = state.run
    ? `<p class="answered" data-testid="answered">Answered by <strong>${esc(providerTitle(state.run.provider))}</strong>${state.run.model ? ` · ${esc(state.run.model)}` : ""}</p>`
    : "";
  return `
    <div class="split">
      <section class="card">
        <h2>Scope</h2>
        <p class="help">Paste only assets the program lists. <span class="pill">*.example.com</span> is one label deep. <span class="pill">.example.com</span> includes the apex and every subdomain. Anything else is refused and written to the audit log.</p>
        ${state.banner ? `<div class="banner ${state.banner.kind}" data-testid="scope-result">${esc(state.banner.text)}</div>` : ""}
        <form id="missionForm">
          <label for="program">Program</label>
          <input id="program" name="program" required value="${esc(saved.program)}" />
          <label for="include">In scope, one host or wildcard per line</label>
          <textarea id="include" name="include" required placeholder="example.com&#10;*.example.com">${esc(saved.include)}</textarea>
          <label for="exclude">Excluded</label>
          <textarea id="exclude" name="exclude" placeholder="payments.example.com">${esc(saved.exclude)}</textarea>
          <label for="authorization">Authorization you hold</label>
          <textarea id="authorization" name="authorization" required minlength="20" placeholder="I am authorized to test these assets under the program rules.">${esc(saved.authorization)}</textarea>
          <label for="target">Target</label>
          <input id="target" name="target" required data-testid="target" placeholder="www.example.com" value="${esc(saved.target)}" />
          <label for="mode">Scanning mode</label>
          <select id="mode" name="mode" data-testid="scan-mode">
            <option value="passive" ${saved.mode === "passive" ? "selected" : ""}>Passive - no packets to the target</option>
            <option value="soft-active" ${saved.mode === "soft-active" ? "selected" : ""}>Soft-active - homepage, headers, fixed ports</option>
            <option value="active-test" ${saved.mode === "active-test" ? "selected" : ""}>Active-test - opt-in, attestation required</option>
          </select>
          <input type="hidden" name="intensity" value="${esc(saved.mode === "active-test" ? "standard" : saved.mode === "soft-active" ? "light" : "passive")}" />
          <label for="attestation">Attestation (required for active-test)</label>
          <textarea id="attestation" name="attestation" minlength="40" placeholder="I am authorized to run non-destructive checks on the in-scope assets.">${esc(saved.attestation || "")}</textarea>
          <p class="help">Passive uses resolvers, certificate logs, and RDAP. Soft-active adds one homepage fetch, headers, and a fixed web-port list. Active-test also allows locked optional binaries after you approve the check and write an attestation. Missing binaries are skipped.</p>
          <label for="run_provider">Provider for this run</label>
          <select id="run_provider" name="run_provider" data-testid="run-provider">
            ${providerOptions(provider)}
          </select>
          <label for="run_model">Model</label>
          <input id="run_model" name="run_model" data-testid="run-model" value="${esc(model)}" placeholder="${esc(defaultModelPlaceholder(provider))}" />
          <label class="checks"><input id="active" name="active_approved" type="checkbox" ${saved.active ? "checked" : ""} /> <span>I approve active checks only against the hosts listed above, at this intensity.</span></label>
          <label class="checks"><input id="notion_yes" name="notion_yes" type="checkbox" data-testid="notion-yes" ${saved.notionYes ? "checked" : ""} ${notionLocked(settings)} /> <span>Create a Notion page when this run finishes. Leave this off to be asked after the report is ready.</span></label>
          <div class="row">
            <button class="btn" type="button" data-action="check" data-testid="check-scope">Check scope</button>
            <button class="btn" type="button" data-action="notion-scope">Load scope from Notion</button>
            <button class="btn primary" type="submit" data-testid="start-recon" ${state.busy ? "disabled" : ""}>Start recon</button>
            ${demo}
          </div>
        </form>
        <p class="help">Saved default: <strong>${esc(modelLabel(settings))}</strong>. OpenCode is primary. Ollama Cloud is optional and runs only if you select it.</p>
      </section>
      <section class="card log-card">
        <h2>Live log</h2>
        ${answered}
        <div id="log" class="log" data-testid="log">${state.log.length ? "" : "No run yet. Start recon and events will stream here."}</div>
      </section>
    </div>`;
}

function mockFallback() {
  if (!state.run || state.run.provider !== "mock") return false;
  const requested = state.requestedProvider || (state.settings && state.settings.provider) || "opencode";
  return requested !== "mock";
}

function defaultModelPlaceholder(provider) {
  if (provider === "opencode") return "deepseek-v4.1-flash";
  if (String(provider).includes("gemini")) return "gemini-flash-lite-latest";
  if (provider === "ollama-local" || provider === "ollama") return "qwen2.5:1.5b";
  return "model id from the provider";
}

function notionLocked(settings) {
  const mode = (settings && settings.notion_publish) || "ask";
  if (mode === "always" || mode === "never") return "disabled";
  return "";
}

function notionPrompt() {
  const run = state.run;
  const mode = (state.settings && state.settings.notion_publish) || "ask";
  if (!run || run.notion !== "ask" || mode !== "ask" || run.status === "running") return "";
  return `
    <section class="card" data-testid="notion-prompt">
      <h2>Create a Notion page for ${esc(run.target)}?</h2>
      <p class="help">Nothing is sent to Notion until you choose Yes.</p>
      <div class="row">
        <button class="btn primary" type="button" data-action="notion-publish" data-id="${esc(run.id)}">Yes</button>
        <button class="btn" type="button" data-action="notion-decline" data-id="${esc(run.id)}">No</button>
      </div>
    </section>`;
}

function trackRun(run) {
  if (!run || !run.id) return;
  const rest = state.runs.filter((item) => item.id !== run.id);
  state.runs = [{ ...run }, ...rest];
}

function runLabel(run) {
  let host = String(run.target || "run");
  if (host.length > 28) host = `${host.slice(0, 27)}...`;
  return `${host} - ${pickerStatus(run.status)}`;
}

function pickerStatus(status) {
  if (status === "complete") return "Complete";
  if (status === "running") return "Running";
  if (status === "error") return "Failed";
  if (status === "refused") return "Refused";
  return statusLabel(status);
}

function runPicker() {
  if (!state.runs.length) {
    return `<section class="card" data-testid="run-history"><h2>Runs</h2><p class="empty">No runs yet. Start one from Mission, then come back here.</p></section>`;
  }
  const current = state.run && state.run.id;
  const options = state.runs.map((run) =>
    `<option value="${esc(run.id)}" ${run.id === current ? "selected" : ""}>${esc(runLabel(run))}</option>`
  ).join("");
  const waiting = !state.run ? `<p class="empty">Loading the latest run.</p>` : "";
  return `<section class="card" data-testid="run-history"><h2>Runs</h2><p class="help">Saved on the server. After a reload, this opens the latest run.</p><label for="runPicker">Run</label><select id="runPicker" data-testid="run-picker">${options}</select>${waiting}</section>`;
}

function findingsView() {
  const prompt = notionPrompt();
  const history = runPicker();
  const groups = groupFindings(state.findings);
  if (!state.run) {
    return `${history}<section class="card"><h2>Findings</h2><p class="empty">${state.runs.length ? "Loading the latest run." : "No findings yet. A refused target is written to the authorization log, not listed here."}</p></section>`;
  }
  if (!groups.length) {
    return `${history}${targetNotes()}${prompt}<section class="card"><h2>Findings</h2><p class="empty">No findings yet. A refused target is written to the authorization log, not listed here.</p></section>`;
  }
  const exportName = state.run
    ? `cybot-${String(state.run.target || "run").replace(/[^A-Za-z0-9._-]+/g, "-")}-${state.run.id}.md`
    : "cybot-report.md";
  const exportLink = state.run
    ? `<a class="btn" href="/api/runs/${esc(state.run.id)}/report.md" download="${esc(exportName)}">Export report</a>`
    : "";
  const cards = groups.map((group) => `
    <article class="finding" data-testid="finding-card">
      <span class="sev ${esc(group.severity)}">${esc(group.severity)}</span>
      <strong>${esc(group.title)}</strong>
      <p class="evidence">${esc(group.hosts.length)} host${group.hosts.length === 1 ? "" : "s"} - ${esc(group.hosts.join(", "))} - ${esc(group.tool)}</p>
      ${submissionCard(group)}
      ${group.explained ? `<p class="plain" id="plain-${esc(group.id)}">${esc(group.plain)}</p>` : `<p class="plain muted" id="plain-${esc(group.id)}"></p>`}
      ${playbookDetails(group.playbook)}
      ${askPanel(group)}
    </article>`).join("");
  return `${history}${prompt}<section class="card" data-testid="findings"><h2>Findings</h2><p class="help">Each card is a draft for a person to retest. Export report downloads the run as Markdown.</p><div class="row">${exportLink}</div>${cards}</section>`;
}

function targetNotes() {
  const notes = state.run && state.run.target_playbook;
  if (!notes) return "";
  const scope = notes.scope || {};
  const list = (items) => (items || []).map((item) => `<li>${esc(item)}</li>`).join("") || "<li>None recorded.</li>";
  return `
    <section class="card" data-testid="target-notes">
      <h2>Target notes</h2>
      <p class="help">${esc(notes.disclaimer || "")}</p>
      <p>${esc(notes.surface || "")}</p>
      <h3>Tech stack</h3>
      <ul>${list(notes.stack)}</ul>
      <h3>Exposed services</h3>
      <ul>${list(notes.services)}</ul>
      <h3>Endpoints</h3>
      <ul>${list(notes.endpoints)}</ul>
      <h3>Scope</h3>
      <p class="evidence">In: ${esc((scope.include || []).join(", ") || "see the run")}</p>
      <p class="evidence">Out: ${esc((scope.exclude || []).join(", ") || "none recorded")}</p>
      <p class="help">${esc(scope.reminder || "")}</p>
    </section>`;
}

function submissionCard(group) {
  const book = group.playbook || {};
  const byClass = { xss: "CWE-79", sqli: "CWE-89", headers: "CWE-693", cve: "CWE-1395" };
  const weakness = (book.references || []).map((item) => item.label).find((label) => String(label).startsWith("CWE-")) || byClass[book.class] || "Not classified";
  const impact = book.impact || "Unverified until a person retests it.";
  const human = group.needsHuman === false ? "no" : "yes";
  return `
    <details class="playbook" open>
      <summary>Submission card</summary>
      <p><strong>Severity.</strong> ${esc(group.severity)}. Not a confirmed CVSS score.</p>
      <p><strong>Asset.</strong> <code>${esc((group.hosts || []).join(", "))}</code></p>
      <p><strong>Weakness.</strong> ${esc(weakness)}</p>
      <p><strong>Summary.</strong> ${esc(group.plain || "")}</p>
      <p><strong>Impact.</strong> ${esc(impact)}</p>
      ${group.repro ? `<p><strong>Steps.</strong></p><pre class="log">${esc(group.repro)}</pre>` : ""}
      ${group.evidence ? `<p><strong>Evidence.</strong> ${esc(group.evidence)}</p>` : ""}
      <p><strong>Validation.</strong> Confidence ${esc(group.confidence || "n/a")}. Needs human validation: ${human}.</p>
      <button class="btn" type="button" data-action="copy-card" data-id="${esc(group.id)}" data-testid="copy-card">Copy as Markdown</button>
    </details>`;
}

function renderChatMarkdown(text) {
  const source = esc(text || "");
  const pieces = source.split("```");
  return pieces.map((part, index) => {
    if (index % 2 === 1) {
      const code = part.replace(/^\n/, "").replace(/\n$/, "");
      return `<div class="md-code"><button type="button" class="btn" data-action="copy-code">Copy</button><pre class="log"><code>${code}</code></pre></div>`;
    }
    return renderChatText(part);
  }).join("");
}

function renderChatText(escaped) {
  const lines = escaped.split("\n");
  let html = "";
  let items = "";
  const flush = () => {
    if (!items) return;
    html += `<ul>${items}</ul>`;
    items = "";
  };
  const inline = (value) => value
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
    .replace(/`([^`]+)`/g, "<code>$1</code>");
  for (const line of lines) {
    const heading = /^(#{1,3}) (.+)$/.exec(line);
    const item = /^(?:[-*]|\d+\.) (.+)$/.exec(line);
    if (heading) {
      flush();
      const level = heading[1].length + 2;
      html += `<h${level}>${inline(heading[2])}</h${level}>`;
    } else if (item) {
      items += `<li>${inline(item[1])}</li>`;
    } else if (!line.trim()) {
      flush();
    } else {
      flush();
      html += `<p>${inline(line)}</p>`;
    }
  }
  flush();
  return html;
}

function chatLog(group) {
  return (group.chat || []).map((row) => {
    const body = row.role === "assistant" ? renderChatMarkdown(row.body) : `<p>${esc(row.body)}</p>`;
    return `<div class="chat-line"><p class="evidence">${esc(row.role)}</p>${body}</div>`;
  }).join("");
}

function askPanel(group) {
  const open = state.openAsk === group.id ? "open" : "";
  const chips = [
    ["explain", "Explain"],
    ["impact", "Impact"],
    ["retest", "Retest steps"],
    ["fix", "Fix / remediation"],
    ["research", "Related research"],
  ].map(([action, label]) =>
    `<button class="btn" type="button" data-action="assist" data-assist="${action}" data-id="${esc(group.id)}">${label}</button>`
  ).join("");
  return `
    <details class="playbook" ${open} data-testid="ask-cybot">
      <summary>Ask CYBOT</summary>
      <p class="help">Guidance for a person to retest this in-scope asset. Not an exploit.</p>
      <div class="row">${chips}</div>
      <label for="ask-${esc(group.id)}">Question</label>
      <textarea id="ask-${esc(group.id)}" data-chat="${esc(group.id)}" placeholder="Ask about this finding"></textarea>
      <div class="row">
        <button class="btn primary" type="button" data-action="assist" data-assist="ask" data-id="${esc(group.id)}">Send</button>
      </div>
      <div class="chat-log" id="chat-${esc(group.id)}">${chatLog(group)}</div>
    </details>`;
}

function furtherBlock(book) {
  const items = (book.further_reading || []).filter((item) => item && item.url && item.url.startsWith("http"));
  if (!items.length) return "";
  const links = items.map((item) => `<li><a href="${esc(item.url)}" rel="noreferrer">${esc(item.label || item.url)}</a></li>`).join("");
  return `
    <details class="playbook" data-testid="further-reading">
      <summary>Further reading / techniques</summary>
      <p class="help">From the vendored catalog. Separate from the CVE reference links.</p>
      <ul>${links}</ul>
    </details>`;
}

function playbookDetails(book) {
  if (!book) return "";
  const steps = (book.verify || []).map((item) => `<li><code>${esc(item)}</code></li>`).join("");
  const next = (book.next_steps || []).map((item) => `<li>${esc(item)}</li>`).join("");
  const evidence = (book.evidence || []).map((item) => `<li>${esc(item)}</li>`).join("");
  const checks = (book.false_positive || []).map((item) => `<li>${esc(item)}</li>`).join("");
  const refs = (book.references || []).map((item) =>
    `<li><a href="${esc(item.url)}" rel="noreferrer">${esc(item.label)}</a></li>`
  ).join("");
  const kev = book.kev === true ? "listed" : book.kev === false ? "not listed" : "not available";
  return `
    <details class="playbook">
      <summary>Next steps</summary>
      <p>${esc(book.why || "")}</p>
      <p class="evidence">Likelihood: ${esc(book.likelihood || "")}</p>
      <p class="evidence">Impact: ${esc(book.impact || "")}</p>
      <p class="evidence">KEV: ${esc(kev)}. EPSS: ${esc(book.epss || "not available")}.</p>
      <ul>${steps}${next}</ul>
      <p class="help">Evidence to capture</p>
      <ul>${evidence}</ul>
      <p class="help">False-positive checks</p>
      <ul>${checks}</ul>
      <p class="help">${esc(book.disclaimer || "")}</p>
    </details>
    <details class="playbook">
      <summary>References</summary>
      <ul>${refs || "<li>No reference links for this note.</li>"}</ul>
    </details>
    ${furtherBlock(book)}`;
}

function groupFindings(rows) {
  const order = { high: 0, medium: 1, low: 2, info: 3 };
  const groups = new Map();
  for (const row of rows) {
    const key = `${row.title}|${row.tool}`;
    const current = groups.get(key);
    if (!current) {
      groups.set(key, {
        id: row.id,
        title: row.title,
        tool: row.tool,
        severity: row.severity || "info",
        hosts: row.host ? [row.host] : [],
        plain: row.plain || "",
        explained: Boolean(state.explained && state.explained[row.id]),
        playbook: row.playbook || null,
        confidence: row.confidence || "",
        repro: row.repro || "",
        evidence: row.evidence || "",
        needsHuman: row.needs_human_validation !== false,
        chat: row.chat || [],
      });
      continue;
    }
    if (row.host && !current.hosts.includes(row.host)) current.hosts.push(row.host);
    if ((order[row.severity] ?? 9) < (order[current.severity] ?? 9)) current.severity = row.severity;
  }
  return [...groups.values()];
}

function terminalView() {
  const run = state.run;
  if (!run) {
    return `<section class="card"><h2>Terminal</h2><p class="empty">Start a mission first. Commands are tied to that run and its scope.</p></section>`;
  }
  const lines = (state.terminal || []).map((row) =>
    `<li><span class="pill">${esc(row.status)}</span> <code>${esc(row.command)}</code><pre class="term-out">${esc(row.output || "")}</pre></li>`
  ).join("");
  const mode = run.mode || "passive";
  const hint = mode === "active-test"
    ? "Active-test waits for confirmation. Submit once, then confirm."
    : "Passive and soft-active commands run after the scope check.";
  return `
    <section class="card" data-testid="terminal">
      <h2>Terminal</h2>
      <p class="help">${hint} Mode: ${esc(mode)}. Output is capped and each command times out.</p>
      <form id="terminalForm">
        <label for="command">Command</label>
        <input id="command" name="command" data-testid="terminal-command" autocomplete="off" placeholder="dig www.example.com" />
        <div class="row">
          <button class="btn primary" type="submit" data-testid="terminal-run">Run</button>
          <button class="btn" type="submit" name="confirm" value="1" data-testid="terminal-confirm">Confirm</button>
          <button class="btn" type="submit" name="confirm" value="0" data-testid="terminal-deny">Deny</button>
        </div>
      </form>
      <ol class="term-log">${lines || "<li class='empty'>No commands yet.</li>"}</ol>
    </section>`;
}

function reportView() {
  const id = state.run && state.run.id;
  const links = id
    ? `<div class="row">
        <a class="btn" href="/api/runs/${esc(id)}/report.md" download="cybot-${esc(String((state.run && state.run.target) || "run").replace(/[^A-Za-z0-9._-]+/g, "-"))}-${esc(id)}.md">Download Markdown</a>
        <a class="btn" href="/api/runs/${esc(id)}/report.pdf">Download PDF</a>
      </div>`
    : "";
  const audit = state.audit.slice(0, 12).map((row) =>
    `<li><span class="pill">${esc(row.decision)}</span> ${esc(row.target)} - ${esc(row.detail)}</li>`
  ).join("");
  const head = state.run
    ? `<div class="report-head" data-testid="report-head">
        <span class="status ${esc(state.run.status)}">${esc(statusLabel(state.run.status))}</span>
        <p>Provider <strong>${esc(providerTitle(state.run.provider))}</strong></p>
        <p>Model <strong>${esc(state.run.model || "none")}</strong></p>
      </div>`
    : `<p class="empty">No report yet. Finish a run and this page will show the final status, the provider that answered, and the model.</p>`;
  return `
    ${runPicker()}
    ${targetNotes()}
    ${notionPrompt()}
    <section class="card">
      <h2>Report</h2>
      ${head}
      ${links}
      <pre id="report" class="log" data-testid="report"></pre>
    </section>
    <section class="card">
      <h2>Authorization log</h2>
      <ul>${audit || "<li class='empty'>No scope decisions yet. Check a target to see what the gate allows.</li>"}</ul>
    </section>`;
}

function statusLabel(status) {
  if (status === "complete") return "Complete";
  if (status === "running") return "Running";
  if (status === "refused") return "Refused";
  if (status === "error") return "Error";
  return status || "Unknown";
}

function toolsView() {
  const runtime = state.tools.length
    ? state.tools.map((tool) =>
        `<tr><td data-label="Tool">${esc(tool.name)}</td><td data-label="Needs">${esc(tool.intensity)}</td><td data-label="Status">${tool.available ? "ready" : esc(tool.reason)}</td></tr>`
      ).join("")
    : `<tr><td colspan="3">No tools are listed yet.</td></tr>`;
  const catalog = state.catalog.map((row) => `
    <tr>
      <td data-label="Name">${row.url ? `<a href="${esc(row.url)}">${esc(row.name)}</a>` : esc(row.name)}</td>
      <td data-label="Status" class="pill ${esc(row.status)}">${esc(row.status)}</td>
      <td data-label="License">${esc(row.license)}</td>
      <td data-label="Decision">${esc(row.why)}</td>
    </tr>`).join("");
  return `
    <section class="card">
      <h2>Ready on this machine</h2>
      <p class="help">These are the checks CYBOT can run here. A row that is not ready names the missing key, binary, or connector.</p>
      <table class="table cards"><thead><tr><th>Tool</th><th>Needs</th><th>Status</th></tr></thead><tbody>${runtime}</tbody></table>
    </section>
    <section class="card">
      <h2>Considered, and why</h2>
      <p class="help">CYBOT does not install these projects. Optional rows run only when you already have the binary or the key.</p>
      <table class="table cards"><thead><tr><th>Name</th><th>Status</th><th>License</th><th>Decision</th></tr></thead><tbody>${catalog || "<tr><td>Nothing is catalogued.</td></tr>"}</tbody></table>
    </section>`;
}

function providerTitle(provider) {
  const value = provider || "mock";
  if (value === "opencode") return "OpenCode";
  if (value === "mock") return "Mock";
  if (value === "auto") return "Auto";
  if (value === "ollama-local" || value === "ollama") return "Ollama on this machine";
  if (value.startsWith("connector:")) {
    const parts = value.split(":");
    return friendlyConnector(parts[1] || value);
  }
  if (value.startsWith("direct-")) return `Direct ${friendlyConnector(value.slice(7))}`;
  return friendlyConnector(value);
}

function friendlyConnector(provider) {
  const names = {
    gemini: "Google Gemini",
    ollama: "Ollama Cloud",
    ollama_cloud: "Ollama Cloud",
    openrouter: "OpenRouter",
    anthropic: "Anthropic",
    openai: "OpenAI",
    grok: "xAI Grok",
    firecrawl: "Firecrawl",
    notion: "Notion",
    pinecone: "Pinecone",
    exa: "Exa",
    tavily: "Tavily",
    typesafe: "TypeSafeAI Jev",
    github: "GitHub",
    tigris: "Tigris",
    s3: "S3",
    pushover: "Pushover",
  };
  return names[provider] || provider;
}

function modelLabel(settings) {
  const provider = settings.provider || "opencode";
  if (provider === "opencode") {
    const product = settings.opencode_product === "zen" ? "Zen" : "Go";
    return `OpenCode ${product} · ${settings.model || "deepseek-v4.1-flash"}`;
  }
  if (provider === "auto") {
    return `Auto · ${settings.provider_order || "opencode, then connectors"}`;
  }
  if (provider === "ollama-local" || provider === "ollama") {
    return `Ollama on this machine · ${settings.model || "qwen2.5:1.5b"}`;
  }
  return `${providerTitle(provider)}${settings.model ? " · " + settings.model : ""}`;
}

function providerOptions(selected) {
  const options = [
    ["opencode", "OpenCode (primary)"],
    ["auto", "Auto · saved provider order"],
    ["ollama-local", "Ollama on this machine (optional)"],
    ["mock", "Mock · no model call"],
  ];
  for (const item of (state.connectors && state.connectors.connectors) || []) {
    if (item.style && item.style !== "other") {
      const name = item.name || friendlyConnector(item.provider);
      options.push([`connector:${item.provider}:${item.id}`, `${name} · ${item.id}`]);
    }
  }
  options.push(
    ["direct-openrouter", "Direct OpenRouter key (fallback, covers Grok)"],
    ["direct-ollama_cloud", "Direct Ollama Cloud key (optional fallback)"],
    ["direct-anthropic", "Direct Anthropic key (fallback)"],
    ["direct-openai", "Direct OpenAI key (fallback)"],
    ["direct-gemini", "Direct Google Gemini key (fallback)"],
    ["direct-grok", "Direct xAI key (fallback, no Sprites connector)"],
  );
  return options.map(([value, label]) =>
    `<option value="${esc(value)}" ${selected === value ? "selected" : ""}>${esc(label)}</option>`
  ).join("");
}

function connectorCards() {
  if (!state.connectors) {
    return `<p class="empty">Connector status appears after this page loads.</p>`;
  }
  if (state.connectors.error) {
    return `<p class="banner info">The gateway list could not be loaded (${esc(state.connectors.error)}). Direct providers and Mock still work. The list succeeds from inside an authorized Sprite.</p>`;
  }
  const items = state.connectors.connectors || [];
  if (!items.length) {
    return `<p class="empty">No Sprites connectors are granted to this machine yet. Add one in the Fly.io dashboard, set an access policy, then refresh.</p>`;
  }
  return items.map((item) => {
    const status = state.connectorStatus[item.id];
    const kind = status ? status.status : "checking";
    const shown = status ? (status.status === "not_granted" ? "not granted" : status.status) : "checking";
    return `
      <div class="connector">
        <div>
          <strong>${esc(item.name || friendlyConnector(item.provider))}</strong>
          <span class="conn-id">${esc(item.id)}</span>
          <span class="status ${esc(kind)}" data-testid="connector-status">${esc(shown)}</span>
          ${status && status.detail ? `<p class="help">${esc(status.detail)}</p>` : ""}
        </div>
        <button class="btn" type="button" data-action="test-connector" data-provider="${esc(item.provider)}" data-id="${esc(item.id)}" data-testid="test-connector">Test</button>
      </div>`;
  }).join("");
}

function settingsView(settings) {
  const saved = state.secrets.length
    ? `<div class="keys">${state.secrets.map((name) => `<span class="key">${esc(name)} <button type="button" data-action="forget" data-name="${esc(name)}" aria-label="Remove ${esc(name)}">×</button></span>`).join("")}</div>`
    : `<p class="empty">No keys stored. Mock mode needs none. A Sprites connector keeps the model key in Fly.io.</p>`;
  const mcpBox = state.mcpOutput
    ? `<pre id="mcpResult" class="log" data-testid="mcp-output">${esc(state.mcpOutput)}</pre>`
    : "";
  return `
    <section class="card">
      <h2>Model</h2>
      <p class="help">OpenCode is the primary provider. Go is the subscription endpoint and Zen is pay as you go. Google Gemini is the active Sprites connector on the live deployment. Ollama Cloud is supported and optional: a run uses it only when you select that connector, or when you put ollama ahead of opencode in the provider order.</p>
      <form id="settingsForm">
        <fieldset class="group">
          <legend>Provider</legend>
        <label for="provider">Provider</label>
        <select id="provider" name="provider" data-testid="provider">
          ${providerOptions(settings.provider || "opencode")}
        </select>
        <label for="opencode_product">OpenCode product</label>
        <select id="opencode_product" name="opencode_product">
          <option value="go" ${settings.opencode_product !== "zen" ? "selected" : ""}>Go (subscription)</option>
          <option value="zen" ${settings.opencode_product === "zen" ? "selected" : ""}>Zen (pay as you go)</option>
        </select>
        <label for="model">Model id</label>
        <input id="model" name="model" value="${esc(settings.model || "")}" placeholder="deepseek-v4.1-flash" data-testid="model" />
        <label for="provider_order">Provider order, used only when provider is Auto</label>
        <input id="provider_order" name="provider_order" value="${esc(settings.provider_order || "")}" />
        <label for="ollama_host">ollama-local URL</label>
        <input id="ollama_host" name="ollama_host" value="${esc(settings.ollama_host || "http://127.0.0.1:11434")}" />
        </fieldset>
        <fieldset class="group">
          <legend>Notion</legend>
        <label for="notion_publish">Notion publishing</label>
        <select id="notion_publish" name="notion_publish">
          <option value="ask" ${settings.notion_publish !== "always" && settings.notion_publish !== "never" ? "selected" : ""}>Ask each run</option>
          <option value="always" ${settings.notion_publish === "always" ? "selected" : ""}>Always publish</option>
          <option value="never" ${settings.notion_publish === "never" ? "selected" : ""}>Never publish</option>
        </select>
        <label for="notion_reports_database">Notion reports database id</label>
        <input id="notion_reports_database" name="notion_reports_database" value="${esc(settings.notion_reports_database || "")}" placeholder="from the database URL" />
        <label for="notion_tracker_database">Notion findings tracker database id</label>
        <input id="notion_tracker_database" name="notion_tracker_database" value="${esc(settings.notion_tracker_database || "")}" />
        <label for="notion_programs_database">Notion Programs &amp; Scope database id</label>
        <input id="notion_programs_database" name="notion_programs_database" value="${esc(settings.notion_programs_database || "")}" />
        </fieldset>
        <fieldset class="group">
          <legend>Memory, Jev, and GitHub</legend>
        <label for="pinecone_index">Pinecone index name</label>
        <input id="pinecone_index" name="pinecone_index" value="${esc(settings.pinecone_index || "")}" placeholder="first index if blank" />
        <label for="pinecone_embed_model">Pinecone embed model</label>
        <input id="pinecone_embed_model" name="pinecone_embed_model" value="${esc(settings.pinecone_embed_model || "multilingual-e5-large")}" />
        <label for="jev_model">TypeSafeAI Jev model</label>
        <input id="jev_model" name="jev_model" value="${esc(settings.jev_model || "jev-latest")}" />
        <label for="github_org">GitHub org for public code paths (optional)</label>
        <input id="github_org" name="github_org" value="${esc(settings.github_org || "")}" placeholder="only the program's org" />
        <label for="github_repo">GitHub repo for report export (optional)</label>
        <input id="github_repo" name="github_repo" value="${esc(settings.github_repo || "")}" placeholder="owner/name" />
        <label for="github_export">Export the report through the GitHub connector</label>
        <select id="github_export" name="github_export">
          <option value="" ${settings.github_export !== "1" ? "selected" : ""}>No</option>
          <option value="1" ${settings.github_export === "1" ? "selected" : ""}>Yes</option>
        </select>
        </fieldset>
        <div class="row"><button class="btn primary" type="submit">Save settings</button></div>
      </form>
    </section>
    <section class="card">
      <h2>Sprites connectors</h2>
      <p class="help">Each row is a connector granted to this machine. Test runs a small gateway call and shows ok, error, or not granted. The id under the name is the connection id.</p>
      <div id="connectors">${connectorCards()}</div>
      <div class="row"><button class="btn" type="button" data-action="connectors" data-testid="refresh-connectors">Refresh connector list</button></div>
    </section>
    <section class="card">
      <h2>Encrypted keys</h2>
      ${saved}
      <form id="secretForm">
        <label for="secretName">Which key</label>
        <select id="secretName" name="name">
          ${["opencode", "shodan", "virustotal", "nvd", "telegram", "pushover_user", "ollama", "openrouter", "gemini", "grok", "anthropic", "openai"].map((name) => `<option value="${name}">${name}</option>`).join("")}
        </select>
        <label for="secretValue">Value</label>
        <input id="secretValue" name="value" type="password" autocomplete="off" data-testid="secret-value" />
        <div class="row"><button class="btn" type="submit">Store encrypted</button></div>
      </form>
    </section>
    <section class="card">
      <h2>Attached MCP servers</h2>
      <p class="help">Default deny. Name the tools you allow. The denylist still blocks exploit, fuzzer, and credential tools. Calls receive only <span class="pill">{target}</span>.</p>
      <form id="mcpForm">
        <label for="mcp">JSON config</label>
        <textarea id="mcp" name="config" placeholder='{"servers":[{"name":"notes","transport":"http","url":"https://example.test/mcp","mode":"passive","allow":["get_domain_report"]}]}'></textarea>
        <div class="row">
          <button class="btn" type="submit">Save MCP config</button>
          <button class="btn" type="button" data-action="discover">Check attached servers</button>
        </div>
      </form>
      ${mcpBox}
    </section>
    <div class="row"><button class="btn" type="button" data-action="logout">Sign out</button></div>`;
}

function paintLog() {
  const node = document.getElementById("log");
  if (!node) return;
  node.textContent = state.log.length
    ? state.log.map((row) => `${row.ts || ""}  ${row.message}`).join("\n")
    : "No run yet. Start recon and events will stream here.";
}

function scopeFromForm(form) {
  const data = Object.fromEntries(new FormData(form).entries());
  return {
    program: data.program,
    include: data.include.split(/\n+/).map((line) => line.trim()).filter(Boolean),
    exclude: data.exclude.split(/\n+/).map((line) => line.trim()).filter(Boolean),
    authorization: data.authorization,
    target: data.target.trim(),
    mode: data.mode || "passive",
    intensity: data.mode === "active-test" ? "standard" : data.mode === "soft-active" ? "light" : "passive",
    attestation: data.attestation || "",
    active_approved: form.elements.active_approved.checked,
    notion: form.elements.notion_yes && form.elements.notion_yes.checked ? "yes" : "ask",
    demo: (state.demoLoaded && (data.target.trim() === "example.com" || data.target.trim() === "www.example.com")) || (state.localDemo && data.target.trim() === "127.0.0.1"),
    provider: data.run_provider || "",
    model: data.run_model || "",
  };
}

async function refreshRunData() {
  if (!state.run) return;
  state.run = await api(`/api/runs/${state.run.id}`);
  trackRun(state.run);
  state.findings = (await api(`/api/runs/${state.run.id}/findings`)).findings;
  state.audit = (await api("/api/audit")).audit;
  if (state.run.status === "running") return;
  try {
    const response = await fetch(`/api/runs/${state.run.id}/report.md`);
    state.report = response.ok ? await response.text() : "";
  } catch { state.report = ""; }
}

function watch(runId) {
  if (source) source.close();
  source = new EventSource(`/api/runs/${runId}/events`);
  source.onmessage = (event) => {
    const row = JSON.parse(event.data);
    if (row && row.message) {
      state.log.push(row);
      paintLog();
    }
  };
  source.addEventListener("done", async () => {
    source.close();
    state.busy = false;
    await refreshRunData();
    render();
  });
}

document.body.addEventListener("submit", async (event) => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement)) return;
  event.preventDefault();
  state.banner = null;
  try {
    if (form.id === "setupForm") {
      if (form.password.value !== form.confirm.value) throw new Error("The two passwords do not match.");
      await api("/api/setup", { method: "POST", body: JSON.stringify({ password: form.password.value }) });
      state.me = { authed: true, needs_setup: false, demo: state.health.demo };
      await loadShell();
      render();
      return;
    }
    if (form.id === "loginForm") {
      await api("/api/login", { method: "POST", body: JSON.stringify({ password: form.password.value }) });
      state.me = { authed: true, needs_setup: false, demo: state.health.demo };
      await loadShell();
      render();
      return;
    }
    if (form.id === "missionForm") {
      rememberMission(form);
      const body = scopeFromForm(form);
      if (body.mode !== "passive" && !body.active_approved) {
        throw new Error("Check the approval box before a soft-active or active-test run.");
      }
      if (body.mode === "active-test" && (body.attestation || "").trim().length < 40) {
        throw new Error("Active-test needs an attestation of at least 40 characters.");
      }
      state.busy = true;
      state.log = [];
      state.requestedProvider = body.provider || (state.settings && state.settings.provider) || "opencode";
      state.explained = {};
      render();
      const run = await api("/api/runs", { method: "POST", body: JSON.stringify(body) });
      state.run = run;
      trackRun(run);
      watch(run.id);
      if (run.status !== "running") {
        await refreshRunData();
        state.busy = false;
        state.view = "findings";
        render();
      }
      return;
    }
    if (form.id === "terminalForm") {
      const submitter = event.submitter;
      const data = new FormData(form);
      if (submitter && submitter.name) data.set(submitter.name, submitter.value);
      const fields = Object.fromEntries(data.entries());
      if (!state.run) throw new Error("Start a mission first.");
      const choice = submitter && submitter.name === "confirm" ? submitter.value : "";
      const result = await api(`/api/runs/${state.run.id}/terminal`, {
        method: "POST",
        body: JSON.stringify({
          command: fields.command || "",
          confirm: choice === "1",
          deny: choice === "0",
        }),
      });
      state.terminal = (await api(`/api/runs/${state.run.id}/terminal`)).lines;
      state.banner = { kind: result.status === "refused" ? "bad" : "ok", text: result.output || result.status };
      state.view = "terminal";
      render();
      return;
    }
    if (form.id === "settingsForm") {
      const data = Object.fromEntries(new FormData(form).entries());
      const saved = await api("/api/settings", { method: "PUT", body: JSON.stringify(data) });
      state.settings = saved.settings;
      state.banner = { kind: "ok", text: "Provider saved." };
      state.view = "settings";
      render();
      return;
    }
    if (form.id === "secretForm") {
      const data = Object.fromEntries(new FormData(form).entries());
      const saved = await api("/api/secrets", { method: "POST", body: JSON.stringify(data) });
      state.secrets = saved.secrets;
      form.elements.value.value = "";
      render();
      return;
    }
    if (form.id === "mcpForm") {
      const parsed = JSON.parse(form.elements.config.value || '{"servers":[]}');
      const saved = await api("/api/mcp/servers", { method: "PUT", body: JSON.stringify(parsed) });
      state.mcpOutput = JSON.stringify(saved, null, 2);
      render();
      return;
    }
  } catch (error) {
    state.banner = { kind: "bad", text: error.message };
    state.busy = false;
    if (form.id === "setupForm" || form.id === "loginForm" || form.id === "missionForm") render();
  }
});

document.body.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-action]");
  if (!button) return;
  const action = button.dataset.action;
  if (action === "nav") {
    state.view = button.dataset.view;
    state.banner = null;
    render();
    window.scrollTo(0, 0);
    if ((state.view === "findings" || state.view === "report") && state.run) {
      refreshRunData()
        .then(() => {
          if (state.view === "findings" || state.view === "report") render();
        })
        .catch(() => {});
    }
    if (state.view === "terminal" && state.run) {
      api(`/api/runs/${state.run.id}/terminal`)
        .then((body) => {
          state.terminal = body.lines || [];
          if (state.view === "terminal") render();
        })
        .catch(() => {});
    }
    return;
  }
  if (action === "local-demo") {
    state.localDemo = true;
    state.demoLoaded = false;
    state.draft = {
      program: "CYBOT local demo",
      include: "127.0.0.1",
      exclude: "",
      authorization: "Local demo only. I am authorized to review the bundled app on 127.0.0.1.",
      target: "127.0.0.1",
      intensity: "standard",
      mode: "active-test",
      attestation: "I am authorized to validate the bundled local demo on 127.0.0.1 only.",
      active: true,
    };
    state.view = "mission";
    render();
    return;
  }
  if (action === "demo") {
    state.localDemo = false;
    state.draft = {
      program: "CYBOT demo",
      include: "example.com\nwww.example.com",
      exclude: "mail.example.com",
      authorization: "Demo fixture only. I am authorized to review this local example.com fixture.",
      target: "www.example.com",
      intensity: "light",
      mode: "soft-active",
      active: true,
    };
    state.demoLoaded = true;
    state.banner = { kind: "info", text: "Demo loaded. This run uses local fixtures and does not contact example.com." };
    render();
    return;
  }
  if (action === "notion-publish" || action === "notion-decline") {
    const path = action === "notion-publish"
      ? `/api/runs/${button.dataset.id}/notion`
      : `/api/runs/${button.dataset.id}/notion/decline`;
    try {
      const result = await api(path, { method: "POST", body: "{}" });
      state.banner = { kind: result.published ? "ok" : "info", text: result.reason || (result.published ? "Notion page created." : "Notion was not published.") };
      if (state.run) state.run.notion = result.published ? "yes" : "no";
      await refreshRunData();
      render();
    } catch (error) {
      state.banner = { kind: "bad", text: error.message };
      render();
    }
    return;
  }
  if (action === "notion-scope") {
    try {
      const loaded = await api("/api/notion/programs");
      const active = (loaded.programs || []).filter((row) => row.active);
      if (!loaded.configured || !active.length) {
        state.banner = { kind: "info", text: loaded.reason || "No active programs in Notion." };
      } else if (active.length === 1) {
        const program = active[0];
        state.draft = {
          ...draft(),
          program: program.program,
          include: program.include.join("\n"),
          exclude: (program.exclude || []).join("\n"),
          authorization: program.authorization,
        };
        state.banner = { kind: "ok", text: `Loaded ${program.program} from Notion. Check scope before you start.` };
      } else {
        state.banner = { kind: "info", text: `Notion programs: ${active.map((row) => row.program).join(", ")}. Type one name, then load again.` };
      }
      render();
    } catch (error) {
      state.banner = { kind: "bad", text: error.message };
      render();
    }
    return;
  }
  if (action === "check") {
    const form = document.getElementById("missionForm");
    rememberMission(form);
    try {
      const result = await api("/api/scope/check", { method: "POST", body: JSON.stringify(scopeFromForm(form)) });
      state.banner = { kind: result.allowed ? "ok" : "bad", text: result.reason };
      state.audit = (await api("/api/audit")).audit;
      render();
    } catch (error) {
      state.banner = { kind: "bad", text: error.message };
      render();
    }
    return;
  }
  if (action === "copy-code") {
    const panel = button.closest("[data-testid='ask-cybot']");
    const owner = panel && panel.querySelector("[data-assist]");
    if (owner) state.openAsk = owner.dataset.id;
    const code = button.parentElement && button.parentElement.querySelector("code");
    try {
      if (code && navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(code.textContent || "");
      }
      state.banner = { kind: "ok", text: "Copied the code block." };
    } catch (error) {
      state.banner = { kind: "bad", text: error.message };
    }
    render();
    return;
  }
  if (action === "copy-card") {
    try {
      const response = await fetch(`/api/findings/${button.dataset.id}/markdown`);
      const text = await response.text();
      if (!response.ok) throw new Error(text.slice(0, 180) || "Could not copy.");
      if (navigator.clipboard && navigator.clipboard.writeText) await navigator.clipboard.writeText(text);
      state.banner = { kind: "ok", text: "Markdown copied. Paste it into the program form." };
      render();
    } catch (error) {
      state.banner = { kind: "bad", text: error.message };
      render();
    }
    return;
  }
  if (action === "assist") {
    button.disabled = true;
    try {
      const box = document.querySelector(`[data-chat="${button.dataset.id}"]`);
      const result = await api(`/api/findings/${button.dataset.id}/assist`, {
        method: "POST",
        body: JSON.stringify({ action: button.dataset.assist || "ask", message: box ? box.value : "" }),
      });
      state.openAsk = button.dataset.id;
      const row = state.findings.find((item) => item.id === button.dataset.id);
      if (row) row.chat = result.history || [];
      if (box) box.value = "";
      state.banner = { kind: "ok", text: result.answer || "Saved." };
      render();
    } catch (error) {
      state.banner = { kind: "bad", text: error.message };
      render();
    }
    return;
  }
  if (action === "explain") {
    button.disabled = true;
    try {
      const result = await api(`/api/findings/${button.dataset.id}/explain`, { method: "POST", body: "{}" });
      state.explained = state.explained || {};
      state.explained[button.dataset.id] = true;
      const row = state.findings.find((item) => item.id === button.dataset.id);
      if (row) row.plain = result.plain;
      const node = document.getElementById(`plain-${button.dataset.id}`);
      if (node) {
        node.textContent = result.plain;
        node.classList.remove("muted");
      }
    } catch (error) {
      state.banner = { kind: "bad", text: error.message };
      render();
    }
    button.disabled = false;
    return;
  }
  if (action === "test-connector") {
    button.disabled = true;
    await testOne({ provider: button.dataset.provider, id: button.dataset.id }, true);
    return;
  }
  if (action === "connectors") {
    state.connectors = await api("/api/connectors");
    state.connectorStatus = {};
    state.connectorPending = {};
    render();
    return;
  }
  if (action === "forget") {
    const saved = await api(`/api/secrets/${button.dataset.name}`, { method: "DELETE" });
    state.secrets = saved.secrets;
    render();
    return;
  }
  if (action === "discover") {
    const result = await api("/api/mcp/discover", { method: "POST", body: "{}" });
    state.mcpOutput = JSON.stringify(result, null, 2);
    render();
    return;
  }
  if (action === "logout") {
    await api("/api/logout", { method: "POST", body: "{}" });
    state.me = { authed: false, needs_setup: false, demo: state.health.demo };
    render();
  }
});

async function openRun(id) {
  if (!id || state.loadingRun === id) return;
  state.loadingRun = id;
  try {
    state.run = await api(`/api/runs/${id}`);
    state.explained = {};
    state.runLoadFailed = null;
    await refreshRunData();
  } catch (error) {
    state.run = null;
    state.runLoadFailed = id;
    state.banner = { kind: "bad", text: error.message };
  } finally {
    state.loadingRun = false;
    render();
  }
}

document.body.addEventListener("change", (event) => {
  const target = event.target;
  if (target instanceof HTMLSelectElement && target.id === "runPicker") {
    openRun(target.value);
  }
});

document.body.addEventListener("input", (event) => {
  const form = document.getElementById("missionForm");
  if (form && event.target instanceof Node && form.contains(event.target)) {
    rememberMission(form);
    if (event.target.id === "target") state.demoLoaded = false;
  }
});

function kickConnectorTests() {
  const items = (state.connectors && state.connectors.connectors) || [];
  state.connectorPending = state.connectorPending || {};
  for (const item of items) {
    if (state.connectorStatus[item.id] || state.connectorPending[item.id]) continue;
    state.connectorPending[item.id] = true;
    testOne(item, true);
  }
}

async function testOne(item, rerender) {
  state.connectorPending = state.connectorPending || {};
  state.connectorPending[item.id] = true;
  try {
    const result = await api("/api/connectors/test", {
      method: "POST",
      body: JSON.stringify({ provider: item.provider, id: item.id }),
    });
    state.connectorStatus[item.id] = result;
  } catch (error) {
    state.connectorStatus[item.id] = { status: "error", detail: error.message, id: item.id, provider: item.provider };
  } finally {
    delete state.connectorPending[item.id];
  }
  if (rerender && state.view === "settings") render();
}

boot();
