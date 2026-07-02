const FIREWALL_PRESETS = [
  {
    id: "qianxin-secaegis",
    label: "&#22855;&#23433;&#20449;&#38450;&#28779;&#22681;&#65288;SecAutoBan &#26041;&#24335;&#65289;",
    note: "Login: /v1.0/login/, Cookie token + __s_sessionid__, REST function add_batch_blacklist in addr_blacklist.",
    baseUrl: "https://firewall.example.com:8443",
    username: "api-admin",
    password: "",
    objectName: "",
    pwdLen: 0,
    advancedOpen: false,
  },
  {
    id: "topsec-secaegis",
    label: "&#22825;&#34701;&#20449;&#38450;&#28779;&#22681;&#65288;SecAutoBan &#26041;&#24335;&#65289;",
    note: "Login: /home/login/, token is parsed from ?[token]? envelope, then blackListSpread/add form post.",
    baseUrl: "https://firewall.example.com",
    username: "api-admin",
    password: "",
    objectName: "",
    pwdLen: 6,
    advancedOpen: false,
  },
  {
    id: "sangfor-secaegis",
    label: "&#28145;&#20449;&#26381;&#38450;&#28779;&#22681;&#65288;SecAutoBan &#26041;&#24335;&#65289;",
    note: "Login: /api/v1/namespaces/@namespace/login, token cookie, whiteblacklist BLACK entry.",
    baseUrl: "https://firewall.example.com",
    username: "api-admin",
    password: "",
    objectName: "",
    pwdLen: 0,
    advancedOpen: false,
  },
  {
    id: "opnsense-secaegis",
    label: "OPNsense &#21035;&#21517; API",
    note: "Uses HTTP Basic auth with API key/secret and /api/firewall/alias_util/add/{alias_name}.",
    baseUrl: "https://opnsense.example.com",
    username: "api_key",
    password: "api_secret",
    objectName: "sec_auto_ban",
    pwdLen: 0,
    advancedOpen: false,
  },
  {
    id: "checkpoint-secaegis",
    label: "Check Point &#31649;&#29702; API",
    note: "Login gets sid, create/find host object, add to group, publish, logout. Object Name is the group name.",
    baseUrl: "https://management.example.com",
    username: "admin",
    password: "",
    objectName: "sec_auto_ban",
    pwdLen: 0,
    advancedOpen: false,
  },
  {
    id: "generic-rest-json",
    label: "&#36890;&#29992; REST JSON",
    note: "Fallback one-shot HTTP request. Use Endpoint/Payload template when your device exposes a simple API.",
    baseUrl: "",
    username: "",
    password: "",
    objectName: "",
    pwdLen: 0,
    endpoint: "https://firewall.example.com/api/v1/blacklist/add",
    method: "POST",
    successStatus: "200,201,204",
    tokenHeader: "Authorization",
    tokenPrefix: "Bearer ",
    payload: { ip: "{{ip}}", expire: "{{ttl}}", reason: "{{reason}}", source: "tianyan-batch-tool" },
    advancedOpen: true,
  },
  {
    id: "panos-xml-generic",
    label: "Palo Alto PAN-OS XML API&#65288;&#36890;&#29992;&#27169;&#26495;&#65289;",
    note: "PAN-OS can use URL query key and XML endpoint. This remains generic because XML API deployment paths differ.",
    endpoint: "https://firewall.example.com/api/?type=config&action=set&key=YOUR_API_KEY&xpath=/config/shared/address/entry[@name='block-{{ip}}']&element=<ip-netmask>{{ip}}</ip-netmask><description>{{reason}}</description>",
    method: "GET",
    successStatus: "200",
    tokenHeader: "Authorization",
    tokenPrefix: "",
    payload: {},
    advancedOpen: true,
  },
  {
    id: "routeros-note",
    label: "RouterOS API&#65288;&#38656;&#35201;&#36741;&#21161;&#31243;&#24207;&#65289;",
    note: "SecAutoBan uses the RouterOS binary API library, not HTTP. This Node GUI does not execute that protocol yet; use a sidecar/helper later.",
    advancedOpen: false,
  },
  {
    id: "bgp-note",
    label: "BGP / GoBGP&#65288;&#38656;&#35201;&#26412;&#22320;&#21629;&#20196;&#65289;",
    note: "SecAutoBan shells out to gobgp. This GUI intentionally does not run route-changing commands yet.",
    advancedOpen: false,
  },
];

const CONFIG_STORAGE_KEY = "tianyanBatchIpBlockTool.config.v1";

const state = { file: null, candidates: [], results: [] };

const els = {
  fileInput: document.querySelector("#fileInput"),
  dropZone: document.querySelector("#dropZone"),
  fileSummary: document.querySelector("#fileSummary"),
  whitelistInput: document.querySelector("#whitelistInput"),
  manualInput: document.querySelector("#manualInput"),
  parseButton: document.querySelector("#parseButton"),
  addManualButton: document.querySelector("#addManualButton"),
  clearButton: document.querySelector("#clearButton"),
  candidateBody: document.querySelector("#candidateBody"),
  selectAll: document.querySelector("#selectAll"),
  statTotal: document.querySelector("#statTotal"),
  statReady: document.querySelector("#statReady"),
  statSkipped: document.querySelector("#statSkipped"),
  statSelected: document.querySelector("#statSelected"),
  firewallPresetInput: document.querySelector("#firewallPresetInput"),
  presetNote: document.querySelector("#presetNote"),
  baseUrlInput: document.querySelector("#baseUrlInput"),
  usernameInput: document.querySelector("#usernameInput"),
  passwordInput: document.querySelector("#passwordInput"),
  objectNameInput: document.querySelector("#objectNameInput"),
  pwdLenInput: document.querySelector("#pwdLenInput"),
  endpointInput: document.querySelector("#endpointInput"),
  methodInput: document.querySelector("#methodInput"),
  successInput: document.querySelector("#successInput"),
  tokenInput: document.querySelector("#tokenInput"),
  tokenHeaderInput: document.querySelector("#tokenHeaderInput"),
  tokenPrefixInput: document.querySelector("#tokenPrefixInput"),
  ttlInput: document.querySelector("#ttlInput"),
  concurrencyInput: document.querySelector("#concurrencyInput"),
  reasonInput: document.querySelector("#reasonInput"),
  payloadInput: document.querySelector("#payloadInput"),
  dryRunInput: document.querySelector("#dryRunInput"),
  ignoreTlsInput: document.querySelector("#ignoreTlsInput"),
  loadExampleButton: document.querySelector("#loadExampleButton"),
  saveConfigButton: document.querySelector("#saveConfigButton"),
  loadConfigButton: document.querySelector("#loadConfigButton"),
  clearConfigButton: document.querySelector("#clearConfigButton"),
  saveSecretsInput: document.querySelector("#saveSecretsInput"),
  runButton: document.querySelector("#runButton"),
  downloadButton: document.querySelector("#downloadButton"),
  logOutput: document.querySelector("#logOutput"),
  advancedConfig: document.querySelector(".advanced-config"),
};

initPresets();

els.fileInput.addEventListener("change", () => { state.file = els.fileInput.files?.[0] || null; updateFileSummary(); });
["dragenter", "dragover"].forEach((name) => els.dropZone.addEventListener(name, (event) => { event.preventDefault(); els.dropZone.classList.add("dragover"); }));
["dragleave", "drop"].forEach((name) => els.dropZone.addEventListener(name, (event) => { event.preventDefault(); els.dropZone.classList.remove("dragover"); }));
els.dropZone.addEventListener("drop", (event) => { state.file = event.dataTransfer.files?.[0] || null; updateFileSummary(); });
els.parseButton.addEventListener("click", parseSelectedFile);
els.addManualButton.addEventListener("click", addManualIps);
els.clearButton.addEventListener("click", clearAll);
els.selectAll.addEventListener("change", toggleSelectAll);
els.firewallPresetInput.addEventListener("change", () => applyPreset(els.firewallPresetInput.value));
els.loadExampleButton.addEventListener("click", () => applyPreset("generic-rest-json"));
els.saveConfigButton.addEventListener("click", saveConfig);
els.loadConfigButton.addEventListener("click", () => loadSavedConfig({ silent: false }));
els.clearConfigButton.addEventListener("click", clearSavedConfig);
els.runButton.addEventListener("click", runBlock);
els.downloadButton.addEventListener("click", downloadResults);

function initPresets() {
  els.firewallPresetInput.innerHTML = "";
  FIREWALL_PRESETS.forEach((preset) => {
    const option = document.createElement("option");
    option.value = preset.id;
    option.textContent = decodeHtml(preset.label);
    els.firewallPresetInput.appendChild(option);
  });
  applyPreset("qianxin-secaegis");
  loadSavedConfig({ silent: true });
}

function applyPreset(id) {
  const preset = FIREWALL_PRESETS.find((item) => item.id === id) || FIREWALL_PRESETS[0];
  els.firewallPresetInput.value = preset.id;
  els.presetNote.textContent = decodeHtml(preset.note);
  els.baseUrlInput.value = preset.baseUrl || "";
  els.usernameInput.value = preset.username || "";
  els.passwordInput.value = preset.password || "";
  els.objectNameInput.value = preset.objectName || "";
  els.pwdLenInput.value = preset.pwdLen || 0;
  els.endpointInput.value = preset.endpoint || "";
  els.methodInput.value = preset.method || "POST";
  els.successInput.value = preset.successStatus || "200,201,204";
  els.tokenInput.value = "";
  els.tokenHeaderInput.value = preset.tokenHeader || "Authorization";
  els.tokenPrefixInput.value = preset.tokenPrefix ?? "Bearer ";
  els.payloadInput.value = JSON.stringify(preset.payload || { ip: "{{ip}}", expire: "{{ttl}}", reason: "{{reason}}" }, null, 2);
  els.advancedConfig.open = Boolean(preset.advancedOpen);
  log(`Preset loaded: ${decodeHtml(preset.label)}\n${decodeHtml(preset.note)}`);
}

function updateFileSummary() {
  els.fileSummary.textContent = state.file ? `${state.file.name} - ${formatSize(state.file.size)}` : "No file selected";
}

async function parseSelectedFile() {
  if (!state.file) return log("Please choose a CSV, TXT, or XLSX file first.");
  setBusy(true, "Parsing file...");
  try {
    const response = await postJson("/api/parse", { fileName: state.file.name, contentBase64: await fileToBase64(state.file), whitelist: els.whitelistInput.value });
    state.candidates = response.candidates.map((item, index) => ({ ...item, id: `${item.ip}-${item.row}-${index}`, selected: !item.skip }));
    renderCandidates();
    log(`Parsed: ${response.fileName}\nRows: ${response.totalRows}\nFound IPs: ${state.candidates.length}\nReady: ${response.ready}\nSkipped: ${response.skipped}`);
  } catch (error) {
    log(`Parse failed: ${error.message}`);
  } finally {
    setBusy(false);
  }
}

async function addManualIps() {
  if (!extractIps(els.manualInput.value).length) return log("No valid IPv4 address found in manual input.");
  setBusy(true, "Adding manual IPs...");
  try {
    const response = await postJson("/api/parse", { fileName: "manual.txt", contentBase64: stringToBase64(els.manualInput.value), whitelist: els.whitelistInput.value });
    const existing = new Set(state.candidates.map((candidate) => candidate.ip));
    const additions = response.candidates.map((item, index) => {
      const duplicate = existing.has(item.ip);
      existing.add(item.ip);
      const flags = [...new Set([...(duplicate ? ["duplicate"] : []), ...(item.flags || [])])];
      return { id: `manual-${Date.now()}-${index}`, ip: item.ip, row: "-", source: "manual input", skip: duplicate || item.skip, flags, selected: !(duplicate || item.skip) };
    });
    state.candidates.push(...additions);
    renderCandidates();
    log(`Added ${additions.length} manual IP(s).`);
  } catch (error) {
    log(`Add manual IPs failed: ${error.message}`);
  } finally {
    setBusy(false);
  }
}

function clearAll() {
  state.file = null;
  state.candidates = [];
  state.results = [];
  els.fileInput.value = "";
  els.manualInput.value = "";
  els.downloadButton.disabled = true;
  updateFileSummary();
  renderCandidates();
  log("Cleared.");
}

function renderCandidates() {
  if (state.candidates.length === 0) {
    els.candidateBody.innerHTML = '<tr><td colspan="4" class="empty">Import a file to preview IPs.</td></tr>';
    updateStats();
    return;
  }
  els.candidateBody.innerHTML = state.candidates.map((item) => {
    const flags = (item.flags || []).map(String);
    const isPrivate = flags.some((flag) => flag.toLowerCase().includes("private"));
    const tags = item.skip ? flags.map((flag) => tag(flag, "skip")).join("") : tag("ready", "ready") + (isPrivate ? tag("private", "warn") : "");
    return `<tr><td><input class="row-check" type="checkbox" data-id="${escapeHtml(item.id)}" ${item.selected ? "checked" : ""} ${item.skip ? "disabled" : ""}></td><td>${escapeHtml(item.ip)}</td><td>${tags || tag("ready", "ready")}</td><td>${escapeHtml(item.source || "")}</td></tr>`;
  }).join("");
  document.querySelectorAll(".row-check").forEach((checkbox) => checkbox.addEventListener("change", () => {
    const item = state.candidates.find((candidate) => candidate.id === checkbox.dataset.id);
    if (item) item.selected = checkbox.checked;
    updateStats();
  }));
  updateStats();
}

function toggleSelectAll() {
  state.candidates.forEach((item) => { if (!item.skip) item.selected = els.selectAll.checked; });
  renderCandidates();
}

function updateStats() {
  const total = state.candidates.length;
  const skipped = state.candidates.filter((item) => item.skip).length;
  const ready = state.candidates.filter((item) => !item.skip).length;
  const selected = selectedIps().length;
  els.statTotal.textContent = total;
  els.statReady.textContent = ready;
  els.statSkipped.textContent = skipped;
  els.statSelected.textContent = selected;
  els.selectAll.checked = ready > 0 && selected === ready;
}

async function runBlock() {
  const ips = selectedIps();
  if (ips.length === 0) return log("No selected IPs to block.");
  const preset = FIREWALL_PRESETS.find((item) => item.id === els.firewallPresetInput.value);
  if (preset?.id.endsWith("-note")) return log("This adapter needs a sidecar/helper and is not executable in the GUI yet.");

  let payload;
  try { payload = JSON.parse(els.payloadInput.value || "{}"); } catch (error) { return log(`Payload JSON is invalid: ${error.message}`); }

  const config = readConfigFromForm(payload);

  const dryRun = els.dryRunInput.checked;
  const confirmText = dryRun ? `模拟执行 ${ips.length} 个 IP，不会调用防火墙 API。` : `确认使用 ${currentPresetLabel(config.vendor)} 封禁 ${ips.length} 个 IP？`;
  if (!window.confirm(confirmText)) return;

  setBusy(true, dryRun ? "正在模拟执行..." : "正在调用防火墙适配器...");
  try {
    const response = await postJson("/api/block", { ips, config, ttl: Number(els.ttlInput.value), reason: els.reasonInput.value, dryRun, concurrency: Number(els.concurrencyInput.value) });
    state.results = response.results;
    els.downloadButton.disabled = state.results.length === 0;
    const success = state.results.filter((item) => item.ok).length;
    const failed = state.results.length - success;
    const title = dryRun
      ? `模拟执行完成：模拟 ${state.results.length} 条，防火墙调用 0 次`
      : `Done: success=${success}, failed=${failed}`;
    log([title, "", ...state.results.map(formatResultLine)].join("\n"));
  } catch (error) {
    log(`Run failed: ${error.message}`);
  } finally {
    setBusy(false);
  }
}

function readConfigFromForm(payloadOverride) {
  const payload = payloadOverride ?? JSON.parse(els.payloadInput.value || "{}");
  return {
    vendor: els.firewallPresetInput.value,
    baseUrl: els.baseUrlInput.value.trim(),
    username: els.usernameInput.value,
    password: els.passwordInput.value,
    apiKey: els.usernameInput.value,
    apiSecret: els.passwordInput.value,
    objectName: els.objectNameInput.value,
    pwdLen: Number(els.pwdLenInput.value),
    endpoint: els.endpointInput.value.trim(),
    method: els.methodInput.value,
    token: els.tokenInput.value,
    tokenHeader: els.tokenHeaderInput.value || "Authorization",
    tokenPrefix: els.tokenPrefixInput.value,
    timeoutSeconds: 15,
    ignoreTlsErrors: els.ignoreTlsInput.checked,
    successStatus: els.successInput.value.split(",").map((item) => Number(item.trim())).filter(Boolean),
    payload,
    ttlSeconds: Number(els.ttlInput.value),
    reason: els.reasonInput.value,
    concurrency: Number(els.concurrencyInput.value),
  };
}

function applyConfigToForm(config) {
  const vendor = config.vendor || "qianxin-secaegis";
  if (FIREWALL_PRESETS.some((preset) => preset.id === vendor)) {
    applyPreset(vendor);
  }
  els.firewallPresetInput.value = vendor;
  els.baseUrlInput.value = config.baseUrl || "";
  els.usernameInput.value = config.username || config.apiKey || "";
  els.passwordInput.value = config.password || config.apiSecret || "";
  els.objectNameInput.value = config.objectName || "";
  els.pwdLenInput.value = Number(config.pwdLen || 0);
  els.endpointInput.value = config.endpoint || "";
  els.methodInput.value = config.method || "POST";
  els.successInput.value = Array.isArray(config.successStatus) ? config.successStatus.join(",") : (config.successStatus || "200,201,204");
  els.tokenInput.value = config.token || "";
  els.tokenHeaderInput.value = config.tokenHeader || "Authorization";
  els.tokenPrefixInput.value = config.tokenPrefix ?? "Bearer ";
  els.ttlInput.value = Number(config.ttlSeconds || 86400);
  els.concurrencyInput.value = Number(config.concurrency || 3);
  els.reasonInput.value = config.reason || "Tianyan batch block";
  els.ignoreTlsInput.checked = Boolean(config.ignoreTlsErrors ?? true);
  if (config.payload && typeof config.payload === "object") {
    els.payloadInput.value = JSON.stringify(config.payload, null, 2);
  }
}

function saveConfig() {
  let config;
  try {
    config = readConfigFromForm();
  } catch (error) {
    log(`Config not saved: payload JSON is invalid: ${error.message}`);
    return;
  }
  config.savedAt = new Date().toISOString();
  config.saveSecrets = els.saveSecretsInput.checked;
  if (!els.saveSecretsInput.checked) {
    config.password = "";
    config.apiSecret = "";
    config.token = "";
  }
  localStorage.setItem(CONFIG_STORAGE_KEY, JSON.stringify(config));
  log(els.saveSecretsInput.checked
    ? "配置已保存到本机，包含密码/Token。请只在可信电脑上使用。"
    : "配置已保存到本机，未保存密码/Token。");
}

function loadSavedConfig({ silent = false } = {}) {
  const raw = localStorage.getItem(CONFIG_STORAGE_KEY);
  if (!raw) {
    if (!silent) log("未找到已保存的配置。");
    return false;
  }
  try {
    const config = JSON.parse(raw);
    applyConfigToForm(config);
    els.saveSecretsInput.checked = Boolean(config.saveSecrets);
    if (!silent) log("已加载本机保存的配置。");
    return true;
  } catch (error) {
    if (!silent) log(`已保存的配置无效：${error.message}`);
    return false;
  }
}

function clearSavedConfig() {
  localStorage.removeItem(CONFIG_STORAGE_KEY);
  els.saveSecretsInput.checked = false;
  log("已清除本机保存的配置。");
}

function formatResultLine(item) {
  if (item.dryRun || item.status === "DRY_RUN") {
    return `[模拟] ${item.ip} (${item.adapter || "adapter"}) -> 仅模拟，未调用防火墙 API。`;
  }
  return `[${item.ok ? "OK" : "FAIL"}] ${item.ip} (${item.adapter || "adapter"}) -> ${item.status} ${item.response}`;
}

function currentPresetLabel(fallback) {
  const preset = FIREWALL_PRESETS.find((item) => item.id === els.firewallPresetInput.value);
  return preset ? decodeHtml(preset.label) : fallback;
}

function selectedIps() { return [...new Set(state.candidates.filter((item) => item.selected && !item.skip).map((item) => item.ip))]; }

function downloadResults() {
  const rows = [["ip", "adapter", "ok", "status", "response", "dry_run", "time"]];
  state.results.forEach((item) => rows.push([item.ip, item.adapter, item.ok, item.status, item.response, item.dryRun, item.time]));
  const csv = rows.map((row) => row.map(csvCell).join(",")).join("\r\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `block-results-${new Date().toISOString().replace(/[:.]/g, "-")}.csv`;
  link.click();
  URL.revokeObjectURL(url);
}

function setBusy(busy, message) { [els.parseButton, els.addManualButton, els.runButton].forEach((button) => { button.disabled = busy; }); if (message) log(message); }
function log(message) { els.logOutput.textContent = message; }
async function postJson(url, body) { const response = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }); const payload = await response.json(); if (!response.ok) throw new Error(payload.error || response.statusText); return payload; }
function fileToBase64(file) { return new Promise((resolve, reject) => { const reader = new FileReader(); reader.onload = () => resolve(String(reader.result).split(",")[1] || ""); reader.onerror = () => reject(reader.error); reader.readAsDataURL(file); }); }
function stringToBase64(value) { const bytes = new TextEncoder().encode(value); let binary = ""; bytes.forEach((byte) => { binary += String.fromCharCode(byte); }); return btoa(binary); }
function extractIps(text) { return [...new Set(String(text).match(/\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g) || [])]; }
function formatSize(bytes) { if (bytes < 1024) return `${bytes} B`; if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`; return `${(bytes / 1024 / 1024).toFixed(1)} MB`; }
function tag(text, type) { return `<span class="tag ${type}">${escapeHtml(text)}</span>`; }
function csvCell(value) { const text = String(value ?? ""); return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text; }
function decodeHtml(value) { const textarea = document.createElement("textarea"); textarea.innerHTML = String(value); return textarea.value; }
function escapeHtml(value) { return String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }
