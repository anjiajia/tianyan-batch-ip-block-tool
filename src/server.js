import { createServer } from "node:http";
import { appendFile, mkdir } from "node:fs/promises";
import { existsSync, createReadStream } from "node:fs";
import { dirname, extname, join, resolve } from "node:path";
import { inflateRawSync } from "node:zlib";
import { request as httpsRequest } from "node:https";
import { request as httpRequest } from "node:http";
import { fileURLToPath } from "node:url";

const moduleDir = dirname(fileURLToPath(import.meta.url));
const rootDir = resolve(moduleDir, "..");
const publicDir = join(rootDir, "public");
const dataDir = process.env.TIANYAN_DATA_DIR || join(process.cwd(), "data");
const auditPath = join(dataDir, "audit-log.jsonl");
const port = Number(process.env.PORT || 8787);

const mimeTypes = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
  ".csv": "text/csv; charset=utf-8",
};

createServer(async (req, res) => {
  try {
    const url = new URL(req.url || "/", `http://${req.headers.host}`);

    if (req.method === "POST" && url.pathname === "/api/parse") {
      return sendJson(res, await handleParse(req));
    }

    if (req.method === "POST" && url.pathname === "/api/block") {
      return sendJson(res, await handleBlock(req));
    }

    if (req.method === "GET" && url.pathname === "/api/config-example") {
      return serveFile(res, join(rootDir, "config.example.json"));
    }

    const requested = url.pathname === "/" ? "/index.html" : url.pathname;
    const safePath = resolve(publicDir, `.${decodeURIComponent(requested)}`);
    if (!safePath.startsWith(publicDir) || !existsSync(safePath)) {
      return sendJson(res, { error: "Not found" }, 404);
    }
    return serveFile(res, safePath);
  } catch (error) {
    return sendJson(res, { error: error.message || String(error) }, 500);
  }
}).listen(port, "127.0.0.1", () => {
  console.log(`Tianyan batch block tool is running: http://127.0.0.1:${port}`);
});

async function handleParse(req) {
  const body = await readJson(req);
  const fileName = String(body.fileName || "");
  const base64 = String(body.contentBase64 || "");
  const buffer = Buffer.from(base64, "base64");
  const ext = extname(fileName).toLowerCase();

  let rows = [];
  if (ext === ".xlsx") {
    rows = parseXlsx(buffer);
  } else {
    rows = parseDelimited(buffer.toString(detectEncoding(buffer)));
  }

  const whitelist = parseWhitelist(String(body.whitelist || ""));
  const candidates = collectCandidates(rows, whitelist);

  return {
    fileName,
    totalRows: rows.length,
    candidates,
    skipped: candidates.filter((item) => item.skip).length,
    ready: candidates.filter((item) => !item.skip).length,
  };
}

async function handleBlock(req) {
  const body = await readJson(req);
  const ips = Array.isArray(body.ips) ? body.ips.map(String) : [];
  const config = normalizeBlockConfig(body.config || {});
  const ttl = Number(body.ttl || config.ttlSeconds || 86400);
  const reason = String(body.reason || config.reason || "Tianyan batch block");
  const dryRun = Boolean(body.dryRun);
  const concurrency = clamp(Number(body.concurrency || config.concurrency || 3), 1, 10);

  const startedAt = new Date().toISOString();
  const adapter = getAdapter(config.vendor);
  const results = await runPool(ips, concurrency, async (ip) => {
    const result = dryRun
      ? { ok: true, status: "DRY_RUN", response: `模拟执行：${adapter.name} 未调用防火墙 API。` }
      : await adapter.block(config, ip, ttl, reason);
    return {
      ip,
      adapter: adapter.name,
      ok: result.ok,
      status: result.status,
      response: result.response,
      dryRun,
      time: new Date().toISOString(),
    };
  });

  await appendAudit({
    startedAt,
    finishedAt: new Date().toISOString(),
    adapter: adapter.name,
    endpoint: config.endpoint || config.baseUrl,
    dryRun,
    ttl,
    reason,
    total: ips.length,
    success: results.filter((item) => item.ok).length,
    failed: results.filter((item) => !item.ok).length,
    results,
  });

  return { results };
}

function getAdapter(vendor) {
  const adapters = {
    "qianxin-secaegis": { name: "奇安信防火墙", block: blockQianxin },
    "topsec-secaegis": { name: "天融信防火墙", block: blockTopsec },
    "sangfor-secaegis": { name: "深信服防火墙", block: blockSangfor },
    "opnsense-secaegis": { name: "OPNsense 别名 API", block: blockOpnsense },
    "checkpoint-secaegis": { name: "Check Point 管理 API", block: blockCheckPoint },
  };
  return adapters[vendor] || { name: "通用 HTTP", block: blockGenericHttp };
}

async function blockQianxin(config, ip) {
  const baseUrl = requireBaseUrl(config);
  const login = await requestJson({
    url: `${baseUrl}/v1.0/login/`,
    method: "POST",
    json: { username: config.username, password: config.password },
    config,
  });
  const cookies = mergeCookies(login.cookies, { token: login.json?.result?.token });
  if (!cookies.token) return { ok: false, status: login.status, response: "Login did not return result.token" };

  try {
    const exists = await qianxinExists(config, cookies, ip);
    if (exists) return { ok: true, status: "EXISTS", response: "IP already exists in blacklist." };

    const add = await requestJson({
      url: `${baseUrl}/v1.0/rest/`,
      method: "POST",
      cookies,
      json: [{
        head: { function: "add_batch_blacklist", module: "addr_blacklist" },
        body: { addr_blacklist_cp: { batch_blacklist_list: [{ ip }] } },
      }],
      config,
    });
    const ok = add.status === 200 && add.json?.head?.error_code === 0;
    return { ok, status: add.status, response: add.text.slice(0, 1000) };
  } finally {
    await requestJson({
      url: `${baseUrl}/v1.0/out/`,
      method: "POST",
      cookies,
      json: { username: config.username },
      config,
    }).catch(() => null);
  }
}

async function qianxinExists(config, cookies, ip) {
  const check = await requestJson({
    url: `${requireBaseUrl(config)}/v1.0/rest/`,
    method: "POST",
    cookies,
    json: [{
      head: { module: "addr_blacklist", function: "show_batch_blacklist" },
      body: { addr_blacklist_cp: { search_key: ip, type: "time" } },
    }],
    config,
  });
  return Number(check.json?.head?.total || 0) !== 0;
}

async function blockSangfor(config, ip, ttl, reason) {
  const baseUrl = requireBaseUrl(config);
  const login = await requestJson({
    url: `${baseUrl}/api/v1/namespaces/@namespace/login`,
    method: "POST",
    json: { name: config.username, password: config.password },
    config,
  });
  const token = login.json?.data?.loginResult?.token;
  if (!token) return { ok: false, status: login.status, response: "Login did not return data.loginResult.token" };
  const cookies = { token };

  try {
    const exists = await sangforExists(config, cookies, ip);
    if (exists) return { ok: true, status: "EXISTS", response: "IP already exists in blacklist." };

    const add = await requestJson({
      url: `${baseUrl}/api/v1/namespaces/@namespace/whiteblacklist`,
      method: "POST",
      cookies,
      json: { type: "BLACK", url: ip, enable: true, description: reason || "Tianyan batch block" },
      config,
    });
    const ok = add.status >= 200 && add.status < 300 && successText(add.text, add.json);
    return { ok, status: add.status, response: add.text.slice(0, 1000) };
  } finally {
    await requestJson({
      url: `${baseUrl}/api/v1/namespaces/@namespace/logout`,
      method: "POST",
      json: { loginResult: { token } },
      config,
    }).catch(() => null);
  }
}

async function sangforExists(config, cookies, ip) {
  const check = await requestJson({
    url: `${requireBaseUrl(config)}/api/v1/namespaces/@namespace/whiteblacklist/${encodeURIComponent(ip)}`,
    method: "GET",
    cookies,
    config,
  });
  if (check.status === 404 || /not exist|not found|does not exist/i.test(check.text)) return false;
  return check.json?.data?.enable !== false && check.json?.data?.type === "BLACK";
}

async function blockTopsec(config, ip) {
  const baseUrl = requireBaseUrl(config);
  const login = await requestText({
    url: `${baseUrl}/home/login/`,
    method: "POST",
    form: { name: config.username, password: config.password, pwdlen: String(config.pwdLen || config.password?.length || 6) },
    config,
  });
  const parsed = parseTopsecToken(login.text);
  if (!parsed.token || !parsed.authid) return { ok: false, status: login.status, response: "Login did not return token/authid" };

  let token = parsed.token;
  const userMark = parsed.authid;
  const headers = { Referer: `${baseUrl}/html/webui/home.html?userMark=${encodeURIComponent(userMark)}` };
  try {
    const exists = await topsecExists(config, userMark, token, headers, ip);
    token = exists.token || token;
    if (exists.exists) return { ok: true, status: "EXISTS", response: "IP already exists in blacklist." };

    const add = await requestText({
      url: `${baseUrl}/home/default/blackListSpread/add/?userMark=${encodeURIComponent(userMark)}`,
      method: "POST",
      headers,
      form: {
        sip: ip,
        sport: "",
        dip: "",
        dport: "",
        l4_protocol: "",
        "@change": "true",
        "commands[0][pf_blacklist_add][sip]": ip,
        "commands[0][pf_blacklist_add][sport]": "",
        "commands[0][pf_blacklist_add][dip]": "",
        "commands[0][pf_blacklist_add][dport]": "",
        "commands[0][pf_blacklist_add][l4_protocol]": "",
        token,
      },
      config,
    });
    const addParsed = parseTopsecToken(add.text);
    const ok = add.status === 200 && /true/i.test(addParsed.data || add.text);
    return { ok, status: add.status, response: add.text.slice(0, 1000) };
  } finally {
    await requestText({
      url: `${baseUrl}/home/index/logout/?userMark=${encodeURIComponent(userMark)}&token=${encodeURIComponent(token)}`,
      method: "GET",
      headers,
      config,
    }).catch(() => null);
  }
}

async function topsecExists(config, userMark, token, headers, ip) {
  const url = `${requireBaseUrl(config)}/home/default/blackListSpread/searchpf/?userMark=${encodeURIComponent(userMark)}&page=1&rows=30&search=${encodeURIComponent(ip)}&%40change=true&commands%5B0%5D%5Bpf_blacklist_static_search%5D%5B0%5D=${encodeURIComponent(ip)}&token=${encodeURIComponent(token)}`;
  const check = await requestText({ url, method: "GET", headers, config });
  const parsed = parseTopsecToken(check.text);
  try {
    const json = JSON.parse(parsed.data || "{}");
    return { token: parsed.token || token, exists: Number(json.total || 0) > 0 };
  } catch {
    return { token: parsed.token || token, exists: false };
  }
}

function parseTopsecToken(text) {
  if (!text.includes("?[")) return { token: "", data: "", authid: "" };
  const [, rest] = text.split("?[");
  const [token, data] = rest.split("}?");
  let authid = "";
  try {
    const decoded = Buffer.from(data, "base64").toString("utf8");
    authid = JSON.parse(decoded).data?.authid || "";
  } catch {
    // Not every response contains authid.
  }
  return { token, data, authid };
}

async function blockOpnsense(config, ip) {
  const baseUrl = requireBaseUrl(config);
  const aliasName = requireObjectName(config, "alias_name");
  const auth = basicAuth(config.username || config.apiKey, config.apiSecret || config.password);

  const list = await requestJson({
    url: `${baseUrl}/api/firewall/alias_util/list/${encodeURIComponent(aliasName)}`,
    method: "GET",
    headers: { Authorization: auth },
    config,
  });
  const rows = Array.isArray(list.json?.rows) ? list.json.rows : [];
  if (rows.some((row) => row.ip === ip || row.address === ip)) {
    return { ok: true, status: "EXISTS", response: "IP already exists in alias." };
  }

  const add = await requestJson({
    url: `${baseUrl}/api/firewall/alias_util/add/${encodeURIComponent(aliasName)}`,
    method: "POST",
    headers: { Authorization: auth },
    json: { address: ip },
    config,
  });
  const ok = add.status === 200 && add.json?.status === "done";
  return { ok, status: add.status, response: add.text.slice(0, 1000) };
}

async function blockCheckPoint(config, ip) {
  const baseUrl = requireBaseUrl(config);
  const groupName = requireObjectName(config, "group_name");
  const login = await requestJson({
    url: `${baseUrl}/web_api/login`,
    method: "POST",
    json: { user: config.username, password: config.password },
    config,
  });
  const sid = login.json?.sid;
  if (!sid) return { ok: false, status: login.status, response: "Login did not return sid" };
  const headers = { "X-chkp-sid": sid };

  try {
    const group = await requestJson({
      url: `${baseUrl}/web_api/show-group`,
      method: "POST",
      headers,
      json: { name: groupName },
      config,
    });
    const members = Array.isArray(group.json?.members) ? group.json.members : [];
    if (members.some((member) => member["ipv4-address"] === ip)) {
      return { ok: true, status: "EXISTS", response: "IP already exists in group." };
    }

    const hostUid = await getCheckPointHostUid(config, headers, ip);
    if (!hostUid) return { ok: false, status: "NO_HOST_UID", response: "Could not create or find host object." };

    const setGroup = await requestJson({
      url: `${baseUrl}/web_api/set-group`,
      method: "POST",
      headers,
      json: { name: groupName, members: { add: hostUid }, "details-level": "uid" },
      config,
    });
    const publish = await requestJson({ url: `${baseUrl}/web_api/publish`, method: "POST", headers, json: {}, config });
    const ok = setGroup.status === 200 && publish.status === 200 && Boolean(publish.json?.["task-id"] || publish.json?.tasks);
    return { ok, status: setGroup.status, response: JSON.stringify({ setGroup: setGroup.json, publish: publish.json }).slice(0, 1000) };
  } finally {
    await requestJson({ url: `${baseUrl}/web_api/logout`, method: "POST", headers, json: {}, config }).catch(() => null);
  }
}

async function getCheckPointHostUid(config, headers, ip) {
  const show = await requestJson({
    url: `${requireBaseUrl(config)}/web_api/show-hosts`,
    method: "POST",
    headers,
    json: { filter: ip },
    config,
  });
  if (Number(show.json?.total || 0) > 0) return show.json.objects?.[0]?.uid || "";
  const add = await requestJson({
    url: `${requireBaseUrl(config)}/web_api/add-host`,
    method: "POST",
    headers,
    json: { name: `block_${ip}`, "ip-address": ip },
    config,
  });
  return add.json?.uid || "";
}

async function blockGenericHttp(config, ip, ttl, reason) {
  if (!config.endpoint) throw new Error("Endpoint is required when dry-run is disabled.");
  const endpoint = renderTemplate(config.endpoint, { ip, ttl, reason });
  const method = String(config.method || "POST").toUpperCase();
  const payload = renderTemplate(config.payload || {}, { ip, ttl, reason });
  const headers = { "content-type": "application/json" };
  if (config.token) headers[config.tokenHeader] = `${config.tokenPrefix}${config.token}`;
  const res = await requestText({
    url: endpoint,
    method,
    headers,
    body: method === "GET" ? undefined : JSON.stringify(payload),
    config,
  });
  const ok = config.successStatus.includes(res.status);
  return { ok, status: res.status, response: res.text.slice(0, 1000) };
}

async function requestJson(options) {
  const res = await requestText(options);
  try {
    return { ...res, json: res.text ? JSON.parse(res.text) : {} };
  } catch {
    return { ...res, json: null };
  }
}

function requestText({ url, method = "GET", headers = {}, json, form, body, cookies, config }) {
  const target = new URL(url);
  const finalHeaders = { ...headers };
  let finalBody = body;
  if (json !== undefined) {
    finalBody = JSON.stringify(json);
    finalHeaders["content-type"] = "application/json";
  }
  if (form !== undefined) {
    finalBody = new URLSearchParams(form).toString();
    finalHeaders["content-type"] = "application/x-www-form-urlencoded";
  }
  if (finalBody !== undefined) finalHeaders["content-length"] = Buffer.byteLength(finalBody);
  if (cookies && Object.keys(cookies).length) finalHeaders.cookie = cookieHeader(cookies);

  const transport = target.protocol === "https:" ? httpsRequest : httpRequest;
  return new Promise((resolveResult) => {
    const req = transport({
      method,
      hostname: target.hostname,
      port: target.port || undefined,
      path: `${target.pathname}${target.search}`,
      headers: finalHeaders,
      rejectUnauthorized: !config.ignoreTlsErrors,
      timeout: Number(config.timeoutSeconds || 15) * 1000,
    }, (res) => {
      let text = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => { text += chunk; });
      res.on("end", () => {
        resolveResult({
          status: res.statusCode || 0,
          text,
          headers: res.headers,
          cookies: parseSetCookie(res.headers["set-cookie"]),
        });
      });
    });
    req.on("timeout", () => req.destroy(new Error("Request timeout")));
    req.on("error", (error) => resolveResult({ status: "ERROR", text: error.message, headers: {}, cookies: {} }));
    if (finalBody !== undefined) req.write(finalBody);
    req.end();
  });
}

function collectCandidates(rows, whitelist) {
  const seen = new Set();
  const items = [];
  rows.forEach((row, rowIndex) => {
    const haystack = Object.values(row).join(" ");
    for (const ip of extractIPv4(haystack)) {
      const duplicate = seen.has(ip);
      seen.add(ip);
      const white = whitelist.some((entry) => ipMatchesWhitelist(ip, entry));
      const privateIp = isPrivateIPv4(ip);
      items.push({
        ip,
        row: rowIndex + 1,
        source: summarizeRow(row),
        skip: duplicate || white,
        flags: [
          duplicate ? "duplicate" : "",
          white ? "whitelist" : "",
          privateIp ? "private/reserved" : "",
        ].filter(Boolean),
      });
    }
  });
  return items;
}

function parseDelimited(text) {
  const clean = text.replace(/^\uFEFF/, "");
  const delimiter = clean.includes("\t") ? "\t" : ",";
  const rows = parseCsv(clean, delimiter);
  if (rows.length === 0) return [];
  const first = rows[0].map((cell) => cell.trim());
  const hasHeader = first.some((cell) => /ip|addr|address|src|dst|source|destination|level|event|alert|risk|severity/i.test(cell));
  const headers = hasHeader ? first : first.map((_, index) => `column_${index + 1}`);
  const dataRows = hasHeader ? rows.slice(1) : rows;
  return dataRows
    .filter((row) => row.some((cell) => String(cell).trim()))
    .map((row) => Object.fromEntries(headers.map((header, index) => [header || `column_${index + 1}`, row[index] || ""])));
}

function parseCsv(text, delimiter) {
  const rows = [];
  let row = [];
  let cell = "";
  let quoted = false;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    const next = text[index + 1];
    if (char === '"') {
      if (quoted && next === '"') {
        cell += '"';
        index += 1;
      } else {
        quoted = !quoted;
      }
    } else if (char === delimiter && !quoted) {
      row.push(cell);
      cell = "";
    } else if ((char === "\n" || char === "\r") && !quoted) {
      if (char === "\r" && next === "\n") index += 1;
      row.push(cell);
      rows.push(row);
      row = [];
      cell = "";
    } else {
      cell += char;
    }
  }
  row.push(cell);
  rows.push(row);
  return rows;
}

function parseXlsx(buffer) {
  const files = unzip(buffer);
  const workbookXml = xmlText(files, "xl/workbook.xml");
  const relsXml = xmlText(files, "xl/_rels/workbook.xml.rels");
  const shared = parseSharedStrings(xmlText(files, "xl/sharedStrings.xml", ""));
  const sheetPath = firstSheetPath(workbookXml, relsXml);
  const sheetXml = xmlText(files, sheetPath);
  const table = parseSheet(sheetXml, shared);
  if (table.length === 0) return [];
  const headers = table[0].map((cell, index) => String(cell || `column_${index + 1}`).trim() || `column_${index + 1}`);
  return table.slice(1)
    .filter((row) => row.some((cell) => String(cell).trim()))
    .map((row) => Object.fromEntries(headers.map((header, index) => [header, row[index] || ""])));
}

function unzip(buffer) {
  const files = new Map();
  let offset = 0;
  while (offset < buffer.length - 30) {
    if (buffer.readUInt32LE(offset) !== 0x04034b50) {
      offset += 1;
      continue;
    }
    const method = buffer.readUInt16LE(offset + 8);
    const compressedSize = buffer.readUInt32LE(offset + 18);
    const fileNameLength = buffer.readUInt16LE(offset + 26);
    const extraLength = buffer.readUInt16LE(offset + 28);
    const nameStart = offset + 30;
    const dataStart = nameStart + fileNameLength + extraLength;
    const name = buffer.subarray(nameStart, nameStart + fileNameLength).toString("utf8");
    const compressed = buffer.subarray(dataStart, dataStart + compressedSize);
    if (method === 0) files.set(name, compressed);
    if (method === 8) files.set(name, inflateRawSync(compressed));
    offset = dataStart + compressedSize;
  }
  return files;
}

function parseSharedStrings(xml) {
  const values = [];
  for (const match of xml.matchAll(/<si[\s\S]*?<\/si>/g)) {
    const text = [...match[0].matchAll(/<t[^>]*>([\s\S]*?)<\/t>/g)].map((part) => decodeXml(part[1])).join("");
    values.push(text);
  }
  return values;
}

function firstSheetPath(workbookXml, relsXml) {
  const sheetMatch = workbookXml.match(/<sheet\b[^>]*r:id="([^"]+)"/);
  if (!sheetMatch) return "xl/worksheets/sheet1.xml";
  const relId = sheetMatch[1];
  const relMatch = relsXml.match(new RegExp(`<Relationship[^>]*Id="${escapeRegExp(relId)}"[^>]*Target="([^"]+)"`));
  if (!relMatch) return "xl/worksheets/sheet1.xml";
  const target = relMatch[1].replace(/^\/+/, "");
  return target.startsWith("xl/") ? target : `xl/${target}`;
}

function parseSheet(xml, shared) {
  const rows = [];
  for (const rowMatch of xml.matchAll(/<row\b[^>]*>([\s\S]*?)<\/row>/g)) {
    const row = [];
    for (const cellMatch of rowMatch[1].matchAll(/<c\b([^>]*)>([\s\S]*?)<\/c>/g)) {
      const attrs = cellMatch[1];
      const body = cellMatch[2];
      const ref = (attrs.match(/r="([A-Z]+)\d+"/) || [])[1];
      const index = ref ? columnIndex(ref) : row.length;
      const type = (attrs.match(/t="([^"]+)"/) || [])[1];
      const valueMatch = body.match(/<v[^>]*>([\s\S]*?)<\/v>/);
      const inlineMatch = body.match(/<t[^>]*>([\s\S]*?)<\/t>/);
      let value = "";
      if (type === "s" && valueMatch) value = shared[Number(valueMatch[1])] || "";
      else if (inlineMatch) value = decodeXml(inlineMatch[1]);
      else if (valueMatch) value = decodeXml(valueMatch[1]);
      row[index] = value;
    }
    rows.push(row.map((cell) => cell || ""));
  }
  return rows;
}

function normalizeBlockConfig(config) {
  const params = config.params && typeof config.params === "object" ? config.params : {};
  return {
    vendor: String(config.vendor || "generic-rest-json"),
    baseUrl: stripTrailingSlash(String(config.baseUrl || params.baseUrl || "")),
    endpoint: String(config.endpoint || ""),
    method: String(config.method || "POST").toUpperCase(),
    username: String(config.username || config.apiKey || params.username || params.apiKey || ""),
    password: String(config.password || params.password || ""),
    apiKey: String(config.apiKey || params.apiKey || config.username || ""),
    apiSecret: String(config.apiSecret || params.apiSecret || ""),
    objectName: String(config.objectName || params.objectName || params.aliasName || params.groupName || ""),
    pwdLen: Number(config.pwdLen || params.pwdLen || 0),
    token: String(config.token || ""),
    tokenHeader: String(config.tokenHeader || "Authorization"),
    tokenPrefix: String(config.tokenPrefix ?? "Bearer "),
    timeoutSeconds: Number(config.timeoutSeconds || 15),
    ignoreTlsErrors: Boolean(config.ignoreTlsErrors),
    successStatus: Array.isArray(config.successStatus) ? config.successStatus.map(Number) : [200, 201, 204],
    payload: config.payload && typeof config.payload === "object" ? config.payload : { ip: "{{ip}}", expire: "{{ttl}}", reason: "{{reason}}" },
    ttlSeconds: Number(config.ttlSeconds || 86400),
    reason: String(config.reason || "Tianyan batch block"),
    concurrency: Number(config.concurrency || 3),
  };
}

function requireBaseUrl(config) {
  if (!config.baseUrl) throw new Error("Base URL is required for this adapter.");
  return config.baseUrl;
}

function requireObjectName(config, name) {
  if (!config.objectName) throw new Error(`Object name is required for this adapter (${name}).`);
  return config.objectName;
}

function successText(text, json) {
  if (json?.message && String(json.message).toLowerCase().includes("success")) return true;
  return /success|done/i.test(text);
}

function parseSetCookie(setCookie) {
  const cookies = {};
  for (const item of Array.isArray(setCookie) ? setCookie : []) {
    const [pair] = item.split(";");
    const eq = pair.indexOf("=");
    if (eq > 0) cookies[pair.slice(0, eq)] = pair.slice(eq + 1);
  }
  return cookies;
}

function mergeCookies(...items) {
  return Object.assign({}, ...items.filter(Boolean));
}

function cookieHeader(cookies) {
  return Object.entries(cookies).filter(([, value]) => value !== undefined && value !== null && value !== "").map(([key, value]) => `${key}=${value}`).join("; ");
}

function basicAuth(username, password) {
  return `Basic ${Buffer.from(`${username}:${password}`).toString("base64")}`;
}

function renderTemplate(value, variables) {
  if (Array.isArray(value)) return value.map((item) => renderTemplate(item, variables));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, renderTemplate(item, variables)]));
  if (typeof value === "string") return value.replace(/\{\{(ip|ttl|reason)\}\}/g, (_, key) => String(variables[key]));
  return value;
}

function stripTrailingSlash(value) {
  return String(value || "").replace(/\/+$/, "");
}

function extractIPv4(text) {
  const matches = String(text).match(/\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g);
  return matches ? [...new Set(matches)] : [];
}

function parseWhitelist(text) {
  return String(text)
    .split(/\r?\n/)
    .map((line) => line.replace(/#.*/, "").trim())
    .filter(Boolean)
    .map((entry) => {
      const [ip, bits] = entry.split("/");
      return { ip, bits: bits === undefined ? 32 : Number(bits) };
    })
    .filter((entry) => ipv4ToInt(entry.ip) !== null && entry.bits >= 0 && entry.bits <= 32);
}

function ipMatchesWhitelist(ip, entry) {
  const value = ipv4ToInt(ip);
  const base = ipv4ToInt(entry.ip);
  if (value === null || base === null) return false;
  const mask = entry.bits === 0 ? 0 : (0xffffffff << (32 - entry.bits)) >>> 0;
  return (value & mask) === (base & mask);
}

function isPrivateIPv4(ip) {
  return [
    { ip: "10.0.0.0", bits: 8 },
    { ip: "172.16.0.0", bits: 12 },
    { ip: "192.168.0.0", bits: 16 },
    { ip: "127.0.0.0", bits: 8 },
    { ip: "169.254.0.0", bits: 16 },
    { ip: "0.0.0.0", bits: 8 },
    { ip: "224.0.0.0", bits: 4 },
  ].some((entry) => ipMatchesWhitelist(ip, entry));
}

function ipv4ToInt(ip) {
  const parts = String(ip).split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return parts.reduce((acc, part) => ((acc << 8) + part) >>> 0, 0);
}

function summarizeRow(row) {
  return Object.entries(row)
    .filter(([, value]) => String(value).trim())
    .slice(0, 4)
    .map(([key, value]) => `${key}: ${String(value).slice(0, 60)}`)
    .join(" | ");
}

async function runPool(items, concurrency, worker) {
  const results = new Array(items.length);
  let cursor = 0;
  const runners = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (cursor < items.length) {
      const index = cursor;
      cursor += 1;
      results[index] = await worker(items[index], index);
    }
  });
  await Promise.all(runners);
  return results;
}

async function appendAudit(entry) {
  await mkdir(dataDir, { recursive: true });
  await appendFile(auditPath, `${JSON.stringify(entry)}\n`, "utf8");
}
async function readJson(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
}

function sendJson(res, payload, status = 200) {
  const body = JSON.stringify(payload);
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "content-length": Buffer.byteLength(body) });
  res.end(body);
}

function serveFile(res, filePath) {
  const type = mimeTypes[extname(filePath).toLowerCase()] || "application/octet-stream";
  res.writeHead(200, { "content-type": type });
  createReadStream(filePath).pipe(res);
}

function detectEncoding(buffer) {
  if (buffer[0] === 0xff && buffer[1] === 0xfe) return "utf16le";
  return "utf8";
}

function decodeXml(value) {
  return String(value)
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&");
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function columnIndex(label) {
  let value = 0;
  for (const char of label) value = value * 26 + char.charCodeAt(0) - 64;
  return value - 1;
}

function xmlText(files, name, fallback) {
  const file = files.get(name);
  if (!file) {
    if (fallback !== undefined) return fallback;
    throw new Error(`XLSX missing ${name}`);
  }
  return file.toString("utf8");
}

function clamp(value, min, max) {
  if (!Number.isFinite(value)) return min;
  return Math.max(min, Math.min(max, value));
}
