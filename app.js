"use strict";
/* CyberShield RSA — front-end only. No server, no database. */

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

/* ---------- safe storage (private mode / blocked storage tolerant) ---------- */
const store = {
  get(k, d = null) { try { const v = localStorage.getItem(k); return v === null ? d : v; } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, v); return true; } catch { return false; } },
  del(k) { try { localStorage.removeItem(k); } catch { /* ignore */ } },
};

/* ---------- theme & menu ---------- */
const root = document.documentElement;
root.dataset.theme = store.get("cs-theme") || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
function updateThemeLabel() {
  const dark = root.dataset.theme === "dark";
  $("themeToggle").innerHTML = dark ? "☀ <span>Light mode</span>" : "☾ <span>Dark mode</span>";
  $("themeToggleMobile").textContent = dark ? "☀ Light mode" : "☾ Dark mode";
}
function toggleTheme() {
  const next = root.dataset.theme === "dark" ? "light" : "dark";
  root.dataset.theme = next; store.set("cs-theme", next); updateThemeLabel();
}
$("themeToggle").addEventListener("click", toggleTheme);
$("themeToggleMobile").addEventListener("click", toggleTheme);
$("menuToggle").addEventListener("click", () => $("topbar").classList.toggle("nav-open"));
document.querySelectorAll(".topbar nav a").forEach((a) => a.addEventListener("click", () => $("topbar").classList.remove("nav-open")));
$("year").textContent = new Date().getFullYear();
updateThemeLabel();

/* ---------- tool definitions ---------- */
const tools = {
  url: { title: "URL scanner", desc: "Look for common warning signs in a link, such as look-alike names, shortened links and unusual domains. Optionally add Google Safe Browsing.", label: "Website URL", placeholder: "https://example.com", hint: "Do not open the link first. Avoid private links containing tokens or reset codes.", button: "Check this link", rows: 2 },
  message: { title: "Scam message checker", desc: "Review a message for common scam patterns such as urgency, impersonation and requests for codes.", label: "Message text", placeholder: "Paste the suspicious SMS or WhatsApp message…", hint: "Remove names, account numbers, OTPs and other personal information first.", button: "Review message", rows: 4 },
  email: { title: "Phishing email checker", desc: "Review email wording and sender details for common phishing indicators.", label: "Email content and sender", placeholder: "From: example@domain.com\nSubject: Urgent account notice\n\nPaste the email text…", hint: "Do not paste attachments, passwords, account numbers or private correspondence.", button: "Review email", rows: 6 },
  phone: { title: "Caller ID lookup", desc: "Type the number that called you. We check your caller book, the community list and the number type. We cannot see live calls from a web page.", label: "Phone number", placeholder: "+27 00 000 0000", hint: "Labels are unverified notes, not proof that someone is a scammer.", button: "Look up number", rows: 1 },
  password: { title: "Password strength", desc: "Estimate password strength locally in this browser. Your input is never sent anywhere.", label: "Password to assess", placeholder: "Enter a password you do not currently use", hint: "Never enter a password you use on a real account. This check runs only in your browser.", button: "Check strength", rows: 1 },
};
let currentTool = "url";

/* ---------- result rendering ---------- */
function showResult(kind, title, message, extraHTML = "") {
  const symbols = { good: "✓", bad: "!", warn: "!", info: "i" };
  const box = $("result");
  box.className = "result-box " + kind;
  box.innerHTML = `<span class="result-symbol">${symbols[kind] || "i"}</span><div><b>${esc(title)}</b><p>${esc(message)}</p>${extraHTML}</div>`;
}
const listHTML = (items) => (items.length ? `<ul>${items.map((s) => `<li>${esc(s)}</li>`).join("")}</ul>` : "");
const noteHTML = (t) => `<p class="note">${esc(t)}</p>`;

/* ---------- shared: scoring ---------- */
function levelFromScore(score) { return score >= 6 ? "high" : score >= 3 ? "medium" : "low"; }

/* ---------- URL analysis (local) ---------- */
const SHORTENERS = new Set(["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "wa.me"]);
const RISKY_TLDS = new Set(["zip", "mov", "top", "xyz", "click", "gq", "tk", "ml", "cf", "ga", "work", "support", "icu", "cyou", "rest", "country", "loan", "monster"]);
const SECOND_LEVELS = new Set(["co", "org", "gov", "ac", "net", "edu", "nom", "web", "mil"]);
const BRANDS = {
  fnb: ["fnb.co.za"], capitec: ["capitecbank.co.za"], absa: ["absa.co.za"], nedbank: ["nedbank.co.za"],
  standardbank: ["standardbank.co.za"], sars: ["sars.gov.za"], sassa: ["sassa.gov.za"],
  paypal: ["paypal.com"], takealot: ["takealot.com"], netflix: ["netflix.com"], microsoft: ["microsoft.com", "live.com", "office.com"],
  google: ["google.com"], apple: ["apple.com", "icloud.com"], amazon: ["amazon.com"], dhl: ["dhl.com"], whatsapp: ["whatsapp.com"],
};
const LONG_BRANDS = ["capitec", "nedbank", "standardbank", "paypal", "takealot", "netflix", "microsoft", "whatsapp"];

function registrableDomain(host) {
  const p = host.split(".");
  if (p.length <= 2) return host;
  const last = p[p.length - 1], second = p[p.length - 2];
  return last.length === 2 && SECOND_LEVELS.has(second) ? p.slice(-3).join(".") : p.slice(-2).join(".");
}
function isIPv4(h) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(h); }

function analyseUrl(raw) {
  let input = raw.trim(), assumed = false;
  if (!/^[a-z][a-z0-9+.-]*:/i.test(input)) { input = "https://" + input; assumed = true; }
  let u;
  try { u = new URL(input); } catch { return { error: "That does not look like a complete web address. Try something like https://example.com." }; }
  if (!["http:", "https:"].includes(u.protocol)) return { error: "Only http:// and https:// links can be reviewed." };
  const host = u.hostname.replace(/\.$/, "").toLowerCase();
  if (!host.includes(".") && !host.includes(":")) return { error: "That address has no domain name, so it cannot be reviewed." };

  const flags = []; // {w, t}
  const add = (w, t) => flags.push({ w, t });
  const reg = isIPv4(host) || host.includes(":") ? host : registrableDomain(host);
  const tld = host.split(".").pop();

  if (u.protocol === "http:") add(1, "Connection is not encrypted (http, not https).");
  if (u.username || u.password) add(4, "The link contains embedded login details, a trick used to disguise the real destination.");
  if (isIPv4(host) || host.includes(":")) add(3, "The link points to a raw IP address instead of a named website.");
  if (host.split(".").some((l) => l.startsWith("xn--"))) add(3, "The domain uses punycode (xn--), which can disguise look-alike characters.");
  if (SHORTENERS.has(reg)) add(3, "Shortened link: the real destination is hidden until you open it.");
  if (RISKY_TLDS.has(tld)) add(2, `The “.${tld}” ending is frequently used in throwaway or abusive sites.`);
  if (host.split(".").length >= 5) add(2, "Unusually many subdomains, often used to bury a fake name in the address.");
  if ((host.match(/-/g) || []).length >= 3) add(1, "The domain contains many hyphens.");
  if (u.port && !["80", "443"].includes(u.port)) add(2, `Uses an unusual port (${u.port}).`);
  if (input.length > 200) add(1, "Very long address, which can hide the real destination.");
  if ((u.pathname + u.search).match(/%[0-9a-f]{2}/gi)?.length > 8) add(1, "Heavy percent-encoding in the address.");
  if (/(login|signin|verify|secure|account|update|confirm|wallet|refund|unlock)/i.test(host)) add(2, "The domain name contains account-related words such as login, verify or secure.");
  else if (/(login|signin|verify|update|confirm|refund|unlock)/i.test(u.pathname)) add(1, "The page path suggests a login or verification page.");
  if (/[?&](otp|pin|password|passwd)=/i.test(u.search)) add(3, "The address carries a password, PIN or OTP in its parameters.");

  const tokens = host.split(/[^a-z0-9]+/);
  for (const [brand, domains] of Object.entries(BRANDS)) {
    const mentioned = tokens.includes(brand) || (LONG_BRANDS.includes(brand) && host.includes(brand));
    if (!mentioned) continue;
    const official = domains.some((d) => host === d || host.endsWith("." + d));
    if (!official) { add(4, `The name “${brand}” appears in the address, but the site's real domain is ${reg}. Check the official ${brand} website yourself.`); break; }
  }
  const score = flags.reduce((n, f) => n + f.w, 0);
  flags.sort((a, b) => b.w - a.w);
  return { flags: flags.map((f) => f.t), level: levelFromScore(score), host: reg, assumed };
}

/* ---------- optional Google Safe Browsing (user's own key) ---------- */
async function safeBrowsing(url, key) {
  const payload = {
    client: { clientId: "cybershield-rsa-frontend", clientVersion: "2.0.0" },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
      platformTypes: ["ANY_PLATFORM"], threatEntryTypes: ["URL"], threatEntries: [{ url }],
    },
  };
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 12000);
  try {
    const r = await fetch("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + encodeURIComponent(key), {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload), signal: ctrl.signal,
    });
    if (r.status === 400 || r.status === 401 || r.status === 403) return { status: "bad_key" };
    if (!r.ok) return { status: "unavailable" };
    const d = await r.json();
    return d.matches?.length ? { status: "threat", types: [...new Set(d.matches.map((m) => m.threatType))] } : { status: "clear" };
  } catch { return { status: "unavailable" }; }
  finally { clearTimeout(timer); }
}

async function checkUrl(value) {
  const local = analyseUrl(value);
  if (local.error) { showResult("warn", "Could not review this link", local.error); return; }
  const target = local.assumed ? "https://" + value.trim() : value.trim();
  const key = store.get("cs-gsb-key", "");
  let g = null;
  if (key) g = await safeBrowsing(target, key);

  const flagsHTML = local.flags.length ? `<p><b>Warning signs found:</b></p>${listHTML(local.flags)}` : "<p>No common warning signs were found in the link itself.</p>";
  let gNote = "";
  if (g?.status === "threat") { showResult("bad", "Potential threat found", "Google Safe Browsing reports this URL as a potential threat. Do not visit it or enter personal information.", `<p><b>Threat types:</b> ${esc(g.types.join(", "))}</p>${flagsHTML}`); return; }
  if (g?.status === "clear") gNote = "Google Safe Browsing found no matching threat.";
  if (g?.status === "bad_key") gNote = "Your Google Safe Browsing key was rejected, so only local checks ran.";
  if (g?.status === "unavailable") gNote = "Google Safe Browsing could not be reached, so only local checks ran.";

  const kind = local.level === "high" ? "bad" : local.level === "medium" ? "warn" : "info";
  const titles = { high: "Several warning signs found", medium: "Some warning signs found", low: "Few warning signs found" };
  const msgs = {
    high: "This link shows several traits common in phishing. Do not open it or enter any details.",
    medium: "This link has traits worth being careful about. Verify it through the organisation's official website or app.",
    low: "Nothing obviously suspicious in the link itself. This is not a safety check: new scam sites often look ordinary.",
  };
  showResult(kind, titles[local.level], msgs[local.level],
    `<p><b>Site domain:</b> ${esc(local.host)}</p>${flagsHTML}${gNote ? noteHTML(gNote) : ""}${key ? "" : noteHTML("Checked locally only. No reputation database was used.")}`);
}

/* ---------- message / email analysis (local) ---------- */
const TEXT_RULES = [
  [/urgent|immediately|within\s+\d+\s+(hours?|minutes?)|act now|final warning|last chance|expires today/, 1, "Urgency or pressure language"],
  [/verify your account|account (has been )?(suspended|blocked|locked|limited)|unusual activity|suspicious activity|confirm your (identity|details)/, 2, "Account verification or suspension claim"],
  [/\botp\b|one.time.pin|verification code|pin code|passcode|\bcvv\b|\bpin\b/, 2, "Verification code or PIN mentioned"],
  [/click here|tap here|open this link|follow this link|click the link|click below/, 1, "Prompt to open a link"],
  [/prize|winner|you have won|claim your (reward|prize)|free gift|lucky draw/, 2, "Unexpected prize or reward"],
  [/payment required|pay now|outstanding (fee|balance)|delivery fee|customs fee|release fee|clearance fee/, 2, "Unexpected payment request"],
  [/gift card|crypto|bitcoin|voucher|e-?wallet|ewallet|cash ?send/, 2, "Unusual payment method"],
  [/\bbank\b|fnb|standard bank|capitec|nedbank|absa|paypal|discovery bank|tymebank/, 1, "Financial brand or payment service mentioned"],
  [/\bsars\b|tax refund|efiling|\bsassa\b|srd grant|grant (has been )?(approved|suspended)/, 2, "Government or grant claim (SARS, SASSA)"],
  [/parcel|package|courier|delivery attempt|postnet|post office|waybill|\bdhl\b|aramex|the courier guy/, 1, "Parcel or delivery notice"],
  [/hi (mum|mom|dad)|new number|lost my phone|changed my number|this is my new/, 2, "“New number” or family-impersonation pattern"],
  [/work from home|earn r?\d|guaranteed (income|returns)|double your money|investment opportunity|forex|no experience needed/, 2, "Too-good-to-be-true money offer"],
  [/do not tell anyone|keep this confidential|don'?t tell|secret/, 2, "Request for secrecy"],
  [/whatsapp me on|contact me on whatsapp|text me on|reply with your (id|password|pin)/, 1, "Request to move the conversation or send details"],
];

function analyseText(text, kind) {
  const s = text.toLowerCase();
  const signals = []; let score = 0;
  for (const [re, w, label] of TEXT_RULES) if (re.test(s)) { signals.push(label); score += w; }

  // links inside the text
  const urls = text.match(/\b(?:https?:\/\/|www\.)[^\s<>"')]+/gi) || [];
  const bare = (text.match(/\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:xyz|top|click|icu|tk|ml|gq|cf|ga|zip|support|work)\b[^\s]*/gi) || []).filter((b) => !urls.some((u) => u.includes(b)));
  const linkFlags = [];
  for (const u of [...urls, ...bare].slice(0, 5)) {
    const a = analyseUrl(u);
    if (a.error) continue;
    if (a.level !== "low" || a.flags.length) { linkFlags.push(`Link ${u.length > 50 ? u.slice(0, 50) + "…" : u}: ${a.flags[0] || "unusual"}`); score += a.level === "high" ? 3 : a.level === "medium" ? 2 : 1; }
  }
  if (urls.length + bare.length) signals.push("Contains a web link (check it with the URL scanner)");

  if (kind === "email") {
    if (/dear customer|dear user|dear client|valued customer|dear account holder/.test(s)) { signals.push("Generic greeting"); score += 1; }
    if (/password|banking details|card number|identity number|id number/.test(s)) { signals.push("Sensitive information referenced"); score += 2; }
    if (/attachment|attached|open the (file|document)|\.(zip|exe|scr|html?)\b/.test(s)) { signals.push("Attachment mentioned or risky file type"); score += 1; }
    const sender = text.match(/from:\s*(?:[^<\n]*<)?([^\s<>@]+@([^\s<>]+))/i);
    if (sender) {
      const domain = sender[2].toLowerCase().replace(/[>.]+$/, "");
      if (/^(gmail|outlook|yahoo|hotmail|icloud)\./.test(domain)) { signals.push("Free email provider used as the sender; genuine organisations rarely do this. Verify independently"); score += 2; }
      for (const [brand, domains] of Object.entries(BRANDS)) {
        if (domain.includes(brand) && !domains.some((d) => domain === d || domain.endsWith("." + d))) { signals.push(`Sender domain “${domain}” imitates ${brand} but is not its official domain`); score += 4; break; }
      }
    } else { signals.push("No sender address found in the text. Paste the From line for a better review"); }
  }
  if (text.trim().length < 25) signals.push("Very little text supplied; assessment may be incomplete");
  return { level: levelFromScore(score), signals: [...signals, ...linkFlags] };
}

function renderTextResult(d, kind) {
  const resKind = d.level === "high" ? "bad" : d.level === "medium" ? "warn" : "info";
  const summaries = {
    high: "Several common scam indicators were found. Treat this with strong caution and verify through an official channel.",
    medium: "Some warning signs were found. Do not follow links or send money until you verify independently.",
    low: "Few common warning signs were detected. This does not prove the message is genuine or safe.",
  };
  const body = d.signals.length ? `<p><b>Signals identified:</b></p>${listHTML(d.signals)}` : "<p>No common patterns were detected in the supplied text.</p>";
  showResult(resKind, `${d.level.charAt(0).toUpperCase() + d.level.slice(1)} number of warning signs`, summaries[d.level],
    `${body}${noteHTML("This is a transparent pattern review, not a definitive scam verdict. When in doubt, contact the organisation using a number from its official website or your bank card.")}`);
}

/* ---------- caller ID (on-device book + static community list) ---------- */
const PHONE_KEY = "cs-phone-reports";
const CATEGORY_LABELS = { safe: "Known / trusted", spam: "Spam", telemarketer: "Telemarketer", impersonation: "Impersonation", payment_scam: "Payment scam", harassment: "Harassment", other: "Other" };
const BAD = new Set(["spam", "telemarketer", "impersonation", "payment_scam", "harassment"]);
let community = [];

function normalisePhone(value) {
  let d = String(value).replace(/\D/g, "");
  if (d.startsWith("00")) d = d.slice(2);
  else if (d.startsWith("0") && d.length === 10) d = "27" + d.slice(1);
  if (d.length < 7 || d.length > 15) return null;
  return d;
}
const matchKey = (d) => (d.length >= 9 ? d.slice(-9) : d);
function loadBook() { try { const a = JSON.parse(store.get(PHONE_KEY, "[]")); return Array.isArray(a) ? a.filter((r) => r && r.n && r.c) : []; } catch { return []; } }
function saveBook(a) { return store.set(PHONE_KEY, JSON.stringify(a.slice(-1000))); }
function updateBookCount() { const n = loadBook().length; $("bookCount").textContent = n ? `(${n} saved)` : ""; }

async function loadCommunity() {
  try {
    const r = await fetch("community-numbers.json", { cache: "no-cache" });
    if (!r.ok) return;
    const d = await r.json();
    community = (d.numbers || []).map((x) => ({ n: normalisePhone(x.number), c: x.category, label: x.label || "", note: x.note || "" })).filter((x) => x.n && x.c);
  } catch { /* offline or opened as a local file: skip */ }
}

function phoneInfo(d) {
  const notes = [];
  if (d.startsWith("27")) {
    const n = d.slice(2);
    if (n.length !== 9) notes.push("This does not match the usual length of a South African number.");
    else if (/^80/.test(n)) notes.push("0800 numbers are normally toll-free.");
    else if (/^86/.test(n)) notes.push("086x numbers are shared-cost lines; calls may be charged.");
    else if (/^90/.test(n)) notes.push("090x numbers are premium-rate lines; calls can be expensive.");
    else if (/^(6|7|8[1-5])/.test(n)) notes.push("Format looks like a South African mobile number.");
    else if (/^[1-5]/.test(n)) notes.push("Format looks like a South African landline.");
  } else {
    notes.push("This is not a South African number. Be extra careful if the caller claims to be your bank, SARS or a local courier.");
  }
  return notes;
}
const catLabel = (c) => CATEGORY_LABELS[c] || c;

function checkPhone(value) {
  const d = normalisePhone(value);
  if (!d) { showResult("warn", "Check the number", "Enter a valid phone number, ideally with its country code (for example +27 …)."); return; }
  const k = matchKey(d);
  const mine = loadBook().filter((r) => matchKey(r.n) === k);
  const comm = community.filter((r) => matchKey(r.n) === k);
  const info = phoneInfo(d);
  const infoHTML = info.length ? `<p><b>About this number:</b></p>${listHTML(info)}` : "";
  const names = [...new Set([...mine, ...comm].map((r) => r.name || r.label).filter(Boolean))];
  const nameHTML = names.length ? `<p><b>Saved as:</b> ${names.map(esc).join(", ")}</p>` : "";
  const entries = [...mine.map((r) => ({ ...r, src: "My caller book" })), ...comm.map((r) => ({ ...r, src: "Community list" }))];

  if (!entries.length) {
    showResult("info", "Unknown number", "This number is not in your caller book or the community list. That does not mean it is safe.",
      infoHTML + noteHTML("Not sure who it is? Do not share OTPs, PINs or banking details. Hang up and call the organisation back on its official number."));
    return;
  }
  const bad = entries.filter((e) => BAD.has(e.c));
  const safe = entries.filter((e) => e.c === "safe");
  const chips = entries.map((e) => `<span class="chip">${esc(e.src)}: ${esc(catLabel(e.c))}</span>`).join("");
  const notes = entries.map((e) => e.note).filter(Boolean);
  const noteList = notes.length ? listHTML(notes) : "";
  if (bad.length) {
    showResult(bad.some((e) => e.c === "payment_scam" || e.c === "impersonation") ? "bad" : "warn", "Flagged number",
      "This number has been labelled as unwanted or suspicious. Labels are unverified notes, not proof.", `${nameHTML}<div class="chips">${chips}</div>${noteList}${infoHTML}`);
  } else if (safe.length) {
    showResult("good", names[0] ? `Known: ${names[0]}` : "Known number", "You marked this number as trusted. Scammers can still spoof a trusted number, so stay alert to what is being asked.", `${nameHTML}<div class="chips">${chips}</div>${infoHTML}`);
  } else {
    showResult("info", "Number found", "This number has a label.", `${nameHTML}<div class="chips">${chips}</div>${noteList}${infoHTML}`);
  }
}

function saveReport() {
  const d = normalisePhone($("toolInput").value);
  if (!d) { showResult("warn", "Check the number", "Enter a valid phone number before saving."); return; }
  const all = loadBook().filter((r) => !(matchKey(r.n) === matchKey(d) && r.c === $("reportCategory").value));
  all.push({ n: d, c: $("reportCategory").value, name: $("callerName").value.trim().slice(0, 60), t: Date.now() });
  if (!saveBook(all)) { showResult("warn", "Could not save", "Your browser is blocking local storage (private mode?), so nothing was saved."); return; }
  updateBookCount(); checkPhone($("toolInput").value);
}

async function shareReport() {
  const d = normalisePhone($("toolInput").value);
  if (!d) { showResult("warn", "Check the number", "Enter a valid phone number before sharing a report."); return; }
  const text = `CyberShield RSA report\nNumber: +${d}\nLabel: ${catLabel($("reportCategory").value)}${$("callerName").value.trim() ? "\nName: " + $("callerName").value.trim() : ""}`;
  try {
    if (navigator.share) { await navigator.share({ title: "CyberShield RSA report", text }); return; }
    await navigator.clipboard.writeText(text);
    showResult("info", "Report copied", "Paste it to whoever maintains the community list (email or WhatsApp). Only labelled numbers they verify are added.", noteHTML(text));
  } catch { showResult("warn", "Could not share", "Copy this manually:", noteHTML(text)); }
}

function exportBook() {
  const blob = new Blob([JSON.stringify({ app: "cybershield-rsa", version: 1, numbers: loadBook() }, null, 2)], { type: "application/json" });
  const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "my-caller-book.json"; a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}
async function importBook(file) {
  try {
    const d = JSON.parse(await file.text());
    const rows = (Array.isArray(d) ? d : d.numbers || []).map((x) => ({ n: normalisePhone(x.n || x.number || ""), c: x.c || x.category, name: String(x.name || x.label || "").slice(0, 60), t: x.t || Date.now() })).filter((x) => x.n && CATEGORY_LABELS[x.c]);
    if (!rows.length) { showResult("warn", "Nothing to import", "No valid numbers were found in that file."); return; }
    const all = loadBook(); const seen = new Set(all.map((r) => matchKey(r.n) + r.c));
    let added = 0; for (const r of rows) if (!seen.has(matchKey(r.n) + r.c)) { all.push(r); added++; }
    saveBook(all); updateBookCount(); showResult("info", "Import complete", `${added} new number${added === 1 ? "" : "s"} added to your caller book.`);
  } catch { showResult("warn", "Import failed", "That file is not a valid caller book (JSON)."); }
}

/* ---------- password ---------- */
const COMMON = /password|passw0rd|qwerty|letmein|admin|welcome|123456|iloveyou|abc123|monkey|dragon|11111|000000/i;
function assessPassword(p) {
  const checks = [
    [p.length >= 12, "Use at least 12 characters"], [p.length >= 16, "16 or more characters is better"],
    [/[a-z]/.test(p), "Add lowercase letters"], [/[A-Z]/.test(p), "Add uppercase letters"],
    [/[0-9]/.test(p), "Add numbers"], [/[^A-Za-z0-9]/.test(p), "Add a symbol"],
  ];
  let score = checks.filter((c) => c[0]).length;
  const tips = checks.filter((c) => !c[0]).map((c) => c[1]);
  if (/(.)\1{2,}/.test(p)) { score -= 1; tips.push("Avoid repeating the same character"); }
  if (/(?:0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef)/i.test(p)) { score -= 1; tips.push("Avoid simple sequences like 1234 or abcd"); }
  if (COMMON.test(p)) { score = 0; tips.unshift("Contains a very common password or pattern"); }
  return { score: Math.max(0, Math.min(6, score)), tips };
}
function checkPassword(p) {
  const { score, tips } = assessPassword(p);
  const label = score >= 5 ? "Stronger pattern" : score >= 3 ? "Moderate pattern" : "Weak pattern";
  const cls = score >= 5 ? "high" : score >= 3 ? "mid" : "low";
  const meter = `<div class="meter ${cls}" aria-hidden="true">${Array.from({ length: 6 }, (_, i) => `<i class="${i < score ? "on" : ""}"></i>`).join("")}</div>`;
  showResult(score >= 5 ? "good" : score >= 3 ? "warn" : "bad", label,
    `Local estimate: ${score}/6 checks met. Use a unique long passphrase and a password manager. This is not a breach check. Your input never leaves this browser.`,
    meter + (tips.length ? `<p><b>To improve:</b></p>${listHTML(tips)}` : ""));
}

/* ---------- tool selection ---------- */
function selectTool(name) {
  currentTool = name; const t = tools[name];
  $("toolTitle").textContent = t.title; $("toolDescription").textContent = t.desc;
  $("inputLabel").textContent = t.label; $("toolInput").placeholder = t.placeholder; $("inputHint").textContent = t.hint;
  $("submitButton").innerHTML = t.button + " <span>→</span>";
  $("toolInput").value = ""; $("toolInput").rows = t.rows;
  $("extra-phone").hidden = name !== "phone";
  $("extra-url").hidden = name !== "url";
  document.querySelectorAll(".tool-card").forEach((b) => b.classList.toggle("active", b.dataset.tool === name));
  const intro = {
    url: ["info", "Ready to check", "The link will be analysed in your browser. It is not opened or sent anywhere unless you add your own Google key."],
    password: ["info", "Private browser check", "Use a test password only. The value stays in this browser."],
    phone: ["info", "Ready to look up", "Enter a number to see who it belongs to in your caller book or the community list, plus its type."],
  }[name] || ["info", "Ready for review", "Your result will include the signals found and what they do and do not mean."];
  showResult(...intro);
}
document.querySelectorAll(".tool-card").forEach((b) => b.addEventListener("click", () => {
  selectTool(b.dataset.tool);
  $("workspace").scrollIntoView({ behavior: "smooth", block: "center" });
}));

/* ---------- submit ---------- */
async function submit() {
  const value = $("toolInput").value.trim();
  if (!value) { showResult("warn", "Input required", "Enter something to check first."); return; }
  const btn = $("submitButton"); btn.disabled = true; btn.textContent = "Checking…";
  try {
    if (currentTool === "url") await checkUrl(value);
    else if (currentTool === "message" || currentTool === "email") renderTextResult(analyseText(value.slice(0, 12000), currentTool), currentTool);
    else if (currentTool === "phone") checkPhone(value);
    else if (currentTool === "password") checkPassword(value);
  } catch (e) {
    showResult("warn", "Could not complete check", "Something went wrong while reviewing this input. Please try again.");
  } finally { btn.disabled = false; btn.innerHTML = tools[currentTool].button + " <span>→</span>"; }
}
$("toolForm").addEventListener("submit", (e) => { e.preventDefault(); submit(); });
$("reportButton").addEventListener("click", saveReport);
$("shareButton").addEventListener("click", shareReport);
$("exportBook").addEventListener("click", exportBook);
$("importBook").addEventListener("click", () => $("importFile").click());
$("importFile").addEventListener("change", (e) => { if (e.target.files[0]) importBook(e.target.files[0]); e.target.value = ""; });
$("clearReports").addEventListener("click", () => {
  if (confirm("Delete your whole caller book from this device?")) { store.del(PHONE_KEY); updateBookCount(); showResult("info", "Caller book cleared", "Everything saved on this device was removed."); }
});

/* ---------- optional Safe Browsing key ---------- */
function refreshKeyUI() {
  const has = !!store.get("cs-gsb-key", "");
  $("removeKey").hidden = !has;
  $("gsbKey").value = ""; $("gsbKey").placeholder = has ? "Key saved in this browser" : "Your Google Safe Browsing API key";
}
$("saveKey").addEventListener("click", () => {
  const k = $("gsbKey").value.trim();
  if (!k) { showResult("warn", "No key entered", "Paste your Google Safe Browsing API key first."); return; }
  if (!store.set("cs-gsb-key", k)) { showResult("warn", "Could not save", "Your browser is blocking local storage."); return; }
  refreshKeyUI(); showResult("info", "Key saved", "URL checks will now also query Google Safe Browsing. The key stays in this browser.");
});
$("removeKey").addEventListener("click", () => { store.del("cs-gsb-key"); refreshKeyUI(); showResult("info", "Key removed", "URL checks will use local analysis only."); });
refreshKeyUI();

selectTool("url");
updateBookCount();
loadCommunity();
if ("serviceWorker" in navigator && location.protocol.startsWith("http")) navigator.serviceWorker.register("sw.js").catch(() => {});
