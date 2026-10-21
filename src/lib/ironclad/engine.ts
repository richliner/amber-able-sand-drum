export type Level = "danger" | "warn" | "caution" | "info";
export type Kind = "malware" | "danger" | "aggressive";

export const ALERT_META: Record<Kind, { title: string; rank: number; seconds: number }> = {
  malware: { title: "Malware blocked", rank: 3, seconds: 9 },
  danger: { title: "Dangerous link blocked", rank: 2, seconds: 8 },
  aggressive: { title: "Aggressive ad blocked", rank: 1, seconds: 6 },
};

export const LEVEL_LABEL: Record<Level, string> = {
  danger: "Dangerous",
  warn: "Suspicious",
  caution: "Caution",
  info: "No red flags",
};

export const AD_DOMAINS = [
  "doubleclick.net",
  "googlesyndication.com",
  "googleadservices.com",
  "google-analytics.com",
  "googletagmanager.com",
  "adnxs.com",
  "criteo.com",
  "taboola.com",
  "outbrain.com",
  "scorecardresearch.com",
  "quantserve.com",
  "amazon-adsystem.com",
  "pubmatic.com",
  "rubiconproject.com",
  "openx.net",
  "2mdn.net",
  "adsrvr.org",
  "casalemedia.com",
  "moatads.com",
  "adform.net",
];

export const AGGRESSIVE_DOMAINS = [
  "popads.net",
  "popcash.net",
  "propellerads.com",
  "adsterra.com",
  "exoclick.com",
  "clickadu.com",
];

export const MALWARE_DOMAINS = ["evil-update.tk", "secure-wallet-check.gq"];

const BRANDS: Record<string, string[]> = {
  paypal: ["paypal.com"],
  microsoft: ["microsoft.com", "live.com", "office.com", "outlook.com"],
  google: ["google.com", "gmail.com"],
  apple: ["apple.com", "icloud.com"],
  amazon: ["amazon.com"],
  netflix: ["netflix.com"],
  facebook: ["facebook.com"],
  instagram: ["instagram.com"],
  steam: ["steampowered.com"],
  discord: ["discord.com"],
  coinbase: ["coinbase.com"],
};

const LEGIT = new Set(Object.values(BRANDS).flat());
const HIGH_TLD = new Set(["zip", "mov", "tk", "gq", "ml", "cf", "ga", "top", "click", "xyz", "rest", "cfd"]);
const SHORTENERS = new Set(["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "rb.gy", "tiny.cc"]);
const KEYWORDS = ["login", "signin", "verify", "secure", "account", "wallet", "update", "banking", "password", "billing"];
const EXEC = new Set(["exe", "scr", "bat", "cmd", "js", "vbs", "ps1", "hta", "jar", "apk", "msi", "dmg"]);

const LEET: Record<string, string> = { "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t" };

export type Finding = { points: number; text: string };
export type Scan = {
  input: string;
  host: string;
  score: number;
  level: Level;
  findings: Finding[];
  error?: string;
};

export type SimRequest = { host: string; delay: number; reason?: string; score?: number };
export type Scenario = { id: string; title: string; detail: string; requests: SimRequest[] };

export const ZAPS = [
  { id: "newsletter", label: "Newsletter modal" },
  { id: "cookie", label: "Cookie banner" },
  { id: "gift", label: "Gift-card popup" },
  { id: "rail", label: "Sidebar advertisement" },
  { id: "sponsor", label: "Sponsored card" },
] as const;

function pack(hosts: string[], start: number, step: number): SimRequest[] {
  return hosts.map((host, i) => ({ host, delay: start + i * step }));
}

export const SCENARIOS: Scenario[] = [
  {
    id: "news",
    title: "Visit a news article",
    detail: "Trackers, a pop network, and a malware frame load together.",
    requests: [
      ...pack(
        ["doubleclick.net", "googletagmanager.com", "criteo.com", "taboola.com", "scorecardresearch.com", "amazon-adsystem.com"],
        30,
        60,
      ),
      { host: "popads.net", delay: 160 },
      { host: "evil-update.tk", delay: 380 },
    ],
  },
  {
    id: "phish",
    title: "Open a lookalike login",
    detail: "A PayPal-style name on a risky domain. Rated dangerous.",
    requests: [{ host: "paypa1-secure-login.xyz", delay: 40, reason: "threat scanner score: 86", score: 86 }],
  },
  {
    id: "burst",
    title: "Fire a tracker burst",
    detail: "Many hits in under a second. The badge counts each one. Alerts fold into a single notice.",
    requests: [
      ...pack(AD_DOMAINS.slice(0, 12), 0, 28),
      { host: "popads.net", delay: 40 },
      { host: "popcash.net", delay: 70 },
      { host: "adsterra.com", delay: 110 },
      { host: "propellerads.com", delay: 150 },
      { host: "secure-wallet-check.gq", delay: 190 },
      { host: "popads.net", delay: 230 },
      { host: "popads.net", delay: 270 },
      { host: "popads.net", delay: 310 },
      { host: "secure-wallet-check.gq", delay: 350 },
    ],
  },
];

export function domainMatches(host: string, domain: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, "");
  const d = domain.toLowerCase().replace(/^\*\./, "");
  return h === d || h.endsWith("." + d);
}

export function listed(host: string, domains: readonly string[]): boolean {
  return domains.some((d) => domainMatches(host, d));
}

export function classifyBlock(host: string, reason: string, score = 0): Kind | null {
  const r = reason.toLowerCase();
  if (r.includes("malware") || r.includes("phishing")) return "malware";
  if (r.includes("dangerous scan")) return "danger";
  const m = r.match(/score\D{0,3}(\d+)/);
  const s = Math.max(score, m ? Number(m[1]) : 0);
  if (s >= 70) return "danger";
  const h = host.toLowerCase().replace(/\.$/, "");
  if (AGGRESSIVE_DOMAINS.some((d) => h === d || h.endsWith("." + d))) return "aggressive";
  return null;
}

export type Decision = { blocked: true; reason: string; score: number };

export function decide(
  host: string,
  hint: { reason?: string; score?: number },
  blockedDomains: readonly string[],
): Decision | null {
  if (listed(host, blockedDomains)) return { blocked: true, reason: "dangerous scan", score: hint.score ?? 80 };
  if (listed(host, MALWARE_DOMAINS)) return { blocked: true, reason: "malware/phishing feed", score: 90 };
  if (listed(host, AGGRESSIVE_DOMAINS)) return { blocked: true, reason: "Aggressive ad/pop-under network", score: 25 };
  if (listed(host, AD_DOMAINS)) return { blocked: true, reason: "ad/tracker list", score: 8 };
  const score = hint.score ?? 0;
  if (score >= 70) return { blocked: true, reason: hint.reason || `threat scanner score: ${score}`, score };
  const m = (hint.reason || "").match(/score\D{0,3}(\d+)/);
  if (m && Number(m[1]) >= 70) return { blocked: true, reason: hint.reason || "", score: Number(m[1]) };
  return null;
}

export type PendingEvent = { kind: Kind; host: string; reason: string; source: string; t: number };
export type Digest = {
  id: string;
  kind: Kind;
  head: PendingEvent;
  hosts: string[];
  events: number;
  suppressed: number;
  total: number;
};

export class AlertThrottle {
  hostCooldown: number;
  coalesce = 1;
  minGap = 3;
  cap = 8;
  capWindow = 300;
  private hostLast = new Map<string, number>();
  private pending: PendingEvent[] = [];
  private firstAt: number | null = null;
  private suppressed = 0;
  private lastToast = -1e18;
  private toasts: number[] = [];

  constructor(hostCooldown = 60) {
    this.hostCooldown = hostCooldown;
  }

  offer(kind: Kind, host: string, reason: string, source: string, now: number): boolean {
    const key = `${kind}|${host}`;
    const last = this.hostLast.get(key);
    if (last != null && now - last < this.hostCooldown) {
      this.suppressed += 1;
      return false;
    }
    this.hostLast.set(key, now);
    if (this.hostLast.size > 3000) {
      const cutoff = now - this.hostCooldown;
      for (const [k, t] of this.hostLast) if (t < cutoff) this.hostLast.delete(k);
    }
    if (this.pending.length === 0) this.firstAt = now;
    this.pending.push({ kind, host, reason, source, t: now });
    if (this.pending.length > 500) this.pending.splice(0, 250);
    return true;
  }

  hasPending(): boolean {
    return this.pending.length > 0;
  }

  private readyAt(now: number): number | null {
    if (!this.pending.length || this.firstAt == null) return null;
    this.toasts = this.toasts.filter((t) => now - t < this.capWindow);
    let t = Math.max(this.firstAt + this.coalesce, this.lastToast + this.minGap);
    if (this.toasts.length >= this.cap && this.toasts[0] != null) t = Math.max(t, this.toasts[0] + this.capWindow);
    return t;
  }

  nextDelay(now: number): number | null {
    const t = this.readyAt(now);
    return t == null ? null : Math.max(0, t - now);
  }

  poll(now: number): Digest | null {
    const ready = this.readyAt(now);
    if (ready == null || now < ready) return null;
    const events = this.pending;
    this.pending = [];
    this.firstAt = null;
    const suppressed = this.suppressed;
    this.suppressed = 0;
    this.lastToast = now;
    this.toasts.push(now);
    events.sort((a, b) => ALERT_META[b.kind].rank - ALERT_META[a.kind].rank);
    const seen = new Set<string>();
    const hosts: string[] = [];
    for (const e of events) {
      if (!seen.has(e.host)) {
        seen.add(e.host);
        hosts.push(e.host);
      }
    }
    const head = events[0];
    if (!head) return null;
    return {
      id: `${now.toFixed(3)}-${head.host}-${Math.random().toString(36).slice(2, 6)}`,
      kind: head.kind,
      head,
      hosts,
      events: events.length,
      suppressed,
      total: events.length + suppressed,
    };
  }

  reset(): void {
    this.hostLast.clear();
    this.pending = [];
    this.firstAt = null;
    this.suppressed = 0;
    this.lastToast = -1e18;
    this.toasts = [];
  }
}

export const throttle = new AlertThrottle(60);

function deleet(s: string): string {
  return s.replace(/[013457]/g, (ch) => LEET[ch] || ch);
}

export function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > 3) return 99;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
    }
    prev = cur;
  }
  return prev[b.length] ?? 99;
}

function regDomain(host: string): string {
  const parts = host.split(".");
  if (parts.length < 2) return host;
  const last2 = parts.slice(-2).join(".");
  const multi = new Set(["co.uk", "com.au", "co.jp", "com.br", "co.nz", "com.mx"]);
  if (multi.has(last2) && parts.length >= 3) return parts.slice(-3).join(".");
  return last2;
}

function levelOf(score: number): Level {
  if (score >= 70) return "danger";
  if (score >= 40) return "warn";
  if (score >= 15) return "caution";
  return "info";
}

export function scanUrl(input: string): Scan {
  const findings: Finding[] = [];
  const add = (points: number, text: string) => {
    if (!findings.some((f) => f.text === text)) findings.push({ points, text });
  };
  const rawIn = input.trim();
  if (!rawIn) {
    return { input, host: "", score: 0, level: "info", findings, error: "Enter a website link." };
  }
  let candidate = rawIn.replace(/\s+/g, "");
  const low = candidate.toLowerCase();
  if (low.startsWith("javascript:") || low.startsWith("data:") || low.startsWith("vbscript:")) {
    add(100, "This link runs code instead of opening a site.");
    return { input: candidate, host: "", score: 100, level: "danger", findings };
  }
  if (!/^[a-z][a-z0-9+.-]*:/i.test(candidate)) candidate = "https://" + candidate;
  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    return { input: candidate, host: "", score: 0, level: "info", findings, error: "That link could not be read." };
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    add(40, `Unusual scheme ${url.protocol}`);
    return { input: candidate, host: "", score: 40, level: "warn", findings };
  }
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  if (!host) {
    return { input: candidate, host: "", score: 0, level: "info", findings, error: "No website name was found." };
  }
  if (url.username) add(40, "A name before @ hides the real destination.");
  const ip = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
  if (ip) add(35, "Uses a raw IP address instead of a domain name.");
  const reg = regDomain(host);
  const main = reg.split(".")[0] || "";
  const labels = host.split(".");
  let official = LEGIT.has(reg) || LEGIT.has(host);
  let brandHit = false;
  if (!official) {
    for (const [brand, domains] of Object.entries(BRANDS)) {
      if (domains.some((d) => host === d || host.endsWith("." + d))) {
        official = true;
        add(0, `Domain matches official ${brand}.`);
        break;
      }
      const near = labels.some((l) => l === brand || deleet(l) === brand || (l.length >= 6 && levenshtein(deleet(l), brand) === 1));
      if (near || (main.length >= 6 && (levenshtein(deleet(main), brand) <= 1 || deleet(main).includes(brand)))) {
        brandHit = true;
        add(50, `“${brand}” appears on ${reg}, which is not the real ${brand} domain.`);
        break;
      }
    }
  } else {
    add(0, "Domain matches a known official name. This does not prove the page is safe.");
  }
  const tld = host.split(".").pop() || "";
  let infra = false;
  if (!official && HIGH_TLD.has(tld)) {
    infra = true;
    add(HIGH_TLD.has(tld) && ["tk", "gq", "ml", "cf", "ga"].includes(tld) ? 24 : 14, `.${tld} is heavily abused for phishing.`);
  }
  if (SHORTENERS.has(host) || SHORTENERS.has(reg)) {
    infra = true;
    add(20, "URL shortener: the final destination is hidden.");
  }
  if (ip) infra = true;
  const flat = host.replace(/\./g, "-");
  const kws = KEYWORDS.filter((k) => flat.includes(k));
  let bait = false;
  if (!official && kws.length >= 2) {
    bait = true;
    add(18, `Host stacks credential words (${kws.slice(0, 3).join(", ")}).`);
  } else if (!official && kws.length === 1) {
    bait = true;
    add(8, `Host contains “${kws[0]}”.`);
  }
  if (!official && (host.match(/-/g) || []).length >= 3) add(10, "Many hyphens, common on phishing domains.");
  const last = url.pathname.split("/").pop() || "";
  const ext = last.includes(".") ? last.split(".").pop()!.toLowerCase() : "";
  if (EXEC.has(ext)) add(35, `Link points straight at a program (.${ext}).`);
  if (url.protocol === "http:" && /login|signin|password|account|verify/.test(url.pathname + url.search)) {
    add(15, "Login page sent over plain HTTP.");
  }
  if (!official && (brandHit || bait) && infra) add(14, "Several independent red flags combine.");
  else if (!official && brandHit && bait) add(14, "A brand name plus credential bait is a typical phishing shape.");
  const score = Math.min(100, findings.reduce((sum, f) => sum + f.points, 0));
  findings.sort((a, b) => b.points - a.points);
  return { input: candidate, host, score, level: levelOf(score), findings };
}

export const HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

export function sourceLabel(source: string): string {
  if (source === "page") return "this tab";
  if (source === "scanner") return "link scanner";
  if (source === "test") return "test alert";
  return source;
}
