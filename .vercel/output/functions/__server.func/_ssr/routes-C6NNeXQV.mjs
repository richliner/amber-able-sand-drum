import { i as __toESM } from "../_runtime.mjs";
import { K as require_react, b as require_jsx_runtime } from "../_libs/@tanstack/react-router+[...].mjs";
import { a as ShieldAlert, c as Puzzle, d as Megaphone, f as ListChecks, g as Activity, h as Bell, i as Shield, l as Plus, m as Download, n as TriangleAlert, o as ScanSearch, p as Laptop, r as Trash2, s as RotateCcw, t as X, u as MousePointer2 } from "../_libs/lucide-react.mjs";
import { t as create } from "../_libs/zustand.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/routes-C6NNeXQV.js
var import_react = /* @__PURE__ */ __toESM(require_react());
var import_jsx_runtime = require_jsx_runtime();
var ALERT_META = {
	malware: {
		title: "Malware blocked",
		rank: 3,
		seconds: 9
	},
	danger: {
		title: "Dangerous link blocked",
		rank: 2,
		seconds: 8
	},
	aggressive: {
		title: "Aggressive ad blocked",
		rank: 1,
		seconds: 6
	}
};
var LEVEL_LABEL = {
	danger: "Dangerous",
	warn: "Suspicious",
	caution: "Caution",
	info: "No red flags"
};
var AD_DOMAINS = [
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
	"adform.net"
];
var AGGRESSIVE_DOMAINS = [
	"popads.net",
	"popcash.net",
	"propellerads.com",
	"adsterra.com",
	"exoclick.com",
	"clickadu.com"
];
var MALWARE_DOMAINS = ["evil-update.tk", "secure-wallet-check.gq"];
var BRANDS = {
	paypal: ["paypal.com"],
	microsoft: [
		"microsoft.com",
		"live.com",
		"office.com",
		"outlook.com"
	],
	google: ["google.com", "gmail.com"],
	apple: ["apple.com", "icloud.com"],
	amazon: ["amazon.com"],
	netflix: ["netflix.com"],
	facebook: ["facebook.com"],
	instagram: ["instagram.com"],
	steam: ["steampowered.com"],
	discord: ["discord.com"],
	coinbase: ["coinbase.com"]
};
var LEGIT = new Set(Object.values(BRANDS).flat());
var HIGH_TLD = /* @__PURE__ */ new Set([
	"zip",
	"mov",
	"tk",
	"gq",
	"ml",
	"cf",
	"ga",
	"top",
	"click",
	"xyz",
	"rest",
	"cfd"
]);
var SHORTENERS = /* @__PURE__ */ new Set([
	"bit.ly",
	"tinyurl.com",
	"t.co",
	"goo.gl",
	"is.gd",
	"ow.ly",
	"cutt.ly",
	"rb.gy",
	"tiny.cc"
]);
var KEYWORDS = [
	"login",
	"signin",
	"verify",
	"secure",
	"account",
	"wallet",
	"update",
	"banking",
	"password",
	"billing"
];
var EXEC = /* @__PURE__ */ new Set([
	"exe",
	"scr",
	"bat",
	"cmd",
	"js",
	"vbs",
	"ps1",
	"hta",
	"jar",
	"apk",
	"msi",
	"dmg"
]);
var LEET = {
	"0": "o",
	"1": "l",
	"3": "e",
	"4": "a",
	"5": "s",
	"7": "t"
};
var ZAPS = [
	{
		id: "newsletter",
		label: "Newsletter modal"
	},
	{
		id: "cookie",
		label: "Cookie banner"
	},
	{
		id: "gift",
		label: "Gift-card popup"
	},
	{
		id: "rail",
		label: "Sidebar advertisement"
	},
	{
		id: "sponsor",
		label: "Sponsored card"
	}
];
function pack(hosts, start, step) {
	return hosts.map((host, i) => ({
		host,
		delay: start + i * step
	}));
}
var SCENARIOS = [
	{
		id: "news",
		title: "Visit a news article",
		detail: "Trackers, a pop network, and a malware frame load together.",
		requests: [
			...pack([
				"doubleclick.net",
				"googletagmanager.com",
				"criteo.com",
				"taboola.com",
				"scorecardresearch.com",
				"amazon-adsystem.com"
			], 30, 60),
			{
				host: "popads.net",
				delay: 160
			},
			{
				host: "evil-update.tk",
				delay: 380
			}
		]
	},
	{
		id: "phish",
		title: "Open a lookalike login",
		detail: "A PayPal-style name on a risky domain. Rated dangerous.",
		requests: [{
			host: "paypa1-secure-login.xyz",
			delay: 40,
			reason: "threat scanner score: 86",
			score: 86
		}]
	},
	{
		id: "burst",
		title: "Fire a tracker burst",
		detail: "Many hits in under a second. The badge counts each one. Alerts fold into a single notice.",
		requests: [
			...pack(AD_DOMAINS.slice(0, 12), 0, 28),
			{
				host: "popads.net",
				delay: 40
			},
			{
				host: "popcash.net",
				delay: 70
			},
			{
				host: "adsterra.com",
				delay: 110
			},
			{
				host: "propellerads.com",
				delay: 150
			},
			{
				host: "secure-wallet-check.gq",
				delay: 190
			},
			{
				host: "popads.net",
				delay: 230
			},
			{
				host: "popads.net",
				delay: 270
			},
			{
				host: "popads.net",
				delay: 310
			},
			{
				host: "secure-wallet-check.gq",
				delay: 350
			}
		]
	}
];
function domainMatches(host, domain) {
	const h = host.toLowerCase().replace(/\.$/, "");
	const d = domain.toLowerCase().replace(/^\*\./, "");
	return h === d || h.endsWith("." + d);
}
function listed(host, domains) {
	return domains.some((d) => domainMatches(host, d));
}
function classifyBlock(host, reason, score = 0) {
	const r = reason.toLowerCase();
	if (r.includes("malware") || r.includes("phishing")) return "malware";
	if (r.includes("dangerous scan")) return "danger";
	const m = r.match(/score\D{0,3}(\d+)/);
	if (Math.max(score, m ? Number(m[1]) : 0) >= 70) return "danger";
	const h = host.toLowerCase().replace(/\.$/, "");
	if (AGGRESSIVE_DOMAINS.some((d) => h === d || h.endsWith("." + d))) return "aggressive";
	return null;
}
function decide(host, hint, blockedDomains) {
	if (listed(host, blockedDomains)) return {
		blocked: true,
		reason: "dangerous scan",
		score: hint.score ?? 80
	};
	if (listed(host, MALWARE_DOMAINS)) return {
		blocked: true,
		reason: "malware/phishing feed",
		score: 90
	};
	if (listed(host, AGGRESSIVE_DOMAINS)) return {
		blocked: true,
		reason: "Aggressive ad/pop-under network",
		score: 25
	};
	if (listed(host, AD_DOMAINS)) return {
		blocked: true,
		reason: "ad/tracker list",
		score: 8
	};
	const score = hint.score ?? 0;
	if (score >= 70) return {
		blocked: true,
		reason: hint.reason || `threat scanner score: ${score}`,
		score
	};
	const m = (hint.reason || "").match(/score\D{0,3}(\d+)/);
	if (m && Number(m[1]) >= 70) return {
		blocked: true,
		reason: hint.reason || "",
		score: Number(m[1])
	};
	return null;
}
var AlertThrottle = class {
	hostCooldown;
	coalesce = 1;
	minGap = 3;
	cap = 8;
	capWindow = 300;
	hostLast = /* @__PURE__ */ new Map();
	pending = [];
	firstAt = null;
	suppressed = 0;
	lastToast = -0xde0b6b3a7640000;
	toasts = [];
	constructor(hostCooldown = 60) {
		this.hostCooldown = hostCooldown;
	}
	offer(kind, host, reason, source, now) {
		const key = `${kind}|${host}`;
		const last = this.hostLast.get(key);
		if (last != null && now - last < this.hostCooldown) {
			this.suppressed += 1;
			return false;
		}
		this.hostLast.set(key, now);
		if (this.hostLast.size > 3e3) {
			const cutoff = now - this.hostCooldown;
			for (const [k, t] of this.hostLast) if (t < cutoff) this.hostLast.delete(k);
		}
		if (this.pending.length === 0) this.firstAt = now;
		this.pending.push({
			kind,
			host,
			reason,
			source,
			t: now
		});
		if (this.pending.length > 500) this.pending.splice(0, 250);
		return true;
	}
	hasPending() {
		return this.pending.length > 0;
	}
	readyAt(now) {
		if (!this.pending.length || this.firstAt == null) return null;
		this.toasts = this.toasts.filter((t) => now - t < this.capWindow);
		let t = Math.max(this.firstAt + this.coalesce, this.lastToast + this.minGap);
		if (this.toasts.length >= this.cap && this.toasts[0] != null) t = Math.max(t, this.toasts[0] + this.capWindow);
		return t;
	}
	nextDelay(now) {
		const t = this.readyAt(now);
		return t == null ? null : Math.max(0, t - now);
	}
	poll(now) {
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
		const seen = /* @__PURE__ */ new Set();
		const hosts = [];
		for (const e of events) if (!seen.has(e.host)) {
			seen.add(e.host);
			hosts.push(e.host);
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
			total: events.length + suppressed
		};
	}
	reset() {
		this.hostLast.clear();
		this.pending = [];
		this.firstAt = null;
		this.suppressed = 0;
		this.lastToast = -0xde0b6b3a7640000;
		this.toasts = [];
	}
};
var throttle = new AlertThrottle(60);
function deleet(s) {
	return s.replace(/[013457]/g, (ch) => LEET[ch] || ch);
}
function levenshtein(a, b) {
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
function regDomain(host) {
	const parts = host.split(".");
	if (parts.length < 2) return host;
	const last2 = parts.slice(-2).join(".");
	if ((/* @__PURE__ */ new Set([
		"co.uk",
		"com.au",
		"co.jp",
		"com.br",
		"co.nz",
		"com.mx"
	])).has(last2) && parts.length >= 3) return parts.slice(-3).join(".");
	return last2;
}
function levelOf(score) {
	if (score >= 70) return "danger";
	if (score >= 40) return "warn";
	if (score >= 15) return "caution";
	return "info";
}
function scanUrl(input) {
	const findings = [];
	const add = (points, text) => {
		if (!findings.some((f) => f.text === text)) findings.push({
			points,
			text
		});
	};
	const rawIn = input.trim();
	if (!rawIn) return {
		input,
		host: "",
		score: 0,
		level: "info",
		findings,
		error: "Enter a website link."
	};
	let candidate = rawIn.replace(/\s+/g, "");
	const low = candidate.toLowerCase();
	if (low.startsWith("javascript:") || low.startsWith("data:") || low.startsWith("vbscript:")) {
		add(100, "This link runs code instead of opening a site.");
		return {
			input: candidate,
			host: "",
			score: 100,
			level: "danger",
			findings
		};
	}
	if (!/^[a-z][a-z0-9+.-]*:/i.test(candidate)) candidate = "https://" + candidate;
	let url;
	try {
		url = new URL(candidate);
	} catch {
		return {
			input: candidate,
			host: "",
			score: 0,
			level: "info",
			findings,
			error: "That link could not be read."
		};
	}
	if (url.protocol !== "http:" && url.protocol !== "https:") {
		add(40, `Unusual scheme ${url.protocol}`);
		return {
			input: candidate,
			host: "",
			score: 40,
			level: "warn",
			findings
		};
	}
	const host = url.hostname.toLowerCase().replace(/\.$/, "");
	if (!host) return {
		input: candidate,
		host: "",
		score: 0,
		level: "info",
		findings,
		error: "No website name was found."
	};
	if (url.username) add(40, "A name before @ hides the real destination.");
	const ip = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
	if (ip) add(35, "Uses a raw IP address instead of a domain name.");
	const reg = regDomain(host);
	const main = reg.split(".")[0] || "";
	const labels = host.split(".");
	let official = LEGIT.has(reg) || LEGIT.has(host);
	let brandHit = false;
	if (!official) for (const [brand, domains] of Object.entries(BRANDS)) {
		if (domains.some((d) => host === d || host.endsWith("." + d))) {
			official = true;
			add(0, `Domain matches official ${brand}.`);
			break;
		}
		if (labels.some((l) => l === brand || deleet(l) === brand || l.length >= 6 && levenshtein(deleet(l), brand) === 1) || main.length >= 6 && (levenshtein(deleet(main), brand) <= 1 || deleet(main).includes(brand))) {
			brandHit = true;
			add(50, `“${brand}” appears on ${reg}, which is not the real ${brand} domain.`);
			break;
		}
	}
	else add(0, "Domain matches a known official name. This does not prove the page is safe.");
	const tld = host.split(".").pop() || "";
	let infra = false;
	if (!official && HIGH_TLD.has(tld)) {
		infra = true;
		add(HIGH_TLD.has(tld) && [
			"tk",
			"gq",
			"ml",
			"cf",
			"ga"
		].includes(tld) ? 24 : 14, `.${tld} is heavily abused for phishing.`);
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
	const ext = last.includes(".") ? last.split(".").pop().toLowerCase() : "";
	if (EXEC.has(ext)) add(35, `Link points straight at a program (.${ext}).`);
	if (url.protocol === "http:" && /login|signin|password|account|verify/.test(url.pathname + url.search)) add(15, "Login page sent over plain HTTP.");
	if (!official && (brandHit || bait) && infra) add(14, "Several independent red flags combine.");
	else if (!official && brandHit && bait) add(14, "A brand name plus credential bait is a typical phishing shape.");
	const score = Math.min(100, findings.reduce((sum, f) => sum + f.points, 0));
	findings.sort((a, b) => b.points - a.points);
	return {
		input: candidate,
		host,
		score,
		level: levelOf(score),
		findings
	};
}
var HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
function sourceLabel(source) {
	if (source === "page") return "this tab";
	if (source === "scanner") return "link scanner";
	if (source === "test") return "test alert";
	return source;
}
var defaultKinds = {
	malware: true,
	danger: true,
	aggressive: true
};
var PERSIST_KEYS = [
	"protection",
	"autoBlock",
	"notifyEnabled",
	"kinds",
	"cooldown",
	"allow",
	"blockedDomains",
	"rules",
	"blocked",
	"allowed",
	"alertsFired",
	"silenced"
];
function stamp() {
	return (/* @__PURE__ */ new Date()).toLocaleTimeString([], {
		hour: "2-digit",
		minute: "2-digit",
		second: "2-digit"
	});
}
function rid() {
	return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;
}
function pushLog(log, row) {
	return [row, ...log].slice(0, 80);
}
var useIronclad = create((set, get) => ({
	surface: "software",
	page: "overview",
	protection: true,
	autoBlock: true,
	notifyEnabled: true,
	kinds: { ...defaultKinds },
	cooldown: 60,
	allow: [],
	blockedDomains: [],
	rules: [],
	sessionHidden: [],
	zapper: false,
	pendingZap: null,
	badge: 0,
	pulseToken: 0,
	blocked: 0,
	allowed: 0,
	alertsFired: 0,
	silenced: 0,
	armRev: 0,
	log: [],
	toasts: [],
	scan: null,
	scanNote: "",
	sysNotify: false,
	setSurface: (surface) => set({ surface }),
	setPage: (page) => set({ page }),
	setProtection: (protection) => set({ protection }),
	setAutoBlock: (autoBlock) => set({ autoBlock }),
	setNotifyEnabled: (notifyEnabled) => set({ notifyEnabled }),
	setKind: (k, on) => set((s) => ({ kinds: {
		...s.kinds,
		[k]: on
	} })),
	setCooldown: (n) => {
		const cooldown = Math.max(0, Math.min(3600, Math.round(n)));
		throttle.hostCooldown = cooldown;
		set({ cooldown });
	},
	setSysNotify: (sysNotify) => set({ sysNotify }),
	ingest: (req) => {
		const state = get();
		const host = req.host.trim().toLowerCase().replace(/\.$/, "");
		if (!host) return;
		const rowBase = {
			id: rid(),
			time: stamp(),
			host
		};
		if (!state.protection) {
			set({
				allowed: state.allowed + 1,
				log: pushLog(state.log, {
					...rowBase,
					blocked: false,
					reason: "Protection is off",
					kind: null
				})
			});
			return;
		}
		if (listed(host, state.allow)) {
			set({
				allowed: state.allowed + 1,
				log: pushLog(state.log, {
					...rowBase,
					blocked: false,
					reason: "Allowlisted",
					kind: null
				})
			});
			return;
		}
		const decision = decide(host, {
			reason: req.reason,
			score: req.score
		}, state.blockedDomains);
		if (!decision) {
			set({
				allowed: state.allowed + 1,
				log: pushLog(state.log, {
					...rowBase,
					blocked: false,
					reason: "Not on a block list",
					kind: null
				})
			});
			return;
		}
		const kind = classifyBlock(host, decision.reason, decision.score);
		let silenced = state.silenced;
		let armRev = state.armRev;
		let badge = state.badge;
		let pulseToken = state.pulseToken;
		if (req.tab) {
			badge += 1;
			pulseToken += 1;
		}
		if (kind && state.notifyEnabled && state.kinds[kind]) {
			throttle.hostCooldown = state.cooldown;
			if (throttle.offer(kind, host, decision.reason, req.source, Date.now() / 1e3)) armRev += 1;
			else silenced += 1;
		}
		set({
			blocked: state.blocked + 1,
			silenced,
			armRev,
			badge,
			pulseToken,
			log: pushLog(state.log, {
				...rowBase,
				blocked: true,
				reason: decision.reason,
				kind
			})
		});
	},
	runScenario: (id) => {
		const scenario = SCENARIOS.find((s) => s.id === id);
		if (!scenario || typeof window === "undefined") return;
		for (const req of scenario.requests) window.setTimeout(() => {
			get().ingest({
				host: req.host,
				reason: req.reason,
				score: req.score,
				source: "page",
				tab: true
			});
		}, req.delay);
	},
	pushToast: (d) => set((s) => ({
		toasts: [...s.toasts, {
			...d,
			created: Date.now()
		}].slice(-3),
		alertsFired: s.alertsFired + 1
	})),
	dismissToast: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),
	testAlert: () => {
		const now = Date.now() / 1e3;
		get().pushToast({
			id: `test-${now}`,
			kind: "malware",
			head: {
				kind: "malware",
				host: "example-malware.test",
				reason: "malware/phishing feed",
				source: "test",
				t: now
			},
			hosts: ["example-malware.test"],
			events: 1,
			suppressed: 0,
			total: 1
		});
	},
	scanUrl: (input) => {
		const result = scanUrl(input);
		const state = get();
		let scanNote = "";
		if (!result.error && result.host && result.level === "danger") {
			if (!state.protection) scanNote = "Protection is off, so this dangerous result was not blocked.";
			else if (listed(result.host, state.allow)) scanNote = `${result.host} is allowlisted, so it was not blocked.`;
			else if (!state.autoBlock) scanNote = "Auto-block is off. Turn it on to stop dangerous results automatically.";
			else {
				const next = state.blockedDomains.includes(result.host) ? state.blockedDomains : [...state.blockedDomains, result.host].slice(-500);
				scanNote = `Protection is on: ${result.host} was blocked.`;
				set({
					blockedDomains: next,
					scan: result,
					scanNote
				});
				get().ingest({
					host: result.host,
					reason: `threat scanner score: ${result.score}`,
					score: result.score,
					source: "scanner",
					tab: false
				});
				return;
			}
		}
		set({
			scan: result,
			scanNote
		});
	},
	addAllow: (host) => {
		const h = host.trim().toLowerCase().replace(/^\*\./, "");
		if (!h) return;
		set((s) => ({ allow: s.allow.includes(h) ? s.allow : [...s.allow, h].sort() }));
	},
	removeAllow: (host) => set((s) => ({ allow: s.allow.filter((d) => d !== host) })),
	removeBlocked: (host) => set((s) => ({ blockedDomains: s.blockedDomains.filter((d) => d !== host) })),
	setZapper: (zapper) => set({
		zapper,
		pendingZap: zapper ? get().pendingZap : null
	}),
	zap: (target, label) => set((s) => ({
		zapper: true,
		pendingZap: {
			target,
			label
		},
		sessionHidden: s.sessionHidden.includes(target) ? s.sessionHidden : [...s.sessionHidden, target]
	})),
	savePending: () => {
		const p = get().pendingZap;
		if (!p) return;
		set((s) => ({
			pendingZap: null,
			rules: s.rules.some((r) => r.target === p.target) ? s.rules : [...s.rules, {
				id: p.target,
				target: p.target,
				label: p.label
			}]
		}));
	},
	undoPending: () => {
		const p = get().pendingZap;
		if (!p) return;
		set((s) => ({
			pendingZap: null,
			sessionHidden: s.sessionHidden.filter((x) => x !== p.target)
		}));
	},
	removeRule: (target) => set((s) => ({ rules: s.rules.filter((r) => r.target !== target) })),
	reloadTab: () => set({
		badge: 0,
		pulseToken: 0,
		sessionHidden: [],
		pendingZap: null
	}),
	resetSession: () => {
		throttle.reset();
		set({
			blocked: 0,
			allowed: 0,
			alertsFired: 0,
			silenced: 0,
			log: [],
			badge: 0,
			pulseToken: 0,
			toasts: [],
			armRev: get().armRev + 1
		});
	},
	hydrate: () => {
		if (typeof localStorage === "undefined") return;
		try {
			const raw = localStorage.getItem("ironclad.v1");
			if (!raw) return;
			const data = JSON.parse(raw);
			const patch = {};
			if (typeof data.protection === "boolean") patch.protection = data.protection;
			if (typeof data.autoBlock === "boolean") patch.autoBlock = data.autoBlock;
			if (typeof data.notifyEnabled === "boolean") patch.notifyEnabled = data.notifyEnabled;
			if (typeof data.cooldown === "number" && Number.isFinite(data.cooldown)) {
				patch.cooldown = Math.max(0, Math.min(3600, data.cooldown));
				throttle.hostCooldown = patch.cooldown;
			}
			if (data.kinds && typeof data.kinds === "object") patch.kinds = {
				...defaultKinds,
				...data.kinds
			};
			if (Array.isArray(data.allow)) patch.allow = data.allow.filter((x) => typeof x === "string");
			if (Array.isArray(data.blockedDomains)) patch.blockedDomains = data.blockedDomains.filter((x) => typeof x === "string");
			if (Array.isArray(data.rules)) patch.rules = data.rules.filter((r) => !!r && typeof r.target === "string" && typeof r.label === "string").map((r) => ({
				id: r.id || r.target,
				target: r.target,
				label: r.label
			}));
			for (const key of [
				"blocked",
				"allowed",
				"alertsFired",
				"silenced"
			]) {
				const n = data[key];
				if (typeof n === "number" && Number.isFinite(n) && n >= 0) patch[key] = Math.floor(n);
			}
			set(patch);
		} catch {}
	}
}));
function Switch({ checked, onChange, label }) {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
		type: "button",
		className: "switch",
		role: "switch",
		"aria-checked": checked,
		"aria-label": label,
		onClick: () => onChange(!checked),
		children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("i", {})
	});
}
function useTween(target) {
	const [n, setN] = (0, import_react.useState)(target);
	const shown = (0, import_react.useRef)(target);
	(0, import_react.useEffect)(() => {
		const from = shown.current;
		if (from === target) return;
		if (typeof matchMedia !== "undefined" && matchMedia("(prefers-reduced-motion: reduce)").matches) {
			shown.current = target;
			setN(target);
			return;
		}
		const t0 = performance.now();
		let raf = 0;
		const step = (now) => {
			const p = Math.min(1, (now - t0) / 420);
			const eased = 1 - (1 - p) ** 3;
			const v = Math.round(from + (target - from) * eased);
			shown.current = v;
			setN(v);
			if (p < 1) raf = requestAnimationFrame(step);
		};
		raf = requestAnimationFrame(step);
		return () => cancelAnimationFrame(raf);
	}, [target]);
	return n;
}
function Mark({ kind }) {
	if (kind === "malware") return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ShieldAlert, {
		size: 18,
		"aria-hidden": true
	});
	if (kind === "danger") return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(TriangleAlert, {
		size: 18,
		"aria-hidden": true
	});
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Megaphone, {
		size: 18,
		"aria-hidden": true
	});
}
function ToastCard({ item }) {
	const dismiss = useIronclad((s) => s.dismissToast);
	const [hover, setHover] = (0, import_react.useState)(false);
	const remain = (0, import_react.useRef)(ALERT_META[item.kind].seconds * 1e3);
	(0, import_react.useEffect)(() => {
		if (hover) return;
		const start = Date.now();
		const id = window.setTimeout(() => dismiss(item.id), remain.current);
		return () => {
			remain.current = Math.max(400, remain.current - (Date.now() - start));
			window.clearTimeout(id);
		};
	}, [
		hover,
		dismiss,
		item.id
	]);
	const more = item.total - 1;
	const others = item.hosts.filter((h) => h !== item.head.host).slice(0, 3);
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("article", {
		className: "glass toast",
		"data-kind": item.kind,
		onMouseEnter: () => setHover(true),
		onMouseLeave: () => setHover(false),
		children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
				className: "toast-mark",
				children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Mark, { kind: item.kind })
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h3", { children: ALERT_META[item.kind].title }),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "mono",
					children: item.head.host
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", { children: [
					item.head.reason,
					" · via ",
					sourceLabel(item.head.source)
				] }),
				more > 0 ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
					className: "more",
					children: [
						"+",
						more,
						" more blocked",
						others.length ? ` (${others.join(", ")}${item.hosts.length > 4 ? "…" : ""})` : ""
					]
				}) : null
			] }),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
				type: "button",
				className: "icon-btn",
				"aria-label": "Dismiss alert",
				onClick: () => dismiss(item.id),
				children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(X, { size: 16 })
			})
		]
	});
}
function ToastStack() {
	const toasts = useIronclad((s) => s.toasts);
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
		className: "toast-stack",
		"aria-live": "polite",
		children: toasts.map((t) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ToastCard, { item: t }, t.id))
	});
}
function AlertPump() {
	const armRev = useIronclad((s) => s.armRev);
	const sys = useIronclad((s) => s.sysNotify);
	(0, import_react.useEffect)(() => {
		if (typeof Notification !== "undefined" && Notification.permission === "granted") useIronclad.getState().setSysNotify(true);
	}, []);
	(0, import_react.useEffect)(() => {
		let timer = 0;
		let cancel = false;
		const loop = () => {
			if (cancel) return;
			const delay = throttle.nextDelay(Date.now() / 1e3);
			if (delay == null) return;
			timer = window.setTimeout(() => {
				const digest = throttle.poll(Date.now() / 1e3);
				if (digest) {
					useIronclad.getState().pushToast(digest);
					if (sys && typeof Notification !== "undefined" && Notification.permission === "granted") {
						const more = digest.total > 1 ? ` +${digest.total - 1} more` : "";
						try {
							new Notification(ALERT_META[digest.kind].title, { body: `${digest.head.host}${more}` });
						} catch {}
					}
				}
				loop();
			}, Math.round(delay * 1e3) + 30);
		};
		loop();
		return () => {
			cancel = true;
			window.clearTimeout(timer);
		};
	}, [armRev, sys]);
	return null;
}
function PersistBridge() {
	(0, import_react.useEffect)(() => {
		useIronclad.getState().hydrate();
		return useIronclad.subscribe((state) => {
			const slice = {};
			for (const key of PERSIST_KEYS) slice[key] = state[key];
			localStorage.setItem("ironclad.v1", JSON.stringify(slice));
		});
	}, []);
	return null;
}
function ScoreRing({ score, level }) {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
		className: `ring-wrap ring-${level}`,
		style: { ["--p"]: String(Math.max(0, Math.min(100, score))) },
		role: "img",
		"aria-label": `Risk score ${score} out of 100`,
		children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
			className: "ring-num",
			children: score
		})
	});
}
var NAV = [
	{
		id: "overview",
		label: "Overview",
		icon: Shield
	},
	{
		id: "alerts",
		label: "Alerts",
		icon: Bell
	},
	{
		id: "traffic",
		label: "Traffic",
		icon: Activity
	},
	{
		id: "scanner",
		label: "Scanner",
		icon: ScanSearch
	},
	{
		id: "lists",
		label: "Rules",
		icon: ListChecks
	}
];
var COPY = {
	overview: ["Overview", "Protection is the master switch. Threats toast once, even when a page fires dozens of requests."],
	alerts: ["Threat alerts", "Malware, dangerous links, and aggressive ad networks. Ordinary trackers stay quiet."],
	traffic: ["Traffic", "Every simulated request the filter saw this session."],
	scanner: ["Link scanner", "Dangerous results are blocked automatically while protection is on."],
	lists: ["Rules", "Allowlist, domains blocked from scans, and elements the zapper saved."]
};
function Stat({ label, value, sub }) {
	const n = useTween(value);
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("article", {
		className: "inset stat",
		children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
				className: "stat-label",
				children: label
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
				className: "stat-value",
				children: n.toLocaleString()
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
				className: "stat-sub",
				children: sub
			})
		]
	});
}
function LogList({ limit }) {
	const log = useIronclad((s) => s.log);
	const rows = limit ? log.slice(0, limit) : log;
	if (!rows.length) return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
		className: "quiet",
		children: "Nothing has reached the filter yet. Visit a page to see blocks land here."
	});
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
		className: "log",
		children: rows.map((row) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
			className: "log-row",
			children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
					className: "time",
					children: row.time
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: row.host }),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
					className: row.kind ? "pill pill-alert" : row.blocked ? "pill pill-block" : "pill pill-allow",
					children: row.kind ?? (row.blocked ? "blocked" : "allowed")
				})
			]
		}, row.id))
	});
}
function Overview() {
	const protection = useIronclad((s) => s.protection);
	const setProtection = useIronclad((s) => s.setProtection);
	const blocked = useIronclad((s) => s.blocked);
	const allowed = useIronclad((s) => s.allowed);
	const alertsFired = useIronclad((s) => s.alertsFired);
	const silenced = useIronclad((s) => s.silenced);
	const run = useIronclad((s) => s.runScenario);
	const reset = useIronclad((s) => s.resetSession);
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(import_jsx_runtime.Fragment, { children: [
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
			className: "stats",
			children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Stat, {
					label: "Blocked",
					value: blocked,
					sub: "requests stopped"
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Stat, {
					label: "Allowed",
					value: allowed,
					sub: "left untouched"
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Stat, {
					label: "Alerts",
					value: alertsFired,
					sub: "notices actually shown"
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Stat, {
					label: "Silenced",
					value: silenced,
					sub: "repeats inside the cooldown"
				})
			]
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
			className: "inset pad stack",
			children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "switch-row",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: protection ? "Protection is on" : "Protection is off" }) }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "hint",
						children: "While it is on, dangerous scans and known bad hosts are stopped and shared with the extension view."
					})] }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Switch, {
						checked: protection,
						onChange: setProtection,
						label: "Protection"
					})]
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "btn-row",
					children: [SCENARIOS.map((s, i) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
						type: "button",
						className: i === 0 ? "btn" : "btn btn-ghost",
						onClick: () => run(s.id),
						children: s.title
					}, s.id)), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("button", {
						type: "button",
						className: "btn btn-ghost",
						onClick: reset,
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(RotateCcw, {
							size: 16,
							"aria-hidden": true
						}), " Reset session"]
					})]
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "quiet",
					children: "A burst waits about a second, then becomes one glass notice instead of a stack of identical warnings. The extension badge still counts every block."
				})
			]
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
			className: "inset pad",
			children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h3", {
				className: "eyebrow",
				children: "Recent"
			}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(LogList, { limit: 6 })]
		})
	] });
}
function AlertsPage() {
	const enabled = useIronclad((s) => s.notifyEnabled);
	const setEnabled = useIronclad((s) => s.setNotifyEnabled);
	const kinds = useIronclad((s) => s.kinds);
	const setKind = useIronclad((s) => s.setKind);
	const cooldown = useIronclad((s) => s.cooldown);
	const setCooldown = useIronclad((s) => s.setCooldown);
	const test = useIronclad((s) => s.testAlert);
	const sys = useIronclad((s) => s.sysNotify);
	const setSys = useIronclad((s) => s.setSysNotify);
	const [permNote, setPermNote] = (0, import_react.useState)("");
	async function allowSystem() {
		if (typeof Notification === "undefined") {
			setPermNote("This browser cannot show system notifications. Glass notices still work.");
			return;
		}
		const perm = await Notification.requestPermission();
		setSys(perm === "granted");
		setPermNote(perm === "granted" ? "System notifications are on." : "Permission was not granted. Glass notices still appear.");
	}
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
		className: "inset pad stack",
		children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "switch-row",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: "Desktop notices" }) }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "hint",
					children: "Glass toasts, plus a system notification when you allow it."
				})] }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Switch, {
					checked: enabled,
					onChange: setEnabled,
					label: "Desktop notices"
				})]
			}),
			[
				{
					id: "malware",
					label: "Malware and phishing feeds",
					detail: "Hosts on a threat list, including frames inside ordinary pages."
				},
				{
					id: "danger",
					label: "Dangerous links",
					detail: "Scanner score of 70 or higher."
				},
				{
					id: "aggressive",
					label: "Aggressive ad networks",
					detail: "Pop-unders, push ads, and redirect networks."
				}
			].map((row) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "switch-row",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { children: row.label }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "hint",
					children: row.detail
				})] }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Switch, {
					checked: kinds[row.id],
					onChange: (on) => setKind(row.id, on),
					label: row.label
				})]
			}, row.id)),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("label", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", { children: [
				"Repeat cooldown per site · ",
				cooldown,
				"s"
			] }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
				className: "slider",
				type: "range",
				min: 5,
				max: 180,
				step: 5,
				value: cooldown,
				onChange: (e) => setCooldown(Number(e.target.value))
			})] }),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
				className: "quiet",
				children: "The same site and category is announced at most once per cooldown. Hits that arrive together wait one second and merge. At least three seconds pass between notices, and no more than eight notices fire in five minutes."
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "btn-row",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
					type: "button",
					className: "btn",
					onClick: () => {
						test();
						if (sys && typeof Notification !== "undefined" && Notification.permission === "granted") try {
							new Notification("Malware blocked", { body: "example-malware.test" });
						} catch {}
					},
					children: "Send test alert"
				}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
					type: "button",
					className: "btn btn-ghost",
					onClick: allowSystem,
					children: sys ? "System notifications on" : "Allow system notifications"
				})]
			}),
			permNote ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
				className: "quiet",
				children: permNote
			}) : null
		]
	});
}
function TrafficPage() {
	const [filter, setFilter] = (0, import_react.useState)("all");
	const rows = useIronclad((s) => s.log).filter((row) => {
		if (filter === "blocked") return row.blocked;
		if (filter === "alerts") return row.kind != null;
		return true;
	});
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(import_jsx_runtime.Fragment, { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
		className: "btn-row",
		children: [
			"all",
			"blocked",
			"alerts"
		].map((id) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
			type: "button",
			className: filter === id ? "btn" : "btn btn-ghost",
			onClick: () => setFilter(id),
			children: id === "all" ? "All" : id === "blocked" ? "Blocked" : "Alert-worthy"
		}, id))
	}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("section", {
		className: "inset pad",
		children: !rows.length ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "quiet",
			children: "No rows for this filter."
		}) : /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
			className: "log",
			children: rows.map((row) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "log-row",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
						className: "time",
						children: row.time
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: row.host }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "quiet",
						children: row.reason
					})] }),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
						className: row.kind ? "pill pill-alert" : row.blocked ? "pill pill-block" : "pill pill-allow",
						children: row.kind ?? (row.blocked ? "blocked" : "allowed")
					})
				]
			}, row.id))
		})
	})] });
}
var SAMPLES = [
	"https://paypal.com",
	"https://paypa1-secure-login.xyz/account",
	"https://bit.ly/free-prize",
	"http://192.168.1.20/login"
];
function ScannerPage() {
	const result = useIronclad((s) => s.scan);
	const note = useIronclad((s) => s.scanNote);
	const run = useIronclad((s) => s.scanUrl);
	const [value, setValue] = (0, import_react.useState)("https://paypa1-secure-login.xyz/account");
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(import_jsx_runtime.Fragment, { children: [
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("form", {
			className: "btn-row",
			onSubmit: (e) => {
				e.preventDefault();
				run(value);
			},
			children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
				className: "field",
				value,
				onChange: (e) => setValue(e.target.value),
				"aria-label": "Link to scan",
				placeholder: "https://",
				spellCheck: false
			}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
				className: "btn",
				type: "submit",
				children: "Scan link"
			})]
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
			className: "btn-row",
			children: SAMPLES.map((sample) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
				type: "button",
				className: "btn btn-ghost",
				onClick: () => {
					setValue(sample);
					run(sample);
				},
				children: sample.replace(/^https?:\/\//, "")
			}, sample))
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("section", {
			className: "inset pad stack",
			children: !result ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
				className: "quiet",
				children: "Paste a link. Official names stay quiet. Lookalikes, shorteners, and raw IPs do not."
			}) : result.error ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { children: result.error }) : /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(import_jsx_runtime.Fragment, { children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "verdict-row",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(ScoreRing, {
						score: result.score,
						level: result.level
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h3", {
							style: { margin: 0 },
							children: LEVEL_LABEL[result.level]
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
							className: "mono",
							children: result.host
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
							className: "quiet",
							children: [result.score, " / 100 · offline check, not a guarantee"]
						})
					] })]
				}),
				note ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { children: note }) : null,
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
					className: "findings",
					children: result.findings.map((f) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
						className: "pts",
						children: f.points > 0 ? `+${f.points}` : "0"
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { children: f.text })] }, f.text))
				})
			] })
		})
	] });
}
function RulesPage() {
	const allow = useIronclad((s) => s.allow);
	const blocked = useIronclad((s) => s.blockedDomains);
	const rules = useIronclad((s) => s.rules);
	const addAllow = useIronclad((s) => s.addAllow);
	const removeAllow = useIronclad((s) => s.removeAllow);
	const removeBlocked = useIronclad((s) => s.removeBlocked);
	const removeRule = useIronclad((s) => s.removeRule);
	const auto = useIronclad((s) => s.autoBlock);
	const setAuto = useIronclad((s) => s.setAutoBlock);
	const setSurface = useIronclad((s) => s.setSurface);
	const [draft, setDraft] = (0, import_react.useState)("");
	const [err, setErr] = (0, import_react.useState)("");
	function add(e) {
		e.preventDefault();
		const h = draft.trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0] ?? "";
		if (!HOST_RE.test(h)) {
			setErr("Enter a domain like example.com.");
			return;
		}
		setErr("");
		addAllow(h);
		setDraft("");
	}
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(import_jsx_runtime.Fragment, { children: [
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("section", {
			className: "inset pad stack",
			children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "switch-row",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: "Auto-block dangerous scans" }) }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "hint",
					children: "Allowlisted sites are never blocked."
				})] }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Switch, {
					checked: auto,
					onChange: setAuto,
					label: "Auto-block dangerous scans"
				})]
			})
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
			className: "inset pad stack",
			children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h3", {
					style: { margin: 0 },
					children: "Allowlist"
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("form", {
					className: "btn-row",
					onSubmit: add,
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
						className: "field",
						value: draft,
						onChange: (e) => setDraft(e.target.value),
						"aria-label": "Domain to allow",
						placeholder: "example.com"
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("button", {
						className: "btn",
						type: "submit",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Plus, {
							size: 16,
							"aria-hidden": true
						}), " Add"]
					})]
				}),
				err ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					role: "alert",
					children: err
				}) : null,
				!allow.length ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "quiet",
					children: "No exceptions yet."
				}) : allow.map((d) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "rule-line",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
						className: "mono",
						children: d
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
						type: "button",
						className: "icon-btn",
						"aria-label": `Remove ${d}`,
						onClick: () => removeAllow(d),
						children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Trash2, { size: 16 })
					})]
				}, d))
			]
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
			className: "inset pad stack",
			children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h3", {
				style: { margin: 0 },
				children: "Blocked from scans"
			}), !blocked.length ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
				className: "quiet",
				children: "Dangerous scan results land here while protection is on."
			}) : blocked.map((d) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "rule-line",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
					className: "mono",
					children: d
				}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
					type: "button",
					className: "icon-btn",
					"aria-label": `Unblock ${d}`,
					onClick: () => removeBlocked(d),
					children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Trash2, { size: 16 })
				})]
			}, d))]
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
			className: "inset pad stack",
			children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h3", {
					style: { margin: 0 },
					children: "Cosmetic rules"
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "quiet",
					children: "Saved from the zapper on the extension surface. They hide that element again after a reload."
				}),
				!rules.length ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
					type: "button",
					className: "btn btn-ghost",
					onClick: () => setSurface("extension"),
					children: "Open the zapper"
				}) : rules.map((r) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "rule-line",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { children: r.label }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
						type: "button",
						className: "icon-btn",
						"aria-label": `Remove ${r.label}`,
						onClick: () => removeRule(r.target),
						children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Trash2, { size: 16 })
					})]
				}, r.id))
			]
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
			className: "inset pad install",
			children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h3", {
				style: { margin: 0 },
				children: "Chrome package"
			}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
				className: "quiet",
				children: "Unzip, then load the folder in chrome://extensions with Developer mode on. The popup, zapper, and badge are the same ideas you see here."
			})] }), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("a", {
				className: "btn",
				href: "/ironclad-adblock.zip",
				download: true,
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Download, {
					size: 16,
					"aria-hidden": true
				}), " Download extension"]
			})]
		})
	] });
}
function DesktopApp() {
	const page = useIronclad((s) => s.page);
	const setPage = useIronclad((s) => s.setPage);
	const [title, sub] = COPY[page];
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
		className: "app-window glass",
		children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("nav", {
			className: "side",
			"aria-label": "Software",
			children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "side-brand",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("img", {
					src: "/favicon.svg",
					alt: "",
					width: 36,
					height: 36
				}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: "IronClad" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { children: "Desktop" })] })]
			}), NAV.map((item) => {
				const Icon = item.icon;
				return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("button", {
					type: "button",
					className: "nav-btn",
					"aria-current": page === item.id ? "page" : void 0,
					onClick: () => setPage(item.id),
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Icon, {
						size: 18,
						"aria-hidden": true
					}), item.label]
				}, item.id);
			})]
		}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
			className: "main-col",
			children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("header", {
				className: "page-head",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", { children: title }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { children: sub })]
			}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "content",
				children: [
					page === "overview" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Overview, {}) : null,
					page === "alerts" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(AlertsPage, {}) : null,
					page === "traffic" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(TrafficPage, {}) : null,
					page === "scanner" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ScannerPage, {}) : null,
					page === "lists" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(RulesPage, {}) : null
				]
			})]
		})]
	});
}
function ExtBadge() {
	const badge = useIronclad((s) => s.badge);
	const pulse = useIronclad((s) => s.pulseToken);
	const shown = useTween(badge);
	const [on, setOn] = (0, import_react.useState)(false);
	(0, import_react.useEffect)(() => {
		if (!pulse) return;
		setOn(false);
		const raf = requestAnimationFrame(() => setOn(true));
		const id = window.setTimeout(() => setOn(false), 620);
		return () => {
			cancelAnimationFrame(raf);
			window.clearTimeout(id);
		};
	}, [pulse]);
	if (!badge) return null;
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
		className: on ? "badge badge-pulse" : "badge",
		children: shown > 999 ? "999+" : shown
	});
}
function ExtensionStudio() {
	const protection = useIronclad((s) => s.protection);
	const setProtection = useIronclad((s) => s.setProtection);
	const zapper = useIronclad((s) => s.zapper);
	const setZapper = useIronclad((s) => s.setZapper);
	const rules = useIronclad((s) => s.rules);
	const sessionHidden = useIronclad((s) => s.sessionHidden);
	const pending = useIronclad((s) => s.pendingZap);
	const zap = useIronclad((s) => s.zap);
	const savePending = useIronclad((s) => s.savePending);
	const undoPending = useIronclad((s) => s.undoPending);
	const removeRule = useIronclad((s) => s.removeRule);
	const reload = useIronclad((s) => s.reloadTab);
	const run = useIronclad((s) => s.runScenario);
	const badge = useIronclad((s) => s.badge);
	const shown = useTween(badge);
	const [popup, setPopup] = (0, import_react.useState)(true);
	const [hover, setHover] = (0, import_react.useState)(null);
	const [pop, setPop] = (0, import_react.useState)(false);
	(0, import_react.useEffect)(() => {
		if (!badge) return;
		setPop(false);
		const raf = requestAnimationFrame(() => setPop(true));
		const id = window.setTimeout(() => setPop(false), 620);
		return () => {
			cancelAnimationFrame(raf);
			window.clearTimeout(id);
		};
	}, [badge]);
	(0, import_react.useEffect)(() => {
		function onKey(e) {
			if (e.key === "Escape") setZapper(false);
		}
		window.addEventListener("keydown", onKey);
		return () => window.removeEventListener("keydown", onKey);
	}, [setZapper]);
	function hidden(id) {
		return sessionHidden.includes(id) || rules.some((r) => r.target === id);
	}
	function onClick(e) {
		if (!zapper) return;
		const el = e.target.closest("[data-zap]");
		if (!el) return;
		const id = el.dataset.zap;
		const label = el.dataset.label || "Element";
		if (!id || hidden(id)) return;
		e.preventDefault();
		e.stopPropagation();
		zap(id, label);
	}
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
		className: "studio glass",
		children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
			className: "browser",
			children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "browser-bar",
					children: [
						/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
							className: "dots",
							"aria-hidden": true,
							children: [
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("i", {}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("i", {}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("i", {})
							]
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: "omnibox",
							children: "meridian.news/harbor/evening-ferry"
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
							type: "button",
							className: "icon-btn",
							"aria-label": "Reload tab",
							onClick: reload,
							children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(RotateCcw, { size: 16 })
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("button", {
							type: "button",
							className: "ext-btn",
							"aria-label": "IronClad extension",
							"aria-expanded": popup,
							onClick: () => setPopup((v) => !v),
							children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("img", {
								src: "/favicon.svg",
								alt: ""
							}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ExtBadge, {})]
						})
					]
				}),
				popup ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "popup glass",
					role: "dialog",
					"aria-label": "IronClad extension",
					children: [
						/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
							className: "switch-row",
							children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h3", { children: "IronClad" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
								className: "quiet",
								children: protection ? "Blocking this tab" : "Paused"
							})] }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Switch, {
								checked: protection,
								onChange: setProtection,
								label: "Extension protection"
							})]
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
							className: pop ? "count-xl pop" : "count-xl",
							"aria-live": "polite",
							children: shown
						}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
							className: "quiet",
							children: "blocked on this tab"
						})] }),
						/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
							className: "btn-row",
							children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("button", {
								type: "button",
								className: zapper ? "btn" : "btn btn-ghost",
								onClick: () => {
									const next = !zapper;
									setZapper(next);
									if (next) setPopup(false);
								},
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(MousePointer2, {
									size: 16,
									"aria-hidden": true
								}), zapper ? "Zapper on" : "Zapper"]
							}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
								type: "button",
								className: "btn btn-ghost",
								onClick: () => run("burst"),
								children: "Replay burst"
							})]
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: "btn-row",
							children: SCENARIOS.filter((s) => s.id !== "burst").map((s) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
								type: "button",
								className: "btn btn-ghost",
								onClick: () => run(s.id),
								children: s.id === "news" ? "News page" : "Lookalike"
							}, s.id))
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
							className: "eyebrow",
							children: "Saved elements"
						}), !rules.length ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
							className: "quiet",
							children: "None yet. Turn the zapper on and click an annoyance."
						}) : rules.map((r) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
							className: "rule-line",
							children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { children: r.label }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
								type: "button",
								className: "btn btn-ghost",
								onClick: () => removeRule(r.target),
								children: "Remove"
							})]
						}, r.id))] }),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("a", {
							className: "quiet",
							href: "/ironclad-adblock.zip",
							download: true,
							children: "Download the Chrome package"
						})
					]
				}) : null,
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: zapper ? "viewport zapper-on" : "viewport",
					onMouseMove: (e) => {
						if (!zapper) return;
						const el = e.target.closest("[data-zap]");
						setHover(el?.dataset.zap ?? null);
					},
					onMouseLeave: () => setHover(null),
					onClick,
					children: [
						zapper ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
							className: "zapper-banner glass",
							children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { children: "Zapper is on. Click a banner, modal, or ad. Esc leaves this mode." }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
								type: "button",
								className: "btn btn-ghost",
								onClick: () => setZapper(false),
								children: "Done"
							})]
						}) : null,
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: "web-page",
							children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
								className: "web-inner",
								children: [
									/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("header", {
										className: "mast",
										children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: "The Meridian" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { children: "Harbor desk" })]
									}),
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
										className: "kicker",
										children: "Evening edition"
									}),
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", { children: "The last ferry waits out the harbor lights" }),
									/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
										className: "layout",
										children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("article", { children: [
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { children: "Captains held the 6:40 at the inner pier while a squall walked up the channel. Passengers stayed aboard. The coffee urn on the lower deck ran dry before the all-clear." }),
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { children: "Dock staff waved the gift-card window off the gangway twice. It drifted back, pinned to the rail by a script that does not know what a gangway is." }),
											/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("aside", {
												className: hidden("sponsor") ? "ad-card is-hidden" : hover === "sponsor" ? "ad-card zap-hot" : "ad-card",
												"data-zap": "sponsor",
												"data-label": ZAPS[4].label,
												children: [
													/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { children: "Sponsored" }),
													/* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: "Claim a harbor gift card" }),
													/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { children: "A floating offer with no publisher behind it. Hide it with the zapper." })
												]
											}),
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { children: "By 7:15 the lights along the breakwater were steady again. The ferry slipped out without the popup, which is more than this page can say." })
										] }), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("aside", {
											className: hidden("rail") ? "ad-card is-hidden" : hover === "rail" ? "ad-card zap-hot" : "ad-card",
											"data-zap": "rail",
											"data-label": ZAPS[3].label,
											children: [
												/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { children: "Advertisement" }),
												/* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: "Sidebar network" }),
												/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { children: "Sticky, loud, and unrelated to the tide." })
											]
										})]
									})
								]
							})
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
							className: hidden("gift") ? "gift is-hidden" : hover === "gift" ? "gift zap-hot" : "gift",
							"data-zap": "gift",
							"data-label": ZAPS[2].label,
							children: [
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { children: "You won" }),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: "Gift card popup" }),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { children: "It follows the scroll. Click it in zapper mode." })
							]
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
							className: hidden("newsletter") ? "newsletter is-hidden" : hover === "newsletter" ? "newsletter zap-hot" : "newsletter",
							"data-zap": "newsletter",
							"data-label": ZAPS[0].label,
							children: [
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { children: "Subscribe" }),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: "Newsletter modal" }),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { children: "Before you have read a sentence." }),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
									type: "button",
									className: "paper-btn",
									children: "Not now"
								})
							]
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
							className: hidden("cookie") ? "cookie is-hidden" : hover === "cookie" ? "cookie zap-hot" : "cookie",
							"data-zap": "cookie",
							"data-label": ZAPS[1].label,
							children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { children: "Cookies" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { children: "A banner that refuses to dock." })] }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
								type: "button",
								className: "paper-btn",
								children: "Dismiss"
							})]
						}),
						pending ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
							className: "savebar glass",
							children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", { children: [
								"Hid ",
								pending.label,
								"."
							] }), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
								className: "btn-row",
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
									type: "button",
									className: "btn",
									onClick: savePending,
									children: "Save rule"
								}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
									type: "button",
									className: "btn btn-ghost",
									onClick: undoPending,
									children: "Undo"
								})]
							})]
						}) : null
					]
				})
			]
		})
	});
}
function Segmented() {
	const surface = useIronclad((s) => s.surface);
	const setSurface = useIronclad((s) => s.setSurface);
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
		className: "seg",
		role: "tablist",
		"aria-label": "Surface",
		children: [{
			id: "software",
			label: "Software",
			icon: Laptop
		}, {
			id: "extension",
			label: "Extension",
			icon: Puzzle
		}].map((item) => {
			const Icon = item.icon;
			return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("button", {
				type: "button",
				role: "tab",
				"aria-selected": surface === item.id,
				onClick: () => setSurface(item.id),
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Icon, {
					size: 16,
					"aria-hidden": true
				}), item.label]
			}, item.id);
		})
	});
}
function Home() {
	const surface = useIronclad((s) => s.surface);
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
		className: "wallpaper",
		children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)(AlertPump, {}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)(PersistBridge, {}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)(ToastStack, {}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "stage",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("header", {
					className: "topbar",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "brand-inline",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("img", {
							src: "/favicon.svg",
							alt: "",
							width: 40,
							height: 40
						}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
							className: "eyebrow",
							children: "IronClad"
						}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("h1", { children: "Liquid glass protection" })] })]
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Segmented, {})]
				}), surface === "software" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(DesktopApp, {}) : /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ExtensionStudio, {})]
			})
		]
	});
}
//#endregion
export { Home as component };
