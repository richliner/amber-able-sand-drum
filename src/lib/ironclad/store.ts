import { create } from "zustand";
import {
  decide,
  classifyBlock,
  listed,
  scanUrl,
  throttle,
  SCENARIOS,
  type Digest,
  type Kind,
  type Scan,
} from "./engine";

export type Surface = "software" | "extension";
export type PageId = "overview" | "alerts" | "traffic" | "scanner" | "lists";

export type LogRow = {
  id: string;
  time: string;
  host: string;
  blocked: boolean;
  reason: string;
  kind: Kind | null;
};

export type CosmeticRule = { id: string; target: string; label: string };
export type ToastItem = Digest & { created: number };

export type IronState = {
  surface: Surface;
  page: PageId;
  protection: boolean;
  autoBlock: boolean;
  notifyEnabled: boolean;
  kinds: Record<Kind, boolean>;
  cooldown: number;
  allow: string[];
  blockedDomains: string[];
  rules: CosmeticRule[];
  sessionHidden: string[];
  zapper: boolean;
  pendingZap: { target: string; label: string } | null;
  badge: number;
  pulseToken: number;
  blocked: number;
  allowed: number;
  alertsFired: number;
  silenced: number;
  armRev: number;
  log: LogRow[];
  toasts: ToastItem[];
  scan: Scan | null;
  scanNote: string;
  sysNotify: boolean;
  setSurface: (s: Surface) => void;
  setPage: (p: PageId) => void;
  setProtection: (on: boolean) => void;
  setAutoBlock: (on: boolean) => void;
  setNotifyEnabled: (on: boolean) => void;
  setKind: (k: Kind, on: boolean) => void;
  setCooldown: (n: number) => void;
  ingest: (req: { host: string; reason?: string; score?: number; source: string; tab?: boolean }) => void;
  runScenario: (id: string) => void;
  pushToast: (d: Digest) => void;
  dismissToast: (id: string) => void;
  testAlert: () => void;
  scanUrl: (input: string) => void;
  addAllow: (host: string) => void;
  removeAllow: (host: string) => void;
  removeBlocked: (host: string) => void;
  setZapper: (on: boolean) => void;
  zap: (target: string, label: string) => void;
  savePending: () => void;
  undoPending: () => void;
  removeRule: (target: string) => void;
  reloadTab: () => void;
  resetSession: () => void;
  hydrate: () => void;
  setSysNotify: (on: boolean) => void;
};

const defaultKinds: Record<Kind, boolean> = { malware: true, danger: true, aggressive: true };

export const PERSIST_KEYS = [
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
  "silenced",
] as const;

function stamp(): string {
  return new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function rid(): string {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;
}

function pushLog(log: LogRow[], row: LogRow): LogRow[] {
  return [row, ...log].slice(0, 80);
}

export const useIronclad = create<IronState>((set, get) => ({
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
  setKind: (k, on) => set((s) => ({ kinds: { ...s.kinds, [k]: on } })),
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
    const rowBase = { id: rid(), time: stamp(), host };
    if (!state.protection) {
      set({
        allowed: state.allowed + 1,
        log: pushLog(state.log, { ...rowBase, blocked: false, reason: "Protection is off", kind: null }),
      });
      return;
    }
    if (listed(host, state.allow)) {
      set({
        allowed: state.allowed + 1,
        log: pushLog(state.log, { ...rowBase, blocked: false, reason: "Allowlisted", kind: null }),
      });
      return;
    }
    const decision = decide(host, { reason: req.reason, score: req.score }, state.blockedDomains);
    if (!decision) {
      set({
        allowed: state.allowed + 1,
        log: pushLog(state.log, { ...rowBase, blocked: false, reason: "Not on a block list", kind: null }),
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
      const announced = throttle.offer(kind, host, decision.reason, req.source, Date.now() / 1000);
      if (announced) armRev += 1;
      else silenced += 1;
    }
    set({
      blocked: state.blocked + 1,
      silenced,
      armRev,
      badge,
      pulseToken,
      log: pushLog(state.log, { ...rowBase, blocked: true, reason: decision.reason, kind }),
    });
  },

  runScenario: (id) => {
    const scenario = SCENARIOS.find((s) => s.id === id);
    if (!scenario || typeof window === "undefined") return;
    for (const req of scenario.requests) {
      window.setTimeout(() => {
        get().ingest({ host: req.host, reason: req.reason, score: req.score, source: "page", tab: true });
      }, req.delay);
    }
  },

  pushToast: (d) =>
    set((s) => ({
      toasts: [...s.toasts, { ...d, created: Date.now() }].slice(-3),
      alertsFired: s.alertsFired + 1,
    })),

  dismissToast: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),

  testAlert: () => {
    const now = Date.now() / 1000;
    get().pushToast({
      id: `test-${now}`,
      kind: "malware",
      head: {
        kind: "malware",
        host: "example-malware.test",
        reason: "malware/phishing feed",
        source: "test",
        t: now,
      },
      hosts: ["example-malware.test"],
      events: 1,
      suppressed: 0,
      total: 1,
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
        const next = state.blockedDomains.includes(result.host)
          ? state.blockedDomains
          : [...state.blockedDomains, result.host].slice(-500);
        scanNote = `Protection is on: ${result.host} was blocked.`;
        set({ blockedDomains: next, scan: result, scanNote });
        get().ingest({
          host: result.host,
          reason: `threat scanner score: ${result.score}`,
          score: result.score,
          source: "scanner",
          tab: false,
        });
        return;
      }
    }
    set({ scan: result, scanNote });
  },

  addAllow: (host) => {
    const h = host.trim().toLowerCase().replace(/^\*\./, "");
    if (!h) return;
    set((s) => ({ allow: s.allow.includes(h) ? s.allow : [...s.allow, h].sort() }));
  },
  removeAllow: (host) => set((s) => ({ allow: s.allow.filter((d) => d !== host) })),
  removeBlocked: (host) => set((s) => ({ blockedDomains: s.blockedDomains.filter((d) => d !== host) })),

  setZapper: (zapper) => set({ zapper, pendingZap: zapper ? get().pendingZap : null }),
  zap: (target, label) =>
    set((s) => ({
      zapper: true,
      pendingZap: { target, label },
      sessionHidden: s.sessionHidden.includes(target) ? s.sessionHidden : [...s.sessionHidden, target],
    })),
  savePending: () => {
    const p = get().pendingZap;
    if (!p) return;
    set((s) => ({
      pendingZap: null,
      rules: s.rules.some((r) => r.target === p.target)
        ? s.rules
        : [...s.rules, { id: p.target, target: p.target, label: p.label }],
    }));
  },
  undoPending: () => {
    const p = get().pendingZap;
    if (!p) return;
    set((s) => ({
      pendingZap: null,
      sessionHidden: s.sessionHidden.filter((x) => x !== p.target),
    }));
  },
  removeRule: (target) => set((s) => ({ rules: s.rules.filter((r) => r.target !== target) })),

  reloadTab: () => set({ badge: 0, pulseToken: 0, sessionHidden: [], pendingZap: null }),

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
      armRev: get().armRev + 1,
    });
  },

  hydrate: () => {
    if (typeof localStorage === "undefined") return;
    try {
      const raw = localStorage.getItem("ironclad.v1");
      if (!raw) return;
      const data = JSON.parse(raw) as Partial<IronState>;
      const patch: Partial<IronState> = {};
      if (typeof data.protection === "boolean") patch.protection = data.protection;
      if (typeof data.autoBlock === "boolean") patch.autoBlock = data.autoBlock;
      if (typeof data.notifyEnabled === "boolean") patch.notifyEnabled = data.notifyEnabled;
      if (typeof data.cooldown === "number" && Number.isFinite(data.cooldown)) {
        patch.cooldown = Math.max(0, Math.min(3600, data.cooldown));
        throttle.hostCooldown = patch.cooldown;
      }
      if (data.kinds && typeof data.kinds === "object") patch.kinds = { ...defaultKinds, ...data.kinds };
      if (Array.isArray(data.allow)) patch.allow = data.allow.filter((x) => typeof x === "string");
      if (Array.isArray(data.blockedDomains)) patch.blockedDomains = data.blockedDomains.filter((x) => typeof x === "string");
      if (Array.isArray(data.rules)) {
        patch.rules = data.rules
          .filter((r): r is CosmeticRule => !!r && typeof r.target === "string" && typeof r.label === "string")
          .map((r) => ({ id: r.id || r.target, target: r.target, label: r.label }));
      }
      for (const key of ["blocked", "allowed", "alertsFired", "silenced"] as const) {
        const n = data[key];
        if (typeof n === "number" && Number.isFinite(n) && n >= 0) patch[key] = Math.floor(n);
      }
      set(patch);
    } catch {
      /* keep defaults */
    }
  },
}));
