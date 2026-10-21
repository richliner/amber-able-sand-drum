import { useState, type FormEvent } from "react";
import {
  Activity,
  Bell,
  Download,
  ListChecks,
  Plus,
  RotateCcw,
  ScanSearch,
  Shield,
  Trash2,
} from "lucide-react";
import { HOST_RE, LEVEL_LABEL, SCENARIOS, type Kind } from "@/lib/ironclad/engine";
import { useIronclad, type PageId } from "@/lib/ironclad/store";
import { ScoreRing, Switch, useTween } from "./ui";

const NAV: { id: PageId; label: string; icon: typeof Shield }[] = [
  { id: "overview", label: "Overview", icon: Shield },
  { id: "alerts", label: "Alerts", icon: Bell },
  { id: "traffic", label: "Traffic", icon: Activity },
  { id: "scanner", label: "Scanner", icon: ScanSearch },
  { id: "lists", label: "Rules", icon: ListChecks },
];

const COPY: Record<PageId, [string, string]> = {
  overview: ["Overview", "Protection is the master switch. Threats toast once, even when a page fires dozens of requests."],
  alerts: ["Threat alerts", "Malware, dangerous links, and aggressive ad networks. Ordinary trackers stay quiet."],
  traffic: ["Traffic", "Every simulated request the filter saw this session."],
  scanner: ["Link scanner", "Dangerous results are blocked automatically while protection is on."],
  lists: ["Rules", "Allowlist, domains blocked from scans, and elements the zapper saved."],
};

function Stat({ label, value, sub }: { label: string; value: number; sub: string }) {
  const n = useTween(value);
  return (
    <article className="inset stat">
      <p className="stat-label">{label}</p>
      <p className="stat-value">{n.toLocaleString()}</p>
      <p className="stat-sub">{sub}</p>
    </article>
  );
}

function LogList({ limit }: { limit?: number }) {
  const log = useIronclad((s) => s.log);
  const rows = limit ? log.slice(0, limit) : log;
  if (!rows.length) {
    return <p className="quiet">Nothing has reached the filter yet. Visit a page to see blocks land here.</p>;
  }
  return (
    <div className="log">
      {rows.map((row) => (
        <div className="log-row" key={row.id}>
          <span className="time">{row.time}</span>
          <strong>{row.host}</strong>
          <span className={row.kind ? "pill pill-alert" : row.blocked ? "pill pill-block" : "pill pill-allow"}>
            {row.kind ?? (row.blocked ? "blocked" : "allowed")}
          </span>
        </div>
      ))}
    </div>
  );
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
  return (
    <>
      <div className="stats">
        <Stat label="Blocked" value={blocked} sub="requests stopped" />
        <Stat label="Allowed" value={allowed} sub="left untouched" />
        <Stat label="Alerts" value={alertsFired} sub="notices actually shown" />
        <Stat label="Silenced" value={silenced} sub="repeats inside the cooldown" />
      </div>
      <section className="inset pad stack">
        <div className="switch-row">
          <div>
            <p><strong>{protection ? "Protection is on" : "Protection is off"}</strong></p>
            <p className="hint">While it is on, dangerous scans and known bad hosts are stopped and shared with the extension view.</p>
          </div>
          <Switch checked={protection} onChange={setProtection} label="Protection" />
        </div>
        <div className="btn-row">
          {SCENARIOS.map((s, i) => (
            <button key={s.id} type="button" className={i === 0 ? "btn" : "btn btn-ghost"} onClick={() => run(s.id)}>
              {s.title}
            </button>
          ))}
          <button type="button" className="btn btn-ghost" onClick={reset}>
            <RotateCcw size={16} aria-hidden /> Reset session
          </button>
        </div>
        <p className="quiet">A burst waits about a second, then becomes one glass notice instead of a stack of identical warnings. The extension badge still counts every block.</p>
      </section>
      <section className="inset pad">
        <h3 className="eyebrow">Recent</h3>
        <LogList limit={6} />
      </section>
    </>
  );
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
  const [permNote, setPermNote] = useState("");

  async function allowSystem() {
    if (typeof Notification === "undefined") {
      setPermNote("This browser cannot show system notifications. Glass notices still work.");
      return;
    }
    const perm = await Notification.requestPermission();
    setSys(perm === "granted");
    setPermNote(perm === "granted" ? "System notifications are on." : "Permission was not granted. Glass notices still appear.");
  }

  const rows: { id: Kind; label: string; detail: string }[] = [
    { id: "malware", label: "Malware and phishing feeds", detail: "Hosts on a threat list, including frames inside ordinary pages." },
    { id: "danger", label: "Dangerous links", detail: "Scanner score of 70 or higher." },
    { id: "aggressive", label: "Aggressive ad networks", detail: "Pop-unders, push ads, and redirect networks." },
  ];

  return (
    <section className="inset pad stack">
      <div className="switch-row">
        <div>
          <p><strong>Desktop notices</strong></p>
          <p className="hint">Glass toasts, plus a system notification when you allow it.</p>
        </div>
        <Switch checked={enabled} onChange={setEnabled} label="Desktop notices" />
      </div>
      {rows.map((row) => (
        <div className="switch-row" key={row.id}>
          <div>
            <p>{row.label}</p>
            <p className="hint">{row.detail}</p>
          </div>
          <Switch checked={kinds[row.id]} onChange={(on) => setKind(row.id, on)} label={row.label} />
        </div>
      ))}
      <label>
        <span>Repeat cooldown per site · {cooldown}s</span>
        <input
          className="slider"
          type="range"
          min={5}
          max={180}
          step={5}
          value={cooldown}
          onChange={(e) => setCooldown(Number(e.target.value))}
        />
      </label>
      <p className="quiet">
        The same site and category is announced at most once per cooldown. Hits that arrive together wait one second and merge.
        At least three seconds pass between notices, and no more than eight notices fire in five minutes.
      </p>
      <div className="btn-row">
        <button
          type="button"
          className="btn"
          onClick={() => {
            test();
            if (sys && typeof Notification !== "undefined" && Notification.permission === "granted") {
              try {
                new Notification("Malware blocked", { body: "example-malware.test" });
              } catch {
                /* ignore */
              }
            }
          }}
        >
          Send test alert
        </button>
        <button type="button" className="btn btn-ghost" onClick={allowSystem}>
          {sys ? "System notifications on" : "Allow system notifications"}
        </button>
      </div>
      {permNote ? <p className="quiet">{permNote}</p> : null}
    </section>
  );
}

function TrafficPage() {
  const [filter, setFilter] = useState<"all" | "blocked" | "alerts">("all");
  const log = useIronclad((s) => s.log);
  const rows = log.filter((row) => {
    if (filter === "blocked") return row.blocked;
    if (filter === "alerts") return row.kind != null;
    return true;
  });
  return (
    <>
      <div className="btn-row">
        {(["all", "blocked", "alerts"] as const).map((id) => (
          <button key={id} type="button" className={filter === id ? "btn" : "btn btn-ghost"} onClick={() => setFilter(id)}>
            {id === "all" ? "All" : id === "blocked" ? "Blocked" : "Alert-worthy"}
          </button>
        ))}
      </div>
      <section className="inset pad">
        {!rows.length ? <p className="quiet">No rows for this filter.</p> : (
          <div className="log">
            {rows.map((row) => (
              <div className="log-row" key={row.id}>
                <span className="time">{row.time}</span>
                <div>
                  <strong>{row.host}</strong>
                  <p className="quiet">{row.reason}</p>
                </div>
                <span className={row.kind ? "pill pill-alert" : row.blocked ? "pill pill-block" : "pill pill-allow"}>
                  {row.kind ?? (row.blocked ? "blocked" : "allowed")}
                </span>
              </div>
            ))}
          </div>
        )}
      </section>
    </>
  );
}

const SAMPLES = [
  "https://paypal.com",
  "https://paypa1-secure-login.xyz/account",
  "https://bit.ly/free-prize",
  "http://192.168.1.20/login",
];

function ScannerPage() {
  const result = useIronclad((s) => s.scan);
  const note = useIronclad((s) => s.scanNote);
  const run = useIronclad((s) => s.scanUrl);
  const [value, setValue] = useState("https://paypa1-secure-login.xyz/account");
  return (
    <>
      <form
        className="btn-row"
        onSubmit={(e) => {
          e.preventDefault();
          run(value);
        }}
      >
        <input
          className="field"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          aria-label="Link to scan"
          placeholder="https://"
          spellCheck={false}
        />
        <button className="btn" type="submit">Scan link</button>
      </form>
      <div className="btn-row">
        {SAMPLES.map((sample) => (
          <button key={sample} type="button" className="btn btn-ghost" onClick={() => { setValue(sample); run(sample); }}>
            {sample.replace(/^https?:\/\//, "")}
          </button>
        ))}
      </div>
      <section className="inset pad stack">
        {!result ? <p className="quiet">Paste a link. Official names stay quiet. Lookalikes, shorteners, and raw IPs do not.</p> : result.error ? (
          <p>{result.error}</p>
        ) : (
          <>
            <div className="verdict-row">
              <ScoreRing score={result.score} level={result.level} />
              <div>
                <h3 style={{ margin: 0 }}>{LEVEL_LABEL[result.level]}</h3>
                <p className="mono">{result.host}</p>
                <p className="quiet">{result.score} / 100 · offline check, not a guarantee</p>
              </div>
            </div>
            {note ? <p>{note}</p> : null}
            <ul className="findings">
              {result.findings.map((f) => (
                <li key={f.text}>
                  <span className="pts">{f.points > 0 ? `+${f.points}` : "0"}</span>
                  <span>{f.text}</span>
                </li>
              ))}
            </ul>
          </>
        )}
      </section>
    </>
  );
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
  const [draft, setDraft] = useState("");
  const [err, setErr] = useState("");

  function add(e: FormEvent) {
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

  return (
    <>
      <section className="inset pad stack">
        <div className="switch-row">
          <div>
            <p><strong>Auto-block dangerous scans</strong></p>
            <p className="hint">Allowlisted sites are never blocked.</p>
          </div>
          <Switch checked={auto} onChange={setAuto} label="Auto-block dangerous scans" />
        </div>
      </section>
      <section className="inset pad stack">
        <h3 style={{ margin: 0 }}>Allowlist</h3>
        <form className="btn-row" onSubmit={add}>
          <input className="field" value={draft} onChange={(e) => setDraft(e.target.value)} aria-label="Domain to allow" placeholder="example.com" />
          <button className="btn" type="submit"><Plus size={16} aria-hidden /> Add</button>
        </form>
        {err ? <p role="alert">{err}</p> : null}
        {!allow.length ? <p className="quiet">No exceptions yet.</p> : allow.map((d) => (
          <div className="rule-line" key={d}>
            <span className="mono">{d}</span>
            <button type="button" className="icon-btn" aria-label={`Remove ${d}`} onClick={() => removeAllow(d)}>
              <Trash2 size={16} />
            </button>
          </div>
        ))}
      </section>
      <section className="inset pad stack">
        <h3 style={{ margin: 0 }}>Blocked from scans</h3>
        {!blocked.length ? <p className="quiet">Dangerous scan results land here while protection is on.</p> : blocked.map((d) => (
          <div className="rule-line" key={d}>
            <span className="mono">{d}</span>
            <button type="button" className="icon-btn" aria-label={`Unblock ${d}`} onClick={() => removeBlocked(d)}>
              <Trash2 size={16} />
            </button>
          </div>
        ))}
      </section>
      <section className="inset pad stack">
        <h3 style={{ margin: 0 }}>Cosmetic rules</h3>
        <p className="quiet">Saved from the zapper on the extension surface. They hide that element again after a reload.</p>
        {!rules.length ? (
          <button type="button" className="btn btn-ghost" onClick={() => setSurface("extension")}>Open the zapper</button>
        ) : rules.map((r) => (
          <div className="rule-line" key={r.id}>
            <span>{r.label}</span>
            <button type="button" className="icon-btn" aria-label={`Remove ${r.label}`} onClick={() => removeRule(r.target)}>
              <Trash2 size={16} />
            </button>
          </div>
        ))}
      </section>
      <section className="inset pad install">
        <div>
          <h3 style={{ margin: 0 }}>Chrome package</h3>
          <p className="quiet">Unzip, then load the folder in chrome://extensions with Developer mode on. The popup, zapper, and badge are the same ideas you see here.</p>
        </div>
        <a className="btn" href="/ironclad-adblock.zip" download>
          <Download size={16} aria-hidden /> Download extension
        </a>
      </section>
    </>
  );
}

export function DesktopApp() {
  const page = useIronclad((s) => s.page);
  const setPage = useIronclad((s) => s.setPage);
  const [title, sub] = COPY[page];
  return (
    <div className="app-window glass">
      <nav className="side" aria-label="Software">
        <div className="side-brand">
          <img src="/favicon.svg" alt="" width={36} height={36} />
          <div>
            <strong>IronClad</strong>
            <span>Desktop</span>
          </div>
        </div>
        {NAV.map((item) => {
          const Icon = item.icon;
          return (
            <button
              key={item.id}
              type="button"
              className="nav-btn"
              aria-current={page === item.id ? "page" : undefined}
              onClick={() => setPage(item.id)}
            >
              <Icon size={18} aria-hidden />
              {item.label}
            </button>
          );
        })}
      </nav>
      <div className="main-col">
        <header className="page-head">
          <h2>{title}</h2>
          <p>{sub}</p>
        </header>
        <div className="content">
          {page === "overview" ? <Overview /> : null}
          {page === "alerts" ? <AlertsPage /> : null}
          {page === "traffic" ? <TrafficPage /> : null}
          {page === "scanner" ? <ScannerPage /> : null}
          {page === "lists" ? <RulesPage /> : null}
        </div>
      </div>
    </div>
  );
}
