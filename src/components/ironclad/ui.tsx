import { useEffect, useRef, useState } from "react";
import { Megaphone, ShieldAlert, TriangleAlert, X } from "lucide-react";
import { ALERT_META, sourceLabel, throttle, type Kind } from "@/lib/ironclad/engine";
import { useIronclad, PERSIST_KEYS, type ToastItem } from "@/lib/ironclad/store";

export function Switch({
  checked,
  onChange,
  label,
}: {
  checked: boolean;
  onChange: (next: boolean) => void;
  label: string;
}) {
  return (
    <button
      type="button"
      className="switch"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      onClick={() => onChange(!checked)}
    >
      <i />
    </button>
  );
}

export function useTween(target: number): number {
  const [n, setN] = useState(target);
  const shown = useRef(target);
  useEffect(() => {
    const from = shown.current;
    if (from === target) return;
    const reduce = typeof matchMedia !== "undefined" && matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) {
      shown.current = target;
      setN(target);
      return;
    }
    const t0 = performance.now();
    let raf = 0;
    const step = (now: number) => {
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

function Mark({ kind }: { kind: Kind }) {
  if (kind === "malware") return <ShieldAlert size={18} aria-hidden />;
  if (kind === "danger") return <TriangleAlert size={18} aria-hidden />;
  return <Megaphone size={18} aria-hidden />;
}

function ToastCard({ item }: { item: ToastItem }) {
  const dismiss = useIronclad((s) => s.dismissToast);
  const [hover, setHover] = useState(false);
  const remain = useRef(ALERT_META[item.kind].seconds * 1000);
  useEffect(() => {
    if (hover) return;
    const start = Date.now();
    const id = window.setTimeout(() => dismiss(item.id), remain.current);
    return () => {
      remain.current = Math.max(400, remain.current - (Date.now() - start));
      window.clearTimeout(id);
    };
  }, [hover, dismiss, item.id]);
  const more = item.total - 1;
  const others = item.hosts.filter((h) => h !== item.head.host).slice(0, 3);
  return (
    <article
      className="glass toast"
      data-kind={item.kind}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
    >
      <div className="toast-mark">
        <Mark kind={item.kind} />
      </div>
      <div>
        <h3>{ALERT_META[item.kind].title}</h3>
        <p className="mono">{item.head.host}</p>
        <p>
          {item.head.reason} · via {sourceLabel(item.head.source)}
        </p>
        {more > 0 ? (
          <p className="more">
            +{more} more blocked
            {others.length ? ` (${others.join(", ")}${item.hosts.length > 4 ? "…" : ""})` : ""}
          </p>
        ) : null}
      </div>
      <button type="button" className="icon-btn" aria-label="Dismiss alert" onClick={() => dismiss(item.id)}>
        <X size={16} />
      </button>
    </article>
  );
}

export function ToastStack() {
  const toasts = useIronclad((s) => s.toasts);
  return (
    <div className="toast-stack" aria-live="polite">
      {toasts.map((t) => (
        <ToastCard key={t.id} item={t} />
      ))}
    </div>
  );
}

export function AlertPump() {
  const armRev = useIronclad((s) => s.armRev);
  const sys = useIronclad((s) => s.sysNotify);
  useEffect(() => {
    if (typeof Notification !== "undefined" && Notification.permission === "granted") {
      useIronclad.getState().setSysNotify(true);
    }
  }, []);
  useEffect(() => {
    let timer = 0;
    let cancel = false;
    const loop = () => {
      if (cancel) return;
      const delay = throttle.nextDelay(Date.now() / 1000);
      if (delay == null) return;
      timer = window.setTimeout(() => {
        const digest = throttle.poll(Date.now() / 1000);
        if (digest) {
          useIronclad.getState().pushToast(digest);
          if (sys && typeof Notification !== "undefined" && Notification.permission === "granted") {
            const more = digest.total > 1 ? ` +${digest.total - 1} more` : "";
            try {
              new Notification(ALERT_META[digest.kind].title, { body: `${digest.head.host}${more}` });
            } catch {
              /* preview may block the Notification constructor */
            }
          }
        }
        loop();
      }, Math.round(delay * 1000) + 30);
    };
    loop();
    return () => {
      cancel = true;
      window.clearTimeout(timer);
    };
  }, [armRev, sys]);
  return null;
}

export function PersistBridge() {
  useEffect(() => {
    useIronclad.getState().hydrate();
    return useIronclad.subscribe((state) => {
      const slice: Record<string, unknown> = {};
      for (const key of PERSIST_KEYS) slice[key] = state[key];
      localStorage.setItem("ironclad.v1", JSON.stringify(slice));
    });
  }, []);
  return null;
}

export function ScoreRing({ score, level }: { score: number; level: string }) {
  return (
    <div
      className={`ring-wrap ring-${level}`}
      style={{ ["--p" as string]: String(Math.max(0, Math.min(100, score))) }}
      role="img"
      aria-label={`Risk score ${score} out of 100`}
    >
      <span className="ring-num">{score}</span>
    </div>
  );
}
