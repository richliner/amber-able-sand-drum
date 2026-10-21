import { useEffect, useState, type MouseEvent } from "react";
import { MousePointer2, RotateCcw } from "lucide-react";
import { SCENARIOS, ZAPS } from "@/lib/ironclad/engine";
import { useIronclad } from "@/lib/ironclad/store";
import { Switch, useTween } from "./ui";

function ExtBadge() {
  const badge = useIronclad((s) => s.badge);
  const pulse = useIronclad((s) => s.pulseToken);
  const shown = useTween(badge);
  const [on, setOn] = useState(false);
  useEffect(() => {
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
  return <span className={on ? "badge badge-pulse" : "badge"}>{shown > 999 ? "999+" : shown}</span>;
}

export function ExtensionStudio() {
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
  const [popup, setPopup] = useState(true);
  const [hover, setHover] = useState<string | null>(null);
  const [pop, setPop] = useState(false);

  useEffect(() => {
    if (!badge) return;
    setPop(false);
    const raf = requestAnimationFrame(() => setPop(true));
    const id = window.setTimeout(() => setPop(false), 620);
    return () => {
      cancelAnimationFrame(raf);
      window.clearTimeout(id);
    };
  }, [badge]);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setZapper(false);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [setZapper]);

  function hidden(id: string) {
    return sessionHidden.includes(id) || rules.some((r) => r.target === id);
  }

  function onClick(e: MouseEvent) {
    if (!zapper) return;
    const el = (e.target as HTMLElement).closest<HTMLElement>("[data-zap]");
    if (!el) return;
    const id = el.dataset.zap;
    const label = el.dataset.label || "Element";
    if (!id || hidden(id)) return;
    e.preventDefault();
    e.stopPropagation();
    zap(id, label);
  }

  return (
    <div className="studio glass">
      <div className="browser">
        <div className="browser-bar">
          <div className="dots" aria-hidden>
            <i />
            <i />
            <i />
          </div>
          <div className="omnibox">meridian.news/harbor/evening-ferry</div>
          <button type="button" className="icon-btn" aria-label="Reload tab" onClick={reload}>
            <RotateCcw size={16} />
          </button>
          <button
            type="button"
            className="ext-btn"
            aria-label="IronClad extension"
            aria-expanded={popup}
            onClick={() => setPopup((v) => !v)}
          >
            <img src="/favicon.svg" alt="" />
            <ExtBadge />
          </button>
        </div>
        {popup ? (
          <div className="popup glass" role="dialog" aria-label="IronClad extension">
            <div className="switch-row">
              <div>
                <h3>IronClad</h3>
                <p className="quiet">{protection ? "Blocking this tab" : "Paused"}</p>
              </div>
              <Switch checked={protection} onChange={setProtection} label="Extension protection" />
            </div>
            <div>
              <p className={pop ? "count-xl pop" : "count-xl"} aria-live="polite">
                {shown}
              </p>
              <p className="quiet">blocked on this tab</p>
            </div>
            <div className="btn-row">
              <button
                type="button"
                className={zapper ? "btn" : "btn btn-ghost"}
                onClick={() => {
                  const next = !zapper;
                  setZapper(next);
                  if (next) setPopup(false);
                }}
              >
                <MousePointer2 size={16} aria-hidden />
                {zapper ? "Zapper on" : "Zapper"}
              </button>
              <button type="button" className="btn btn-ghost" onClick={() => run("burst")}>
                Replay burst
              </button>
            </div>
            <div className="btn-row">
              {SCENARIOS.filter((s) => s.id !== "burst").map((s) => (
                <button key={s.id} type="button" className="btn btn-ghost" onClick={() => run(s.id)}>
                  {s.id === "news" ? "News page" : "Lookalike"}
                </button>
              ))}
            </div>
            <div>
              <p className="eyebrow">Saved elements</p>
              {!rules.length ? (
                <p className="quiet">None yet. Turn the zapper on and click an annoyance.</p>
              ) : (
                rules.map((r) => (
                  <div className="rule-line" key={r.id}>
                    <span>{r.label}</span>
                    <button type="button" className="btn btn-ghost" onClick={() => removeRule(r.target)}>
                      Remove
                    </button>
                  </div>
                ))
              )}
            </div>
            <a className="quiet" href="/ironclad-adblock.zip" download>
              Download the Chrome package
            </a>
          </div>
        ) : null}
        <div
          className={zapper ? "viewport zapper-on" : "viewport"}
          onMouseMove={(e) => {
            if (!zapper) return;
            const el = (e.target as HTMLElement).closest<HTMLElement>("[data-zap]");
            setHover(el?.dataset.zap ?? null);
          }}
          onMouseLeave={() => setHover(null)}
          onClick={onClick}
        >
          {zapper ? (
            <div className="zapper-banner glass">
              <p>Zapper is on. Click a banner, modal, or ad. Esc leaves this mode.</p>
              <button type="button" className="btn btn-ghost" onClick={() => setZapper(false)}>
                Done
              </button>
            </div>
          ) : null}
          <div className="web-page">
            <div className="web-inner">
              <header className="mast">
                <strong>The Meridian</strong>
                <span>Harbor desk</span>
              </header>
              <p className="kicker">Evening edition</p>
              <h2>The last ferry waits out the harbor lights</h2>
              <div className="layout">
                <article>
                  <p>
                    Captains held the 6:40 at the inner pier while a squall walked up the channel. Passengers stayed
                    aboard. The coffee urn on the lower deck ran dry before the all-clear.
                  </p>
                  <p>
                    Dock staff waved the gift-card window off the gangway twice. It drifted back, pinned to the rail by
                    a script that does not know what a gangway is.
                  </p>
                  <aside
                    className={hidden("sponsor") ? "ad-card is-hidden" : hover === "sponsor" ? "ad-card zap-hot" : "ad-card"}
                    data-zap="sponsor"
                    data-label={ZAPS[4].label}
                  >
                    <span>Sponsored</span>
                    <strong>Claim a harbor gift card</strong>
                    <p>A floating offer with no publisher behind it. Hide it with the zapper.</p>
                  </aside>
                  <p>
                    By 7:15 the lights along the breakwater were steady again. The ferry slipped out without the popup,
                    which is more than this page can say.
                  </p>
                </article>
                <aside
                  className={hidden("rail") ? "ad-card is-hidden" : hover === "rail" ? "ad-card zap-hot" : "ad-card"}
                  data-zap="rail"
                  data-label={ZAPS[3].label}
                >
                  <span>Advertisement</span>
                  <strong>Sidebar network</strong>
                  <p>Sticky, loud, and unrelated to the tide.</p>
                </aside>
              </div>
            </div>
          </div>
          <div
            className={hidden("gift") ? "gift is-hidden" : hover === "gift" ? "gift zap-hot" : "gift"}
            data-zap="gift"
            data-label={ZAPS[2].label}
          >
            <span>You won</span>
            <strong>Gift card popup</strong>
            <p>It follows the scroll. Click it in zapper mode.</p>
          </div>
          <div
            className={hidden("newsletter") ? "newsletter is-hidden" : hover === "newsletter" ? "newsletter zap-hot" : "newsletter"}
            data-zap="newsletter"
            data-label={ZAPS[0].label}
          >
            <span>Subscribe</span>
            <strong>Newsletter modal</strong>
            <p>Before you have read a sentence.</p>
            <button type="button" className="paper-btn">
              Not now
            </button>
          </div>
          <div
            className={hidden("cookie") ? "cookie is-hidden" : hover === "cookie" ? "cookie zap-hot" : "cookie"}
            data-zap="cookie"
            data-label={ZAPS[1].label}
          >
            <div>
              <span>Cookies</span>
              <p>A banner that refuses to dock.</p>
            </div>
            <button type="button" className="paper-btn">
              Dismiss
            </button>
          </div>
          {pending ? (
            <div className="savebar glass">
              <p>Hid {pending.label}.</p>
              <div className="btn-row">
                <button type="button" className="btn" onClick={savePending}>
                  Save rule
                </button>
                <button type="button" className="btn btn-ghost" onClick={undoPending}>
                  Undo
                </button>
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}
