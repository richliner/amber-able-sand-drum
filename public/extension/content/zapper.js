if (!window.__ironcladZapper) {
  window.__ironcladZapper = true;

  let armed = false;
  let hoverBox = null;
  let hud = null;
  let current = null;

  const host = document.createElement("div");
  host.id = "ironclad-zapper-root";
  host.style.all = "initial";
  const root = host.attachShadow({ mode: "open" });
  root.innerHTML = `
    <style>
      :host { all: initial; }
      .box {
        position: fixed; z-index: 2147483646; pointer-events: none;
        border-radius: 12px;
        box-shadow: inset 0 0 0 2px #2ee6c7, 0 0 0 6px rgba(46,230,199,.18);
        display: none;
      }
      .hud {
        position: fixed; z-index: 2147483647; left: 16px; right: 16px; bottom: 16px;
        display: none; gap: 10px; align-items: center; justify-content: space-between; flex-wrap: wrap;
        padding: 12px 14px; border-radius: 22px; color: #f4f7fb;
        font: 500 14px/1.4 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        background: linear-gradient(180deg, rgba(255,255,255,.22), rgba(255,255,255,.08));
        backdrop-filter: blur(22px) saturate(1.6);
        box-shadow: inset 0 1px 0 rgba(255,255,255,.55), inset 0 0 0 1px rgba(255,255,255,.16), 0 18px 50px rgba(0,0,0,.35);
      }
      .hud p { margin: 0; }
      .hud strong { display: block; }
      .row { display: flex; gap: 8px; flex-wrap: wrap; }
      button {
        min-height: 40px; border: 0; border-radius: 999px; padding: 0 14px; font: 650 14px/1 inherit; cursor: pointer;
      }
      .go { background: #2ee6c7; color: #071018; }
      .ghost { background: rgba(255,255,255,.12); color: #f4f7fb; box-shadow: inset 0 0 0 1px rgba(255,255,255,.2); }
      .banner {
        position: fixed; z-index: 2147483646; top: 12px; left: 50%; transform: translateX(-50%);
        display: none; padding: 8px 14px; border-radius: 999px; color: #f4f7fb;
        font: 600 13px/1.3 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        background: rgba(7,16,24,.72); backdrop-filter: blur(16px);
        box-shadow: inset 0 1px 0 rgba(255,255,255,.35);
      }
    </style>
    <div class="banner" id="banner">Zapper — click an element to hide it. Esc cancels.</div>
    <div class="box" id="box"></div>
    <div class="hud" id="hud">
      <p><strong id="title">Hidden</strong><span id="sel"></span></p>
      <div class="row">
        <button class="go" id="save" type="button">Save rule</button>
        <button class="ghost" id="once" type="button">This page only</button>
        <button class="ghost" id="undo" type="button">Undo</button>
      </div>
    </div>
  `;

  function mount() {
    if (!host.isConnected) (document.documentElement || document.body).appendChild(host);
    hoverBox = root.getElementById("box");
    hud = root.getElementById("hud");
  }

  function selectorFor(el) {
    if (!(el instanceof Element)) return "";
    if (el.id && /^[A-Za-z][\w:-]*$/.test(el.id)) return `#${CSS.escape(el.id)}`;
    const parts = [];
    let node = el;
    while (node && node.nodeType === 1 && node !== document.body && parts.length < 4) {
      let part = node.tagName.toLowerCase();
      const cls = [...node.classList]
        .filter((c) => /^[A-Za-z][\w-]*$/.test(c))
        .slice(0, 2);
      if (cls.length) part += cls.map((c) => "." + CSS.escape(c)).join("");
      const parent = node.parentElement;
      if (parent) {
        const same = [...parent.children].filter((ch) => ch.tagName === node.tagName);
        if (same.length > 1) part += `:nth-of-type(${same.indexOf(node) + 1})`;
      }
      parts.unshift(part);
      node = node.parentElement;
    }
    return parts.join(" > ");
  }

  function placeBox(el) {
    if (!hoverBox) return;
    if (!el) {
      hoverBox.style.display = "none";
      return;
    }
    const r = el.getBoundingClientRect();
    hoverBox.style.display = "block";
    hoverBox.style.left = r.left + "px";
    hoverBox.style.top = r.top + "px";
    hoverBox.style.width = r.width + "px";
    hoverBox.style.height = r.height + "px";
  }

  function arm() {
    mount();
    armed = true;
    document.documentElement.classList.add("ironclad-zapper");
    root.getElementById("banner").style.display = "block";
  }

  function disarm() {
    armed = false;
    document.documentElement.classList.remove("ironclad-zapper");
    if (root.getElementById("banner")) root.getElementById("banner").style.display = "none";
    placeBox(null);
  }

  function targetFrom(event) {
    const path = event.composedPath ? event.composedPath() : [];
    if (path.includes(host)) return null;
    for (const node of path) {
      if (!(node instanceof Element)) continue;
      if (node === document.body || node === document.documentElement) continue;
      return node;
    }
    return null;
  }

  function onMove(event) {
    if (!armed) return;
    placeBox(targetFrom(event));
  }

  function showHud(el, selector) {
    current = { el, selector, prev: el.getAttribute("style") };
    el.style.setProperty("display", "none", "important");
    placeBox(null);
    const title = root.getElementById("title");
    const sel = root.getElementById("sel");
    title.textContent = "Hid " + el.tagName.toLowerCase();
    sel.textContent = selector;
    hud.style.display = "flex";
  }

  function onClick(event) {
    if (!armed) return;
    if (hud && hud.style.display === "flex") return;
    const el = targetFrom(event);
    if (!el) return;
    event.preventDefault();
    event.stopPropagation();
    const selector = selectorFor(el);
    if (!selector) return;
    showHud(el, selector);
  }

  function onKey(event) {
    if (event.key === "Escape") {
      undo();
      disarm();
    }
  }

  function undo() {
    if (!current) return;
    if (current.prev == null) current.el.removeAttribute("style");
    else current.el.setAttribute("style", current.prev);
    current = null;
    if (hud) hud.style.display = "none";
  }

  function closeHud() {
    current = null;
    if (hud) hud.style.display = "none";
    disarm();
  }

  root.getElementById("undo").addEventListener("click", (e) => {
    e.stopPropagation();
    undo();
  });
  root.getElementById("once").addEventListener("click", (e) => {
    e.stopPropagation();
    closeHud();
  });
  root.getElementById("save").addEventListener("click", (e) => {
    e.stopPropagation();
    if (!current) return;
    const rule = {
      id: `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`,
      selector: current.selector,
      host: location.hostname,
      label: current.selector.slice(0, 80),
    };
    chrome.storage.local.get({ rules: [] }, (data) => {
      const rules = Array.isArray(data.rules) ? data.rules : [];
      rules.push(rule);
      chrome.storage.local.set({ rules });
    });
    closeHud();
  });

  document.addEventListener("mousemove", onMove, true);
  document.addEventListener("click", onClick, true);
  document.addEventListener("keydown", onKey, true);

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (!msg || !msg.type) return;
    if (msg.type === "zapper-arm") {
      arm();
      sendResponse({ ok: true });
    } else if (msg.type === "zapper-disarm") {
      disarm();
      sendResponse({ ok: true });
    }
  });
}
