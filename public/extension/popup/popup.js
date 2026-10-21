const power = document.getElementById("power");
const state = document.getElementById("state");
const countEl = document.getElementById("count");
const rulesEl = document.getElementById("rules");
const zapper = document.getElementById("zapper");

function setPower(on) {
  power.setAttribute("aria-checked", on ? "true" : "false");
  state.textContent = on ? "Blocking this tab" : "Paused";
}

power.addEventListener("click", () => {
  const on = power.getAttribute("aria-checked") !== "true";
  setPower(on);
  chrome.runtime.sendMessage({ type: "protection", on });
});

chrome.storage.local.get({ protection: true }, (data) => setPower(data.protection !== false));
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.protection) setPower(changes.protection.newValue !== false);
  if (area === "local" && changes.rules) renderRules(changes.rules.newValue || []);
  if (area === "session") refreshCount();
});

async function refreshCount() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || tab.id == null) return;
  const text = await chrome.action.getBadgeText({ tabId: tab.id });
  const n = parseInt(text || "0", 10) || 0;
  const prev = Number(countEl.dataset.n || "0");
  countEl.dataset.n = String(n);
  countEl.textContent = String(n);
  if (n !== prev) {
    countEl.classList.remove("pop");
    void countEl.offsetWidth;
    countEl.classList.add("pop");
  }
}

function renderRules(rules) {
  rulesEl.replaceChildren();
  const list = Array.isArray(rules) ? rules : [];
  if (!list.length) {
    const p = document.createElement("p");
    p.className = "quiet";
    p.textContent = "No cosmetic rules yet.";
    rulesEl.appendChild(p);
    return;
  }
  for (const rule of list.slice().reverse()) {
    const row = document.createElement("div");
    row.className = "rule";
    const label = document.createElement("span");
    label.textContent = rule.label || rule.selector;
    const del = document.createElement("button");
    del.type = "button";
    del.textContent = "Remove";
    del.addEventListener("click", () => {
      chrome.storage.local.get({ rules: [] }, (data) => {
        const next = (data.rules || []).filter((r) => r.id !== rule.id);
        chrome.storage.local.set({ rules: next });
      });
    });
    row.append(label, del);
    rulesEl.appendChild(row);
  }
}

zapper.addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || tab.id == null) return;
  await chrome.runtime.sendMessage({ type: "arm-zapper", tabId: tab.id });
  window.close();
});

chrome.storage.local.get({ rules: [] }, (data) => renderRules(data.rules));
refreshCount();
setInterval(refreshCount, 700);
