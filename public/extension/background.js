const PULSE = ["#2ee6c7", "#b8fff4", "#2ee6c7", "#0e8f7e"];
const counts = new Map();
const pulses = new Map();
let protection = true;

function textFor(n) {
  if (!n) return "";
  return n > 999 ? "999+" : String(n);
}

function paint(tabId, animate) {
  if (tabId < 0) return;
  const n = counts.get(tabId) || 0;
  const text = textFor(n);
  chrome.action.setBadgeText({ tabId, text });
  try {
    chrome.action.setBadgeTextColor({ tabId, color: "#071018" });
  } catch (e) {
    /* older Chrome */
  }
  chrome.action.setBadgeBackgroundColor({ tabId, color: "#2ee6c7" });
  chrome.storage.session.set({ ["tab:" + tabId]: n });
  if (!animate || !n) return;
  const prev = pulses.get(tabId);
  if (prev) clearInterval(prev);
  let i = 0;
  const timer = setInterval(() => {
    chrome.action.setBadgeBackgroundColor({ tabId, color: PULSE[i % PULSE.length] });
    i += 1;
    if (i >= PULSE.length) {
      clearInterval(timer);
      pulses.delete(tabId);
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#2ee6c7" });
    }
  }, 140);
  pulses.set(tabId, timer);
}

function bump(tabId) {
  if (!protection || tabId == null || tabId < 0) return;
  counts.set(tabId, (counts.get(tabId) || 0) + 1);
  paint(tabId, true);
}

function applyRuleset() {
  const payload = protection
    ? { enableRulesetIds: ["ads"], disableRulesetIds: [] }
    : { enableRulesetIds: [], disableRulesetIds: ["ads"] };
  chrome.declarativeNetRequest.updateEnabledRulesets(payload).catch(() => {});
}

function ensureMenu() {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: "ironclad-zapper",
      title: "IronClad Zapper — hide an element",
      contexts: ["page", "frame", "selection", "image", "link", "video", "audio"],
    });
  });
}

async function arm(tabId) {
  if (tabId == null) return;
  try {
    await chrome.tabs.sendMessage(tabId, { type: "zapper-arm" });
  } catch (e) {
    await chrome.scripting.executeScript({ target: { tabId }, files: ["content/zapper.js"] });
    await chrome.tabs.sendMessage(tabId, { type: "zapper-arm" });
  }
}

chrome.runtime.onInstalled.addListener(() => {
  ensureMenu();
  chrome.storage.local.get({ protection: true }, (v) => {
    protection = v.protection !== false;
    applyRuleset();
  });
});
chrome.runtime.onStartup.addListener(ensureMenu);

chrome.storage.local.get({ protection: true }, (v) => {
  protection = v.protection !== false;
  applyRuleset();
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.protection) {
    protection = changes.protection.newValue !== false;
    applyRuleset();
  }
});

if (chrome.declarativeNetRequest.onRuleMatchedDebug) {
  chrome.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => {
    bump(info.request.tabId);
  });
}

chrome.tabs.onRemoved.addListener((tabId) => {
  counts.delete(tabId);
  const timer = pulses.get(tabId);
  if (timer) clearInterval(timer);
  pulses.delete(tabId);
});

chrome.tabs.onUpdated.addListener((tabId, info) => {
  if (!info.url) return;
  counts.set(tabId, 0);
  paint(tabId, false);
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "ironclad-zapper" && tab && tab.id != null) arm(tab.id);
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.type === "arm-zapper") {
    const tabId = msg.tabId != null ? msg.tabId : sender.tab && sender.tab.id;
    arm(tabId).then(
      () => sendResponse({ ok: true }),
      (err) => sendResponse({ ok: false, error: String(err) }),
    );
    return true;
  }
  if (msg && msg.type === "protection" && typeof msg.on === "boolean") {
    protection = msg.on;
    chrome.storage.local.set({ protection: msg.on });
    applyRuleset();
    sendResponse({ ok: true, protection });
    return true;
  }
  return false;
});
