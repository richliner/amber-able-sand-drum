function apply(rules) {
  const host = location.hostname;
  const list = Array.isArray(rules) ? rules : [];
  const css = list
    .filter((r) => r && r.selector && (!r.host || r.host === host))
    .map((r) => `${r.selector}{display:none !important;}`)
    .join("\n");
  let style = document.getElementById("ironclad-cosmetic");
  if (!style) {
    style = document.createElement("style");
    style.id = "ironclad-cosmetic";
    (document.documentElement || document.head).appendChild(style);
  }
  style.textContent = css;
}

chrome.storage.local.get({ rules: [] }, (data) => apply(data.rules));
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.rules) apply(changes.rules.newValue || []);
});
