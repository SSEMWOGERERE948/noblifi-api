const fs = require("fs");
const path = require("path");
const { db, listPlans } = require("./db");

const defaultTemplate = fs.readFileSync(path.join(__dirname, "..", "templates", "login.default.html"), "utf8");

function getTemplate(accountId) {
  const row = db.prepare("SELECT html FROM portal_templates WHERE account_id = ?").get(accountId);
  return row ? row.html : defaultTemplate;
}

function saveTemplate(accountId, html) {
  db.prepare(`
    INSERT INTO portal_templates (account_id, html, updated_at)
    VALUES (?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(account_id) DO UPDATE SET html = excluded.html, updated_at = CURRENT_TIMESTAMP
  `).run(accountId, html);
}

function renderPortal(account, publicBaseUrl) {
  const plans = listPlans(account.id).map((p) => ({
    id: p.id,
    name: p.name,
    price: p.price,
    seconds: p.seconds
  }));
  const tokens = {
    ACCOUNT_NAME: account.name,
    ACCOUNT_SLUG: account.slug,
    SUPPORT_PHONE: account.support_phone || "",
    PRIMARY_COLOR: account.primary_color,
    ACCENT_COLOR: account.accent_color,
    API_BASE: `${publicBaseUrl.replace(/\/+$/, "")}/api/${account.slug}`,
    PLANS_JSON: JSON.stringify(plans)
  };
  return getTemplate(account.id).replace(/\{\{([A-Z0-9_]+)\}\}/g, (_, key) => tokens[key] ?? "");
}

module.exports = {
  renderPortal,
  getTemplate,
  saveTemplate
};
