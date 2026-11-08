// All requests use relative URLs so the app works on whatever port it's served from.

const form = document.getElementById("scan-form");
const authPanel = document.getElementById("auth-panel");
const formLoginFields = document.getElementById("form-login-fields");
const manualSessionPanel = document.getElementById("manual-session-panel");
const testLoginBtn = document.getElementById("test-login-btn");
const testLoginResult = document.getElementById("test-login-result");
const startScanBtn = document.getElementById("start-scan-btn");
const stageLabel = document.getElementById("stage-label");
const progressFill = document.getElementById("progress-fill");
const errorsBox = document.getElementById("errors-box");
const resultsBody = document.getElementById("results-body");

let pollTimer = null;

function modeRadios() {
  return document.querySelectorAll('input[name="mode"]');
}
function authModeRadios() {
  return document.querySelectorAll('input[name="auth_mode"]');
}

function currentMode() {
  const checked = document.querySelector('input[name="mode"]:checked');
  return checked ? checked.value : "unauthenticated";
}

function currentAuthMode() {
  const checked = document.querySelector('input[name="auth_mode"]:checked');
  return checked ? checked.value : "form";
}

function refreshAuthPanelVisibility() {
  if (currentMode() === "authenticated") {
    authPanel.classList.remove("hidden");
  } else {
    authPanel.classList.add("hidden");
  }
  refreshAuthSubPanels();
}

function refreshAuthSubPanels() {
  if (currentAuthMode() === "manual") {
    formLoginFields.classList.add("hidden");
  } else {
    formLoginFields.classList.remove("hidden");
  }
}

modeRadios().forEach((r) => r.addEventListener("change", refreshAuthPanelVisibility));
authModeRadios().forEach((r) => r.addEventListener("change", refreshAuthSubPanels));
refreshAuthPanelVisibility();

function parseExtraFields(text) {
  const out = {};
  text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && l.includes("="))
    .forEach((l) => {
      const idx = l.indexOf("=");
      const key = l.slice(0, idx).trim();
      const value = l.slice(idx + 1).trim();
      if (key) out[key] = value;
    });
  return out;
}

function collectFormLoginPayload() {
  return {
    login_url: document.getElementById("login_url").value.trim(),
    username: document.getElementById("username").value,
    password: document.getElementById("password").value,
    username_selector: document.getElementById("username_selector").value.trim(),
    password_selector: document.getElementById("password_selector").value.trim(),
    submit_selector: document.getElementById("submit_selector").value.trim(),
    extra_fields: parseExtraFields(document.getElementById("extra_fields").value),
  };
}

testLoginBtn.addEventListener("click", async () => {
  testLoginResult.textContent = "Testing...";
  testLoginResult.className = "test-result";
  testLoginBtn.disabled = true;

  const payload = collectFormLoginPayload();

  try {
    const resp = await fetch("/login/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await resp.json();
    if (data.ok) {
      testLoginResult.textContent = data.message || "Login successful ✓";
      testLoginResult.classList.add("ok");
    } else {
      testLoginResult.textContent = data.message || "Login failed";
      testLoginResult.classList.add("fail");
    }
  } catch (err) {
    testLoginResult.textContent = "Request error: " + err.message;
    testLoginResult.classList.add("fail");
  } finally {
    testLoginBtn.disabled = false;
  }
});

function severityBadge(severity) {
  const cls =
    {
      High: "badge-high",
      Medium: "badge-medium",
      Low: "badge-low",
      Info: "badge-info",
    }[severity] || "badge-info";
  return `<span class="badge ${cls}">${severity}</span>`;
}

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderResults(results) {
  if (!results || results.length === 0) {
    resultsBody.innerHTML =
      '<tr class="empty-row"><td colspan="6">No findings yet.</td></tr>';
    return;
  }
  resultsBody.innerHTML = results
    .map(
      (r) => `
      <tr>
        <td>${severityBadge(r.severity)}</td>
        <td>${escapeHtml(r.vuln_type)}</td>
        <td class="url-cell">${escapeHtml(r.url)}</td>
        <td>${escapeHtml(r.parameter)}</td>
        <td class="payload-cell">${escapeHtml(r.payload)}</td>
        <td class="evidence-cell">${escapeHtml(r.evidence)}</td>
      </tr>`
    )
    .join("");
}

function renderErrors(errors) {
  if (!errors || errors.length === 0) {
    errorsBox.classList.add("hidden");
    errorsBox.innerHTML = "";
    return;
  }
  errorsBox.classList.remove("hidden");
  errorsBox.innerHTML = errors.map((e) => `<div>⚠ ${escapeHtml(e)}</div>`).join("");
}

async function pollStatus(scanId) {
  try {
    const resp = await fetch(`/scan/${scanId}/status`);
    if (!resp.ok) {
      stageLabel.textContent = "Error fetching status";
      clearInterval(pollTimer);
      startScanBtn.disabled = false;
      return;
    }
    const data = await resp.json();
    stageLabel.textContent = data.stage || "Running";
    progressFill.style.width = (data.progress || 0) + "%";
    renderResults(data.results);
    renderErrors(data.errors);

    if (data.finished) {
      clearInterval(pollTimer);
      startScanBtn.disabled = false;
    }
  } catch (err) {
    stageLabel.textContent = "Polling error: " + err.message;
  }
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();

  startScanBtn.disabled = true;
  stageLabel.textContent = "Starting...";
  progressFill.style.width = "0%";
  errorsBox.classList.add("hidden");
  errorsBox.innerHTML = "";
  resultsBody.innerHTML =
    '<tr class="empty-row"><td colspan="6">Scan starting…</td></tr>';

  const mode = currentMode();
  const authMode = currentAuthMode();

  const payload = {
    target_url: document.getElementById("target_url").value.trim(),
    mode: mode,
    auth_mode: authMode,
    urls_to_scan: document
      .getElementById("urls_to_scan")
      .value.split("\n")
      .map((l) => l.trim())
      .filter((l) => l.length > 0),
    also_crawl: document.getElementById("also_crawl").checked,
  };

  if (mode === "authenticated") {
    if (authMode === "form") {
      Object.assign(payload, collectFormLoginPayload());
    } else {
      payload.manual_session = document.getElementById("manual_session").value;
    }
  }

  try {
    const resp = await fetch("/scan/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await resp.json();
    if (!data.scan_id) {
      stageLabel.textContent = "Failed to start scan";
      startScanBtn.disabled = false;
      return;
    }
    pollTimer = setInterval(() => pollStatus(data.scan_id), 1000);
    pollStatus(data.scan_id);
  } catch (err) {
    stageLabel.textContent = "Error starting scan: " + err.message;
    startScanBtn.disabled = false;
  }
});
