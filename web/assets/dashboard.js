(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const state = { mode: "register", apiKey: "", agentId: "", report: null, lastRun: null };
  const ratingLabels = { high_score: "High score", review: "Review", low_score: "Low score" };
  const factorLabels = {
    identity_verified: "Identity · key control",
    permission_declared: "Permissions · signed declaration",
    audit_log: "Audit · signed digest",
    incidents: "Incident count · requester supplied",
  };

  function setError(message) {
    $("error-box").textContent = message;
    $("error-box").hidden = false;
  }
  function clearError() {
    $("error-box").hidden = true;
    $("error-box").textContent = "";
  }
  function setBusy(busy) {
    $("run-assessment").disabled = busy;
    $("spinner").hidden = !busy;
    $("run-label").textContent = busy ? "Working…" : "Run assessment";
  }
  function showApiError(response, body) {
    const message = body && body.error && typeof body.error.message === "string"
      ? body.error.message
      : "The local API could not complete this request.";
    if (response.status === 409) return "This agent is already registered. Choose “Use API key” and enter its saved key.";
    if (response.status === 401) return "Authentication failed. Check the registration token or API key and try again.";
    if (response.status === 429) return "The API rate limit was reached. Wait briefly, then retry.";
    if (response.status >= 500) return "The local API is temporarily unavailable. Check the server terminal and retry.";
    return message;
  }
  async function request(path, options = {}) {
    let response;
    try {
      response = await fetch(path, { ...options, headers: { ...(options.headers || {}) } });
    } catch (_) {
      throw new Error("Could not reach the local API. Confirm the server is running at this page’s URL.");
    }
    let body = {};
    try { body = await response.json(); } catch (_) { /* Keep a safe generic error below. */ }
    if (!response.ok) throw new Error(showApiError(response, body));
    return body;
  }
  function jsonOptions(payload, apiKey) {
    const headers = { "Content-Type": "application/json" };
    if (apiKey) headers["X-API-Key"] = apiKey;
    return { method: "POST", headers, body: JSON.stringify(payload) };
  }
  function base64(bytes) {
    let binary = "";
    new Uint8Array(bytes).forEach((value) => { binary += String.fromCharCode(value); });
    return btoa(binary);
  }
  function pemToDer(pem) {
    const match = pem.match(/-----BEGIN PRIVATE KEY-----([\s\S]+?)-----END PRIVATE KEY-----/);
    if (!match) throw new Error("Choose an unencrypted PKCS8 Ed25519 private key in PEM format.");
    const binary = atob(match[1].replace(/\s/g, ""));
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
    return bytes;
  }
  async function loadSigningKey() {
    const file = $("private-key").files[0];
    if (!file) throw new Error("Choose the agent’s Ed25519 private key file to sign this assessment.");
    if (file.size > 16384) throw new Error("The selected private key file is unexpectedly large.");
    if (!window.crypto || !window.crypto.subtle) throw new Error("Browser cryptography is unavailable. Open this dashboard at its local 127.0.0.1 URL in a modern browser.");
    try {
      return await crypto.subtle.importKey("pkcs8", pemToDer(await file.text()), { name: "Ed25519" }, false, ["sign"]);
    } catch (error) {
      if (error && error.message && error.message.startsWith("Choose")) throw error;
      throw new Error("The selected file could not be imported as an Ed25519 private key.");
    }
  }
  async function sign(key, bytes) {
    return base64(await crypto.subtle.sign({ name: "Ed25519" }, key, bytes));
  }
  function utf8(text) { return new TextEncoder().encode(text); }
  function canonicalPermissions(agentId, actions) {
    return JSON.stringify({ agent_id: agentId, allowed_actions: actions, context: "agent-permissions-v1" });
  }
  function utcTimestamp() {
    return new Date().toISOString().replace(/\.(\d{3})Z$/, (_, ms) => `.${ms}000Z`);
  }
  function canonicalAudit(agentId, digest, createdAt) {
    return JSON.stringify({ agent_id: agentId, algorithm: "sha256", context: "agent-audit-digest-v1", created_at: createdAt, digest });
  }
  async function sha256Hex(text) {
    const hash = await crypto.subtle.digest("SHA-256", utf8(text));
    return Array.from(new Uint8Array(hash), (byte) => byte.toString(16).padStart(2, "0")).join("");
  }
  function renderReasons(report) {
    const list = $("reason-list");
    list.replaceChildren();
    report.reasons.forEach((reason) => {
      const row = document.createElement("div");
      row.className = "reason-row";
      const bullet = document.createElement("span");
      bullet.className = "reason-bullet";
      bullet.textContent = "!";
      const text = document.createElement("span");
      text.textContent = reason;
      row.append(bullet, text);
      list.append(row);
    });
  }
  function renderFactors(report) {
    const list = $("factor-list");
    list.replaceChildren();
    report.factor_scores.forEach((factor) => {
      const row = document.createElement("div");
      row.className = "factor-row";
      const name = document.createElement("div");
      name.className = "factor-name";
      name.textContent = factorLabels[factor.factor] || factor.factor;
      const status = document.createElement("div");
      const verified = factor.status === "verified";
      status.className = `factor-status ${verified ? "pass" : factor.factor === "incidents" ? "" : "fail"}`;
      const icon = document.createElement("span");
      icon.className = "status-icon";
      icon.textContent = factor.factor === "incidents" ? "·" : verified ? "✓" : "!";
      const statusText = document.createElement("span");
      statusText.textContent = factor.factor === "incidents" ? "Requester supplied" : verified ? "Signature verified" : "Not verified";
      status.append(icon, statusText);
      const reason = document.createElement("div");
      reason.className = "factor-reason";
      reason.textContent = factor.reason;
      row.append(name, status, reason);
      list.append(row);
    });
  }
  function displayReport(report, compact) {
    state.report = report;
    $("result").hidden = false;
    $("result-score").textContent = String(report.overall_score);
    $("result-rating").textContent = ratingLabels[report.rating] || "Formula result";
    $("result-rating").className = `rating-pill ${report.rating}`;
    $("result-summary").textContent = compact.reason;
    $("result-subtitle").textContent = `Agent ${report.agent_id} · score calculated by the local V1 formula`;
    const scoreBand = report.overall_score >= 80 ? "high" : report.overall_score >= 50 ? "review" : "low";
    $("score-marker").className = `score-marker score-${scoreBand}`;
    $("checked-at").textContent = `Checked ${new Date(report.checked_at).toLocaleString()}`;
    renderReasons(report);
    renderFactors(report);
    $("summary-score").textContent = String(report.overall_score);
    $("summary-rating").textContent = ratingLabels[report.rating] || report.rating;
    const verifiedCount = Object.values(report.evidence_results).filter((item) => item.valid && item.verification === "cryptographic").length;
    $("summary-checks").textContent = `${verifiedCount} / 3`;
    $("summary-history").textContent = "1";
    $("recent-list").className = "recent-card";
    $("recent-list").replaceChildren();
    const recentText = document.createElement("div");
    const agent = document.createElement("div"); agent.className = "recent-agent"; agent.textContent = report.agent_id;
    const date = document.createElement("div"); date.className = "recent-date"; date.textContent = new Date(report.checked_at).toLocaleString();
    recentText.append(agent, date);
    const score = document.createElement("div"); score.className = "recent-score"; score.textContent = String(report.overall_score);
    const open = document.createElement("button"); open.className = "recent-open"; open.type = "button"; open.textContent = "View result"; open.addEventListener("click", () => $("result").scrollIntoView({ behavior: "smooth" }));
    $("recent-list").append(recentText, score, open);
    $("rotate-key").hidden = !state.apiKey;
    $("download-key").hidden = !state.apiKey;
    $("result").scrollIntoView({ behavior: "smooth", block: "start" });
  }
  async function runAssessment() {
    clearError();
    setBusy(true);
    try {
      const agentId = $("agent-id").value.trim();
      if (!agentId || agentId.length > 128) throw new Error("Enter an agent ID between 1 and 128 characters.");
      const signingKey = await loadSigningKey();
      let apiKey = "";
      if (state.mode === "register") {
        const token = $("registration-token").value;
        if (!token) throw new Error("Enter the local registration token from .dev/registration.env.");
        const registered = await request("/v1/agents/register", {
          method: "POST", headers: { "Content-Type": "application/json", "X-Registration-Token": token },
          body: JSON.stringify({ agent_id: agentId }),
        });
        apiKey = registered.api_key;
        $("registration-token").value = "";
      } else {
        apiKey = $("api-key").value.trim();
        if (!apiKey) throw new Error("Enter the API key for this agent.");
        $("api-key").value = "";
        const check = await request(`/v1/score?agent_id=${encodeURIComponent(agentId)}`, { headers: { "X-API-Key": apiKey } });
        if (check.agent_id !== agentId) throw new Error("The API key did not authenticate the selected agent.");
      }
      state.apiKey = apiKey;
      state.agentId = agentId;
      $("download-key").hidden = false;
      $("key-save-note").hidden = false;
      $("key-save-note").textContent = "API key is held in this tab only. Save it now if you need to authenticate again later.";

      const challenge = await request("/v1/identity/challenge", jsonOptions({ agent_id: agentId }, apiKey));
      const identitySignature = await sign(signingKey, utf8(challenge.challenge));
      await request("/v1/identity/verify", jsonOptions({ agent_id: agentId, challenge_id: challenge.challenge_id, signature: identitySignature }, apiKey));

      const actions = $("actions").value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
      if (!actions.length || actions.length > 100) throw new Error("Enter between 1 and 100 declared actions.");
      const permissionManifest = {
        allowed_actions: actions,
        signature: await sign(signingKey, utf8(canonicalPermissions(agentId, actions))),
      };
      const createdAt = utcTimestamp();
      const digest = await sha256Hex($("audit-text").value);
      const auditLog = {
        digest,
        created_at: createdAt,
        signature: await sign(signingKey, utf8(canonicalAudit(agentId, digest, createdAt))),
      };
      const incidentCount = Number($("incidents").value);
      if (!Number.isInteger(incidentCount) || incidentCount < 0 || incidentCount > 1000000) throw new Error("Incident count must be a whole number from 0 to 1,000,000.");
      const evidence = { agent_id: agentId, permission_manifest: permissionManifest, audit_log: auditLog, incident_count: incidentCount };
      const headers = { "X-API-Key": apiKey, "Content-Type": "application/json" };
      const compact = await request("/v1/score", { method: "POST", headers, body: JSON.stringify(evidence) });
      const report = await request("/v1/score/report", { method: "POST", headers, body: JSON.stringify(evidence) });
      displayReport(report, compact);
      state.lastRun = { agentId, at: report.checked_at };
      $("download-key").hidden = false;
      $("key-save-note").hidden = false;
    } catch (error) {
      setError(error instanceof Error ? error.message : "The assessment could not be completed. Check the inputs and local API.");
    } finally {
      setBusy(false);
    }
  }
  function saveApiKey() {
    if (!state.apiKey) return;
    const blob = new Blob([`${state.apiKey}\n`], { type: "text/plain" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `${state.agentId}.api-key.txt`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
    $("key-save-note").textContent = "Key downloaded. Treat this file as a secret; the previous key becomes invalid if you rotate it.";
  }
  async function rotateApiKey() {
    if (!state.apiKey || !window.confirm("Rotate this agent’s API key? The current key will stop working immediately.")) return;
    clearError();
    try {
      const rotated = await request("/v1/agents/rotate-key", jsonOptions({ agent_id: state.agentId }, state.apiKey));
      state.apiKey = rotated.api_key;
      $("download-key").hidden = false;
      $("key-save-note").hidden = false;
      $("key-save-note").textContent = "New key is only held in this tab. Download it now if you need access later; the previous key has been revoked.";
      $("rotation-message").textContent = "API key rotated. The previous key is revoked immediately. Save the replacement key if you need to authenticate again.";
      $("rotation-message").hidden = false;
    } catch (error) {
      setError(error instanceof Error ? error.message : "Key rotation failed. The local API could not complete the request.");
    }
  }
  async function checkHealth() {
    try {
      const health = await request("/v1/health");
      $("health-label").textContent = health.status === "ok" ? "Local API connected" : "API unavailable";
      $("health-dot").className = `pulse ${health.status === "ok" ? "ok" : "bad"}`;
    } catch (_) {
      $("health-label").textContent = "Local API unavailable";
      $("health-dot").className = "pulse bad";
    }
  }
  function setMode(mode) {
    state.mode = mode;
    const isRegister = mode === "register";
    $("register-tab").classList.toggle("selected", isRegister);
    $("existing-tab").classList.toggle("selected", !isRegister);
    $("register-fields").hidden = !isRegister;
    $("existing-fields").hidden = isRegister;
  }
  document.querySelectorAll("[data-scroll]").forEach((button) => button.addEventListener("click", () => $(button.dataset.scroll).scrollIntoView({ behavior: "smooth" })));
  $("register-tab").addEventListener("click", () => setMode("register"));
  $("existing-tab").addEventListener("click", () => setMode("existing"));
  $("run-assessment").addEventListener("click", runAssessment);
  $("download-key").addEventListener("click", saveApiKey);
  $("rotate-key").addEventListener("click", rotateApiKey);
  checkHealth();
})();
