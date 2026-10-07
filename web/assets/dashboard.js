(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const state = {
    mode: "register",
    adminToken: "",
    agents: [],
    selectedAgent: "",
    selectedDetails: null,
    agentKeys: new Map(),
    reportSigningKeyId: "",
  };
  const ratings = { high_score: "High score", review: "Review", low_score: "Low score" };
  const factorNames = {
    identity_verified: "Identity · key control",
    permission_declared: "Permissions · signed declaration",
    audit_log: "Audit · signed digest",
    incidents: "Incident count · requester supplied",
  };

  function showMessage(element, message, kind = "success") {
    element.textContent = message;
    element.className = `inline-message ${kind}`;
    element.hidden = false;
  }
  function hide(element) {
    element.hidden = true;
    element.textContent = "";
  }
  function setError(element, message) {
    element.textContent = message;
    element.hidden = false;
  }
  function apiMessage(response, body) {
    if (response.status === 401) return "Authentication failed. Check the local token or agent API key.";
    if (response.status === 404) return "That agent or report was not found in this local API.";
    if (response.status === 409) return "This agent is already registered. Choose “Use API key” and authenticate with its saved key.";
    if (response.status === 410) return "The identity challenge expired. Run the assessment again.";
    if (response.status === 429) return "The local API rate limit was reached. Wait briefly and retry.";
    if (response.status >= 500) return "The local API could not complete this request. Check its terminal for startup or configuration errors.";
    return body?.error?.message || "The local API could not complete this request.";
  }
  async function request(path, options = {}) {
    let response;
    try {
      response = await fetch(path, { ...options, headers: { ...(options.headers || {}) } });
    } catch (_) {
      throw new Error("Could not reach the local API. Confirm that Agent Signal is running.");
    }
    let body = {};
    try { body = await response.json(); } catch (_) { /* Keep a safe fallback message. */ }
    if (!response.ok) throw new Error(apiMessage(response, body));
    return body;
  }
  function jsonPost(payload, apiKey) {
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
    if (!file) throw new Error("Choose the agent’s Ed25519 private key file to sign the challenge and evidence.");
    if (file.size > 16384) throw new Error("The selected private key file is unexpectedly large.");
    if (!window.crypto?.subtle) throw new Error("Browser cryptography is unavailable. Open the dashboard at its local 127.0.0.1 URL.");
    try {
      return await crypto.subtle.importKey("pkcs8", pemToDer(await file.text()), { name: "Ed25519" }, false, ["sign"]);
    } catch (error) {
      if (error instanceof Error && error.message.startsWith("Choose")) throw error;
      throw new Error("The selected file could not be imported as an Ed25519 private key.");
    }
  }
  async function sign(key, bytes) {
    return base64(await crypto.subtle.sign({ name: "Ed25519" }, key, bytes));
  }
  const utf8 = (text) => new TextEncoder().encode(text);
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
    const digest = await crypto.subtle.digest("SHA-256", utf8(text));
    return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
  }

  function renderAgentList(agents) {
    const list = $("agents-list");
    list.replaceChildren();
    list.className = "agent-list";
    if (!agents.length) {
      list.className = "agent-list empty-state";
      const icon = document.createElement("div"); icon.className = "empty-icon"; icon.textContent = "◉";
      const title = document.createElement("b"); title.textContent = "No agents registered yet";
      const body = document.createElement("p"); body.textContent = "Register an agent below to create the first local record.";
      list.append(icon, title, body);
      return;
    }
    const heading = document.createElement("div");
    heading.className = "agent-row agent-head";
    ["Agent ID", "Status", "Latest score", "Rating", ""].forEach((label, index) => {
      const cell = document.createElement("div");
      cell.className = `agent-cell${index === 1 || index === 3 ? " optional" : ""}`;
      cell.textContent = label;
      heading.append(cell);
    });
    list.append(heading);
    agents.forEach((agent) => {
      const row = document.createElement("div"); row.className = "agent-row";
      const id = document.createElement("div"); id.className = "agent-cell agent-id"; id.textContent = agent.agent_id;
      const status = document.createElement("div"); status.className = "agent-cell optional";
      const pill = document.createElement("span"); pill.className = "status-pill active"; pill.textContent = "Active"; status.append(pill);
      const score = document.createElement("div"); score.className = "agent-cell"; score.textContent = agent.score === null ? "No report" : `${agent.score} / 100`;
      const rating = document.createElement("div"); rating.className = "agent-cell optional";
      if (agent.rating) { const ratingPill = document.createElement("span"); ratingPill.className = "rating-pill"; ratingPill.textContent = ratings[agent.rating] || agent.rating; rating.append(ratingPill); }
      else rating.textContent = "—";
      const action = document.createElement("button"); action.className = "button subtle row-action"; action.type = "button"; action.textContent = "Open";
      action.setAttribute("aria-label", `Open agent ${agent.agent_id}`);
      action.addEventListener("click", () => openAgent(agent.agent_id));
      row.append(id, status, score, rating, action);
      list.append(row);
    });
  }
  async function refreshAgents() {
    if (!state.adminToken) throw new Error("Connect the workspace with the local registration token first.");
    hide($("agents-error"));
    const data = await request("/v1/agents", { headers: { "X-Registration-Token": state.adminToken } });
    state.agents = data.agents;
    renderAgentList(data.agents);
    $("metric-agents").textContent = String(data.agents.length);
    const assessed = data.agents.filter((agent) => agent.score !== null);
    const signedReports = assessed.filter((agent) => agent.report_signed);
    $("metric-reports").textContent = String(signedReports.length);
    const latest = assessed[0];
    $("metric-score").textContent = latest ? String(latest.score) : "—";
    $("metric-rating").textContent = latest ? ratings[latest.rating] || latest.rating : "No saved report yet";
    $("refresh-agents").disabled = false;
  }
  async function connectWorkspace() {
    hide($("workspace-message"));
    const token = $("workspace-token").value;
    if (!token) { showMessage($("workspace-message"), "Enter the local registration token from .dev/registration.env.", "error"); return; }
    state.adminToken = token;
    try {
      await refreshAgents();
      $("workspace-token").value = "";
      const signingKey = await request("/v1/reports/signing-key");
      state.reportSigningKeyId = signingKey.signing_key_id;
      $("signing-key-label").textContent = `Verification key ID ${signingKey.signing_key_id}. The private signing key stays on this API.`;
      showMessage($("workspace-message"), "Workspace connected. The registration token is held in this tab only.");
    } catch (error) {
      state.adminToken = "";
      showMessage($("workspace-message"), error.message, "error");
    }
  }
  function addReportFactors(report) {
    const container = $("detail-factors");
    container.replaceChildren();
    report.factor_scores.forEach((factor) => {
      const row = document.createElement("div"); row.className = "factor-row";
      const name = document.createElement("div"); name.className = "factor-name"; name.textContent = factorNames[factor.factor] || factor.factor;
      const status = document.createElement("div");
      const isSupplied = factor.factor === "incidents";
      const isVerified = factor.status === "verified";
      status.className = `factor-status ${isSupplied ? "supplied" : isVerified ? "verified" : ""}`;
      status.textContent = isSupplied ? "Requester supplied" : isVerified ? "Signature verified" : "Not verified";
      const reason = document.createElement("div"); reason.className = "factor-reason"; reason.textContent = factor.reason;
      row.append(name, status, reason);
      container.append(row);
    });
  }
  function renderAgentDetails(details) {
    state.selectedDetails = details;
    state.selectedAgent = details.agent_id;
    $("agent-detail").hidden = false;
    $("detail-title").textContent = details.agent_id;
    $("detail-subtitle").textContent = `Agent ID ${details.agent_id} · registered and active in this local API`;
    $("agent-status").textContent = "Active";
    $("agent-status").className = "status-pill active";
    const hasReport = Boolean(details.report);
    $("detail-empty").hidden = hasReport;
    $("detail-report").hidden = !hasReport;
    if (!hasReport) return;

    const report = details.report;
    $("detail-score").textContent = String(report.overall_score);
    $("detail-rating").textContent = ratings[report.rating] || report.rating;
    $("detail-summary").textContent = report.reasons.join(" ");
    $("detail-marker").style.left = `${report.overall_score}%`;
    $("detail-report-id").textContent = details.signed_report ? `Report ${details.signed_report.report_id}` : `Checked ${report.checked_at}`;
    const reasons = $("detail-reasons"); reasons.replaceChildren();
    report.reasons.forEach((reason) => { const item = document.createElement("li"); item.textContent = reason; reasons.append(item); });
    addReportFactors(report);

    const signed = details.signed_report;
    $("signed-report-state").textContent = signed
      ? `Ed25519 signature · key ${signed.signing_key_id} · ${signed.report_id}`
      : "This report predates the signed report format. Run another assessment to create a signed envelope.";
    $("signed-report-json").textContent = signed ? JSON.stringify(signed, null, 2) : "No signed report envelope is available.";
    $("verify-current-report").disabled = !signed;
    $("download-report").disabled = !signed;
    $("verify-current-report").dataset.report = signed ? "available" : "missing";

    const key = state.agentKeys.get(details.agent_id);
    $("rotate-key").hidden = !key;
    $("save-api-key").hidden = !key;
    hide($("credential-message"));
  }
  async function openAgent(agentId) {
    try {
      const details = await request(`/v1/agents/${encodeURIComponent(agentId)}`, {
        headers: { "X-Registration-Token": state.adminToken },
      });
      renderAgentDetails(details);
      $("agent-detail").scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (error) {
      setError($("agents-error"), error.message);
    }
  }
  function setBusy(busy) {
    $("run-assessment").disabled = busy;
    $("run-spinner").hidden = !busy;
    $("run-label").textContent = busy ? "Working…" : "Run assessment";
  }
  async function runAssessment() {
    hide($("assessment-error"));
    hide($("assessment-message"));
    setBusy(true);
    try {
      if (!state.adminToken) throw new Error("Connect this workspace with the local registration token before assessing agents.");
      const agentId = $("agent-id").value.trim();
      if (!agentId || agentId.length > 128) throw new Error("Enter an agent ID between 1 and 128 characters.");
      const signingKey = await loadSigningKey();
      let apiKey;
      if (state.mode === "register") {
        const registration = await request("/v1/agents/register", {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-Registration-Token": state.adminToken },
          body: JSON.stringify({ agent_id: agentId }),
        });
        apiKey = registration.api_key;
      } else {
        apiKey = $("api-key").value.trim();
        if (!apiKey) throw new Error("Enter this agent’s API key.");
        const authenticated = await request(`/v1/score?agent_id=${encodeURIComponent(agentId)}`, { headers: { "X-API-Key": apiKey } });
        if (authenticated.agent_id !== agentId) throw new Error("The API key did not authenticate this agent.");
        $("api-key").value = "";
      }
      state.agentKeys.set(agentId, apiKey);

      const challenge = await request("/v1/identity/challenge", jsonPost({ agent_id: agentId }, apiKey));
      const identitySignature = await sign(signingKey, utf8(challenge.challenge));
      await request("/v1/identity/verify", jsonPost({
        agent_id: agentId,
        challenge_id: challenge.challenge_id,
        signature: identitySignature,
      }, apiKey));

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
      if (!Number.isInteger(incidentCount) || incidentCount < 0 || incidentCount > 1000000) {
        throw new Error("Incident count must be a whole number from 0 to 1,000,000.");
      }
      const evidence = { agent_id: agentId, permission_manifest: permissionManifest, audit_log: auditLog, incident_count: incidentCount };
      const headers = { "X-API-Key": apiKey, "Content-Type": "application/json" };
      const compact = await request("/v1/score", { method: "POST", headers, body: JSON.stringify(evidence) });
      const signed = await request("/v1/score/report/signed", { method: "POST", headers, body: JSON.stringify(evidence) });
      if (compact.score !== signed.report.overall_score || compact.rating !== signed.report.rating) {
        throw new Error("The API returned inconsistent score and report values. No report was displayed.");
      }
      $("report-input").value = JSON.stringify(signed, null, 2);
      await refreshAgents();
      await openAgent(agentId);
      showMessage($("assessment-message"), `Assessment complete. Report ${signed.report_id} was signed by the local Agent Signal service.`);
    } catch (error) {
      setError($("assessment-error"), error instanceof Error ? error.message : "The assessment could not be completed.");
    } finally {
      setBusy(false);
    }
  }
  async function verifyReport() {
    const result = $("verification-result");
    result.className = "verification-result";
    try {
      let envelope;
      try { envelope = JSON.parse($("report-input").value); }
      catch (_) { throw new Error("Enter a complete signed report as valid JSON."); }
      const verified = await request("/v1/reports/verify", jsonPost(envelope));
      result.classList.toggle("invalid", !verified.valid);
      result.textContent = `${verified.valid ? "Signature verified" : "Signature invalid"} · ${verified.reason} Report ${verified.report_id}.`;
      result.hidden = false;
    } catch (error) {
      result.className = "verification-result invalid";
      result.textContent = error.message;
      result.hidden = false;
    }
  }
  function loadCurrentReportForVerification() {
    const signed = state.selectedDetails?.signed_report;
    if (!signed) return;
    $("report-input").value = JSON.stringify(signed, null, 2);
    $("verify").scrollIntoView({ behavior: "smooth", block: "start" });
    verifyReport();
  }
  function downloadReport() {
    const signed = state.selectedDetails?.signed_report;
    if (!signed) return;
    const blob = new Blob([`${JSON.stringify(signed, null, 2)}\n`], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${signed.report.agent_id}-${signed.report_id}.signed-report.json`;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  async function rotateCredential() {
    const agentId = state.selectedAgent;
    const oldKey = state.agentKeys.get(agentId);
    if (!oldKey || !window.confirm("Rotate this agent’s API key? The current credential will be revoked immediately.")) return;
    hide($("credential-message"));
    try {
      const replacement = await request("/v1/agents/rotate-key", jsonPost({ agent_id: agentId }, oldKey));
      const oldResponse = await fetch(`/v1/score?agent_id=${encodeURIComponent(agentId)}`, { headers: { "X-API-Key": oldKey } });
      const newResponse = await fetch(`/v1/score?agent_id=${encodeURIComponent(agentId)}`, { headers: { "X-API-Key": replacement.api_key } });
      if (oldResponse.status !== 401 || !newResponse.ok) {
        throw new Error("The API did not confirm that the old credential was revoked and the replacement works.");
      }
      state.agentKeys.set(agentId, replacement.api_key);
      showMessage($("credential-message"), "Old credential revoked (HTTP 401 confirmed). The replacement credential is active in this tab.");
      await refreshAgents();
      await openAgent(agentId);
      showMessage($("credential-message"), "Old credential revoked (HTTP 401 confirmed). The replacement is active in this tab; save it if you need access later.");
    } catch (error) {
      showMessage($("credential-message"), error.message, "error");
    }
  }
  function saveApiKey() {
    const apiKey = state.agentKeys.get(state.selectedAgent);
    if (!apiKey) return;
    const blob = new Blob([`${apiKey}\n`], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${state.selectedAgent}.api-key.txt`;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  function setMode(mode) {
    state.mode = mode;
    const isRegister = mode === "register";
    $("register-tab").classList.toggle("selected", isRegister);
    $("existing-tab").classList.toggle("selected", !isRegister);
    $("existing-fields").hidden = isRegister;
  }
  async function checkHealth() {
    try {
      const health = await request("/v1/health");
      $("health-label").textContent = health.status === "ok" ? "Local API connected" : "Local API unavailable";
      $("health-dot").className = `health-dot ${health.status === "ok" ? "ok" : "bad"}`;
    } catch (_) {
      $("health-label").textContent = "Local API unavailable";
      $("health-dot").className = "health-dot bad";
    }
  }

  $("connect-workspace").addEventListener("click", connectWorkspace);
  $("refresh-agents").addEventListener("click", () => refreshAgents().catch((error) => setError($("agents-error"), error.message)));
  $("register-tab").addEventListener("click", () => setMode("register"));
  $("existing-tab").addEventListener("click", () => setMode("existing"));
  $("run-assessment").addEventListener("click", runAssessment);
  $("verify-report").addEventListener("click", verifyReport);
  $("verify-current-report").addEventListener("click", loadCurrentReportForVerification);
  $("download-report").addEventListener("click", downloadReport);
  $("rotate-key").addEventListener("click", rotateCredential);
  $("save-api-key").addEventListener("click", saveApiKey);
  document.querySelectorAll(".nav-link").forEach((link) => link.addEventListener("click", () => {
    document.querySelectorAll(".nav-link").forEach((item) => item.classList.remove("active"));
    link.classList.add("active");
  }));
  checkHealth();
})();
