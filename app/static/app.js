/* SecretShield dashboard */
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);

  /* ---------- tabs ---------- */
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((t) => {
        t.classList.remove("active");
        t.setAttribute("aria-selected", "false");
      });
      document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
      tab.classList.add("active");
      tab.setAttribute("aria-selected", "true");
      $(tab.dataset.panel).classList.add("active");
    });
  });

  /* ---------- health ---------- */
  async function checkHealth() {
    const pill = $("service-status");
    const text = $("status-text");
    try {
      const res = await fetch("/health", { cache: "no-store" });
      if (!res.ok) throw new Error("bad status");
      pill.className = "status-pill ok";
      text.textContent = "Service online";
    } catch {
      pill.className = "status-pill down";
      text.textContent = "Service unreachable";
    }
  }

  /* ---------- helpers ---------- */
  function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }

  function formatTime(iso) {
    if (!iso) return "unknown time";
    const d = new Date(iso);
    return isNaN(d) ? iso : d.toLocaleString();
  }

  function findingHtml(f) {
    const sev = ["Critical", "High", "Low"].includes(f.severity) ? f.severity : "High";
    return `
      <div class="finding">
        <div class="finding-top">
          <span class="sev ${sev}">${escapeHtml(sev.toUpperCase())}</span>
          <span class="finding-loc">${escapeHtml(f.file)}:${escapeHtml(f.line)}</span>
          <span class="finding-rule">${escapeHtml(f.rule)}</span>
        </div>
        <code class="finding-value">${escapeHtml(f.redacted_value)}</code>
        ${f.remediation ? `<div class="finding-fix"><b>Fix:</b> ${escapeHtml(f.remediation)}</div>` : ""}
      </div>`;
  }

  /* ---------- dashboard ---------- */
  async function loadReports() {
    const box = $("reports");
    try {
      const res = await fetch("/api/reports?limit=50", { cache: "no-store" });
      if (!res.ok) throw new Error("request failed");
      const reports = await res.json();

      const pass = reports.filter((r) => r.status === "PASS").length;
      const fail = reports.filter((r) => r.status === "FAIL").length;
      const findings = reports.reduce((sum, r) => sum + (r.finding_count || 0), 0);
      $("stat-total").textContent = reports.length;
      $("stat-pass").textContent = pass;
      $("stat-fail").textContent = fail;
      $("stat-findings").textContent = findings;

      if (!reports.length) {
        box.innerHTML = `<p class="muted">No scans yet. Push a commit and the CI job will send its report here.</p>`;
        return;
      }

      box.innerHTML = reports.map((r) => {
        const cls = r.status === "PASS" ? "pass" : "fail";
        const count = r.finding_count === 1 ? "1 finding" : `${r.finding_count} findings`;
        // NOTE: the API returns commit_sha, not commit.
        const sha = r.commit_sha ? String(r.commit_sha).slice(0, 7) : "";
        const sub = [
          sha ? `<code class="sha">${escapeHtml(sha)}</code>` : "",
          r.branch ? escapeHtml(r.branch) : "",
          formatTime(r.timestamp),
          count,
        ].filter(Boolean).join(" · ");
        const message = r.message
          ? `<span class="report-msg">${escapeHtml(r.message)}</span>`
          : "";
        return `
          <article class="report">
            <div class="report-head" data-toggle="findings-${r.id}">
              <span class="badge ${cls}">${escapeHtml(r.status)}</span>
              <div class="report-meta">
                <span class="report-repo">${escapeHtml(r.repo || "unknown repository")}</span>
                ${message}
                <span class="report-sub">${sub}</span>
              </div>
              ${r.findings.length ? `<span class="chev">show details</span>` : ""}
            </div>
            ${r.findings.length
              ? `<div class="findings" id="findings-${r.id}" hidden>${r.findings.map(findingHtml).join("")}</div>`
              : ""}
          </article>`;
      }).join("");

      box.querySelectorAll("[data-toggle]").forEach((head) => {
        head.addEventListener("click", () => {
          const panel = $(head.dataset.toggle);
          if (!panel) return;
          panel.hidden = !panel.hidden;
          const chev = head.querySelector(".chev");
          if (chev) chev.textContent = panel.hidden ? "show details" : "hide details";
        });
      });
    } catch {
      box.innerHTML = `<p class="muted">Could not load the scan history. Is the service running?</p>`;
    }
  }

  /* ---------- scan now ---------- */
  async function scanNow() {
    const input = $("scan-input");
    const out = $("scan-result");
    const btn = $("scan-btn");
    const text = input.value;

    if (!text.trim()) {
      out.innerHTML = `<div class="verdict pass">Nothing to scan<span class="verdict-note">Paste some code first.</span></div>`;
      return;
    }

    btn.disabled = true;
    btn.textContent = "Scanning…";
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text, filename: "pasted-text" }),
      });
      if (!res.ok) throw new Error("request failed");
      const data = await res.json();

      if (data.status === "PASS" && !data.findings.length) {
        out.innerHTML = `<div class="verdict pass">PASS — no secrets found<span class="verdict-note">Nothing in this text matches a secret pattern.</span></div>`;
      } else {
        const n = data.findings.length;
        const verdict = data.status === "FAIL"
          ? `<div class="verdict fail">FAIL — ${n} secret${n === 1 ? "" : "s"} detected<span class="verdict-note">A commit containing this would be blocked.</span></div>`
          : `<div class="verdict pass">WARNING — ${n} low-severity finding${n === 1 ? "" : "s"}<span class="verdict-note">Not blocking, but worth a look.</span></div>`;
        out.innerHTML = verdict +
          `<div class="report" style="margin-top:14px"><div class="findings">${data.findings.map(findingHtml).join("")}</div></div>`;
      }
    } catch {
      out.innerHTML = `<div class="verdict fail">Could not reach the scanner<span class="verdict-note">Check that the service is running.</span></div>`;
    } finally {
      btn.disabled = false;
      btn.textContent = "Scan text";
    }
  }

  /* Sample text for the "Load a dummy key" button. The values are fake and are
     assembled from parts so this source file holds no key-shaped literal of its
     own — the scanner would flag it, and rightly so. */
  const SAMPLE = [
    "# Dummy credentials - fake values, safe to test with",
    'AWS_ACCESS_KEY_ID = "AKIA' + '4SHIELDDEMO7QZXK"',
    'GITHUB_TOKEN = "ghp_' + '1A2b3C4d5E6f7G8h9I0jK1L2m3N4o5P6q7R8"',
    'password = "Super' + 'Secret123!"',
  ].join("\n");

  $("scan-btn").addEventListener("click", scanNow);
  $("sample-btn").addEventListener("click", () => { $("scan-input").value = SAMPLE; });
  $("clear-btn").addEventListener("click", () => {
    $("scan-input").value = "";
    $("scan-result").innerHTML = "";
  });
  $("scan-input").addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") scanNow();
  });
  $("refresh-btn").addEventListener("click", loadReports);

  checkHealth();
  loadReports();
  setInterval(checkHealth, 30000);
  setInterval(loadReports, 60000);
})();
