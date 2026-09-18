/* review.js - evidence-derived engagement, host, and attack-path readiness.
 * Reads structured AEROS state through app/features/readiness/readiness.js.
 * Rendering is read-only. Action buttons navigate to the owning host/workspace.
 */
(function () {
  "use strict";

  var activeFilter = "all";

  function S() { try { return state; } catch (e) { return (typeof window !== "undefined" && window.state) || null; } }
  function esc(v) {
    if (typeof escapeHtml === "function") return escapeHtml(v);
    return String(v == null ? "" : v).replace(/[&<>"']/g, function (character) {
      return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character];
    });
  }
  function api() { return (typeof window !== "undefined" && window.AEROSReadiness) || null; }
  function exploitApi() { return (typeof window !== "undefined" && window.AEROSExploitAttempts) || null; }
  function profile() { try { return typeof activeProfile === "function" ? activeProfile() : {}; } catch (e) { return {}; } }
  function assessment() {
    var model = api();
    if (!model) return null;
    return model.assessEngagement(S() || {}, { profile: profile(), exploitAttemptsApi: exploitApi(), findingsApi: window.AEROSFindings || null });
  }
  function stateClass(value) { return ["ready", "review", "blocked", "in-progress"].includes(value) ? value : "blocked"; }
  function issueIcon(severity) { return severity === "blocking" ? "!" : "i"; }
  function visibleIssue(issue) {
    if (activeFilter === "blocking") return issue.severity === "blocking";
    if (activeFilter === "warning") return issue.severity === "warning";
    return true;
  }
  function issueAction(issue) {
    if (!issue || (!issue.hostId && issue.action && issue.action.tab === "review")) return "";
    return '<button class="readiness-open" type="button" data-readiness-open="' + esc(issue.id) + '"' +
      (issue.hostId ? ' data-readiness-host="' + esc(issue.hostId) + '"' : "") +
      (issue.action && issue.action.tab ? ' data-readiness-tab="' + esc(issue.action.tab) + '"' : "") +
      (issue.action && issue.action.anchor ? ' data-readiness-anchor="' + esc(issue.action.anchor) + '"' : "") +
      (issue.action && issue.action.attemptId ? ' data-readiness-attempt="' + esc(issue.action.attemptId) + '"' : "") +
      '>Open</button>';
  }
  function issueRows(items) {
    var rows = (items || []).filter(visibleIssue);
    if (!rows.length) return '<div class="readiness-empty">No items in this filter.</div>';
    return '<div class="readiness-issue-list">' + rows.map(function (item) {
      return '<article class="readiness-issue ' + esc(item.severity) + '"><span class="readiness-issue-icon">' + issueIcon(item.severity) + '</span><div><strong>' + esc(item.title) + '</strong><p>' + esc(item.detail) + '</p><small>' + esc((window.AEROSReadiness.CATEGORY_LABELS || {})[item.category] || item.category) + '</small></div>' + issueAction(item) + '</article>';
    }).join("") + '</div>';
  }
  function scoreRing(score, state) {
    return '<div class="readiness-score-ring ' + esc(stateClass(state)) + '" style="--readiness-score:' + Number(score || 0) + '"><div><strong>' + Number(score || 0) + '%</strong><span>evidence complete</span></div></div>';
  }
  function summaryHtml(result) {
    return '<section class="readiness-summary ' + esc(stateClass(result.state)) + '">' + scoreRing(result.score, result.state) +
      '<div class="readiness-summary-copy"><span class="readiness-kicker">Evidence-derived status</span><h4>' + esc(result.stateLabel) + '</h4><p>Readiness is calculated from saved target, scan, access, proof, evidence, and report records. It is not a manual completion checkbox.</p><div class="readiness-summary-facts"><span><strong>' + result.blockers + '</strong> blockers</span><span><strong>' + result.warnings + '</strong> warnings</span><span><strong>' + result.readyHosts + '</strong> / ' + result.reportableHosts + ' reportable hosts ready</span><span><strong>' + result.totalHosts + '</strong> total hosts</span></div></div></section>';
  }
  function filtersHtml(result) {
    var values = [
      ["all", "All", result.blockers + result.warnings],
      ["blocking", "Blocking", result.blockers],
      ["warning", "Warnings", result.warnings]
    ];
    return '<div class="readiness-filter-bar"><div class="readiness-filter-buttons">' + values.map(function (row) {
      return '<button type="button" class="' + (activeFilter === row[0] ? "active" : "") + '" data-readiness-filter="' + row[0] + '">' + row[1] + ' <span>' + row[2] + '</span></button>';
    }).join("") + '</div><span class="readiness-filter-note">Review every blocker before export; warnings identify useful OSCP/pentest documentation gaps.</span></div>';
  }
  function pathHtml(path) {
    var shown = path.issues.filter(visibleIssue);
    if (activeFilter !== "all" && !shown.length) return "";
    return '<details class="readiness-path ' + esc(stateClass(path.state)) + '"' + (shown.length ? " open" : "") + '><summary><div><span>Attack path</span><strong>' + esc(path.label) + '</strong></div><div class="readiness-path-meta"><span>' + path.score + '%</span><span>' + path.issues.filter(function (item) { return item.severity === "blocking"; }).length + ' blockers</span><span>' + (path.issues.length - path.issues.filter(function (item) { return item.severity === "blocking"; }).length) + ' warnings</span></div></summary>' + issueRows(path.issues) + '</details>';
  }
  function hostHtml(host) {
    var shown = host.issues.filter(visibleIssue);
    var paths = host.pathAssessments.map(pathHtml).filter(Boolean).join("");
    if (activeFilter !== "all" && !shown.length && !paths) return "";
    return '<article class="readiness-host-card ' + esc(stateClass(host.state)) + '" data-readiness-host-card="' + esc(host.id) + '"><header><div><span class="readiness-kicker">' + (host.reportable ? "Reportable host" : "Host workflow") + '</span><h4>' + esc(host.label) + '</h4><p>' + esc(host.host.ip || "No IP") + (host.host.hostname ? " · " + esc(host.host.hostname) : "") + '</p></div><div class="readiness-host-status"><strong>' + esc(host.stateLabel) + '</strong><span>' + host.score + '% · ' + host.blockers + ' blockers · ' + host.warnings + ' warnings</span><button type="button" data-readiness-host="' + esc(host.id) + '" data-readiness-tab="profile">Open Host</button></div></header>' +
      '<div class="readiness-stage-grid">' + ["target", "enumeration", "access", "proof", "reporting"].map(function (key) {
        var rows = host.categories[key] || [], blockers = rows.filter(function (item) { return item.severity === "blocking"; }).length;
        return '<div class="' + (blockers ? "blocked" : rows.length ? "review" : "ready") + '"><span>' + esc((window.AEROSReadiness.CATEGORY_LABELS || {})[key] || key) + '</span><strong>' + (blockers ? blockers + " blocker" + (blockers === 1 ? "" : "s") : rows.length ? rows.length + " warning" + (rows.length === 1 ? "" : "s") : "Complete") + '</strong></div>';
      }).join("") + '</div>' + issueRows(host.issues) + (paths ? '<div class="readiness-path-list"><h5>Structured attack paths</h5>' + paths + '</div>' : "") + '</article>';
  }

  function renderReview() {
    var root = document.getElementById("reviewResults");
    if (!root) return;
    var result = assessment();
    if (!result) {
      root.innerHTML = '<div class="review-banner bad">Readiness engine is unavailable.</div>';
      return;
    }
    var engagementShown = result.engagementIssues.filter(visibleIssue);
    var hostCards = result.hosts.map(hostHtml).filter(Boolean).join("");
    root.innerHTML = summaryHtml(result) + filtersHtml(result) +
      '<section class="readiness-section"><div class="readiness-section-head"><div><span class="readiness-kicker">Whole engagement</span><h4>Engagement checks</h4></div><span>' + engagementShown.length + ' shown</span></div>' + issueRows(result.engagementIssues) + '</section>' +
      '<section class="readiness-section"><div class="readiness-section-head"><div><span class="readiness-kicker">Per host and attack path</span><h4>Host readiness</h4></div><span>' + result.hosts.length + ' hosts</span></div><div class="readiness-host-list">' + (hostCards || '<div class="readiness-empty">No hosts match this filter.</div>') + '</div></section>';
    bindReviewActions(root);
  }

  function openIssueTarget(button) {
    var st = S();
    if (!st) return;
    var hostId = button.dataset.readinessHost || "";
    var tab = button.dataset.readinessTab || "review";
    var anchor = button.dataset.readinessAnchor || "";
    var attemptId = button.dataset.readinessAttempt || "";
    if (hostId && st.hosts && st.hosts[hostId]) {
      st.activeHost = hostId;
      try { if (typeof persist === "function") persist(); } catch (e) {}
      try { if (typeof render === "function") render(); else if (typeof renderWorkspace === "function") renderWorkspace(); } catch (e) {}
    }
    if (tab === "options") {
      try { if (typeof openOptionsFromSidebar === "function") openOptionsFromSidebar(); } catch (e) {}
    } else {
      try { if (typeof setWorkspaceTab === "function") setWorkspaceTab(tab); } catch (e) {}
    }
    if (attemptId) {
      try { if (typeof editExploitAttempt === "function") editExploitAttempt(attemptId); } catch (e) {}
    }
    window.setTimeout(function () {
      var target = anchor ? document.getElementById(anchor) : null;
      if (!target && attemptId) target = document.getElementById("exploitAttemptForm");
      if (target) target.scrollIntoView({ behavior: "smooth", block: "start" });
    }, 100);
  }
  function bindReviewActions(root) {
    root.onclick = function (event) {
      var filter = event.target.closest && event.target.closest("[data-readiness-filter]");
      if (filter) { activeFilter = filter.dataset.readinessFilter || "all"; renderReview(); return; }
      var open = event.target.closest && event.target.closest("[data-readiness-host], [data-readiness-open]");
      if (open) openIssueTarget(open);
    };
  }
  function initReview() {
    var button = document.getElementById("recheckBtn");
    if (button) button.addEventListener("click", renderReview);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", initReview);
  else initReview();

  window.renderReview = renderReview;
  window.collectReadiness = assessment;
})();
