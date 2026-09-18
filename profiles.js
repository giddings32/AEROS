/* profiles.js - engagement profile definitions. An engagement profile drives
 * exam scoring, timeboxing, restricted-tool controls, and completeness checks.
 * The saved assessment model is authoritative; non-OSCP engagements do not
 * inherit exam-only behavior.
 *
 * Scoring numbers are a sensible OSCP-shaped default (3 standalone @20 + AD @40
 * = 100, pass 70) and are meant to be edited here if the exam format changes.
 * Loaded before the application runtime. Reads the current application state at
 * call time and retains explicit legacy engagementType values only as fallback.
 */
window.ENGAGEMENT_PROFILES = {
  oscp: {
    id: "oscp", label: "OSCP Exam", exam: true,
    workflow: { preset: "oscp", landingPage: "oscp-navigator", startupPreflight: true },
    scoring: { total: 100, passing: 70, standalone: { full: 20, partialLocal: 10 }, adSet: 40 },
    checks: { requireOsid: true, requireLocalProof: true },
    controls: {
      examClock: { enabled: true, defaultDurationMinutes: 1440 },
      hostTimeboxing: { enabled: true, defaultBudgetMinutes: 120 },
      restrictedTools: { metasploit: { mode: "single-target" } }
    }
  },
  generic: {
    id: "generic", label: "Generic Pentest", exam: false,
    scoring: null,
    checks: { requireOsid: false, requireLocalProof: false },
    controls: {
      examClock: { enabled: false, defaultDurationMinutes: 1440 },
      hostTimeboxing: { enabled: true, defaultBudgetMinutes: 120 },
      restrictedTools: { metasploit: { mode: "off" } }
    }
  }
};

window.activeProfile = function () {
  var current = {};
  try { current = window.getAerosState ? window.getAerosState() : (state || {}); } catch (e) { current = {}; }
  var feature = window.AEROSExamControls;
  var id = feature && typeof feature.profileIdForState === "function"
    ? feature.profileIdForState(current)
    : "generic";
  return window.ENGAGEMENT_PROFILES[id] || window.ENGAGEMENT_PROFILES.generic;
};
