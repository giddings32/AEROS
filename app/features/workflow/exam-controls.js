(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.AEROSExamControls = api;
})(typeof window !== "undefined" ? window : globalThis, function () {
  "use strict";

  const TIMER_STATES = new Set(["idle", "running", "paused"]);
  const RESTRICTED_TOOL_RE = /\b(?:metasploit|msfconsole|meterpreter)\b|(?:^|[\s"'`])(?:exploit|auxiliary|post|payload)\/[a-z0-9_./-]+/i;

  function object(value) {
    return value && typeof value === "object" && !Array.isArray(value) ? value : {};
  }

  function positiveInteger(value, fallback, minimum = 1, maximum = 10080) {
    const number = Number(value);
    if (!Number.isFinite(number)) return fallback;
    return Math.min(maximum, Math.max(minimum, Math.round(number)));
  }

  function timestamp(value) {
    const parsed = Date.parse(String(value || ""));
    return Number.isFinite(parsed) ? parsed : 0;
  }

  function iso(now) {
    return new Date(Number.isFinite(Number(now)) ? Number(now) : Date.now()).toISOString();
  }

  function profileIdForState(state) {
    const assessment = object(object(state).engagementConfig?.assessment);
    const category = String(assessment.category || "").trim().toLowerCase();
    const type = String(assessment.type || "").trim().toLowerCase();
    if (category === "certification-lab" && type === "oscp") return "oscp";
    const legacy = String(object(state).engagementType || "").trim().toLowerCase();
    if (!category && !type && ["oscp", "generic"].includes(legacy)) return legacy;
    return "generic";
  }

  function timerDefaults(durationMinutes) {
    return {
      status: "idle",
      durationMinutes: positiveInteger(durationMinutes, 120),
      accumulatedMs: 0,
      startedAt: "",
      lastStartedAt: "",
      pausedAt: "",
      resetAt: "",
      updatedAt: ""
    };
  }

  function ensureTimer(timer, durationMinutes) {
    const source = object(timer);
    const defaults = timerDefaults(durationMinutes);
    Object.keys(defaults).forEach(key => {
      if (!(key in source)) source[key] = defaults[key];
    });
    source.status = TIMER_STATES.has(source.status) ? source.status : "idle";
    source.durationMinutes = positiveInteger(source.durationMinutes, defaults.durationMinutes);
    source.accumulatedMs = Math.max(0, Number(source.accumulatedMs) || 0);
    ["startedAt", "lastStartedAt", "pausedAt", "resetAt", "updatedAt"].forEach(key => {
      source[key] = typeof source[key] === "string" ? source[key] : "";
    });
    if (source.status === "running" && !timestamp(source.lastStartedAt)) {
      source.status = source.accumulatedMs ? "paused" : "idle";
      source.lastStartedAt = "";
    }
    return source;
  }

  function elapsedMs(timer, now = Date.now()) {
    const value = ensureTimer(timer, timer?.durationMinutes || 120);
    const active = value.status === "running" ? Math.max(0, Number(now) - timestamp(value.lastStartedAt)) : 0;
    return Math.max(0, value.accumulatedMs + active);
  }

  function timerSnapshot(timer, now = Date.now()) {
    const value = ensureTimer(timer, timer?.durationMinutes || 120);
    const elapsed = elapsedMs(value, now);
    const duration = value.durationMinutes * 60000;
    const remaining = duration - elapsed;
    return {
      status: remaining <= 0 && value.status !== "idle" ? "expired" : value.status,
      persistedStatus: value.status,
      durationMs: duration,
      elapsedMs: elapsed,
      remainingMs: Math.max(0, remaining),
      overrunMs: Math.max(0, -remaining),
      percent: duration ? Math.min(100, Math.round((elapsed / duration) * 100)) : 0
    };
  }

  function startTimer(timer, now = Date.now()) {
    const value = ensureTimer(timer, timer?.durationMinutes || 120);
    if (value.status === "running") return value;
    const at = iso(now);
    value.status = "running";
    value.lastStartedAt = at;
    value.startedAt = value.startedAt || at;
    value.pausedAt = "";
    value.updatedAt = at;
    return value;
  }

  function pauseTimer(timer, now = Date.now()) {
    const value = ensureTimer(timer, timer?.durationMinutes || 120);
    if (value.status !== "running") return value;
    const at = iso(now);
    value.accumulatedMs = elapsedMs(value, now);
    value.status = "paused";
    value.lastStartedAt = "";
    value.pausedAt = at;
    value.updatedAt = at;
    return value;
  }

  function resetTimer(timer, now = Date.now()) {
    const value = ensureTimer(timer, timer?.durationMinutes || 120);
    const at = iso(now);
    Object.assign(value, timerDefaults(value.durationMinutes), { resetAt: at, updatedAt: at });
    return value;
  }

  function setTimerDuration(timer, minutes, now = Date.now()) {
    const value = ensureTimer(timer, timer?.durationMinutes || 120);
    if (value.status === "running") pauseTimer(value, now);
    value.durationMinutes = positiveInteger(minutes, value.durationMinutes);
    value.updatedAt = iso(now);
    return value;
  }

  function ensureWorkflowState(state, profile) {
    const current = object(state);
    current.engagementConfig = object(current.engagementConfig);
    current.engagementConfig.workflow = object(current.engagementConfig.workflow);
    const workflow = current.engagementConfig.workflow;
    workflow.examControls = object(workflow.examControls);
    const controls = workflow.examControls;
    controls.schemaVersion = 1;
    const examMinutes = positiveInteger(profile?.controls?.examClock?.defaultDurationMinutes, 1440);
    const hostMinutes = positiveInteger(profile?.controls?.hostTimeboxing?.defaultBudgetMinutes, 120);
    controls.clock = ensureTimer(controls.clock, examMinutes);
    controls.hostDefaultMinutes = positiveInteger(controls.hostDefaultMinutes, hostMinutes);
    controls.restrictedTools = object(controls.restrictedTools);
    controls.restrictedTools.metasploit = object(controls.restrictedTools.metasploit);
    const metasploit = controls.restrictedTools.metasploit;
    if (typeof metasploit.targetHostId !== "string") metasploit.targetHostId = "";
    if (typeof metasploit.selectedAt !== "string") metasploit.selectedAt = "";
    if (typeof metasploit.clearedAt !== "string") metasploit.clearedAt = "";
    if (!Array.isArray(metasploit.history)) metasploit.history = [];
    if (metasploit.targetHostId && !object(current.hosts)[metasploit.targetHostId]) {
      recordHistory(metasploit, {
        action: "target-cleared",
        hostId: metasploit.targetHostId,
        at: iso(Date.now()),
        reason: "host-no-longer-present"
      });
      metasploit.targetHostId = "";
      metasploit.selectedAt = "";
    }
    return controls;
  }

  function recordHistory(metasploit, entry) {
    metasploit.history.push(entry);
    if (metasploit.history.length > 100) metasploit.history.splice(0, metasploit.history.length - 100);
  }

  function ensureHostTimer(host, profile, workflowControls) {
    const current = object(host);
    current.workflow = object(current.workflow);
    const fallback = positiveInteger(
      workflowControls?.hostDefaultMinutes,
      positiveInteger(profile?.controls?.hostTimeboxing?.defaultBudgetMinutes, 120)
    );
    current.workflow.timebox = ensureTimer(current.workflow.timebox, fallback);
    return current.workflow.timebox;
  }

  function startHostTimer(state, hostId, profile, now = Date.now()) {
    const hosts = object(object(state).hosts);
    if (!hosts[hostId]) throw new Error("Select a valid host before starting its timebox.");
    const controls = ensureWorkflowState(state, profile);
    const pausedHostIds = [];
    Object.entries(hosts).forEach(([id, host]) => {
      const timer = ensureHostTimer(host, profile, controls);
      if (id !== hostId && timer.status === "running") {
        pauseTimer(timer, now);
        pausedHostIds.push(id);
      }
    });
    startTimer(ensureHostTimer(hosts[hostId], profile, controls), now);
    return { timer: hosts[hostId].workflow.timebox, pausedHostIds };
  }

  function pauseHostTimer(state, hostId, profile, now = Date.now()) {
    const host = object(object(state).hosts)[hostId];
    if (!host) throw new Error("Select a valid host before pausing its timebox.");
    return pauseTimer(ensureHostTimer(host, profile, ensureWorkflowState(state, profile)), now);
  }

  function resetHostTimer(state, hostId, profile, now = Date.now()) {
    const host = object(object(state).hosts)[hostId];
    if (!host) throw new Error("Select a valid host before resetting its timebox.");
    return resetTimer(ensureHostTimer(host, profile, ensureWorkflowState(state, profile)), now);
  }

  function setHostBudget(state, hostId, profile, minutes, now = Date.now()) {
    const host = object(object(state).hosts)[hostId];
    if (!host) throw new Error("Select a valid host before changing its timebox.");
    return setTimerDuration(ensureHostTimer(host, profile, ensureWorkflowState(state, profile)), minutes, now);
  }

  function restrictedToolKind(text) {
    return RESTRICTED_TOOL_RE.test(String(text || "")) ? "metasploit" : "";
  }

  function restrictedMode(profile) {
    return String(profile?.controls?.restrictedTools?.metasploit?.mode || "off");
  }

  function authorizeRestrictedUse(state, profile, hostId, text) {
    const tool = restrictedToolKind(text);
    const mode = restrictedMode(profile);
    if (!tool || mode !== "single-target") return { allowed: true, tool, mode };
    const hosts = object(object(state).hosts);
    if (!hostId || !hosts[hostId]) {
      return {
        allowed: false,
        tool,
        mode,
        code: "host-required",
        message: "Select the host that will own this restricted Metasploit/Meterpreter action."
      };
    }
    const selected = ensureWorkflowState(state, profile).restrictedTools.metasploit.targetHostId;
    if (!selected) {
      return {
        allowed: false,
        tool,
        mode,
        code: "target-required",
        requiresSelection: true,
        hostId,
        message: "No restricted Metasploit/Meterpreter target is selected for this engagement."
      };
    }
    if (selected !== hostId) {
      return {
        allowed: false,
        tool,
        mode,
        code: "target-mismatch",
        selectedHostId: selected,
        hostId,
        message: "Restricted Metasploit/Meterpreter use is assigned to another host in this engagement."
      };
    }
    return { allowed: true, tool, mode, hostId, selectedHostId: selected };
  }

  function selectRestrictedTarget(state, profile, hostId, options = {}) {
    const hosts = object(object(state).hosts);
    if (!hostId || !hosts[hostId]) throw new Error("Choose a valid host as the restricted-tool target.");
    if (restrictedMode(profile) !== "single-target") return { changed: false, mode: restrictedMode(profile) };
    const metasploit = ensureWorkflowState(state, profile).restrictedTools.metasploit;
    if (metasploit.targetHostId && metasploit.targetHostId !== hostId && !options.replace) {
      return { changed: false, requiresReplace: true, selectedHostId: metasploit.targetHostId };
    }
    if (metasploit.targetHostId === hostId) return { changed: false, selectedHostId: hostId };
    const at = iso(options.now);
    if (metasploit.targetHostId) {
      recordHistory(metasploit, {
        action: "target-replaced",
        hostId: metasploit.targetHostId,
        replacementHostId: hostId,
        at
      });
    } else {
      recordHistory(metasploit, { action: "target-selected", hostId, at });
    }
    metasploit.targetHostId = hostId;
    metasploit.selectedAt = at;
    metasploit.clearedAt = "";
    return { changed: true, selectedHostId: hostId };
  }

  function clearRestrictedTarget(state, profile, now = Date.now()) {
    const metasploit = ensureWorkflowState(state, profile).restrictedTools.metasploit;
    if (!metasploit.targetHostId) return { changed: false };
    const prior = metasploit.targetHostId;
    const at = iso(now);
    recordHistory(metasploit, { action: "target-cleared", hostId: prior, at, reason: "operator-cleared" });
    metasploit.targetHostId = "";
    metasploit.selectedAt = "";
    metasploit.clearedAt = at;
    return { changed: true, priorHostId: prior };
  }

  function attemptText(attempt) {
    const provenance = object(attempt?.provenance);
    const success = object(attempt?.success);
    return [
      attempt?.title,
      provenance.compileCommand,
      provenance.transferCommand,
      provenance.executeCommand,
      provenance.cleanupCommand,
      provenance.output,
      provenance.proof,
      attempt?.notes,
      success.method
    ].filter(Boolean).join("\n");
  }

  function formatDuration(milliseconds) {
    const total = Math.max(0, Math.floor(Number(milliseconds) / 1000));
    const hours = Math.floor(total / 3600);
    const minutes = Math.floor((total % 3600) / 60);
    const seconds = total % 60;
    return `${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
  }

  function create(deps = {}) {
    const byId = deps.byId || (id => document.getElementById(id));
    const getState = deps.getState || (() => ({}));
    const getProfile = deps.getProfile || (() => ({}));
    const escapeHtml = deps.escapeHtml || (value => String(value == null ? "" : value));
    const hostLabel = deps.hostLabel || (host => host?.hostname || host?.ip || "Host");
    const persistState = deps.persistState || (() => {});
    const saveState = deps.saveState || (async () => {});
    const showToast = deps.showToast || (() => {});
    const confirmAction = deps.confirmAction || (async () => true);
    const navigateToOverview = deps.navigateToOverview || (() => {});
    let bound = false;
    let tickHandle = 0;

    function stateAndProfile() {
      const state = getState();
      const profile = getProfile();
      const controls = ensureWorkflowState(state, profile);
      Object.values(object(state.hosts)).forEach(host => ensureHostTimer(host, profile, controls));
      return { state, profile, controls };
    }

    async function commit(message) {
      persistState();
      try {
        await saveState();
        if (message) showToast(message, "success");
      } catch (error) {
        showToast(`The workflow change is saved locally but file storage synchronization failed: ${error.message || error}`, "error");
      }
    }

    function profileIsExam(profile) {
      return profile?.exam === true && profile?.controls?.examClock?.enabled !== false;
    }

    function renderHeader() {
      const button = byId("workflowClockBtn");
      if (!button) return;
      const { state, profile, controls } = stateAndProfile();
      const visible = !!state.projectName && profileIsExam(profile);
      button.classList.toggle("hidden", !visible);
      button.setAttribute("aria-hidden", visible ? "false" : "true");
      if (visible) {
        const snapshot = timerSnapshot(controls.clock);
        button.dataset.clockStatus = snapshot.status;
        button.innerHTML = `<span class="workflow-clock-dot"></span><span>Exam</span><strong data-exam-clock>${formatDuration(snapshot.remainingMs)}</strong>`;
      }
    }

    function render() {
      renderHeader();
      scheduleTick();
    }

    function refreshDisplays() {
      const { state, profile, controls } = stateAndProfile();
      const exam = timerSnapshot(controls.clock);
      document.querySelectorAll("[data-exam-clock]").forEach(node => { node.textContent = formatDuration(exam.remainingMs); });
      document.querySelectorAll("[data-exam-status]").forEach(node => {
        node.textContent = exam.status;
        node.className = `workflow-status ${exam.status}`;
      });
      document.querySelectorAll("[data-exam-progress]").forEach(node => { node.style.width = `${exam.percent}%`; });
      const header = byId("workflowClockBtn");
      if (header && !header.classList.contains("hidden")) header.dataset.clockStatus = exam.status;
      const host = object(state.hosts)[state.activeHost];
      if (host) {
        const hostSnapshot = timerSnapshot(ensureHostTimer(host, profile, controls));
        document.querySelectorAll("[data-host-clock]").forEach(node => { node.textContent = formatDuration(hostSnapshot.elapsedMs); });
        document.querySelectorAll("[data-host-status]").forEach(node => {
          node.textContent = hostSnapshot.status;
          node.className = `workflow-status ${hostSnapshot.status}`;
        });
        document.querySelectorAll("[data-host-progress]").forEach(node => { node.style.width = `${hostSnapshot.percent}%`; });
      }
    }

    function hasRunningTimer() {
      const { state, profile, controls } = stateAndProfile();
      if (profileIsExam(profile) && controls.clock.status === "running") return true;
      return Object.values(object(state.hosts)).some(host => ensureHostTimer(host, profile, controls).status === "running");
    }

    function scheduleTick() {
      if (tickHandle) clearTimeout(tickHandle);
      tickHandle = 0;
      refreshDisplays();
      if (typeof document !== "undefined" && !document.hidden && hasRunningTimer()) {
        tickHandle = setTimeout(function tick() {
          tickHandle = 0;
          refreshDisplays();
          scheduleTick();
        }, 1000);
      }
    }

    async function setTarget(hostId) {
      const { state, profile, controls } = stateAndProfile();
      if (!hostId) return;
      const current = controls.restrictedTools.metasploit.targetHostId;
      let replace = false;
      if (current && current !== hostId) {
        const currentHost = object(state.hosts)[current];
        const nextHost = object(state.hosts)[hostId];
        replace = await confirmAction(
          `Replace the restricted Metasploit/Meterpreter target ${hostLabel(currentHost)} with ${hostLabel(nextHost)}?`,
          { title: "Replace Restricted Target", confirmText: "Replace target", danger: true }
        );
        if (!replace) {
          render();
          return;
        }
      }
      const result = selectRestrictedTarget(state, profile, hostId, { replace });
      if (result.changed) await commit("Restricted-tool target selected.");
      render();
    }

    function bind() {
      if (bound) return;
      bound = true;
      byId("workflowClockBtn")?.addEventListener("click", navigateToOverview);
      if (typeof document !== "undefined") {
        document.addEventListener("visibilitychange", scheduleTick);
      }
    }

    async function selectTargetForCurrentHost(hostId) {
      const { state, profile } = stateAndProfile();
      const result = selectRestrictedTarget(state, profile, hostId);
      if (result.requiresReplace) return result;
      if (result.changed) await commit("Restricted-tool target selected.");
      render();
      return result;
    }

    return {
      bind,
      render,
      refreshDisplays,
      guardCommand(text, hostId) {
        const { state, profile } = stateAndProfile();
        return authorizeRestrictedUse(state, profile, hostId, text);
      },
      guardAttempt(attempt, hostId) {
        const { state, profile } = stateAndProfile();
        return authorizeRestrictedUse(state, profile, hostId, attemptText(attempt));
      },
      selectTargetForCurrentHost,
      stop() {
        if (tickHandle) clearTimeout(tickHandle);
        tickHandle = 0;
      }
    };
  }

  return Object.freeze({
    TIMER_STATES,
    profileIdForState,
    ensureTimer,
    ensureWorkflowState,
    ensureHostTimer,
    elapsedMs,
    timerSnapshot,
    startTimer,
    pauseTimer,
    resetTimer,
    setTimerDuration,
    startHostTimer,
    pauseHostTimer,
    resetHostTimer,
    setHostBudget,
    restrictedToolKind,
    authorizeRestrictedUse,
    selectRestrictedTarget,
    clearRestrictedTarget,
    attemptText,
    formatDuration,
    create
  });
});
