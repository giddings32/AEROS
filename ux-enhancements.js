/* AEROS V1 - additive UX layer.
 * Loaded after the application bootstrap. Adds features without modifying existing code:
 *   - Autosave (debounced) with a live status badge
 *   - Ctrl/Cmd+S to save immediately
 *   - Warn before leaving with unsaved changes
 *   - Paste a screenshot (Ctrl+V) straight into the focused scan upload
 * All hooks are defensive: if an application-runtime function is missing, the feature
 * simply no-ops instead of throwing.
 */
(function () {
  "use strict";

  var byId = function (id) { return document.getElementById(id); };

  // The application runtime declares `state` with let/const, so it is not on window; reach it by
  // bare reference guarded with try/catch.
  function getState() { try { return state; } catch (e) { return (typeof window !== "undefined" && window.state) || null; } }

  /* ---------------------------------------------------------------- badge -- */
  var badge = document.createElement("div");
  badge.id = "autosaveBadge";
  badge.style.cssText = [
    "position:fixed", "bottom:12px", "right:14px", "z-index:99999",
    "font:12px/1.4 system-ui,Segoe UI,sans-serif", "padding:6px 10px",
    "border-radius:6px", "background:#161c26", "color:#9fb0c3",
    "border:1px solid #2c3543", "opacity:0", "transition:opacity .3s",
    "pointer-events:none", "user-select:none"
  ].join(";");

  function attachBadge() { if (document.body && !badge.isConnected) document.body.appendChild(badge); }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", attachBadge);
  } else {
    attachBadge();
  }

  var badgeHideTimer = null;
  function setBadge(text, color, autohide) {
    attachBadge();
    badge.textContent = text;
    badge.style.color = color || "#9fb0c3";
    badge.style.opacity = "0.96";
    clearTimeout(badgeHideTimer);
    if (autohide) badgeHideTimer = setTimeout(function () { badge.style.opacity = "0"; }, 2500);
  }

  /* ------------------------------------------------- dirty + autosave ----- */
  var dirty = false;
  var saveTimer = null;
  var saveInFlight = null;
  var savePending = false;

  function hasLoadedDiskEngagement(st) {
    try {
      if(document.body.classList.contains("engagement-wizard-open") && typeof engagementWizardMode!=="undefined" && engagementWizardMode==="create")return false;
      return !!(st && st.serverAvailable && typeof activeLabName === "function" && activeLabName());
    } catch (e) {
      return false;
    }
  }

  async function queueDiskSave(silent) {
    if (saveInFlight) {
      savePending = true;
      return saveInFlight;
    }
    saveInFlight = (async function () {
      do {
        savePending = false;
        await saveLabState(silent);
      } while (savePending);
    })();
    try {
      return await saveInFlight;
    } finally {
      saveInFlight = null;
    }
  }

  function scheduleSave() {
    setBadge("Editing…", "#c9a24a", false);
    clearTimeout(saveTimer);
    saveTimer = setTimeout(runAutosave, 2500);
  }

  async function runAutosave() {
    try {
      if (typeof save === "function") save();      // DOM -> state + emergency browser cache
      var st = getState();
      if (typeof saveLabState === "function" && hasLoadedDiskEngagement(st)) {
        setBadge("Saving to files…", "#c9a24a", false);
        await queueDiskSave(true);
        setBadge("Saved to files ✓ " + new Date().toLocaleTimeString(), "#5fb37a", true);
      } else {
        setBadge("Cached in browser only", "#c9a24a", true);
      }
      dirty = false;
    } catch (e) {
      setBadge("Disk save failed — browser cache retained", "#d66a6a", false);
    }
  }

  function markDirty() { dirty = true; scheduleSave(); }
  // Capture phase so we see edits regardless of stopPropagation downstream.
  // Programmatic value changes do NOT fire input/change, so app.js re-renders
  // will not trigger false autosaves.
  document.addEventListener("input", markDirty, true);
  document.addEventListener("change", markDirty, true);

  /* --------------------------------------------------- Ctrl / Cmd + S ----- */
  document.addEventListener("keydown", function (e) {
    if ((e.ctrlKey || e.metaKey) && (e.key === "s" || e.key === "S")) {
      e.preventDefault();
      clearTimeout(saveTimer);
      var st = getState();
      if (typeof save === "function") save();
      if (typeof saveLabState === "function" && hasLoadedDiskEngagement(st)) {
        setBadge("Saving to files…", "#c9a24a", false);
        Promise.resolve(queueDiskSave(false)).then(function () {
          dirty = false;
          setBadge("Saved to files ✓ " + new Date().toLocaleTimeString(), "#5fb37a", true);
        }).catch(function () {
          setBadge("Disk save failed — browser cache retained", "#d66a6a", true);
        });
      } else {
        dirty = false;
        setBadge("Cached in browser only", "#c9a24a", true);
      }
    }
  });

  /* -------------------------------------------- unsaved-changes guard ----- */
  window.addEventListener("beforeunload", function (e) {
    if (dirty) { e.preventDefault(); e.returnValue = ""; return ""; }
  });

  /* --------------------------------------- paste screenshot to upload ----- */
  var SCAN_INPUTS = { port: "scanPortImage", tcp: "scanTcpImage", udp: "scanUdpImage" };
  var lastScanType = null;

  function bindScanInputs() {
    Object.keys(SCAN_INPUTS).forEach(function (type) {
      var input = byId(SCAN_INPUTS[type]);
      if (!input || input.__pasteBound) return;
      input.__pasteBound = true;
      ["focusin", "mousedown"].forEach(function (evt) {
        input.addEventListener(evt, function () { lastScanType = type; });
      });
    });
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bindScanInputs);
  } else {
    bindScanInputs();
  }
  // Re-bind in case the inputs are re-rendered later.
  document.addEventListener("focusin", function (e) {
    if (!e.target || !e.target.id) return;
    Object.keys(SCAN_INPUTS).forEach(function (type) {
      if (e.target.id === SCAN_INPUTS[type]) lastScanType = type;
    });
  });

  document.addEventListener("paste", function (e) {
    if (!e.clipboardData) return;
    var items = Array.prototype.slice.call(e.clipboardData.items || []);
    var imgItem = items.find(function (i) { return i.type && i.type.indexOf("image/") === 0; });
    if (!imgItem) return;
    // Only hijack the paste when the user last interacted with a scan upload.
    if (!lastScanType) {
      setBadge("Click a scan upload field first, then paste", "#c9a24a", true);
      return;
    }
    var input = byId(SCAN_INPUTS[lastScanType]);
    if (!input) return;
    var blob = imgItem.getAsFile();
    if (!blob) return;
    try {
      var ext = (blob.type.split("/")[1] || "png").replace("jpeg", "jpg");
      var named = new File([blob], "pasted-" + Date.now() + "." + ext, { type: blob.type });
      var dt = new DataTransfer();
      dt.items.add(named);
      input.files = dt.files;
      e.preventDefault();
      if (typeof uploadScanImage === "function") {
        setBadge("Uploading pasted screenshot\u2026", "#c9a24a", false);
        uploadScanImage(lastScanType);
      }
    } catch (err) {
      // DataTransfer unsupported: leave the normal paste behavior intact.
    }
  });
})();

/* Color theme selector (Options > Appearance). Applies data-theme on <html> and
 * persists to localStorage. The early <head> script in index.html applies the
 * saved theme before first paint; this block keeps the dropdown in sync. */
(function () {
  "use strict";
  function applyTheme(t) { document.documentElement.setAttribute("data-theme", t || "blue"); }
  function initTheme() {
    var saved = "blue";
    try { saved = localStorage.getItem("appTheme") || "blue"; } catch (e) {}
    applyTheme(saved);
    var sel = document.getElementById("themeSelect");
    if (sel) {
      sel.value = saved;
      sel.addEventListener("change", function () {
        applyTheme(sel.value);
        try { localStorage.setItem("appTheme", sel.value); } catch (e) {}
        if (typeof saveActiveProfilePreferences === "function") saveActiveProfilePreferences();
      });
    }
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", initTheme);
  else initTheme();
})();

/* -------------------------------------------------------------------------
 * Theme-aware custom selects
 *
 * Native select popups are rendered by Windows/Chromium and ignore much of
 * the application theme. This layer keeps every original <select> element
 * and its existing event listeners, but presents it through a custom trigger
 * and listbox so all dropdowns share the selected profile color.
 * ---------------------------------------------------------------------- */
(function () {
  "use strict";

  var activeControl = null;
  var controlCounter = 0;
  var positionFrame = null;

  var ICONS = {
    engagement: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3.5 7.25h6l1.75 2h9.25v8.5a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2V7.25Z"/><path d="M3.5 7.25v-1a2 2 0 0 1 2-2h4l1.75 2h5.25"/><circle cx="12" cy="14" r="2.35"/><path d="M12 10.1v1.55M12 16.35v1.55M8.1 14h1.55M14.35 14h1.55"/></svg>',
    user: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="8" r="3.45"/><path d="M5.25 19.5c.55-4.05 2.8-6.08 6.75-6.08s6.2 2.03 6.75 6.08"/></svg>',
    theme: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3.25a8.75 8.75 0 1 0 0 17.5h1.2a1.75 1.75 0 0 0 0-3.5h-.65a1.5 1.5 0 0 1 0-3h2.2A5.75 5.75 0 0 0 20.5 8.5C20.5 5.6 17 3.25 12 3.25Z"/><circle cx="7.5" cy="9" r=".75" fill="currentColor" stroke="none"/><circle cx="10" cy="6.75" r=".75" fill="currentColor" stroke="none"/><circle cx="14" cy="6.5" r=".75" fill="currentColor" stroke="none"/></svg>',
    target: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8.25"/><circle cx="12" cy="12" r="4.4"/><path d="M12 1.75v3M12 19.25v3M1.75 12h3M19.25 12h3"/></svg>',
    monitor: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8M12 17v4"/></svg>',
    key: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="7.15" cy="10.15" r="4.15"/><circle cx="7.15" cy="10.15" r="1"/><path d="M11.3 10.15h10.2M18.4 10.15v3.1M15.25 10.15v2.2"/></svg>',
    host: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="4" width="18" height="6" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><path d="M7 7h.01M7 17h.01M11 7h6M11 17h6"/></svg>'
  };

  function iconFor(select) {
    var id = select.id || "";
    if (id === "labSelect") return ICONS.engagement;
    if (id === "startupProfileSelect" || id === "profileSelect") return ICONS.user;
    if (id === "themeSelect") return ICONS.theme;
    if (id === "engagementSelect") return ICONS.target;
    if (id === "hostSelect") return ICONS.host;
    if (id === "hostOs") return ICONS.monitor;
    if (/cred/i.test(id)) return ICONS.key;
    return '<span class="select-marker-dot" aria-hidden="true"></span>';
  }

  function optionSignature(select) {
    var parts = [String(select.selectedIndex), select.disabled ? "1" : "0"];
    for (var i = 0; i < select.options.length; i += 1) {
      var o = select.options[i];
      parts.push([o.value, o.textContent, o.disabled ? "1" : "0", o.hidden ? "1" : "0"].join("\u001f"));
    }
    return parts.join("\u001e");
  }

  function currentOption(select) {
    return select.selectedIndex >= 0 ? select.options[select.selectedIndex] : null;
  }

  function isPlaceholder(select, option) {
    return !option || (String(option.value) === "" && select.selectedIndex === 0);
  }

  function makeCheckIcon() {
    return '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="m3 8.25 3.05 3.05L13 4.75"/></svg>';
  }

  function makeChevronIcon() {
    return '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="m3.5 6 4.5 4 4.5-4"/></svg>';
  }

  function syncControl(control, forceRebuild) {
    if (!control || !control.select.isConnected) {
      if (activeControl === control) closeControl(control, false);
      return;
    }

    var signature = optionSignature(control.select);
    if (forceRebuild || signature !== control.signature) {
      control.signature = signature;
      buildPanel(control);
    }

    var selected = currentOption(control.select);
    control.value.textContent = selected ? selected.textContent.trim() : "Select an option...";
    control.wrapper.classList.toggle("is-placeholder", isPlaceholder(control.select, selected));
    control.trigger.disabled = !!control.select.disabled;
    control.trigger.setAttribute("aria-disabled", control.select.disabled ? "true" : "false");

    var optionButtons = control.panel.querySelectorAll(".custom-select-option");
    for (var i = 0; i < optionButtons.length; i += 1) {
      var button = optionButtons[i];
      var selectedNow = Number(button.dataset.optionIndex) === control.select.selectedIndex;
      button.classList.toggle("is-selected", selectedNow);
      button.setAttribute("aria-selected", selectedNow ? "true" : "false");
    }
  }

  function buildPanel(control) {
    var select = control.select;
    var panel = control.panel;
    panel.textContent = "";

    var children = Array.prototype.slice.call(select.children);
    children.forEach(function (child) {
      if (child.tagName === "OPTGROUP") {
        var groupLabel = document.createElement("div");
        groupLabel.className = "custom-select-group-label";
        groupLabel.textContent = child.label || "Options";
        panel.appendChild(groupLabel);
        Array.prototype.slice.call(child.children).forEach(function (option) {
          appendOption(control, option, Array.prototype.indexOf.call(select.options, option));
        });
      } else if (child.tagName === "OPTION") {
        appendOption(control, child, Array.prototype.indexOf.call(select.options, child));
      }
    });
  }

  function appendOption(control, option, index) {
    if (option.hidden) return;
    var button = document.createElement("button");
    button.type = "button";
    button.id = control.id + "-option-" + index;
    button.className = "custom-select-option";
    button.dataset.optionIndex = String(index);
    button.setAttribute("role", "option");
    button.setAttribute("aria-selected", option.selected ? "true" : "false");
    button.disabled = !!option.disabled;
    if (option.disabled) button.classList.add("is-disabled");
    if (String(option.value) === "") button.classList.add("is-placeholder");
    if (String(option.value) === "__new__") button.classList.add("is-action");
    if (option.selected) button.classList.add("is-selected");

    var text = document.createElement("span");
    text.className = "custom-select-option-text";
    text.textContent = option.textContent.trim();

    var check = document.createElement("span");
    check.className = "custom-select-option-check";
    check.innerHTML = makeCheckIcon();

    button.appendChild(text);
    button.appendChild(check);
    button.addEventListener("mousedown", function (event) { event.preventDefault(); });
    button.addEventListener("click", function () { chooseOption(control, index); });
    panelAppend(control.panel, button);
  }

  function panelAppend(panel, node) {
    panel.appendChild(node);
  }

  function chooseOption(control, index) {
    var option = control.select.options[index];
    if (!option || option.disabled) return;
    var changed = control.select.selectedIndex !== index;
    control.select.selectedIndex = index;
    syncControl(control, false);
    closeControl(control, true);
    if (changed) {
      control.select.dispatchEvent(new Event("input", { bubbles: true }));
      control.select.dispatchEvent(new Event("change", { bubbles: true }));
    }
  }

  function selectableButtons(control) {
    return Array.prototype.slice.call(control.panel.querySelectorAll(".custom-select-option:not(:disabled)"));
  }

  function setActiveButton(control, button) {
    var buttons = control.panel.querySelectorAll(".custom-select-option");
    for (var i = 0; i < buttons.length; i += 1) buttons[i].classList.remove("is-active");
    if (!button) return;
    button.classList.add("is-active");
    control.trigger.setAttribute("aria-activedescendant", button.id);
    button.scrollIntoView({ block: "nearest" });
  }

  function moveActive(control, delta) {
    var buttons = selectableButtons(control);
    if (!buttons.length) return;
    var current = control.panel.querySelector(".custom-select-option.is-active");
    var index = buttons.indexOf(current);
    if (index < 0) {
      current = control.panel.querySelector(".custom-select-option.is-selected:not(:disabled)");
      index = buttons.indexOf(current);
    }
    index = Math.max(0, Math.min(buttons.length - 1, index + delta));
    setActiveButton(control, buttons[index]);
  }

  function positionPanel(control) {
    if (!control || !control.trigger.isConnected) return;
    var rect = control.trigger.getBoundingClientRect();
    var viewportWidth = document.documentElement.clientWidth;
    var viewportHeight = document.documentElement.clientHeight;
    var margin = 8;
    var gap = 6;
    var width = Math.min(Math.max(rect.width, 210), viewportWidth - margin * 2);
    var left = Math.min(Math.max(rect.left, margin), viewportWidth - width - margin);
    var below = viewportHeight - rect.bottom - margin;
    var above = rect.top - margin;
    var opensUp = below < 170 && above > below;
    var maxHeight = Math.max(100, Math.min(330, (opensUp ? above : below) - gap));

    control.panel.style.width = width + "px";
    control.panel.style.left = left + "px";
    control.panel.style.maxHeight = maxHeight + "px";
    control.panel.classList.toggle("opens-up", opensUp);

    if (opensUp) {
      control.panel.style.top = "auto";
      control.panel.style.bottom = (viewportHeight - rect.top + gap) + "px";
    } else {
      control.panel.style.bottom = "auto";
      control.panel.style.top = (rect.bottom + gap) + "px";
    }
  }

  function openControl(control) {
    if (!control || control.select.disabled) return;
    if (activeControl && activeControl !== control) closeControl(activeControl, false);
    syncControl(control, false);
    activeControl = control;
    control.wrapper.classList.add("is-open");
    control.trigger.setAttribute("aria-expanded", "true");
    positionPanel(control);
    control.panel.classList.add("is-visible");
    var selected = control.panel.querySelector(".custom-select-option.is-selected:not(:disabled)") || selectableButtons(control)[0];
    setActiveButton(control, selected || null);
  }

  function closeControl(control, returnFocus) {
    if (!control) return;
    control.wrapper.classList.remove("is-open");
    control.panel.classList.remove("is-visible");
    control.trigger.setAttribute("aria-expanded", "false");
    control.trigger.removeAttribute("aria-activedescendant");
    setActiveButton(control, null);
    if (activeControl === control) activeControl = null;
    if (returnFocus && control.trigger.isConnected) control.trigger.focus();
  }

  function toggleControl(control) {
    if (activeControl === control) closeControl(control, true);
    else openControl(control);
  }

  function handleTriggerKeydown(control, event) {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      if (activeControl !== control) openControl(control);
      else moveActive(control, event.key === "ArrowDown" ? 1 : -1);
      return;
    }
    if (event.key === "Home" && activeControl === control) {
      event.preventDefault();
      setActiveButton(control, selectableButtons(control)[0] || null);
      return;
    }
    if (event.key === "End" && activeControl === control) {
      event.preventDefault();
      var buttons = selectableButtons(control);
      setActiveButton(control, buttons[buttons.length - 1] || null);
      return;
    }
    if ((event.key === "Enter" || event.key === " ") && activeControl === control) {
      event.preventDefault();
      var active = control.panel.querySelector(".custom-select-option.is-active");
      if (active) chooseOption(control, Number(active.dataset.optionIndex));
      return;
    }
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      openControl(control);
      return;
    }
    if (event.key === "Escape" && activeControl === control) {
      event.preventDefault();
      closeControl(control, true);
      return;
    }

    if (event.key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey) {
      control.typeBuffer = (control.typeBuffer || "") + event.key.toLowerCase();
      clearTimeout(control.typeTimer);
      control.typeTimer = setTimeout(function () { control.typeBuffer = ""; }, 550);
      var buttons = selectableButtons(control);
      var match = buttons.find(function (button) {
        return button.textContent.trim().toLowerCase().indexOf(control.typeBuffer) === 0;
      });
      if (match) {
        if (activeControl !== control) openControl(control);
        setActiveButton(control, match);
      }
    }
  }

  function enhanceSelect(select) {
    if (!select || select.dataset.customSelectReady === "true") return;
    select.dataset.customSelectReady = "true";
    select.classList.add("select-enhanced-native");

    var wrapper = document.createElement("div");
    wrapper.className = "custom-select";
    wrapper.dataset.selectId = select.id || "";

    var trigger = document.createElement("button");
    trigger.type = "button";
    trigger.className = "custom-select-trigger";
    trigger.setAttribute("role", "combobox");
    trigger.setAttribute("aria-haspopup", "listbox");
    trigger.setAttribute("aria-expanded", "false");

    var leading = document.createElement("span");
    leading.className = "custom-select-leading";
    leading.innerHTML = iconFor(select);

    var value = document.createElement("span");
    value.className = "custom-select-value";

    var chevron = document.createElement("span");
    chevron.className = "custom-select-chevron";
    chevron.innerHTML = makeChevronIcon();

    trigger.appendChild(leading);
    trigger.appendChild(value);
    trigger.appendChild(chevron);

    var panel = document.createElement("div");
    panel.className = "custom-select-panel";
    panel.setAttribute("role", "listbox");
    panel.tabIndex = -1;

    controlCounter += 1;
    var controlId = "custom-select-" + controlCounter;
    panel.id = controlId + "-listbox";
    trigger.setAttribute("aria-controls", panel.id);

    var parent = select.parentNode;
    parent.insertBefore(wrapper, select);
    wrapper.appendChild(select);
    wrapper.appendChild(trigger);
    document.body.appendChild(panel);

    var control = {
      id: controlId,
      select: select,
      wrapper: wrapper,
      trigger: trigger,
      value: value,
      panel: panel,
      signature: "",
      typeBuffer: "",
      typeTimer: null
    };
    select.__customSelectControl = control;
    wrapper.__customSelectControl = control;
    panel.__customSelectControl = control;

    trigger.addEventListener("click", function (event) {
      event.preventDefault();
      event.stopPropagation();
      toggleControl(control);
    });
    trigger.addEventListener("keydown", function (event) { handleTriggerKeydown(control, event); });
    select.addEventListener("change", function () { syncControl(control, false); });
    select.addEventListener("input", function () { syncControl(control, false); });
    select.addEventListener("focus", function () { trigger.focus(); });

    var optionObserver = new MutationObserver(function () { syncControl(control, true); });
    optionObserver.observe(select, { childList: true, subtree: true, attributes: true, characterData: true });
    control.observer = optionObserver;

    syncControl(control, true);
  }

  function enhanceWithin(root) {
    if (!root) return;
    if (root.matches && root.matches("select")) enhanceSelect(root);
    var selects = root.querySelectorAll ? root.querySelectorAll("select") : [];
    for (var i = 0; i < selects.length; i += 1) enhanceSelect(selects[i]);
  }

  function removeDetachedPanels() {
    var panels = document.querySelectorAll(".custom-select-panel");
    for (var i = 0; i < panels.length; i += 1) {
      var control = panels[i].__customSelectControl;
      if (control && !control.select.isConnected) {
        if (activeControl === control) activeControl = null;
        if (control.observer) control.observer.disconnect();
        panels[i].remove();
      }
    }
  }

  function refreshAll() {
    var selects = document.querySelectorAll("select[data-custom-select-ready='true']");
    for (var i = 0; i < selects.length; i += 1) {
      var control = selects[i].__customSelectControl;
      if (control) syncControl(control, false);
    }
    removeDetachedPanels();
    if (activeControl) positionPanel(activeControl);
  }

  function scheduleActivePosition() {
    if (!activeControl || positionFrame !== null) return;
    positionFrame = window.requestAnimationFrame(function () {
      positionFrame = null;
      if (activeControl) positionPanel(activeControl);
    });
  }

  function initCustomSelects() {
    enhanceWithin(document);

    var bodyObserver = new MutationObserver(function (mutations) {
      mutations.forEach(function (mutation) {
        Array.prototype.slice.call(mutation.addedNodes || []).forEach(function (node) {
          if (node.nodeType === 1) enhanceWithin(node);
        });
      });
      removeDetachedPanels();
    });
    bodyObserver.observe(document.body, { childList: true, subtree: true });

    document.addEventListener("mousedown", function (event) {
      if (!activeControl) return;
      if (activeControl.wrapper.contains(event.target) || activeControl.panel.contains(event.target)) return;
      closeControl(activeControl, false);
    }, true);

    document.addEventListener("click", function (event) {
      var label = event.target.closest ? event.target.closest("label") : null;
      if (!label) return;
      var select = null;
      var targetId = label.getAttribute("for");
      if (targetId) select = document.getElementById(targetId);
      else select = label.querySelector("select[data-custom-select-ready='true']");
      if (!select || !select.__customSelectControl) return;
      if (event.target.closest(".custom-select")) return;
      event.preventDefault();
      select.__customSelectControl.trigger.focus();
    }, true);

    window.addEventListener("resize", scheduleActivePosition);
    window.addEventListener("scroll", scheduleActivePosition, true);
    window.addEventListener("pageshow", refreshAll);
    document.addEventListener("visibilitychange", function () {
      if (!document.hidden) refreshAll();
    });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", initCustomSelects);
  else initCustomSelects();
})();
