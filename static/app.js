(function () {
  "use strict";
  var html = document.documentElement;

  var toggle = document.getElementById("theme-toggle");
  if (toggle) {
    var label = function () { toggle.textContent = html.dataset.theme === "dark" ? "light" : "dark"; };
    label();
    toggle.addEventListener("click", function () {
      html.dataset.theme = html.dataset.theme === "dark" ? "light" : "dark";
      try { localStorage.setItem("anpi-theme", html.dataset.theme); } catch (e) {}
      label();
    });
  }

  document.querySelectorAll("form[data-confirm]").forEach(function (f) {
    f.addEventListener("submit", function (e) {
      if (!window.confirm(f.dataset.confirm)) e.preventDefault();
    });
  });

  // Show only the fields that apply to the selected type; hidden ones are disabled so they are not submitted.
  document.querySelectorAll("form[data-kind-form]").forEach(function (form) {
    var select = form.querySelector("[data-kind-select]");
    if (!select) return;
    var apply = function () {
      form.querySelectorAll("[data-kinds]").forEach(function (el) {
        var show = el.dataset.kinds.split(" ").indexOf(select.value) !== -1;
        el.hidden = !show;
        el.querySelectorAll("input, select, textarea").forEach(function (i) { i.disabled = !show; });
      });
    };
    select.addEventListener("change", apply);
    apply();
  });

  document.querySelectorAll("[data-tz-offset]").forEach(function (i) { i.value = String(new Date().getTimezoneOffset()); });

  document.querySelectorAll("[data-toggle-target]").forEach(function (box) {
    var target = document.getElementById(box.dataset.toggleTarget);
    var apply = function () { if (target) target.hidden = box.checked; };
    box.addEventListener("change", apply);
    apply();
  });

  document.querySelectorAll("[data-file-into]").forEach(function (input) {
    input.addEventListener("change", function () {
      var file = input.files && input.files[0];
      var target = document.getElementById(input.dataset.fileInto);
      if (!file || !target) return;
      file.text().then(function (t) { target.value = t; });
    });
  });

  document.querySelectorAll("pre[data-copy]").forEach(function (pre) {
    pre.title = "Click to copy";
    pre.addEventListener("click", function () {
      if (!navigator.clipboard) return;
      navigator.clipboard.writeText(pre.textContent.trim()).then(function () {
        pre.classList.add("copied");
        setTimeout(function () { pre.classList.remove("copied"); }, 1200);
      });
    });
  });

  // Live updates over server-sent events.
  var source = document.body.dataset.events;
  if (!source || !window.EventSource) return;
  var isPublic = document.body.classList.contains("public");
  var classes = { up: "s-up", down: "s-down", pending: "s-pending", maintenance: "s-maint" };
  var labels = { up: "Up", down: "Down", pending: isPublic ? "Degraded" : "Pending", maintenance: "Maintenance" };
  var allStatus = ["s-up", "s-down", "s-pending", "s-maint", "s-paused", "s-none"];

  function setStatus(el, status) {
    allStatus.forEach(function (c) { el.classList.remove(c); });
    el.classList.add(classes[status] || "s-none");
    var l = el.querySelector("[data-role=label]");
    if (l) l.textContent = labels[status] || status;
  }

  function pushBeat(strip, ev) {
    var bar = document.createElement("span");
    bar.className = "hb " + (classes[ev.status] || "");
    bar.title = ev.time + " · " + (labels[ev.status] || ev.status) + (ev.latency !== "–" ? " · " + ev.latency : "") + (ev.message ? " · " + ev.message : "");
    strip.appendChild(bar);
    if (strip.firstElementChild) strip.removeChild(strip.firstElementChild);
  }

  function updateOverall() {
    var box = document.getElementById("overall");
    if (!box) return;
    var states = [];
    document.querySelectorAll("[data-monitor] [data-role=status]").forEach(function (s) {
      if (s.classList.contains("s-paused") || s.classList.contains("s-none")) return;
      states.push(s.classList.contains("s-down") ? "down" : s.classList.contains("s-pending") ? "pending" : s.classList.contains("s-maint") ? "maint" : "up");
    });
    var down = states.filter(function (s) { return s === "down"; }).length;
    var cls = "s-up", text = "All systems operational";
    if (!states.length) { cls = "s-none"; text = "No data yet"; }
    else if (down === states.length) { cls = "s-down"; text = "Major outage"; }
    else if (down) { cls = "s-down"; text = "Partial outage"; }
    else if (states.indexOf("pending") !== -1) { cls = "s-pending"; text = "Degraded performance"; }
    else if (states.indexOf("maint") !== -1) { cls = "s-maint"; text = "Under maintenance"; }
    allStatus.forEach(function (c) { box.classList.remove(c); });
    box.classList.add(cls);
    box.querySelector(".overall-label").textContent = text;
  }

  var es = new EventSource(source);
  es.onmessage = function (msg) {
    var ev;
    try { ev = JSON.parse(msg.data); } catch (e) { return; }
    document.querySelectorAll('[data-monitor="' + ev.monitor_id + '"]').forEach(function (row) {
      var st = row.querySelector("[data-role=status]");
      if (st) setStatus(st, ev.status);
      var lat = row.querySelector("[data-role=latency]");
      if (lat) lat.textContent = ev.latency;
      var strip = row.querySelector("[data-role=beats]");
      if (strip) pushBeat(strip, ev);
    });
    document.querySelectorAll('[data-monitor-beats="' + ev.monitor_id + '"]').forEach(function (s) { pushBeat(s, ev); });
    updateOverall();
  };
})();
