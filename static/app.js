(function () {
  "use strict";
  var html = document.documentElement;

  var toggle = document.getElementById("theme-toggle");
  if (toggle) {
    toggle.addEventListener("click", function () {
      html.dataset.theme = html.dataset.theme === "dark" ? "light" : "dark";
      try { localStorage.setItem("anpi-theme", html.dataset.theme); } catch (e) {}
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

  // Collapsible sub-monitors; the choice is remembered per parent.
  var COLLAPSE_KEY = "anpi-collapsed";
  var collapsedIds = {};
  try { collapsedIds = JSON.parse(localStorage.getItem(COLLAPSE_KEY) || "{}"); } catch (e) {}
  function applyCollapse(id) {
    var shut = !!collapsedIds[id];
    document.querySelectorAll('[data-parent="' + id + '"]').forEach(function (c) { c.hidden = shut; });
    document.querySelectorAll('[data-toggle="' + id + '"]').forEach(function (b) {
      b.classList.toggle("open", !shut);
      b.setAttribute("aria-expanded", String(!shut));
    });
  }
  document.querySelectorAll("[data-toggle]").forEach(function (b) {
    applyCollapse(b.dataset.toggle);
    b.addEventListener("click", function (e) {
      e.preventDefault();
      e.stopPropagation();
      collapsedIds[b.dataset.toggle] = !collapsedIds[b.dataset.toggle];
      try { localStorage.setItem(COLLAPSE_KEY, JSON.stringify(collapsedIds)); } catch (err) {}
      applyCollapse(b.dataset.toggle);
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

  var severity = { up: 0, maintenance: 1, pending: 2, down: 3 };
  function statusFromClass(el) {
    if (el.classList.contains("s-down")) return "down";
    if (el.classList.contains("s-pending")) return "pending";
    if (el.classList.contains("s-maint")) return "maintenance";
    if (el.classList.contains("s-up")) return "up";
    return null;
  }

  // A parent row shows the worst of its own status (unless it is an aggregate) and its children.
  function recomputeParent(row) {
    var states = [];
    if (row.dataset.aggregate === "false" && row.dataset.own) states.push(row.dataset.own);
    document.querySelectorAll('[data-parent="' + row.dataset.monitor + '"] [data-role=status]').forEach(function (s) {
      var v = statusFromClass(s);
      if (v) states.push(v);
    });
    if (!states.length) return;
    var worst = states.reduce(function (a, b) { return severity[b] > severity[a] ? b : a; });
    var st = row.querySelector("[data-role=status]");
    if (st) setStatus(st, worst);
  }

  function updateOverall() {
    var box = document.getElementById("overall");
    if (!box) return;
    var states = [];
    document.querySelectorAll("[data-monitor]:not([data-parent]) [data-role=status]").forEach(function (s) {
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
      if (row.dataset.aggregate !== undefined) {
        row.dataset.own = ev.status;
        recomputeParent(row);
      } else if (st) {
        setStatus(st, ev.status);
      }
      var lat = row.querySelector("[data-role=latency]");
      if (lat) lat.textContent = ev.latency;
      var strip = row.querySelector("[data-role=beats]");
      if (strip) pushBeat(strip, ev);
    });
    document.querySelectorAll('[data-monitor-beats="' + ev.monitor_id + '"]').forEach(function (s) { pushBeat(s, ev); });
    var child = document.querySelector('[data-monitor="' + ev.monitor_id + '"][data-parent]');
    if (child) {
      var parent = document.querySelector('[data-monitor="' + child.dataset.parent + '"][data-aggregate]');
      if (parent) recomputeParent(parent);
    }
    updateOverall();
  };
})();
