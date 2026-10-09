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
  // Fields follow the chosen type (data-kinds) and other selects (data-when="name:value value").
  // Anything hidden is disabled so it is not submitted.
  document.querySelectorAll("form[data-kind-form]").forEach(function (form) {
    var kind = form.querySelector("[data-kind-select]");
    var valueOf = function (name) { var el = form.querySelector('[name="' + name + '"]'); return el ? el.value : ""; };
    var summary = form.querySelector("[data-rule-summary]");
    var describe = function () {
      if (!summary) return;
      var k = kind.value, rule = valueOf("content_kind"), v = valueOf("content_value").trim(), eq = valueOf("content_expected").trim();
      if (k !== "http" && k !== "websocket") { summary.textContent = ""; return; }
      var parts = [];
      if (k === "http") parts.push("the status is " + (valueOf("expected_status").trim() || "200-299"));
      else parts.push("the WebSocket handshake succeeds");
      var q = function (t) { return "\u201c" + (t || "\u2026") + "\u201d"; };
      var what = k === "http" ? "the body" : "the first reply";
      if (rule === "contains") parts.push(what + " contains " + q(v));
      if (rule === "not_contains") parts.push(what + " does not contain " + q(v));
      if (rule === "regex") parts.push(what + " matches /" + (v || "\u2026") + "/");
      if (rule === "json_path") parts.push("JSON " + (v || "$.\u2026") + (eq ? " equals " + q(eq) : " exists"));
      summary.textContent = "Up when " + parts.join(" and ") + ".";
    };
    var apply = function () {
      form.querySelectorAll("[data-kinds]").forEach(function (el) {
        el.hidden = el.dataset.kinds.split(" ").indexOf(kind.value) === -1;
      });
      form.querySelectorAll("[data-when]").forEach(function (el) {
        var parts = el.dataset.when.split(":");
        el.hidden = parts[1].split(" ").indexOf(valueOf(parts[0])) === -1;
      });
      form.querySelectorAll("input, select, textarea").forEach(function (i) {
        if (i.type !== "hidden") i.disabled = !!i.closest("[hidden]");
      });
      describe();
    };
    form.addEventListener("change", apply);
    form.addEventListener("input", describe);
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

  // "Run check now": runs the unsaved form through the real checker.
  document.querySelectorAll("[data-run-check]").forEach(function (btn) {
    var form = btn.closest("form");
    var box = document.getElementById("test-result");
    btn.addEventListener("click", function () {
      var esc = function (v) { var d = document.createElement("div"); d.textContent = v == null ? "" : String(v); return d.innerHTML; };
      btn.disabled = true;
      box.hidden = false;
      box.className = "test-result";
      box.textContent = "Running…";
      fetch("/admin/monitors/test", { method: "POST", body: new URLSearchParams(new FormData(form)), credentials: "same-origin" })
        .then(function (r) { return r.json(); })
        .then(function (res) {
          if (res.error) { box.className = "test-result bad"; box.innerHTML = "<strong>Not run:</strong> " + esc(res.error); return; }
          var html = '<p class="test-head"><span class="status ' + (res.ok ? "s-up" : "s-down") + '"><span class="dot"></span>' + (res.ok ? "Would be up" : "Would fail") + "</span> " + esc(res.message) + "</p>";
          var facts = [];
          if (res.status_code) facts.push("Status " + esc(res.status_code));
          if (res.remote_ip) facts.push("IP " + esc(res.remote_ip));
          (res.timings || []).forEach(function (t) { facts.push(esc(t[0]) + " " + esc(t[1])); });
          if (res.cert) facts.push("Certificate " + esc(res.cert));
          if (facts.length) html += '<p class="muted">' + facts.join(" · ") + "</p>";
          if (res.preview) html += "<pre>" + esc(res.preview) + "</pre>";
          box.className = "test-result " + (res.ok ? "good" : "bad");
          box.innerHTML = html;
        })
        .catch(function () { box.className = "test-result bad"; box.textContent = "Request failed."; })
        .then(function () { btn.disabled = false; });
    });
  });

  document.querySelectorAll("[data-sso-test]").forEach(function (btn) {
    var form = btn.closest("form");
    var box = document.getElementById("sso-result");
    btn.addEventListener("click", function () {
      btn.disabled = true;
      box.hidden = false;
      box.className = "test-result";
      box.textContent = "Contacting the identity provider…";
      fetch("/admin/sso/test", { method: "POST", body: new URLSearchParams(new FormData(form)), credentials: "same-origin" })
        .then(function (r) { return r.json(); })
        .then(function (res) {
          box.className = "test-result " + (res.ok ? "good" : "bad");
          box.textContent = res.message;
        })
        .catch(function () { box.className = "test-result bad"; box.textContent = "Request failed."; })
        .then(function () { btn.disabled = false; });
    });
  });

  document.querySelectorAll("[data-show]").forEach(function (b) {
    b.addEventListener("click", function () {
      var el = document.getElementById(b.dataset.show);
      if (!el) return;
      el.hidden = false;
      var input = el.querySelector("input:not([type=hidden])");
      if (input) input.focus();
    });
  });
  document.querySelectorAll("[data-hide]").forEach(function (b) {
    b.addEventListener("click", function () {
      var el = document.getElementById(b.dataset.hide);
      if (el) el.hidden = true;
    });
  });

  // Rows are not links so dragging them never drags a URL; they open on click instead.
  document.querySelectorAll(".monitor-row[data-href]").forEach(function (row) {
    var open = function (newTab) {
      if (newTab) window.open(row.dataset.href, "_blank");
      else window.location.href = row.dataset.href;
    };
    row.addEventListener("click", function (e) {
      if (e.target.closest("button, a, input, label")) return;
      open(e.ctrlKey || e.metaKey);
    });
    row.addEventListener("auxclick", function (e) { if (e.button === 1) open(true); });
    row.addEventListener("keydown", function (e) { if (e.key === "Enter") open(e.ctrlKey || e.metaKey); });
  });

  // Bulk actions: ticking a parent ticks its sub-monitors too.
  var bulk = document.querySelector("form[data-bulk]");
  if (bulk) {
    var picks = function () { return Array.prototype.slice.call(document.querySelectorAll("[data-pick]")); };
    var all = bulk.querySelector("[data-pick-all]");
    var count = bulk.querySelector("[data-bulk-count]");
    var actions = bulk.querySelector("[data-bulk-actions]");
    var sync = function () {
      var list = picks(), n = list.filter(function (p) { return p.checked; }).length;
      all.checked = n > 0 && n === list.length;
      all.indeterminate = n > 0 && n < list.length;
      count.textContent = n ? n + " selected" : "Select all";
      actions.hidden = n === 0;
      list.forEach(function (p) { p.closest(".monitor-row").classList.toggle("picked", p.checked); });
    };
    all.addEventListener("change", function () {
      picks().forEach(function (p) { p.checked = all.checked; });
      sync();
    });
    document.addEventListener("change", function (e) {
      if (!e.target.matches || !e.target.matches("[data-pick]")) return;
      var row = e.target.closest(".monitor-row");
      if (row.hasAttribute("data-has-children")) {
        document.querySelectorAll('[data-parent="' + row.dataset.monitor + '"] [data-pick]').forEach(function (c) { c.checked = e.target.checked; });
      }
      sync();
    });
    bulk.addEventListener("submit", function (e) {
      if (!e.submitter || e.submitter.value !== "delete") return;
      var n = picks().filter(function (p) { return p.checked; }).length;
      if (!window.confirm("Delete " + n + " monitor" + (n === 1 ? "" : "s") + " with all their history?")) e.preventDefault();
    });
    sync();
  }

  // Drag monitors onto a group to move them, or onto another monitor to nest them.
  var dragList = document.querySelector("[data-drag-list]");
  if (dragList) {
    var dragged = null;
    var errorBox = document.querySelector(".drop-error");
    var clearOver = function () {
      dragList.querySelectorAll(".drop-over").forEach(function (el) { el.classList.remove("drop-over"); });
    };
    var targetFor = function (el) {
      if (!dragged) return null;
      var group = el.closest(".drop-group");
      if (group) return { el: group, group: group.dataset.groupId, parent: "" };
      var row = el.closest(".monitor-row");
      if (row && row.dataset.parent) row = dragList.querySelector('.monitor-row[data-monitor="' + row.dataset.parent + '"]');
      if (!row || row === dragged || dragged.hasAttribute("data-has-children")) return null;
      if (dragged.dataset.parent === row.dataset.monitor) return null;
      return { el: row, group: "", parent: row.dataset.monitor };
    };
    dragList.addEventListener("dragstart", function (e) {
      var row = e.target.closest && e.target.closest(".monitor-row");
      if (!row) return;
      dragged = row;
      e.dataTransfer.effectAllowed = "move";
      e.dataTransfer.setData("text/plain", row.dataset.name || "");
      document.body.classList.add("dragging");
      row.classList.add("is-dragged");
    });
    dragList.addEventListener("dragend", function () {
      document.body.classList.remove("dragging");
      if (dragged) dragged.classList.remove("is-dragged");
      dragged = null;
      clearOver();
    });
    dragList.addEventListener("dragover", function (e) {
      var t = targetFor(e.target);
      clearOver();
      if (!t) return;
      e.preventDefault();
      e.dataTransfer.dropEffect = "move";
      t.el.classList.add("drop-over");
    });
    dragList.addEventListener("drop", function (e) {
      var t = targetFor(e.target);
      if (!t) return;
      e.preventDefault();
      var body = new URLSearchParams({ csrf: document.body.dataset.csrf, group_id: t.group, parent_id: t.parent });
      fetch("/admin/monitors/" + dragged.dataset.monitor + "/move", { method: "POST", body: body, credentials: "same-origin" })
        .then(function (r) { return r.json().catch(function () { return { ok: false, error: "Move failed (" + r.status + ")" }; }); })
        .then(function (res) {
          if (res.ok) { window.location.reload(); return; }
          if (errorBox) { errorBox.textContent = res.error; errorBox.hidden = false; }
        });
    });
  }

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
