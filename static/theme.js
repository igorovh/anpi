(function () {
  var root = document.documentElement;
  var t = null;
  try { t = localStorage.getItem("anpi-theme"); } catch (e) {}
  if (t !== "light" && t !== "dark") {
    t = root.dataset.defaultTheme;
  }
  if (t !== "light" && t !== "dark") {
    t = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }
  root.dataset.theme = t;
})();
