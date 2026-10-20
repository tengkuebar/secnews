/* Light/dark toggle. Loaded in <head> so the saved choice is applied before the page paints. */
(function () {
  var root = document.documentElement, KEY = "secnews-theme";
  function saved() { try { return localStorage.getItem(KEY); } catch (e) { return null; } }
  function current() {
    return root.getAttribute("data-theme") ||
      (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  }
  var s = saved();
  if (s === "light" || s === "dark") root.setAttribute("data-theme", s);

  document.addEventListener("DOMContentLoaded", function () {
    var btn = document.getElementById("theme-toggle");
    if (!btn) return;
    function label() {
      var dark = current() === "dark";
      btn.querySelector(".lbl").textContent = dark ? "Light mode" : "Dark mode";
      btn.classList.toggle("lit", !dark);   // the bulb is lit while the page is light
      btn.setAttribute("aria-label", dark ? "Switch to light mode" : "Switch to dark mode");
    }
    label();
    btn.hidden = false;   // without JavaScript the button stays hidden, and the system setting applies
    btn.addEventListener("click", function () {
      var next = current() === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      try { localStorage.setItem(KEY, next); } catch (e) { /* private window: applies until reload */ }
      label();
    });
  });
})();
