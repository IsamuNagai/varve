(function () {
  "use strict";
  var root = document.documentElement;
  root.classList.add("js");

  var hasMedia = typeof window.matchMedia === "function";
  var darkQuery = hasMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;
  var reduceMotion = hasMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* Theme toggle */
  function activeTheme() {
    var t = root.dataset.theme;
    if (t === "light" || t === "dark") { return t; }
    return darkQuery && darkQuery.matches ? "dark" : "light";
  }

  function syncButtons() {
    var dark = activeTheme() === "dark";
    var buttons = document.querySelectorAll(".theme-toggle");
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].setAttribute("aria-pressed", dark ? "true" : "false");
      buttons[i].setAttribute("aria-label", dark ? "Switch to light mode" : "Switch to dark mode");
    }
  }

  function onToggle() {
    var next = activeTheme() === "dark" ? "light" : "dark";
    root.dataset.theme = next;
    try {
      localStorage.setItem("varve-theme", next);
    } catch (e) {
      /* storage unavailable: the choice applies to this page only */
    }
    syncButtons();
  }

  var toggles = document.querySelectorAll(".theme-toggle");
  for (var i = 0; i < toggles.length; i++) {
    toggles[i].addEventListener("click", onToggle);
  }
  if (darkQuery && darkQuery.addEventListener) {
    darkQuery.addEventListener("change", syncButtons);
  }
  syncButtons();

  /* Scroll reveal */
  var items = document.querySelectorAll(".reveal");
  var groups = document.querySelectorAll(".stagger");
  for (var g = 0; g < groups.length; g++) {
    var kids = groups[g].querySelectorAll(":scope > .reveal");
    for (var k = 0; k < kids.length; k++) {
      kids[k].classList.add("d" + Math.min(k, 5));
    }
  }

  function show(el) {
    el.classList.add("is-visible");
    window.setTimeout(function () {
      el.classList.remove("d0", "d1", "d2", "d3", "d4", "d5");
      el.classList.add("is-done");
    }, 1400);
  }

  if (reduceMotion || !("IntersectionObserver" in window)) {
    for (var r = 0; r < items.length; r++) { items[r].classList.add("is-visible", "is-done"); }
  } else {
    var io = new IntersectionObserver(function (entries) {
      for (var n = 0; n < entries.length; n++) {
        if (entries[n].isIntersecting) {
          show(entries[n].target);
          io.unobserve(entries[n].target);
        }
      }
    }, { threshold: 0.15, rootMargin: "0px 0px -4% 0px" });
    for (var m = 0; m < items.length; m++) { io.observe(items[m]); }
  }

  /* Header state on scroll */
  var header = document.querySelector(".site-header");
  if (header) {
    var ticking = false;
    var update = function () {
      header.classList.toggle("is-scrolled", window.scrollY > 8);
      ticking = false;
    };
    window.addEventListener("scroll", function () {
      if (!ticking) {
        ticking = true;
        window.requestAnimationFrame(update);
      }
    }, { passive: true });
    update();
  }
})();
