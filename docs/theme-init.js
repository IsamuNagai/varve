(function () {
  try {
    var t = localStorage.getItem("varve-theme");
    if (t === "light" || t === "dark") {
      document.documentElement.dataset.theme = t;
    }
  } catch (e) {
    /* storage unavailable: follow the OS setting */
  }
})();
