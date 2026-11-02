/* Offline startup gate. No payload or exploit logic is executed here. */
(function () {
  window.startWithOfflineCache = function (start) {
    var box = document.getElementById("cache-status");
    if (!box) {
      box = document.createElement("div");
      box.id = "cache-status";
      box.style.cssText = "position:fixed;top:0;left:0;right:0;z-index:10000;padding:14px;background:#11151b;color:#e6ebf2;font:16px sans-serif";
      document.body.appendChild(box);
    }
    var cache = window.applicationCache;
    var finished = false;
    var timer;
    function message(text) { box.textContent = text; }
    function launch(text) {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      message(text);
      box.style.display = "none";
      start();
    }
    function reloadUpdated() {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      message("Cache updated. Opening the new offline snapshot...");
      // No application modules have started, so switching snapshots is safe here.
      try { cache.swapCache(); } catch (error) {}
      location.reload();
    }
    function failed() {
      if (finished) return;
      if (cache.status === cache.UPDATEREADY) return reloadUpdated();
      if (cache.status === cache.IDLE) return launch("Using the saved offline cache.");
      message("Could not save offline files. Reconnect and reload; offline cache is not ready.");
    }
    if (!cache || !document.documentElement.hasAttribute("manifest")) {
      message("Offline cache is unsupported by this browser. Opening online.");
      launch("Opening online.");
      return;
    }
    cache.addEventListener("checking", function () { if (!finished) message("Checking offline cache..."); });
    cache.addEventListener("downloading", function () { if (!finished) message("Saving files for offline use..."); });
    cache.addEventListener("progress", function (event) {
      if (!finished && event.lengthComputable && event.total) {
        message("Saving offline cache: " + Math.round(event.loaded / event.total * 100) + "%");
      }
    });
    cache.addEventListener("cached", function () { launch("Offline cache saved."); });
    cache.addEventListener("noupdate", function () { launch("Offline cache ready."); });
    cache.addEventListener("updateready", reloadUpdated);
    cache.addEventListener("error", failed);
    cache.addEventListener("obsolete", function () {
      if (!finished) message("Offline cache is obsolete. Reconnect and reload.");
    });
    if (cache.status === cache.UPDATEREADY) return reloadUpdated();
    if (navigator.onLine === false && cache.status === cache.IDLE) {
      launch("Offline: starting the saved snapshot.");
      return;
    }
    message("Checking and saving offline files...");
    // IDLE may mean the automatic check already finished before this script loaded.
    // Explicitly request an update so an online visit never skips the check.
    if (cache.status === cache.IDLE) {
      try { cache.update(); } catch (error) {}
    }
    timer = setTimeout(function () {
      if (finished) return;
      if (cache.status === cache.IDLE) launch("Using the saved offline cache.");
      else if (cache.status === cache.UPDATEREADY) reloadUpdated();
      else if (cache.status === cache.UNCACHED) failed();
      // Downloads remain active; do not launch while a new snapshot is incomplete.
    }, 30000);
  };
})();
