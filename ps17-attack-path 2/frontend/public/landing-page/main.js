(function () {
  "use strict";

  /* ---------- Mobile menu ---------- */

  var burger = document.getElementById("burger");
  var overlay = document.getElementById("menu-overlay");
  var body = document.body;

  function openMenu() {
    burger.setAttribute("aria-expanded", "true");
    overlay.hidden = false;
    body.classList.add("menu-open");
  }

  function closeMenu() {
    burger.setAttribute("aria-expanded", "false");
    overlay.hidden = true;
    body.classList.remove("menu-open");
  }

  function isMenuOpen() {
    return burger.getAttribute("aria-expanded") === "true";
  }

  burger.addEventListener("click", function () {
    isMenuOpen() ? closeMenu() : openMenu();
  });

  overlay.addEventListener("click", function (e) {
    if (e.target === overlay) closeMenu();
  });

  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && isMenuOpen()) closeMenu();
  });

  overlay.querySelectorAll(".menu-link").forEach(function (link) {
    link.addEventListener("click", closeMenu);
  });

  window.addEventListener("resize", function () {
    if (window.innerWidth > 720 && isMenuOpen()) closeMenu();
  });

  /* ---------- Count-up stats ---------- */

  function easeOutCubic(t) {
    return 1 - Math.pow(1 - t, 3);
  }

  function formatValue(value, decimals, suffix) {
    return value.toFixed(decimals) + suffix;
  }

  function animateStat(el, index) {
    var target = parseFloat(el.dataset.target);
    var decimals = parseInt(el.dataset.decimals, 10) || 0;
    var suffix = el.dataset.suffix || "";
    var numEl = el.querySelector(".num");
    var startOffset = 480 + index * 90;
    var duration = 1500 + index * 80;

    setTimeout(function () {
      var startTime = null;

      function step(timestamp) {
        if (startTime === null) startTime = timestamp;
        var elapsed = timestamp - startTime;
        var progress = Math.min(elapsed / duration, 1);
        var eased = easeOutCubic(progress);
        var current = target * eased;
        numEl.textContent = formatValue(current, decimals, suffix);

        if (progress < 1) {
          requestAnimationFrame(step);
        } else {
          numEl.textContent = formatValue(target, decimals, suffix);
        }
      }
      requestAnimationFrame(step);
    }, startOffset);
  }

  var statsEls = document.querySelectorAll(".stat");
  var hasAnimated = false;

  if ("IntersectionObserver" in window) {
    var observer = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting && !hasAnimated) {
            hasAnimated = true;
            statsEls.forEach(function (el, i) {
              animateStat(el, i);
            });
            observer.disconnect();
          }
        });
      },
      { threshold: 0.25 }
    );

    if (statsEls.length) {
      observer.observe(statsEls[0].parentElement);
    }
  } else {
    // Fallback: animate immediately if IntersectionObserver isn't supported.
    statsEls.forEach(function (el, i) {
      animateStat(el, i);
    });
  }
})();
