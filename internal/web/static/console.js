// Tule console: the little the pages need beyond htmx. Every page works
// without it; it asks before destructive actions and gives search a key.
(function () {
  "use strict";

  // A form with data-confirm asks before it is sent.
  document.addEventListener("submit", function (e) {
    var message = e.target.getAttribute("data-confirm");
    if (message && !window.confirm(message)) {
      e.preventDefault();
      e.stopImmediatePropagation();
    }
  }, true);

  // "/" moves to the page's search field, as in most consoles.
  document.addEventListener("keydown", function (e) {
    if (e.key !== "/" || e.ctrlKey || e.metaKey || e.altKey) {
      return;
    }
    var t = e.target;
    if (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName)) {
      return;
    }
    var search = document.querySelector("[data-search]");
    if (search) {
      e.preventDefault();
      search.focus();
    }
  });
})();
