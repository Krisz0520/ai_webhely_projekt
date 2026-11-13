/* Runs before first paint: applies the saved theme (if any) and enables JS-only styles. */
(function () {
  var root = document.documentElement;
  root.classList.add('js');
  try {
    var m = localStorage.getItem('theme');
    if (m === 'light' || m === 'dark') root.setAttribute('data-theme', m);
  } catch (e) { /* storage blocked: stay on automatic */ }
})();
