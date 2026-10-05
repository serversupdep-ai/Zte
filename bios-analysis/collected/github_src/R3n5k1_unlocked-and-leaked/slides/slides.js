// Keyboard nav for the slide deck.
// Each slide page has <a class="prev"> and/or <a class="next"> in its footer;
// arrow keys / space / pgup-pgdn click them. F toggles fullscreen.

document.addEventListener('keydown', (e) => {
  // Ignore typing into inputs (in case any slide has one)
  if (['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName)) return;

  switch (e.key) {
    case 'ArrowRight':
    case 'PageDown':
    case ' ':
    case 'n':
    case 'N': {
      const next = document.querySelector('a.next');
      if (next && !next.classList.contains('disabled')) {
        e.preventDefault();
        window.location.href = next.href;
      }
      break;
    }
    case 'ArrowLeft':
    case 'PageUp':
    case 'p':
    case 'P': {
      const prev = document.querySelector('a.prev');
      if (prev && !prev.classList.contains('disabled')) {
        e.preventDefault();
        window.location.href = prev.href;
      }
      break;
    }
    case 'Home': {
      const home = document.querySelector('a.home');
      if (home) { e.preventDefault(); window.location.href = home.href; }
      break;
    }
    case 'f':
    case 'F': {
      e.preventDefault();
      if (document.fullscreenElement) {
        document.exitFullscreen();
      } else {
        document.documentElement.requestFullscreen().catch(() => {});
      }
      break;
    }
  }
});

// ---- Palette + zoom controls -----------------------------------------------
// "t" cycles palettes (Shift+T reverses). "+/-" change presentation zoom, "0"
// resets. Both persist across slides via localStorage and ride the prev/next/
// home links as a "#theme,scale" hash, so they survive even on file:// setups
// where localStorage may be blocked. The inline <head> script applies both
// before paint (no flash). Ctrl/Cmd are left alone so native browser zoom works.
(function () {
  const THEMES = ['amber', 'bright', 'mono', 'light'];
  const LABELS = {
    amber:  'AMBER · CRT',
    bright: 'AMBER · HIGH CONTRAST',
    mono:   'WHITE ON BLACK',
    light:  'BLACK ON WHITE',
  };
  const BASE = 16, ZMIN = 0.8, ZMAX = 4, ZSTEP = 0.1;

  function curTheme() {
    const t = document.documentElement.getAttribute('data-theme');
    return THEMES.indexOf(t) >= 0 ? t : 'amber';
  }
  function curScale() {
    const z = parseFloat(document.documentElement.style.fontSize) / BASE;
    return (z && isFinite(z)) ? z : 1;
  }
  function clampZ(z) { return Math.min(ZMAX, Math.max(ZMIN, Math.round(z * 10) / 10)); }

  let toast;
  function showToast(msg) {
    if (!toast) {
      toast = document.createElement('div');
      toast.className = 'theme-toast';
      document.body.appendChild(toast);
    }
    toast.textContent = msg;
    toast.classList.add('show');
    clearTimeout(showToast._t);
    showToast._t = setTimeout(() => toast.classList.remove('show'), 1300);
  }

  // Carry current state on the nav links so click-navigation persists it too.
  function carryHrefs() {
    const frag = '#' + curTheme() + ',' + curScale();
    document.querySelectorAll('a.prev, a.next, a.home').forEach((a) => {
      a.href = a.href.split('#')[0] + frag;
    });
  }
  function persist() {
    try {
      localStorage.setItem('deckTheme', curTheme());
      localStorage.setItem('deckScale', String(curScale()));
    } catch (e) {}
    try {
      history.replaceState(null, '', location.pathname.split('#')[0] + '#' + curTheme() + ',' + curScale());
    } catch (e) {}
    carryHrefs();
  }

  function setTheme(t) {
    document.documentElement.setAttribute('data-theme', t);
    persist();
    showToast(LABELS[t] || t);
  }
  function cycleTheme(dir) {
    let i = THEMES.indexOf(curTheme());
    i = (i + dir + THEMES.length) % THEMES.length;
    setTheme(THEMES[i]);
  }
  function setScale(z) {
    z = clampZ(z);
    document.documentElement.style.fontSize = (BASE * z) + 'px';
    document.documentElement.style.setProperty('--zoom', z);  // images scale via calc(<vh> * var(--zoom))
    persist();
    showToast('ZOOM ' + Math.round(z * 100) + '%');
  }

  // On load the <head> script has already applied theme + zoom; just make the
  // nav links carry the state forward.
  carryHrefs();

  document.addEventListener('keydown', (e) => {
    if (['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName)) return;
    if (e.ctrlKey || e.metaKey || e.altKey) return;  // leave native browser zoom alone
    switch (e.key) {
      case 't': e.preventDefault(); cycleTheme(1); break;
      case 'T': e.preventDefault(); cycleTheme(-1); break;
      case '=': case '+': e.preventDefault(); setScale(curScale() + ZSTEP); break;
      case '-': case '_': e.preventDefault(); setScale(curScale() - ZSTEP); break;
      case '0': e.preventDefault(); setScale(1); break;
    }
  });
})();
