/* Shared client code: theme, language, menu, reveal animations and every interactive widget.
   No inline scripts or styles are used anywhere (strict CSP), and user data is only ever
   inserted with textContent, never as HTML. */
(() => {
  'use strict';

  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const dictEl = $('#dict');
  const T = dictEl ? JSON.parse(dictEl.textContent) : {};
  const lang = document.documentElement.lang || 'en';
  const t = (k, v) => {
    let s = T[k] !== undefined ? T[k] : k;
    if (v) for (const key of Object.keys(v)) s = s.split('{' + key + '}').join(String(v[key]));
    return s;
  };
  const list = (k) => t(k).split('|');
  const metaCsrf = $('meta[name="csrf-token"]');
  const csrf = metaCsrf ? metaCsrf.content : '';
  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const pick = (a) => a[Math.floor(Math.random() * a.length)];
  const shuffle = (a) => { const r = a.slice(); for (let i = r.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [r[i], r[j]] = [r[j], r[i]]; } return r; };

  function h(tag, attrs, ...kids) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === 'class') e.className = v;
      else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
      else if (v === true) e.setAttribute(k, '');
      else if (v !== false && v != null) e.setAttribute(k, v);
    }
    for (const kid of kids.flat()) if (kid != null) e.append(kid.nodeType ? kid : document.createTextNode(kid));
    return e;
  }

  async function api(method, url, body) {
    const r = await fetch(url, {
      method, credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
      body: body ? JSON.stringify(body) : undefined,
    });
    let data = {};
    try { data = await r.json(); } catch { /* empty body */ }
    if (r.status === 401 && data.error === 'unauthenticated' && !location.pathname.startsWith('/login')) location.href = '/login';
    return { ok: r.ok, status: r.status, data };
  }
  const errText = (res) => t('err.' + (res.data.error || 'server_error'), { s: res.data.retry || 0 });
  let mePromise = null;
  const loadMe = () => (mePromise = mePromise || api('GET', '/api/me').then((r) => r.data));

  const fmtDate = (ts) => ts ? new Intl.DateTimeFormat(lang === 'hu' ? 'hu-HU' : 'en-GB', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(ts)) : '–';

  const RING = 2 * Math.PI * 52;
  function setRing(el, pct) {
    if (!el) return;
    el.style.strokeDasharray = String(RING);
    el.style.strokeDashoffset = String(RING * (1 - pct / 100));
  }

  /* ---------------------------------------------------------- theme / lang / menu */
  const modes = ['auto', 'light', 'dark'];
  const getMode = () => { try { const m = localStorage.getItem('theme'); return modes.includes(m) ? m : 'auto'; } catch { return 'auto'; } };
  const themeBtn = $('#theme-btn');
  function paintTheme() {
    const m = getMode();
    themeBtn.setAttribute('aria-label', t('theme.' + m));
    themeBtn.title = t('theme.' + m);
    $('use', themeBtn).setAttribute('href', '#i-' + { auto: 'auto', light: 'sun', dark: 'moon' }[m]);
  }
  if (themeBtn) {
    paintTheme();
    themeBtn.addEventListener('click', () => {
      const m = modes[(modes.indexOf(getMode()) + 1) % modes.length];
      try { if (m === 'auto') localStorage.removeItem('theme'); else localStorage.setItem('theme', m); } catch { /* ignore */ }
      if (m === 'auto') document.documentElement.removeAttribute('data-theme'); else document.documentElement.setAttribute('data-theme', m);
      paintTheme();
    });
  }

  const langBtn = $('#lang-btn');
  if (langBtn) {
    langBtn.addEventListener('click', () => {
      const next = lang === 'hu' ? 'en' : 'hu';
      document.cookie = `lang=${next}; Path=/; Max-Age=31536000; SameSite=Lax${location.protocol === 'https:' ? '; Secure' : ''}`;
      location.reload();
    });
  }

  const menuBtn = $('#menu-btn');
  const nav = $('#nav');
  if (menuBtn && nav) {
    menuBtn.addEventListener('click', () => {
      const open = nav.classList.toggle('open');
      menuBtn.setAttribute('aria-expanded', String(open));
    });
  }

  const logoutBtn = $('#logout-btn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
      await api('POST', '/api/logout');
      location.href = '/login';
    });
  }

  /* ---------------------------------------------------------------- reveal motion */
  function onReveal(el) {
    el.classList.add('in');
    $$('mark', el).forEach((m, i) => setTimeout(() => m.classList.add('in'), 300 + i * 220));
    $$('[data-w]', el).forEach((b) => { b.style.width = b.dataset.w + '%'; });
    $$('.tw[data-type]', el).forEach(typewrite);
  }
  const revealEls = $$('.reveal');
  if (reduce || !('IntersectionObserver' in window)) {
    revealEls.forEach(onReveal);
    $$('mark').forEach((m) => m.classList.add('in'));
  } else {
    const io = new IntersectionObserver((entries) => {
      for (const e of entries) if (e.isIntersecting) { onReveal(e.target); io.unobserve(e.target); }
    }, { threshold: 0.12 });
    revealEls.forEach((el, i) => { el.style.setProperty('--d', (i % 3) * 70 + 'ms'); io.observe(el); });
  }
  $$('.page-head mark, .hero mark').forEach((m) => m.classList.add('in'));

  function typewrite(el) {
    const text = el.dataset.type;
    if (!text || el.dataset.done) return;
    el.dataset.done = '1';
    if (reduce) return;
    el.textContent = '';
    let i = 0;
    const timer = setInterval(() => {
      el.textContent = text.slice(0, ++i);
      if (i >= text.length) clearInterval(timer);
    }, 55);
  }

  /* ------------------------------------------------------------ home: generator */
  const genOut = $('#gen-out');
  if (genOut) {
    const A = list('gen.a'), B = list('gen.b'), C = list('gen.c'), D = list('gen.d');
    let timer = null;
    $('#gen-btn').addEventListener('click', () => {
      const s = t('gen.tpl', { a: pick(A), b: pick(B), c: pick(C), d: pick(D) });
      clearInterval(timer);
      if (reduce) { genOut.textContent = s; return; }
      genOut.textContent = '';
      genOut.classList.add('typing');
      let i = 0;
      timer = setInterval(() => {
        genOut.textContent = s.slice(0, ++i);
        if (i >= s.length) { clearInterval(timer); genOut.classList.remove('typing'); }
      }, 22);
    });
    $('#gen-copy').addEventListener('click', async (e) => {
      const btn = e.currentTarget;
      const old = btn.textContent;
      try {
        await navigator.clipboard.writeText(genOut.textContent);
        btn.textContent = t('gen.copied');
        setTimeout(() => { btn.textContent = old; }, 1400);
      } catch { /* clipboard unavailable */ }
    });
  }

  /* --------------------------------------------------------- home: progress card */
  const pQuiz = $('#p-quiz');
  if (pQuiz) {
    setRing($('#p-ring'), 0);
    loadMe().then((me) => {
      if (!me || !me.progress) return;
      pQuiz.textContent = me.progress.quizBest ? t('quiz.score', { s: me.progress.quizBest, total: 8 }) : t('prog.none');
      const c = me.progress.checklist || [];
      const pct = Math.round((c.filter(Boolean).length / 6) * 100);
      $('#p-def').textContent = pct + '%';
      setTimeout(() => setRing($('#p-ring'), pct), 150);
    });
  }

  /* ------------------------------------------------------ frankfurt: role lab */
  const care = $('#care');
  if (care) {
    const truthful = $('#truthful'), out = $('#care-out'), role = $('#role');
    let last = '';
    const update = () => {
      const v = Number(care.value);
      care.style.setProperty('--p', v + '%');
      out.textContent = v + '%';
      truthful.disabled = v < 25;
      const k = v < 25 ? 'bs' : (truthful.checked ? 'honest' : 'liar');
      $('#role-t').textContent = t(`ff.role.${k}.t`);
      $('#role-d').textContent = t(`ff.role.${k}.d`);
      role.dataset.k = k;
      if (k !== last && !reduce) { role.classList.remove('swap'); void role.offsetWidth; role.classList.add('swap'); }
      last = k;
    };
    care.addEventListener('input', update);
    truthful.addEventListener('change', update);
    update();
  }

  /* ------------------------------------------------------------- types: filter */
  const chips = $$('.chip[data-f]');
  if (chips.length) {
    chips.forEach((chip) => chip.addEventListener('click', () => {
      chips.forEach((c) => c.setAttribute('aria-pressed', String(c === chip)));
      const f = chip.dataset.f;
      $$('.type-card').forEach((card) => {
        const show = f === 'all' || card.dataset.level === f;
        card.hidden = !show;
        if (show && !reduce) { card.classList.remove('pop'); void card.offsetWidth; card.classList.add('pop'); }
      });
    }));
  }

  /* ---------------------------------------------------------------- detector */
  const detIn = $('#det-in');
  if (detIn) {
    const stems = t('det.words').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
    const meter = $('#det-meter');
    const fill = $('span', meter);
    const analyse = () => {
      const text = detIn.value.toLowerCase();
      const words = (text.match(/[\p{L}\p{N}'’-]+/gu) || []).length;
      const hitsEl = $('#det-hits');
      hitsEl.replaceChildren();
      if (words < 3) {
        $('#det-num').textContent = '0';
        fill.style.width = '0%';
        meter.dataset.l = '0';
        $('#det-label').textContent = t('det.empty');
        for (const id of ['det-words', 'det-buzz', 'det-fig']) $('#' + id).textContent = '';
        return;
      }
      let total = 0;
      const found = [];
      for (const s of stems) {
        const n = text.split(s).length - 1;
        if (n > 0) { found.push([s, n]); total += n; }
      }
      const figures = (text.match(/\d+/g) || []).length;
      let score = Math.min(100, Math.round((total / words) * 400));
      if (figures) score = Math.round(score * Math.max(0.5, 1 - figures * 0.1));
      const level = score < 15 ? 0 : score < 40 ? 1 : score < 70 ? 2 : 3;
      $('#det-num').textContent = String(score);
      fill.style.width = score + '%';
      meter.dataset.l = String(level);
      $('#det-label').textContent = t('det.l' + level);
      $('#det-words').textContent = t('det.wordcount', { n: words });
      $('#det-buzz').textContent = t('det.buzz', { n: total });
      $('#det-fig').textContent = t('det.fig', { n: figures });
      if (found.length) found.forEach(([s, n]) => hitsEl.append(h('span', { class: 'tag' }, `${s} ×${n}`)));
      else hitsEl.append(h('span', { class: 'muted' }, t('det.none')));
    };
    let timer = null;
    detIn.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(analyse, 120); });
    $('#det-sample').addEventListener('click', () => { detIn.value = t('det.sample.text'); analyse(); });
    $('#det-clear').addEventListener('click', () => { detIn.value = ''; analyse(); detIn.focus(); });
    analyse();
  }

  /* -------------------------------------------------------------------- quiz */
  const quiz = $('#quiz');
  if (quiz) {
    const ANSWERS = ['b', 'm', 'b', 'm', 'b', 'm', 'b', 'm']; // b = bullshit, m = meaningful
    const TOTAL = ANSWERS.length;
    let order = [], pos = 0, score = 0;
    const play = $('#q-play'), res = $('#q-res'), fb = $('#q-fb'), actions = $('#q-actions');

    const show = () => {
      const q = order[pos];
      $('#q-count').textContent = t('quiz.count', { n: pos + 1, total: TOTAL });
      $('#q-bar').style.width = (pos / TOTAL) * 100 + '%';
      $('#q-text').textContent = t(`quiz.q${q + 1}.t`);
      fb.hidden = true;
      actions.hidden = false;
    };
    const start = () => {
      order = shuffle([...Array(TOTAL).keys()]);
      pos = 0; score = 0;
      res.hidden = true; play.hidden = false;
      show();
    };
    const finish = async () => {
      play.hidden = true; res.hidden = false;
      $('#q-score').textContent = t('quiz.score', { s: score, total: TOTAL });
      $('#q-msg').textContent = t(score >= 7 ? 'quiz.r.high' : score >= 4 ? 'quiz.r.mid' : 'quiz.r.low');
      const r = await api('PUT', '/api/progress', { quizBest: score });
      const best = r.ok ? r.data.progress.quizBest : score;
      $('#q-best').textContent = t('quiz.best', { b: best, total: TOTAL });
    };
    $$('[data-a]', actions).forEach((btn) => btn.addEventListener('click', () => {
      const q = order[pos];
      const right = btn.dataset.a === ANSWERS[q];
      if (right) score++;
      $('#q-bar').style.width = ((pos + 1) / TOTAL) * 100 + '%';
      const head = $('#q-fb-t');
      head.textContent = t(right ? 'quiz.right' : 'quiz.wrong');
      head.className = right ? 'good' : 'bad';
      $('#q-fb-p').textContent = t(`quiz.q${q + 1}.w`);
      $('#q-next').textContent = t(pos === TOTAL - 1 ? 'quiz.finish' : 'quiz.next');
      actions.hidden = true;
      fb.hidden = false;
      $('#q-next').focus();
    }));
    $('#q-next').addEventListener('click', () => { if (pos === TOTAL - 1) finish(); else { pos++; show(); } });
    $('#q-again').addEventListener('click', start);
    start();
  }

  /* ------------------------------------------------------------ workplace: bingo */
  const board = $('#bingo');
  if (board) {
    const pool = t('work.bingo.words').split(',');
    const LINES = [[0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11], [12, 13, 14, 15], [0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15], [0, 5, 10, 15], [3, 6, 9, 12]];
    let marked = new Set(), done = 0, cells = [];
    const count = () => {
      $('#bingo-count').textContent = t('work.bingo.count', { m: marked.size, l: done });
    };
    const evaluate = () => {
      const complete = LINES.filter((l) => l.every((i) => marked.has(i)));
      cells.forEach((c, i) => c.classList.toggle('win', complete.some((l) => l.includes(i))));
      if (complete.length > done) $('#bingo-win').textContent = t('work.bingo.win');
      else if (!complete.length) $('#bingo-win').textContent = '';
      done = complete.length;
      count();
    };
    const build = () => {
      marked = new Set(); done = 0;
      cells = shuffle(pool).slice(0, 16).map((word, i) => h('button', {
        type: 'button', class: 'cell', 'aria-pressed': 'false',
        onclick: (e) => {
          const on = !marked.has(i);
          if (on) marked.add(i); else marked.delete(i);
          e.currentTarget.setAttribute('aria-pressed', String(on));
          evaluate();
        },
      }, word));
      board.replaceChildren(...cells);
      $('#bingo-win').textContent = '';
      count();
    };
    $('#bingo-new').addEventListener('click', build);
    build();
  }

  /* ------------------------------------------------------------ defense: checklist */
  const checks = $$('#checks input');
  if (checks.length) {
    const ring = $('#def-ring'), pctEl = $('#def-pct');
    const paint = () => {
      const pct = Math.round((checks.filter((c) => c.checked).length / checks.length) * 100);
      pctEl.textContent = pct + '%';
      setRing(ring, pct);
    };
    setRing(ring, 0);
    loadMe().then((me) => {
      const saved = (me && me.progress && me.progress.checklist) || [];
      checks.forEach((c, i) => { c.checked = !!saved[i]; });
      paint();
    });
    let timer = null;
    checks.forEach((c) => c.addEventListener('change', () => {
      paint();
      clearTimeout(timer);
      timer = setTimeout(() => api('PUT', '/api/progress', { checklist: checks.map((x) => x.checked) }), 400);
    }));

    const bl = $('#bl');
    const MAXW = 600;
    const upd = () => {
      const n = Number(bl.value), m = n * 10;
      bl.style.setProperty('--p', ((n - 3) / 57) * 100 + '%');
      $('#bl-out').textContent = String(n);
      $('#bl-a').style.width = (n / MAXW) * 100 + '%';
      $('#bl-b').style.width = (m / MAXW) * 100 + '%';
      $('#bl-text').textContent = t('def.bl.out', { n, m });
    };
    bl.addEventListener('input', upd);
    upd();
  }

  /* ------------------------------------------------------------------ account */
  const accUser = $('#acc-user');
  if (accUser) {
    const setMsg = (id, text, ok) => { const el = $('#' + id); el.textContent = text; el.className = 'msg ' + (ok ? 'ok' : 'err'); };
    let twofa = false;

    const paintTwofa = () => {
      $('#acc-2fa-state').textContent = t(twofa ? 'acc.2fa.on' : 'acc.2fa.off');
      $('#tf-off').hidden = twofa;
      $('#tf-disable-form').hidden = !twofa;
      $('#pw-code-field').hidden = !twofa;
      $('#del-code-field').hidden = !twofa;
      $('#pw-code').required = twofa;
      $('#del-code').required = twofa;
    };

    const paintMe = (me) => {
      twofa = me.twofa;
      accUser.textContent = me.user;
      $('#acc-since').textContent = fmtDate(me.created);
      $('#acc-last').textContent = fmtDate(me.lastLogin);
      $('#acc-sessions').textContent = String(me.sessions);
      const log = $('#acc-log');
      log.replaceChildren();
      if (!me.events.length) log.append(h('li', { class: 'muted' }, t('acc.log.empty')));
      for (const e of me.events) {
        log.append(h('li', {}, h('span', {}, t('ev.' + e.e)), h('span', { class: 'when' }, `${fmtDate(e.t)} · ${e.ip}`)));
      }
      paintTwofa();
    };
    const refresh = async () => { mePromise = null; paintMe(await loadMe()); };
    refresh();

    $('#tf-start').addEventListener('click', async () => {
      const r = await api('POST', '/api/2fa/setup');
      if (!r.ok) return setMsg('tf-msg', errText(r), false);
      $('#tf-secret').textContent = r.data.secret.match(/.{1,4}/g).join(' ');
      $('#tf-uri').textContent = r.data.uri;
      $('#tf-enable-form').hidden = false;
      $('#tf-start').hidden = true;
      $('#tf-code').focus();
    });
    $('#tf-enable-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const r = await api('POST', '/api/2fa/enable', { code: $('#tf-code').value.trim() });
      if (!r.ok) return setMsg('tf-msg', errText(r), false);
      $('#tf-enable-form').hidden = true;
      $('#tf-start').hidden = false;
      $('#tf-code').value = '';
      setMsg('tf-msg', t('acc.2fa.enabled'), true);
      refresh();
    });
    $('#tf-disable-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const r = await api('POST', '/api/2fa/disable', { password: $('#tf-dpw').value, code: $('#tf-dcode').value.trim() });
      if (!r.ok) return setMsg('tf-msg', errText(r), false);
      $('#tf-dpw').value = ''; $('#tf-dcode').value = '';
      setMsg('tf-msg', t('acc.2fa.disabled'), true);
      refresh();
    });
    $('#pw-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const r = await api('POST', '/api/password', { current: $('#pw-cur').value, next: $('#pw-new').value, code: $('#pw-code').value.trim() });
      if (!r.ok) return setMsg('pw-msg', errText(r), false);
      $('#pw-cur').value = ''; $('#pw-new').value = ''; $('#pw-code').value = '';
      setMsg('pw-msg', t('acc.pw.done'), true);
      refresh();
    });
    $('#out-all').addEventListener('click', async () => {
      await api('POST', '/api/logout-all');
      location.href = '/login';
    });
    $('#del-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      if (!confirm(t('acc.del.confirm'))) return;
      const r = await api('POST', '/api/account/delete', { password: $('#del-pw').value, code: $('#del-code').value.trim() });
      if (!r.ok) return setMsg('del-msg', errText(r), false);
      location.href = '/login';
    });
  }

  window.BS = { $, $$, t, h, api, errText, lang, reduce };
})();
