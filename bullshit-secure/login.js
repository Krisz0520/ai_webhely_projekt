/* Login page: sign in, 2FA step, registration with live password-strength meter. */
(() => {
  'use strict';
  const { $, t, api, errText } = window.BS;

  const msg = $('#auth-msg');
  const say = (text) => { msg.textContent = text || ''; msg.className = 'msg' + (text ? ' err' : ''); };
  const busy = (btn, on) => { btn.disabled = on; };

  /* tabs */
  const tabs = { in: $('#tab-in'), up: $('#tab-up') };
  const panels = { in: $('#panel-in'), up: $('#panel-up') };
  function selectTab(which) {
    for (const k of Object.keys(tabs)) {
      tabs[k].setAttribute('aria-selected', String(k === which));
      panels[k].hidden = k !== which;
    }
    say('');
    $(which === 'in' ? '#li-user' : '#re-user').focus();
  }
  tabs.in.addEventListener('click', () => selectTab('in'));
  tabs.up.addEventListener('click', () => selectTab('up'));

  /* show / hide password */
  document.querySelectorAll('.pw-toggle').forEach((b) => b.addEventListener('click', () => {
    const input = document.getElementById(b.dataset.for);
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    b.textContent = t(show ? 'login.hide' : 'login.show');
    b.setAttribute('aria-pressed', String(show));
  }));

  /* sign in */
  let ticket = null;
  const formLogin = $('#form-login');
  const form2fa = $('#form-2fa');

  formLogin.addEventListener('submit', async (e) => {
    e.preventDefault();
    say('');
    const btn = $('#li-btn');
    busy(btn, true);
    const r = await api('POST', '/api/login', { username: $('#li-user').value, password: $('#li-pw').value });
    busy(btn, false);
    if (!r.ok) return say(errText(r));
    if (r.data.step === '2fa') {
      ticket = r.data.ticket;
      formLogin.hidden = true;
      $('#tabs').hidden = true;
      form2fa.hidden = false;
      $('#tf-code').focus();
      return;
    }
    location.href = '/';
  });

  form2fa.addEventListener('submit', async (e) => {
    e.preventDefault();
    say('');
    const r = await api('POST', '/api/login/2fa', { ticket, code: $('#tf-code').value.trim() });
    if (!r.ok) {
      if (r.data.error === 'ticket_expired') { form2fa.hidden = true; formLogin.hidden = false; $('#tabs').hidden = false; }
      return say(errText(r));
    }
    location.href = '/';
  });

  $('#tf-back').addEventListener('click', () => {
    ticket = null;
    form2fa.hidden = true;
    formLogin.hidden = false;
    $('#tabs').hidden = false;
    $('#tf-code').value = '';
    $('#li-pw').value = '';
    say('');
    $('#li-user').focus();
  });

  /* password strength (UX hint only: the server enforces the real policy) */
  function strength(pw) {
    if (pw.length < 10) return pw.length ? 1 : 0;
    let s = 2;
    const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((re) => re.test(pw)).length;
    if (pw.length >= 14 || classes >= 3) s++;
    if (pw.length >= 18 && classes >= 2) s++;
    if (new Set(pw).size < 6) s = Math.min(s, 1);
    return Math.min(4, s);
  }
  const reUser = $('#re-user');
  const rePw = $('#re-pw');
  rePw.addEventListener('input', () => {
    const s = strength(rePw.value);
    $('#strength').dataset.s = String(s);
    $('#strength-label').textContent = rePw.value ? `${t('login.strength')}: ${t('login.s' + s)}` : t('login.hint.pw');
  });

  /* register */
  $('#form-register').addEventListener('submit', async (e) => {
    e.preventDefault();
    say('');
    if (rePw.value !== $('#re-pw2').value) return say(t('err.mismatch'));
    const btn = $('#re-btn');
    busy(btn, true);
    const r = await api('POST', '/api/register', { username: reUser.value, password: rePw.value });
    busy(btn, false);
    if (!r.ok) return say(errText(r));
    location.href = '/';
  });
})();
