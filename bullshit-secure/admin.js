'use strict';
/**
 * Small admin tool. STOP THE SERVER BEFORE USING IT (it edits the same encrypted file).
 *
 *   node admin.js list
 *   node admin.js create <user>             (creates an account, prints a one-time temporary password)
 *   node admin.js delete <user>
 *   node admin.js disable-2fa <user>
 *   node admin.js reset-password <user>     (prints a one-time temporary password)
 */
const crypto = require('crypto');
const store = require('./store');
const auth = require('./auth');

(async () => {
  const [cmd, name] = process.argv.slice(2);
  store.init();
  const need = () => {
    const u = store.get(String(name || '').toLowerCase());
    if (!u) { console.error('No such user.'); process.exit(1); }
    return u;
  };
  switch (cmd) {
    case 'list':
      for (const u of store.all()) {
        console.log(`${u.name}  created ${new Date(u.created).toISOString()}  2FA: ${u.twofa ? 'on' : 'off'}`);
      }
      console.log(`${store.count()} user(s)`);
      break;
    case 'create': {
      const n = String(name || '').trim().toLowerCase();
      if (!/^[a-z0-9][a-z0-9_.-]{2,31}$/.test(n)) { console.error('Invalid username (3-32 chars: a-z, 0-9, dot, hyphen, underscore).'); process.exit(1); }
      if (store.has(n)) { console.error('That user already exists.'); process.exit(1); }
      const tmp = crypto.randomBytes(12).toString('base64url');
      store.put({ name: n, hash: await auth.hashPassword(tmp), created: Date.now(), lastLogin: null, twofa: null, progress: { quizBest: 0, checklist: [] }, events: [] });
      store.save(true);
      console.log(`Created ${n}. Temporary password: ${tmp}\nAsk the user to change it right after signing in.`);
      break;
    }
    case 'delete': {
      const u = need(); store.remove(u.name); store.save(true); console.log(`Deleted ${u.name}.`); break;
    }
    case 'disable-2fa': {
      const u = need(); u.twofa = null; store.save(true); console.log(`2FA disabled for ${u.name}.`); break;
    }
    case 'reset-password': {
      const u = need();
      const tmp = crypto.randomBytes(12).toString('base64url');
      u.hash = await auth.hashPassword(tmp);
      store.save(true);
      console.log(`Temporary password for ${u.name}: ${tmp}\nAsk the user to change it right after signing in.`);
      break;
    }
    default:
      console.log('Usage: node admin.js list | create <user> | delete <user> | disable-2fa <user> | reset-password <user>');
  }
  process.exit(0);
})();
