/* Sign-in gate: unwraps the content key, decrypts data.enc.js (data + map + renderer)
   and serves encrypted assets (aerial.bin) to the renderer as blob URLs through window.ARK_ASSET. */
(function () {
  var E = window.ARK_ENC, S = window.crypto && window.crypto.subtle;
  var form = document.querySelector('#gate form'), err = document.querySelector('#gate .err');
  var btn = form.querySelector('button[type="submit"]'), KEY = 'arkland_k_v1';
  function ub(s) { var b = atob(s), u = new Uint8Array(b.length); for (var i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; }
  function bu(u) { var s = ''; for (var i = 0; i < u.length; i++) s += String.fromCharCode(u[i]); return btoa(s); }
  function forgetSaved() { try { sessionStorage.removeItem(KEY); } catch (e) {} }
  function reset(message) { btn.disabled = false; btn.textContent = 'View dashboard'; err.textContent = message || ''; }
  function open(K) {
    return S.importKey('raw', K, 'AES-GCM', false, ['decrypt'])
      .then(function (k) {
        var cache = {};
        window.ARK_ASSET = function (name) {
          var a = E.assets && E.assets[name]; if (!a) return Promise.reject(new Error('no asset ' + name));
          // asset URLs carry a content hash (make_gate.mjs: terrain.enc?v=<sha256 of the ciphertext>), so a copy cached under an earlier key is
          // never reused. If a decrypt still fails (a stale copy from a proxy), fetch once more straight from the network before giving up.
          // Errors name the step that failed: fetch, decrypt (or, in the renderer, parse).
          function stage(st, e) { var x = new Error(st + ': ' + name + ' ' + (e && (e.message || e.name) || '')); x.stage = st; x.cause = e; return x; }
          function get(mode) { return fetch(a.file, { cache: mode }).then(function (r) { if (!r.ok) throw stage('fetch', new Error('HTTP ' + r.status)); return r.arrayBuffer(); }, function (e) { throw stage('fetch', e); })
            .then(function (buf) { return S.decrypt({ name: 'AES-GCM', iv: ub(a.iv) }, k, buf).catch(function (e) { throw stage('decrypt', e && e.name === 'OperationError' ? new Error('stale or corrupt copy, does not match this build\u2019s key') : e); }); }); }
          if (!cache[name]) cache[name] = get('default').catch(function (e) { if (window.console) console.warn('[arkland] ' + e.message + '; refetching from the network'); return get('reload'); })
            .then(function (pt) { return URL.createObjectURL(new Blob([pt], { type: a.type })); },
                  function (e) { if (window.console) console.error('[arkland] asset failed:', e.message, e.cause || ''); delete cache[name]; throw e; });
          return cache[name];
        };
        return S.decrypt({ name: 'AES-GCM', iv: ub(E.iv) }, k, ub(E.ct)).catch(function (e) { var x = new Error('decrypt: dashboard bundle ' + (e && e.name || '')); x.name = 'decrypt'; throw x; });
      })
      .then(function (pt) { document.body.classList.remove('is-locked'); try { (0, eval)(new TextDecoder().decode(pt)); } catch (e) { if (window.console) console.error('[arkland] parse: dashboard bundle', e); var x = new Error('parse: dashboard bundle ' + (e && e.message || '')); x.name = 'parse'; throw x; } })
      .then(function () { try { sessionStorage.setItem(KEY, bu(K)); } catch (e) {} });
  }
  function unwrap(u, p) {
    var a = E.users[u]; if (!a) return Promise.reject(new Error('bad'));
    return S.importKey('raw', new TextEncoder().encode(u + ':' + p), 'PBKDF2', false, ['deriveKey'])
      .then(function (base) { return S.deriveKey({ name: 'PBKDF2', salt: ub(a.salt), iterations: E.iter, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']); })
      .then(function (kek) { return S.decrypt({ name: 'AES-GCM', iv: ub(a.iv) }, kek, ub(a.wk)); })
      .then(function (K) { return new Uint8Array(K); });
  }
  form.addEventListener('submit', function (ev) {
    ev.preventDefault();
    if (!E || !S || btn.disabled) return;
    err.textContent = '';
    var u = document.getElementById('gate-u').value.trim().toLowerCase(), p = document.getElementById('gate-p').value.trim().toUpperCase();
    if (!u || !p) { reset('Enter your username and password.'); return; }
    btn.disabled = true; btn.textContent = 'Checking\u2026';
    Promise.resolve().then(function () { return unwrap(u, p); }).then(function (K) {
      return open(K).catch(function (e) { document.body.classList.add('is-locked'); reset('Signed in, but the dashboard failed to load (' + (e && (e.message || e.name) || 'unknown step') + '). Refresh and try again.'); });
    }, function () { reset('That username and password don\u2019t match.'); document.getElementById('gate-p').select(); });
  });
  var show = document.getElementById('gate-show');
  if (show) show.addEventListener('click', function () {
    var input = document.getElementById('gate-p'), visible = input.type === 'password';
    input.type = visible ? 'text' : 'password'; show.textContent = visible ? 'Hide' : 'Show';
    show.setAttribute('aria-pressed', String(visible)); show.setAttribute('aria-label', visible ? 'Hide password' : 'Show password');
  });
  if (!E || !E.users || !S) { btn.disabled = true; err.textContent = !S ? 'A secure (https) connection is required.' : 'The sign-in files could not load. Refresh this page.'; return; }
  reset();
  var saved = null; try { saved = sessionStorage.getItem(KEY); } catch (e) {}
  if (saved) {
    btn.disabled = true;
    Promise.resolve().then(function () { return open(ub(saved)); }).then(function () { reset(); }, function () { forgetSaved(); document.body.classList.add('is-locked'); reset('Your saved session could not be restored. Please sign in again.'); });
  } else if (document.activeElement === document.body) document.getElementById('gate-u').focus();
})();
