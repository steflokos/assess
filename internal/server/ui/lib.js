// SPDX-License-Identifier: Apache-2.0. Copyright 2026 Stefanos Flokos.
// The small things that every page needs: making elements, talking to the server, the theme, toasts and dialogs. No text is ever put
// into the page as HTML. Everything goes in as text.

export const $ = (sel, root) => (root || document).querySelector(sel);

// h makes an element. Attributes starting with "on" are event listeners, a few are properties, the others are attributes.
export function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k === 'style') el.style.cssText = v; // the content policy allows this, and not a style attribute
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (['value', 'checked', 'disabled', 'selected', 'open', 'hidden'].includes(k)) el[k] = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
// put appends children to an element and leaves out what is not there. Element.append would write the word null.
export function put(el, ...kids) {
  for (const kid of kids.flat(Infinity)) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
export const clear = (el) => { while (el.firstChild) el.removeChild(el.firstChild); return el; };
export const plural = (n, word) => n + ' ' + word + (n === 1 ? '' : 's');
export const debounce = (fn, ms) => { let t; const d = (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; d.cancel = () => clearTimeout(t); return d; };
let counter = 0;
export const uid = () => 'f' + (++counter);
export const lines = (text) => text.split('\n').map((l) => l.trim()).filter(Boolean);
export const canon = (v) => (v && typeof v === 'object' && !Array.isArray(v)
  ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, canon(v[k])]))
  : Array.isArray(v) ? v.map(canon) : v);
export const same = (a, b) => JSON.stringify(canon(a)) === JSON.stringify(canon(b));
// mod is the name of the key for shortcuts on this computer.
export const mod = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent || '') ? '⌘' : 'Ctrl';
export const short = (hash) => String(hash || '').replace('sha256:', '').slice(0, 12);
export const upper = (s) => (s ? s[0].toUpperCase() + s.slice(1) : s);
// slug turns a name into an id: lower case letters and digits with hyphens between the words, accents taken off.
export const slug = (t) => String(t || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48).replace(/-+$/, '');
// when writes a date and time from a file in plain form: 23 Oct 2026, 12:04. A text that is not a date is given back as it is.
export function when(iso) {
  const d = new Date(iso);
  if (!iso || Number.isNaN(d.getTime())) return String(iso || '');
  return d.toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' }) + ', ' + d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
}
export const firstSentence = (s) => { const m = /^.*?[.!?](\s|$)/.exec(s || ''); return (m ? m[0] : s || '').trim(); };

// chip shows a risk value, 1 to 5, in its color. A value that is not there is a dash.
export function chip(v, title) {
  const none = v === undefined || v === null;
  return h('span', { class: 'chip v' + (none ? '' : v), title: title || (none ? 'Not calculated' : 'Risk ' + v + ' of 5'), text: none ? '–' : v });
}

// ---- theme ----------------------------------------------------------------------------------------------------------
const THEMES = ['auto', 'light', 'dark'];
let theme = 'auto';
try { theme = localStorage.getItem('assess-theme') || 'auto'; } catch (e) { /* no storage: stay with auto */ }
if (!THEMES.includes(theme)) theme = 'auto';
export const currentTheme = () => theme;
export function paintTheme() {
  if (theme === 'auto') document.documentElement.removeAttribute('data-theme');
  else document.documentElement.setAttribute('data-theme', theme);
}
export function nextTheme() {
  theme = THEMES[(THEMES.indexOf(theme) + 1) % THEMES.length];
  try { localStorage.setItem('assess-theme', theme); } catch (e) { /* no storage */ }
  paintTheme();
  return theme;
}

// remember keeps a small preference for this browser. It works without storage too.
export function remember(key, value) {
  try {
    if (value === undefined) return localStorage.getItem('assess-' + key);
    localStorage.setItem('assess-' + key, value);
  } catch (e) { /* no storage */ }
  return null;
}

// ---- the token and the API -------------------------------------------------------------------------------------------
// The address that assess serve prints has the token in its fragment. It is kept for this tab only, and taken out of the address bar.
let token = '';
try { token = sessionStorage.getItem('assess-token') || ''; } catch (e) { /* no storage */ }
const given = /[#&]t=([0-9a-f]+)/.exec(location.hash);
if (given) {
  token = given[1];
  try { sessionStorage.setItem('assess-token', token); } catch (e) { /* no storage */ }
  history.replaceState(null, '', location.pathname + '#/');
}
export const tokenValue = () => token;

// api calls the server and always returns a document: the JSON of a command, or one that says what went wrong.
export async function api(path, opt) {
  opt = opt || {};
  let res;
  try {
    res = await fetch(path, {
      method: opt.method || 'GET', cache: 'no-store',
      headers: Object.assign({ 'X-Assess-Token': token }, opt.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      body: opt.body !== undefined ? JSON.stringify(opt.body) : undefined,
    });
  } catch (e) {
    return { ok: false, status: 0, diagnostics: [{ severity: 'error', code: 'offline', message: 'The server does not answer. Is assess serve still running?' }] };
  }
  const body = await res.text();
  let doc;
  try { doc = JSON.parse(body); } catch (e) { doc = { ok: false, diagnostics: [{ severity: 'error', code: 'failed', message: body || 'HTTP ' + res.status }] }; }
  doc.status = res.status;
  return doc;
}

// plainText fetches a route that answers with text.
export async function plainText(path) {
  try {
    const res = await fetch(path, { headers: { 'X-Assess-Token': token }, cache: 'no-store' });
    return await res.text();
  } catch (e) {
    return 'The server does not answer.';
  }
}

// ---- toasts and dialogs -----------------------------------------------------------------------------------------------
// toast tells what happened. An action, such as Undo, is a button in it. Toasts stack in one place, so a new one does not hide the
// one before it, and the place is a live region, so a screen reader says them.
export function toasts() {
  let box = document.getElementById('toasts');
  if (!box) {
    box = h('div', { id: 'toasts', class: 'toasts', role: 'status', 'aria-live': 'polite' });
    document.body.append(box);
  }
  return box;
}
export function toast(text, kind, action, ms) {
  const el = h('div', { class: 'toast alert ' + (kind || 'ok') }, h('span', { text }),
    action ? h('button', { class: 'btn small', type: 'button', onclick: () => { el.remove(); action.run(); } }, action.label) : null);
  toasts().append(el);
  setTimeout(() => el.remove(), ms || (action ? 9000 : Math.min(4500 + String(text).length * 30, 12000)));
  return el;
}

// ask puts a question in a modal dialog. body is a node. It resolves to true when the person confirms.
export function ask(opt) {
  return new Promise((resolve) => {
    const title = uid();
    const dlg = h('dialog', { 'aria-labelledby': title },
      h('h2', { id: title, text: opt.title }),
      opt.body,
      h('div', { class: 'actions' },
        opt.noCancel ? null : h('button', { class: 'btn', type: 'button', onclick: () => dlg.close('no') }, 'Cancel'),
        h('button', { class: 'btn ' + (opt.danger ? 'solid-danger' : 'primary'), type: 'button', onclick: () => dlg.close('yes') }, opt.ok || 'OK')));
    dlg.addEventListener('close', () => { const yes = dlg.returnValue === 'yes'; dlg.remove(); resolve(yes); });
    document.body.append(dlg);
    dlg.showModal();
  });
}
