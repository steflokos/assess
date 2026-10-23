// SPDX-License-Identifier: Apache-2.0. Copyright 2026 Stefanos Flokos.
// The web interface of assess. It shows what the commands say and writes only through `assess apply`, so a record is never written in a
// way that the command line would not write it. No framework, no build step, and no text is ever put into the page as HTML.

import { $, h, put, clear, plural, toast, toasts, api, tokenValue, paintTheme, nextTheme, currentTheme, remember, mod } from './lib.js';
import { icon, KIND_ICON } from './icons.js';
import { S, load, nameOf, kindTitle, workflow } from './data.js';
import { editor } from './editor.js';
import { overview, list, decisions, openItems, calc, explain, reportView, diagramView, iterations, files, welcome } from './views.js';
import { openPalette } from './palette.js';
import { notFound, empty } from './parts.js';

const state = { dirty: false, hash: '', suppress: false, changedOnDisk: false, drawn: '', pageTitle: '' };

// ---- the way through the page ----------------------------------------------------------------------------------------------------------
const unescape = (s) => { try { return decodeURIComponent(s); } catch (e) { return s; } }; // an address that was typed by hand may be broken
const path = () => location.hash.replace(/^#\/?/, '').split('/').filter(Boolean).map(unescape);
const go = (...parts) => { location.hash = '#/' + parts.map(encodeURIComponent).join('/'); };

const ui = {
  go,
  dirty: () => state.dirty,
  render: () => render(),
  // refresh reads the project again. A page with changes that are not saved is not drawn again, because that would throw them away.
  // The menu and the top bar still show the new numbers.
  refresh: async () => {
    await load();
    if (state.dirty) { drawNav(S.noProject ? ['none'] : path()); drawTop(); } else render();
  },
  setDirty(v) {
    state.dirty = v;
    if (!v) state.changedOnDisk = false;
    paintTitle();
  },
};

function paintTitle() {
  const item = (S.of.item || [])[0];
  // the page, the item and the tool, so that the history of the browser and its tabs tell the pages apart
  document.title = (state.dirty ? '• ' : '') + [state.pageTitle, item ? nameOf('item', item.id) : '', 'assess'].filter(Boolean).join(' · ');
}

window.addEventListener('hashchange', () => {
  if (state.suppress) { state.suppress = false; return; }
  if (state.dirty && !confirm('Leave this page without saving your changes?')) { state.suppress = true; location.hash = state.hash; return; }
  ui.setDirty(false);
  state.hash = location.hash;
  render();
});
window.addEventListener('beforeunload', (e) => { if (state.dirty) { e.preventDefault(); e.returnValue = ''; } });

// ---- the menu ------------------------------------------------------------------------------------------------------------------------------
const GROUPS = [
  { key: 'describe', title: 'Describe', steps: [1], kinds: ['item', 'assumption', 'function', 'component', 'interface', 'channel', 'data'] },
  { key: 'analyse', title: 'Analyse', steps: [2, 3, 4, 5], kinds: ['asset', 'damage', 'threat', 'step', 'control'] },
  { key: 'decide', title: 'Decide', steps: [6], kinds: ['risk'], extra: [{ label: 'Decisions', icon: 'checkCircle', parts: ['decisions'] }] },
  { key: 'share', title: 'Share', steps: [7], extra: [
    { label: 'Open items', icon: 'list', parts: ['open'], count: () => S.open.length }, { label: 'Calculation', icon: 'chart', parts: ['calc'] },
    { label: 'Report', icon: 'page', parts: ['report'] }, { label: 'Diagram', icon: 'image', parts: ['diagram'] }, { label: 'Iterations', icon: 'clock', parts: ['iterations'] }] },
  { key: 'settings', title: 'Settings', kinds: ['rule'], extra: [{ label: 'Files', icon: 'folder', parts: ['files'] }] },
];

function drawNav(here) {
  const nav = clear($('#nav'));
  const steps = S.desc ? workflow() : [];
  const link = (label, iconName, parts, count) => {
    const on = parts.length > 0 && here.length >= parts.length && parts.every((p, i) => p === here[i]);
    return h('a', { href: '#/' + parts.map(encodeURIComponent).join('/'), class: on ? 'on' : '', 'aria-current': on ? 'page' : null },
      icon(iconName, 17), h('span', { class: 'nl', text: label }), count === undefined ? null : h('span', { class: 'n' + (count ? '' : ' zero'), text: count }));
  };
  nav.append(h('a', { href: '#/', class: here.length === 0 ? 'on' : '', 'aria-current': here.length === 0 ? 'page' : null }, icon('home', 17), h('span', { class: 'nl', text: 'Overview' })));
  for (const g of GROUPS) {
    const mine = steps.filter((s) => g.steps && g.steps.includes(s.n));
    const dot = !mine.length ? 'none' : mine.every((s) => s.state === 'done') ? 'done' : mine.some((s) => s.state === 'now') ? 'now' : 'todo';
    const active = here.length >= 2 && here[0] === 'kind' && (g.kinds || []).includes(here[1]) || (g.extra || []).some((x) => x.parts[0] === here[0]);
    const saved = remember('fold-' + g.key);
    const folded = active ? false : saved === null ? (g.key === 'describe' && dot === 'done') : saved === '1';
    const body = h('div', { class: 'ngroup-body', hidden: folded });
    for (const k of g.kinds || []) body.append(link(kindTitle(k), KIND_ICON[k] || 'circle', ['kind', k], (S.of[k] || []).length));
    for (const x of g.extra || []) body.append(link(x.label, x.icon, x.parts, x.count ? x.count() : undefined));
    const head = h('button', { type: 'button', class: 'ngroup-h', 'aria-expanded': String(!folded), onclick: () => {
      body.hidden = !body.hidden;
      head.setAttribute('aria-expanded', String(!body.hidden));
      remember('fold-' + g.key, body.hidden ? '1' : '0');
    } }, dot === 'none' ? null : h('span', { class: 'dot ' + dot, title: dot === 'done' ? 'Done' : dot === 'now' ? 'Do this next' : 'Not yet' }), h('span', { text: g.title }), icon('chevron', 14));
    nav.append(h('div', { class: 'ngroup' }, head, body));
  }
}

function drawTop() {
  const item = (S.of.item || [])[0];
  $('#item').textContent = item ? nameOf('item', item.id) : '';
  const errors = S.diag.filter((d) => d.severity === 'error').length;
  const open = S.open.length;
  const counts = clear($('#counts'));
  put(counts,
    h('a', { href: '#/', class: 'pill ' + (errors ? 'err' : 'ok'), title: errors ? 'Errors in the project. Open the overview.' : 'The project has no errors' }, icon(errors ? 'alert' : 'check', 14), errors ? plural(errors, 'error') : 'No errors'),
    open ? h('a', { href: '#/open', class: 'pill info', title: 'What is still open' }, open + ' open') : null);
  const t = currentTheme();
  const btn = clear($('#theme'));
  btn.append(icon(t === 'dark' ? 'moon' : t === 'light' ? 'sun' : 'sparkle', 17));
  btn.title = 'Theme: ' + t + '. Click to change.';
  btn.setAttribute('aria-label', btn.title);
}

// ---- drawing the page ------------------------------------------------------------------------------------------------------------------
function skeleton() {
  return h('div', { class: 'page' }, h('div', { class: 'skel', style: 'height: 2rem; width: 40%' }), h('div', { class: 'skel', style: 'height: 8rem; margin-top: 1rem' }), h('div', { class: 'skel', style: 'height: 14rem; margin-top: 1rem' }));
}

function render() {
  window.dispatchEvent(new CustomEvent('assess:leave')); // what the page that goes away registered, goes away with it
  const parts = path();
  const top = $('#main').scrollTop; // read before the page is cleared, which sets it to 0
  const main = clear($('#main'));
  if (S.fatal) {
    main.append(h('div', { class: 'page' }, h('div', { class: 'card' }, empty('lock', S.fatal === 'token' ? 'This page needs the address that assess serve printed' : 'Something went wrong',
      S.fatal === 'token' ? 'The address has a token at its end. Copy the whole line from the terminal into the address bar.' : S.fatal))));
    return;
  }
  document.body.classList.toggle('noproject', S.noProject);
  drawNav(S.noProject ? ['none'] : parts);
  drawTop();
  paintTitle();
  const [a, b, c] = parts;
  const again = state.drawn === location.hash; // the same page again: the person keeps their place
  let view;
  if (S.noProject) view = welcome(ui);
  else if (!a) view = overview(ui);
  else if (a === 'kind' && b && c) view = editor(b, c, false, ui);
  else if (a === 'kind' && b) view = list(b, ui);
  else if (a === 'new' && b) view = editor(b, '', true, ui);
  else if (a === 'decisions') view = decisions(ui);
  else if (a === 'open') view = openItems(ui);
  else if (a === 'calc') view = b ? explain(b) : calc();
  else if (a === 'report') view = reportView();
  else if (a === 'diagram') view = diagramView(b, ui);
  else if (a === 'iterations') view = iterations(ui);
  else if (a === 'files') view = files(ui);
  else view = notFound('There is no such page.');
  main.append(view);
  state.pageTitle = (main.querySelector('h1') || {}).textContent || '';
  paintTitle();
  main.scrollTop = again ? top : 0;
  if (!again) { // a screen reader and the keyboard start at the new page
    const heading = main.querySelector('h1');
    if (heading) { heading.tabIndex = -1; heading.focus({ preventScroll: true }); }
  }
  state.drawn = location.hash;
  if (state.changedOnDisk) banner();
}

// banner tells a person who is editing that the files changed on disk. The form stays as it is.
function banner() {
  if ($('#changed')) return;
  $('#main').prepend(h('div', { id: 'changed', class: 'alert warn row', style: 'margin: 16px 24px 0' }, 'The files changed on disk while you were editing.',
    h('button', { class: 'btn small', type: 'button', onclick: async () => { ui.setDirty(false); await ui.refresh(); } }, 'Reload and discard my changes')));
}

// ---- keys ---------------------------------------------------------------------------------------------------------------------------------------
const typing = (el) => el && (el.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(el.tagName));
document.addEventListener('keydown', (e) => {
  if (typeof e.key !== 'string' || document.querySelector('dialog[open]')) return; // a dialog has the keyboard
  const key = e.key.toLowerCase();
  const withMod = e.metaKey || e.ctrlKey;
  if (withMod && key === 'k') { e.preventDefault(); if (S.desc) openPalette(ui); }
  else if (withMod && key === 's') { e.preventDefault(); window.dispatchEvent(new CustomEvent('assess:save')); }
  else if (key === '/' && !withMod && !typing(e.target) && S.desc) { e.preventDefault(); openPalette(ui); }
});

// ---- start ----------------------------------------------------------------------------------------------------------------------------------------
async function start() {
  paintTheme();
  toasts();
  $('.kbd').textContent = mod + ' K';
  $('#skip').addEventListener('click', () => $('#main').focus());
  $('#theme').addEventListener('click', () => { nextTheme(); drawTop(); });
  $('#search').addEventListener('click', () => { if (S.desc) openPalette(ui); });
  state.hash = location.hash;
  if (!tokenValue()) { S.fatal = 'token'; render(); return; }
  $('#main').append(skeleton());
  await load();
  render();
  // The files may change under the page: an editor, or a command. A change is noticed within a few seconds. A form with unsaved
  // changes is not replaced. The person is told instead.
  setInterval(async () => {
    if (document.hidden || S.fatal) return;
    const st = await api('/api/stamp');
    if (!st.stamp || st.stamp === S.stamp) return;
    if (state.dirty) { state.changedOnDisk = true; banner(); return; }
    await load();
    if (state.dirty) { // the person typed while the project was read: the form stays, and they are told
      state.changedOnDisk = true;
      drawNav(S.noProject ? ['none'] : path());
      drawTop();
      banner();
      return;
    }
    if (S.changed) render(); // a file that was touched and not changed leaves the page as it is
  }, 2000);
}
start();
