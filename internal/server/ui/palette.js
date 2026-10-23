// SPDX-License-Identifier: Apache-2.0. Copyright 2026 Stefanos Flokos.
// The search of the page: records by name or id, and the pages. It works on what the page already has.

import { h, clear } from './lib.js';
import { icon, KIND_ICON } from './icons.js';
import { S, kindName, kindTitle } from './data.js';

const PAGES = [
  { label: 'Overview', go: [], icon: 'home' }, { label: 'Open items', go: ['open'], icon: 'list' }, { label: 'Decisions', go: ['decisions'], icon: 'checkCircle' },
  { label: 'Calculation', go: ['calc'], icon: 'chart' }, { label: 'Report', go: ['report'], icon: 'page' }, { label: 'Diagram', go: ['diagram'], icon: 'image' },
  { label: 'Iterations', go: ['iterations'], icon: 'clock' }, { label: 'Files', go: ['files'], icon: 'folder' },
];

// stem makes "steps" and "step", or "scenarios" and "scenario", the same word.
const stem = (w) => (w.length > 3 ? w.replace(/(es|s)$/, '') : w);

// pagesFor lists the pages that match what was typed: the fixed ones, the list of each kind and a way to make a new record of each kind.
export function pagesFor(q) {
  const words = q.toLowerCase().split(/\s+/).filter(Boolean).map(stem);
  const all = [
    ...PAGES.map((p) => ({ go: p.go, icon: p.icon, title: p.label, tag: 'Page' })),
    ...Object.keys(S.kinds).map((k) => ({ go: ['kind', k], icon: KIND_ICON[k] || 'circle', title: kindTitle(k), tag: 'List' })),
    ...Object.keys(S.kinds).map((k) => ({ go: ['new', k], icon: 'plus', title: 'New ' + kindName(k), tag: 'Create' })),
  ];
  return all.filter((p) => { const t = p.title.toLowerCase(); return words.every((w) => t.includes(w)); });
}

// find ranks the records for what was typed. Every word has to be in the name, the id or the kind. A name that starts with the
// first word comes first.
function find(q) {
  const words = q.toLowerCase().split(/\s+/).filter(Boolean).map(stem);
  if (!words.length) return [];
  const out = [];
  for (const r of S.index) {
    if (!words.every((w) => r.hay.includes(w))) continue;
    const n = r.name.toLowerCase(), id = r.id.toLowerCase();
    out.push({ r, score: n.startsWith(words[0]) ? 0 : id.startsWith(words[0]) ? 1 : n.includes(words[0]) ? 2 : 3 });
  }
  return out.sort((a, b) => a.score - b.score || a.r.name.localeCompare(b.r.name)).slice(0, 12).map((x) => x.r);
}

export function openPalette(ui) {
  if (document.getElementById('palette')) return;
  const input = h('input', { type: 'search', placeholder: 'Search records and pages', 'aria-label': 'Search', autocomplete: 'off', spellcheck: 'false', role: 'combobox', 'aria-expanded': 'true', 'aria-controls': 'palette-list', 'aria-autocomplete': 'list' });
  const list = h('ul', { class: 'plist', role: 'listbox', id: 'palette-list', 'aria-label': 'Results' });
  const dlg = h('dialog', { id: 'palette', class: 'palette', 'aria-label': 'Search' },
    h('div', { class: 'pbox' }, icon('search', 18), input, h('span', { class: 'kbd', text: 'Esc' })), list,
    h('div', { class: 'phint small muted', text: 'Up and Down to choose, Enter to open' }));
  let items = [], at = 0;

  const open = (it) => { dlg.close(); ui.go(...it.go); };
  const mark = () => {
    [...list.children].forEach((li, i) => { li.classList.toggle('on', i === at); li.setAttribute('aria-selected', String(i === at)); if (i === at) { li.scrollIntoView({ block: 'nearest' }); input.setAttribute('aria-activedescendant', li.id); } });
  };
  const draw = () => {
    const q = input.value.trim().toLowerCase();
    items = [
      ...find(q).map((r) => ({ go: ['kind', r.kind, r.id], icon: KIND_ICON[r.kind] || 'circle', title: r.name, sub: r.id, tag: kindName(r.kind) })),
      ...(q ? pagesFor(q) : PAGES.map((p) => ({ go: p.go, icon: p.icon, title: p.label, tag: 'Page' }))),
    ];
    at = 0;
    clear(list);
    items.forEach((it, i) => list.append(h('li', { role: 'option', id: 'palette-' + i, 'aria-selected': String(i === 0), class: i === 0 ? 'on' : '', onmousemove: () => { at = i; mark(); }, onclick: () => open(it) },
      icon(it.icon, 16), h('span', { class: 'pt', text: it.title }), it.sub ? h('span', { class: 'ps', text: it.sub }) : null, h('span', { class: 'ptag', text: it.tag }))));
    if (!items.length) list.append(h('li', { class: 'none', text: 'Nothing matches ' + input.value }));
    else input.setAttribute('aria-activedescendant', 'palette-0');
  };
  input.addEventListener('input', draw);
  input.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); at = Math.min(at + 1, items.length - 1); mark(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); at = Math.max(at - 1, 0); mark(); }
    else if (e.key === 'Enter') { e.preventDefault(); if (items[at]) open(items[at]); }
  });
  dlg.addEventListener('close', () => dlg.remove());
  dlg.addEventListener('click', (e) => { if (e.target === dlg) dlg.close(); });
  document.body.append(dlg);
  draw();
  dlg.showModal();
  input.focus();
}
