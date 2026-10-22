// SPDX-License-Identifier: Apache-2.0. Copyright 2026 Stefanos Flokos.
// Pieces that more than one page uses: findings, diffs, the effects of a change, breadcrumbs and empty states.

import { h, chip, plural } from './lib.js';
import { icon } from './icons.js';
import { recordAt, kindTitle } from './data.js';

export const hrefOf = (...parts) => '#/' + parts.map(encodeURIComponent).join('/');
export const where = (d) => (d.file ? d.file + (d.line ? ':' + d.line + (d.column ? ':' + d.column : '') : '') : '');

// diagnostic is one finding: a message with where it is, linked to the record when there is one.
export function diagnostic(d) {
  const cls = d.severity === 'error' ? 'err' : 'warn';
  const real = d.file && d.file !== '<stdin>'; // a place in the change set is not a place in the project
  const at = real ? recordAt(d.file, d.line || 1) : null;
  return h('div', { class: 'alert ' + cls },
    h('span', { class: 'code', text: d.code }), d.message,
    real ? h('div', { class: 'where' }, at ? h('a', { href: hrefOf('kind', at.kind, at.id) }, where(d)) : where(d)) : null);
}
export const diagnostics = (list) => { const f = document.createDocumentFragment(); list.forEach((d) => f.append(diagnostic(d))); return f; };
// said shows what a command said for a person, when the document has it.
export const said = (env) => (env.text ? h('pre', { class: 'plain', text: env.text }) : null);

export function diff(text) {
  const pre = h('pre', { class: 'diff' });
  for (const l of String(text || '').split('\n')) {
    const cls = l.startsWith('+++') || l.startsWith('---') || l.startsWith('@@') ? 'hunk' : l.startsWith('+') ? 'add' : l.startsWith('-') ? 'del' : 'ctx';
    pre.append(h('span', { class: cls, text: l + '\n' }));
  }
  return pre;
}

// effects says what a change does to the calculation: which threat scenarios and the item move, from what to what.
export function effects(list) {
  if (!list || !list.length) return null;
  const pair = (a, b, what, word) => (a === undefined && b === undefined ? null : h('span', { class: 'fx-pair', title: what },
    h('span', { class: 'faint small', text: word }), chip(a, what + ' before'), h('span', { class: 'faint', text: '→' }), chip(b, what + ' after')));
  const rows = list.slice(0, 12).map((e) => {
    const b = e.before || {}, a = e.after || {};
    const label = e.kind === 'item' ? 'The item' : e.name || e.id;
    const note = !e.before ? 'new' : !e.after ? 'removed' : '';
    return h('div', { class: 'fx-row' },
      h('span', { class: 'fx-name', text: label }),
      note ? h('span', { class: 'tag', text: note }) : null,
      e.after || e.before ? [pair(b.base, a.base, 'Risk before the controls', 'before'), pair(b.residual, a.residual, 'Risk with the controls', 'with controls')] : null,
      b.baseLevel !== a.baseLevel || b.residualLevel !== a.residualLevel
        ? h('span', { class: 'fx-lv small', text: 'Feasibility ' + (b.baseLevel || '–') + ' → ' + (a.baseLevel || '–') + ', with controls ' + (b.residualLevel || '–') + ' → ' + (a.residualLevel || '–') }) : null);
  });
  const threats = list.filter((e) => e.kind === 'threat').length;
  const lowers = list.filter((e) => e.before && e.after && ((e.after.base || 0) + (e.after.residual || 0)) < ((e.before.base || 0) + (e.before.residual || 0))).length;
  const text = threats ? 'This change moves the result of ' + plural(threats, 'threat scenario') + (lowers === threats ? ' down.' : lowers === 0 ? '.' : '.') : 'This change moves the risk of the item.';
  return h('div', { class: 'fx' }, h('div', { class: 'fx-head' }, icon('sparkle', 15), h('strong', { text: text })), rows,
    list.length > 12 ? h('div', { class: 'muted small', text: '… and ' + (list.length - 12) + ' more.' }) : null);
}

export function crumbs(...parts) {
  return h('nav', { class: 'crumbs', 'aria-label': 'You are here' }, parts.flatMap((p, i) => [
    i ? h('span', { class: 'sep', text: '/' }) : null,
    p.href ? h('a', { href: p.href, text: p.text }) : h('span', { class: 'here', 'aria-current': 'page', text: p.text })]));
}

export function empty(iconName, title, text, action) {
  return h('div', { class: 'empty' }, icon(iconName, 34), h('h2', { text: title }), text ? h('p', { text }) : null,
    action ? (action.href ? h('a', { class: 'btn primary', href: action.href }, action.label) : h('button', { class: 'btn primary', type: 'button', onclick: action.run }, action.label)) : null);
}

export function notFound(text) {
  return h('div', { class: 'page' }, empty('search', 'Not found', text, { label: 'Back to the overview', href: '#/' }));
}

export const kindHeading = (k) => kindTitle(k);
