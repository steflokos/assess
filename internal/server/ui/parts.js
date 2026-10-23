// SPDX-License-Identifier: Apache-2.0. Copyright 2026 Stefanos Flokos.
// Pieces that more than one page uses: findings, diffs, the effects of a change, breadcrumbs and empty states.

import { h, chip, plural } from './lib.js';
import { icon } from './icons.js';
import { recordAt, kindTitle, kindName, nameOf } from './data.js';
import { labelOf } from './form.js';

export const hrefOf = (...parts) => '#/' + parts.map(encodeURIComponent).join('/');
export const where = (d) => (d.file ? d.file + (d.line ? ':' + d.line + (d.column ? ':' + d.column : '') : '') : '');

// diagnostic is one finding: a message with where it is, linked to the record when there is one.
export function diagnostic(d) {
  const cls = d.severity === 'error' ? 'err' : 'warn';
  const real = d.file && d.file !== '<stdin>'; // a place in the change set is not a place in the project
  const at = real ? recordAt(d.file, d.line || 1) : null;
  return h('div', { class: 'alert ' + cls },
    h('span', { class: 'code', text: d.code }), ' ', d.message,
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
    h('span', { class: 'faint small', text: word }), chip(a, what + ', before the change'), h('span', { class: 'faint', text: '→' }), chip(b, what + ', after the change')));
  const rows = list.slice(0, 12).map((e) => {
    const b = e.before || {}, a = e.after || {};
    const label = e.kind === 'item' ? 'The item' : e.name || e.id;
    const note = !e.before ? 'new' : !e.after ? 'removed' : '';
    return h('div', { class: 'fx-row' },
      h('span', { class: 'fx-name', text: label }),
      note ? h('span', { class: 'tag', text: note }) : null,
      e.after || e.before ? [pair(b.base, a.base, 'Risk without the controls', 'without controls'), pair(b.residual, a.residual, 'Risk with the controls', 'with controls')] : null,
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

// ---- when someone else changed the files first --------------------------------------------------------------------------------------
const shown = (v) => (v === null || v === undefined ? 'not set' : typeof v === 'string' ? '"' + v + '"' : JSON.stringify(v));

// conflictText says in words what a conflict of apply means.
export function conflictText(c) {
  if (c.kind === 'file') return c.id + ' was changed on disk after you opened it.';
  const what = kindName(c.kind) + ' "' + nameOf(c.kind, c.id) + '"';
  if (c.reason === 'gone') return 'The ' + what + ' was deleted after you opened it.';
  if (c.reason === 'exists') return 'There is a ' + what + ' with this id already. Choose another id.';
  return labelOf(c.attribute) + ' of the ' + what + ' was ' + shown(c.was) + ' when you opened this page. It is ' + shown(c.now) + ' now.';
}

// conflicts shows what changed under a person and what to do about it. keep writes the change over theirs, and reload throws the
// change away and shows what is there. Nothing was written. An id that is taken is not a change by someone else, and has no reload:
// the person only has to choose another id.
export function conflicts(list, { keep, reload }) {
  if (list.length && list.every((c) => c.reason === 'exists')) {
    return h('div', { class: 'alert err conflict' }, h('strong', { text: 'That id is taken. Nothing was written.' }), h('ul', {}, list.map((c) => h('li', { text: conflictText(c) }))));
  }
  const gone = list.some((c) => c.reason === 'gone' || c.reason === 'exists');
  return h('div', { class: 'alert warn conflict' },
    h('strong', { text: 'Someone changed this after you opened it. Nothing was written.' }),
    h('ul', {}, list.map((c) => h('li', { text: conflictText(c) }))),
    h('div', { class: 'row' },
      keep && !gone ? h('button', { class: 'btn small', type: 'button', onclick: keep }, 'Keep my change') : null,
      reload ? h('button', { class: 'btn small', type: 'button', onclick: reload }, gone ? 'Reload' : 'Discard mine and reload') : null));
}
