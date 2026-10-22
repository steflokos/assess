// SPDX-License-Identifier: Apache-2.0. Copyright 2026 Stefanos Flokos.
// The pages that are not the page of one record: the overview with the next step, the lists, the decisions, what is open, the
// calculation, the report, the diagram, the iterations and the files.

import { h, put, clear, plural, debounce, ask, toast, api, plainText, chip, tokenValue, short, firstSentence, upper } from './lib.js';
import { icon, KIND_ICON } from './icons.js';
import { S, rec, nameOf, kindName, kindsName, kindTitle, kindOfId, workflow } from './data.js';
import { choice } from './form.js';
import { hrefOf, diagnostics, diagnostic, said, diff, effects, conflicts, crumbs, empty, notFound } from './parts.js';
import { signIteration } from './sign.js';

// ---- doing what a step of the path asks ---------------------------------------------------------------------------------------------
export async function act(action, ui) {
  if (action.go) { ui.go(...action.go); return; }
  if (action.generate) {
    const env = await api('/api/generate?what=' + action.generate, { method: 'POST', body: {} });
    await ui.refresh();
    toast((env.text || '').split('\n')[0] || (env.ok ? 'Done.' : (env.diagnostics[0] || {}).message || 'It did not work.'), env.ok ? 'ok' : 'err');
    return;
  }
  if (action.finalize) await finalizeDialog(ui);
}

async function finalizeDialog(ui) {
  const assessors = ((S.exp.project || {}).assessors || []).join(', ');
  const note = h('textarea', { rows: 2, 'aria-label': 'What this iteration was', placeholder: 'What this iteration was, in a sentence' });
  const by = h('input', { type: 'text', 'aria-label': 'Who closes it', placeholder: assessors || 'Names, separated by commas' });
  const out = h('div', {});
  const body = h('div', {}, h('div', { class: 'field' }, h('div', { class: 'flabel' }, h('label', { text: 'Note' })), note),
    h('div', { class: 'field' }, h('div', { class: 'flabel' }, h('label', { text: 'By' })), by, h('p', { class: 'doc', text: 'Leave it empty to use the assessors of project.yaml.' })), out);
  const payload = () => ({ note: note.value.trim(), by: by.value.split(',').map((s) => s.trim()).filter(Boolean) });
  body.append(h('div', { class: 'row' }, h('button', { class: 'btn', type: 'button', onclick: async () => {
    const env = await api('/api/finalize?dry=1', { method: 'POST', body: payload() });
    clear(out);
    put(out, env.ok ? h('div', { class: 'alert ok', text: 'This is what would be closed:' }) : h('div', { class: 'alert warn', text: 'It cannot be closed yet:' }), said(env), diagnostics((env.diagnostics || []).slice(0, 10)));
  } }, 'Preview')));
  if (!(await ask({ title: 'Close the iteration', body, ok: 'Close iteration' }))) return;
  const env = await api('/api/finalize', { method: 'POST', body: payload() });
  await ui.refresh();
  if (env.ok) toast('Iteration closed.');
  else await ask({ title: 'The iteration was not closed', noCancel: true, body: h('div', {}, said(env), diagnostics((env.diagnostics || []).slice(0, 10))) });
}

// ---- the overview ---------------------------------------------------------------------------------------------------------------------
function actionButton(a, ui) {
  return h('button', { class: 'btn ' + (a.primary ? 'primary' : ''), type: 'button', onclick: (e) => { e.currentTarget.disabled = true; act(a, ui).finally(() => { e.currentTarget.disabled = false; }); } }, a.label);
}

export function overview(ui) {
  const exp = S.exp, p = exp.project || {};
  const results = exp.results;
  const errors = S.diag.filter((d) => d.severity === 'error');
  const path = workflow();
  const next = path.find((s) => s.state === 'now');
  const page = h('div', { class: 'page' });
  page.append(h('div', { class: 'phead' }, h('div', { class: 'grow' }, h('h1', { text: p.name || 'Project' }), p.description ? h('p', { class: 'muted', text: p.description }) : null)));

  if (errors.length) {
    page.append(h('div', { class: 'card errors' }, h('h2', {}, icon('alert', 18), ' ' + plural(errors.length, 'error') + ' to fix first'),
      h('p', { class: 'muted', text: 'The calculation waits for them. Each one says where it is in the files.' }), diagnostics(errors.slice(0, 5)),
      errors.length > 5 ? h('p', { class: 'muted small', text: '… and ' + (errors.length - 5) + ' more below.' }) : null));
  }

  const left = h('div', { class: 'stack' });
  if (next) {
    left.append(h('div', { class: 'card next' }, h('div', { class: 'label', text: 'Next step, ' + next.n + ' of ' + path.length }),
      h('h2', { text: next.title }), h('p', { class: 'muted', text: next.text }),
      next.action ? h('div', { class: 'row' }, actionButton(Object.assign({}, next.action, { primary: true }), ui)) : h('p', { class: 'muted small', text: 'Finish the steps before it first.' })));
  } else {
    left.append(h('div', { class: 'card next done' }, h('div', { class: 'label', text: 'All seven steps are done' }), h('h2', {}, icon('checkCircle', 22), ' The assessment is closed'),
      h('p', { class: 'muted', text: 'Nothing is open and the last iteration is up to date. Open the report to share it.' }), h('div', { class: 'row' }, h('a', { class: 'btn primary', href: '#/report' }, 'Open the report'))));
  }
  left.append(h('div', { class: 'card' }, h('h2', { text: 'Your path' }), h('ol', { class: 'path' }, path.map((s) =>
    h('li', { class: s.state }, h('span', { class: 'num ' + s.state }, s.state === 'done' ? icon('check', 13) : s.n),
      h('div', { class: 'ptext' }, h('strong', { text: s.title }), h('div', { class: 'muted small', text: s.text })),
      s.action && s.state !== 'now' ? h('span', { class: 'pact' }, actionButton(Object.assign({}, s.action, { primary: false }), ui)) : null)))));

  const right = h('div', { class: 'stack' });
  if (results && S.threats.size) {
    const count = (which) => [1, 2, 3, 4, 5].map((n) => [...S.threats.values()].filter((t) => t.risk && t.risk[which] === n).length);
    const before = count('base'), after = count('residual');
    right.append(h('div', { class: 'card' }, h('h2', { text: 'Risk' }),
      h('div', { class: 'row', style: 'margin-bottom: 12px' }, h('span', { class: 'muted', text: 'The item' }), chip(results.item.base, 'Risk of the item before the controls'), h('span', { class: 'faint', text: '→' }), chip(results.item.residual, 'Risk of the item with the controls')),
      h('div', { class: 'bars' }, [0, 1, 2, 3, 4].map((i) => h('div', { class: 'col' }, chip(i + 1), h('div', { class: 'n', title: 'Before the controls', text: before[i] }), h('div', { class: 'n2', title: 'With the controls', text: after[i] })))),
      h('div', { class: 'legend small muted' }, h('span', { text: 'Upper number: before the controls' }), h('span', { text: 'Lower: with them' })),
      h('p', { class: 'muted small', text: plural(S.threats.size, 'threat scenario') + ', one risk each.' })));
  }
  const open = S.open.length;
  right.append(h('div', { class: 'card' }, h('h2', { text: 'What needs you' }),
    open ? h('p', {}, h('strong', { text: plural(open, 'item') }), ' open. ', h('a', { href: '#/open', text: 'See them' })) : h('p', { class: 'muted', text: results ? 'Nothing is open.' : 'Nothing yet.' }),
    S.diag.filter((d) => d.severity !== 'error').length ? h('p', { class: 'muted small', text: plural(S.diag.filter((d) => d.severity !== 'error').length, 'warning') + ' in the files.' }) : null));
  const its = exp.iterations || [];
  if (its.length) {
    const last = its[its.length - 1];
    right.append(h('div', { class: 'card' }, h('h2', { text: 'Last iteration' }), h('p', {}, h('strong', { text: 'Number ' + last.number }), h('span', { class: 'muted', text: ', closed ' + last.date })),
      h('a', { href: '#/iterations', text: 'See the iterations' })));
  }
  const facts = h('dl', { class: 'facts' });
  const add = (k, v) => { if (v) facts.append(h('dt', { text: k }), h('dd', { text: v })); };
  const item = (S.of.item || [])[0];
  add('Item', item ? nameOf('item', item.id) : '');
  add('Standards', (p.standards || []).join(', '));
  add('Assessors', (p.assessors || []).join(', '));
  add('Date', p.date);
  if (facts.children.length) right.append(h('div', { class: 'card' }, h('h2', { text: 'Project' }), facts));

  page.append(h('div', { class: 'cols2' }, left, right));
  const warnings = S.diag.filter((d) => d.severity !== 'error');
  if (warnings.length) page.append(h('div', { class: 'card' }, h('h2', { text: 'Warnings' }), diagnostics(warnings.slice(0, 20)), warnings.length > 20 ? h('p', { class: 'muted small', text: '… and ' + (warnings.length - 20) + ' more. Run assess validate for the whole list.' }) : null));
  return page;
}

// ---- lists ------------------------------------------------------------------------------------------------------------------------------
const initial = { Confidentiality: 'C', Integrity: 'I', Availability: 'A', Authenticity: 'Au', 'Non Repudiation': 'NR' };

// details is the one thing about a record that is worth seeing in a list, besides its name.
function details(kind, r) {
  const a = r.attributes || {};
  if (kind === 'risk') return h('span', { class: 'row tight' }, chip(a.base, 'Before the controls'), h('span', { class: 'faint', text: '→' }), chip(a.residual, 'With the controls'),
    a.treatment ? h('span', { class: 'tag', text: a.treatment }) : h('span', { class: 'tag warn', text: 'Undecided' }));
  if (kind === 'threat') { const t = S.threats.get(r.id); return t && t.risk ? h('span', { class: 'row tight' }, chip(t.risk.base), h('span', { class: 'faint', text: '→' }), chip(t.risk.residual)) : h('span', { class: 'faint small', text: 'Not calculated' }); }
  if (kind === 'asset') return h('span', { class: 'row tight' }, [].concat(a.properties || []).map((p) => h('span', { class: 'tag', title: p, text: initial[p] || p })));
  if (kind === 'step' && a.potential) return h('span', { class: 'mono small muted', text: ['time', 'expertise', 'knowledge', 'window', 'equipment'].map((k) => a.potential[k] || '–').join(' ') });
  return h('span', { class: 'muted small clamp', text: firstSentence(a.description) });
}

// the name of the record that a record is written inside
const parentName = (kind, r) => { const k = r.parent && kindOfId(r.parent, (S.kinds[kind] || {}).parents); return k ? nameOf(k, r.parent) : r.parent || ''; };

const sortValue = (kind, r, key) => {
  const a = r.attributes || {};
  if (key === 'name') return (a.name || r.id).toLowerCase();
  if (key === 'risk') { const t = S.threats.get(r.id); return kind === 'risk' ? (a.base || 0) : t && t.risk ? t.risk.base || 0 : 0; }
  if (key === 'inside') return parentName(kind, r).toLowerCase();
  return 0;
};

export function list(kind, ui) {
  const info = S.kinds[kind];
  if (!info) return notFound('There is no such kind of record: ' + kind);
  const rows = S.of[kind] || [];
  const state = { sort: '', dir: 1, q: '', only: kind === 'risk' && rows.some((r) => !(r.attributes || {}).treatment) ? 'undecided' : '' };
  const body = h('tbody');
  const count = h('span', { class: 'muted small' });
  const filter = h('input', { class: 'filter', type: 'search', placeholder: 'Filter by name or id', 'aria-label': 'Filter the list', oninput: () => { state.q = filter.value.trim().toLowerCase(); draw(); } });
  const nested = rows.some((r) => r.parent);
  const heads = [['name', 'Name'], [kind === 'risk' || kind === 'threat' ? 'risk' : '', 'Details'], ...(nested ? [['inside', 'Inside']] : [])];
  const th = heads.map(([key, text]) => h('th', { 'aria-sort': 'none' }, key ? h('button', { type: 'button', class: 'sort', onclick: () => {
    state.dir = state.sort === key ? -state.dir : 1;
    state.sort = key;
    draw();
  } }, text, h('span', { class: 'arrow' })) : text));

  const draw = () => {
    clear(body);
    let list = rows.filter((r) => {
      const name = ((r.attributes || {}).name || '').toLowerCase();
      if (state.q && !(name.includes(state.q) || r.id.toLowerCase().includes(state.q))) return false;
      if (state.only === 'undecided' && (r.attributes || {}).treatment) return false;
      return true;
    });
    if (state.sort) list = [...list].sort((a, b) => { const x = sortValue(kind, a, state.sort), y = sortValue(kind, b, state.sort); return (x < y ? -1 : x > y ? 1 : 0) * state.dir; });
    th.forEach((el, i) => { const key = heads[i][0]; el.setAttribute('aria-sort', key && key === state.sort ? (state.dir > 0 ? 'ascending' : 'descending') : 'none'); });
    for (const r of list) {
      const name = (r.attributes || {}).name || r.id;
      body.append(h('tr', { class: 'row-link', onclick: (e) => { if (!e.target.closest('a')) ui.go('kind', kind, r.id); } },
        h('td', {}, h('a', { class: 'nm', href: hrefOf('kind', kind, r.id), text: name }), h('div', { class: 'faint small mono', text: r.id })),
        h('td', {}, details(kind, r)),
        nested ? h('td', { class: 'muted small', text: parentName(kind, r) }) : null));
    }
    count.textContent = list.length === rows.length ? plural(rows.length, 'record') : list.length + ' of ' + plural(rows.length, 'record');
    if (!list.length) body.append(h('tr', {}, h('td', { colspan: heads.length, class: 'muted center', text: 'Nothing matches.' })));
  };
  draw();

  const page = h('div', { class: 'page' }, crumbs({ text: kindTitle(kind) }),
    h('div', { class: 'phead' }, h('div', { class: 'grow' }, h('h1', { text: kindTitle(kind) }), h('p', { class: 'muted', text: info.doc })),
      h('a', { class: 'btn primary', href: hrefOf('new', kind) }, icon('plus', 15), 'New ' + info.name)));
  if (!rows.length) {
    page.append(h('div', { class: 'card' }, empty(KIND_ICON[kind] || 'circle', 'No ' + kindsName(kind) + ' yet', 'Add the first one. ' + firstSentence(info.doc), { label: 'New ' + info.name, href: hrefOf('new', kind) })));
    return page;
  }
  const tools = h('div', { class: 'row', style: 'margin-bottom: 12px' }, filter, count);
  if (kind === 'risk') {
    const undecided = rows.filter((r) => !(r.attributes || {}).treatment).length;
    const seg = choice({ values: ['', 'undecided'], text: (v) => (v ? 'Undecided (' + undecided + ')' : 'All (' + rows.length + ')'), label: 'Which risks', value: state.only, required: true, onChange: () => { state.only = seg.get(); draw(); } });
    tools.append(seg.node, h('a', { class: 'btn', href: '#/decisions' }, 'Decide in a table'));
  }
  page.append(tools, h('div', { class: 'card flush scroll' }, h('table', { class: 't' }, h('thead', {}, h('tr', {}, th)), body)));
  return page;
}

// ---- the decisions --------------------------------------------------------------------------------------------------------------------------
// One table for the decision on every risk. A person decides a whole assessment here, and the changes are checked and saved together.
export function decisions(ui) {
  const risks = S.of.risk || [];
  const info = S.kinds.risk;
  const treatments = ((info && info.attributes.find((a) => a.name === 'treatment')) || {}).values || ['Avoid', 'Reduce', 'Share', 'Accept'];
  const page = h('div', { class: 'page wide' }, crumbs({ text: 'Risks', href: hrefOf('kind', 'risk') }, { text: 'Decisions' }));
  page.append(h('div', { class: 'phead' }, h('div', { class: 'grow' }, h('h1', { text: 'Decisions' }),
    h('p', { class: 'muted', text: 'What you do about each risk: avoid it, reduce it, share it or accept it. Changes are checked together and saved together.' }))));
  if (!risks.length) {
    page.append(h('div', { class: 'card' }, empty('scale', 'No risks yet', 'assess writes a risk for each threat scenario once it can be calculated.', S.exp.results && S.threats.size ? { label: 'Write the risks', run: () => act({ generate: 'risks' }, ui) } : null)));
    return page;
  }

  const pending = new Map(); // risk id to what changed
  const state = { only: risks.some((r) => !(r.attributes || {}).treatment) ? 'undecided' : '', q: '' };
  const body = h('tbody');
  const status = h('div', { 'aria-live': 'polite' });
  const save = h('button', { class: 'btn primary', type: 'button', disabled: true }, 'Save');
  let seq = 0;

  // each change expects to find what the page read, so that a decision that someone else made in the meantime is not overwritten
  const changes = () => [...pending.entries()].map(([id, c]) => ({
    op: 'put', kind: 'risk', id, attributes: c,
    was: Object.fromEntries(Object.keys(c).map((k) => [k, (rec('risk', id).attributes || {})[k] === undefined ? null : rec('risk', id).attributes[k]])),
  })).filter((c) => Object.keys(c.attributes).length);
  const clash = (env) => {
    const list = (env.result || {}).conflicts || [];
    if (!list.length) return false;
    clear(status);
    put(status, conflicts(list, { reload: async () => { pending.clear(); ui.setDirty(false); await ui.refresh(); } }));
    return true;
  };
  const check = async () => {
    const mine = ++seq;
    const list = changes();
    clear(status);
    save.disabled = true;
    save.textContent = 'Save';
    if (!list.length) return;
    const env = await api('/api/apply?dry=1', { method: 'POST', body: { apiVersion: S.apiVersion, changes: list } });
    if (mine !== seq) return;
    clear(status);
    if (clash(env)) return;
    if (!env.ok) { status.append(diagnostics((env.diagnostics || []).slice(0, 10))); return; }
    save.textContent = 'Save ' + plural(list.length, 'decision');
    save.disabled = false;
  };
  const checkLater = debounce(check, 350);
  const touch = () => { ui.setDirty(pending.size > 0); clear(status); if (pending.size) status.append(h('p', { class: 'muted small', text: 'Checking…' })); save.disabled = true; checkLater(); };
  const set = (r, key, value) => {
    const a = r.attributes || {};
    const c = pending.get(r.id) || {};
    if ((value || '') === (a[key] || '')) delete c[key]; else c[key] = value === '' ? null : value;
    if (Object.keys(c).length) pending.set(r.id, c); else pending.delete(r.id);
    touch();
  };

  const draw = () => {
    clear(body);
    const shown = risks.filter((r) => {
      const a = r.attributes || {};
      const name = (a.name || '').toLowerCase();
      if (state.q && !(name.includes(state.q) || r.id.toLowerCase().includes(state.q))) return false;
      return state.only !== 'undecided' || !a.treatment;
    });
    for (const r of shown) {
      const a = r.attributes || {};
      const t = S.threats.get(r.id);
      const treat = choice({ values: treatments, label: 'Treatment of ' + (a.name || r.id), value: (pending.get(r.id) || {}).treatment !== undefined ? (pending.get(r.id) || {}).treatment : a.treatment, required: false, onChange: () => set(r, 'treatment', treat.get() || '') });
      const why = h('textarea', { rows: 2, placeholder: 'Why this decision', 'aria-label': 'Why this decision for ' + (a.name || r.id), oninput: () => set(r, 'rationale', why.value) });
      why.value = (pending.get(r.id) || {}).rationale !== undefined ? (pending.get(r.id) || {}).rationale || '' : a.rationale || '';
      const wrap = h('div', { hidden: true }, why);
      body.append(h('tr', {},
        h('td', {}, h('a', { class: 'nm', href: hrefOf('kind', 'risk', r.id), text: a.name || r.id }), h('div', { class: 'faint small mono', text: r.id })),
        h('td', {}, h('span', { class: 'row tight' }, chip(a.base, 'Before the controls'), h('span', { class: 'faint', text: '→' }), chip(a.residual, 'With the controls'), a.type ? h('span', { class: 'tag', text: a.type }) : null)),
        h('td', {}, treat.node, h('button', { type: 'button', class: 'linkish', title: why.value, onclick: () => { wrap.hidden = !wrap.hidden; if (!wrap.hidden) why.focus(); } }, why.value ? 'Show the reason' : 'Add a reason'), wrap)));
    }
    if (!shown.length) body.append(h('tr', {}, h('td', { colspan: 3, class: 'muted center', text: state.only === 'undecided' ? 'Every risk has a decision.' : 'Nothing matches.' })));
  };
  draw();

  const undecided = risks.filter((r) => !(r.attributes || {}).treatment).length;
  const seg = choice({ values: ['', 'undecided'], text: (v) => (v ? 'Undecided (' + undecided + ')' : 'All (' + risks.length + ')'), label: 'Which risks', value: state.only, required: true, onChange: () => { state.only = seg.get(); draw(); } });
  const filter = h('input', { class: 'filter', type: 'search', placeholder: 'Filter by name or id', 'aria-label': 'Filter the risks', oninput: () => { state.q = filter.value.trim().toLowerCase(); draw(); } });

  save.addEventListener('click', async () => {
    const list = changes();
    if (!list.length || save.disabled) return;
    save.disabled = true;
    const env = await api('/api/apply', { method: 'POST', body: { apiVersion: S.apiVersion, changes: list } });
    if (clash(env)) return;
    if (!env.ok) { clear(status); status.append(diagnostics((env.diagnostics || []).slice(0, 10))); return; }
    const back = list.map((c) => ({ op: 'put', kind: 'risk', id: c.id, attributes: c.was, was: c.attributes }));
    pending.clear();
    ui.setDirty(false);
    await ui.refresh();
    toast('Saved ' + plural(list.length, 'decision') + '.', 'ok', { label: 'Undo', run: async () => {
      const undone = await api('/api/apply', { method: 'POST', body: { apiVersion: S.apiVersion, changes: back } });
      await ui.refresh();
      toast(undone.ok ? 'Undone.' : ((undone.result || {}).conflicts || []).length ? 'Someone changed it since. It was not undone.' : 'That could not be undone.', undone.ok ? 'ok' : 'err');
    } });
  });
  // Ctrl S saves the decisions, for as long as this page is on the screen.
  const keySave = () => save.click();
  window.addEventListener('assess:save', keySave);
  window.addEventListener('assess:leave', () => window.removeEventListener('assess:save', keySave), { once: true });

  page.append(h('div', { class: 'row', style: 'margin-bottom: 12px' }, filter, seg.node),
    h('div', { class: 'card flush scroll' }, h('table', { class: 't decide' }, h('thead', {}, h('tr', {}, ['Risk', 'Value', 'Treatment'].map((t) => h('th', { text: t })))), body)),
    h('div', { class: 'sticky' }, status, h('div', { class: 'row' }, save, h('span', { class: 'faint small', text: 'Ctrl S' }))));
  return page;
}

// ---- what is open --------------------------------------------------------------------------------------------------------------------------
const OPEN_TITLES = {
  'no-item': 'No item yet', 'policy-gap': 'The policy lacks values', 'not-calculated': 'Cannot be calculated', 'risk-not-calculated': 'Risk cannot be calculated',
  'damage-uncaused': 'No threat scenario causes it', 'no-risks': 'No risks yet', 'risk-missing': 'Risk missing', 'risk-stale': 'Risk out of date',
  'no-treatment': 'Needs a decision', 'rule-finding': 'Found by a rule', 'rule-not-checked': 'A rule could not be checked',
};

export function openItems(ui) {
  const items = S.open;
  const page = h('div', { class: 'page' }, crumbs({ text: 'Open items' }), h('div', { class: 'phead' }, h('div', { class: 'grow' }, h('h1', { text: 'Open items' }),
    h('p', { class: 'muted', text: 'What is not calculated, what has no decision yet and what the rules found. It is the same list as in the report.' }))));
  if (!S.exp.results) page.append(h('div', { class: 'alert warn', text: 'The project has errors, so the list is not there yet. See the findings in the overview.' }));
  else if (!items.length) page.append(h('div', { class: 'card' }, empty('checkCircle', 'Nothing is open', 'Every threat scenario is calculated and every risk has its decision.')));
  else page.append(h('div', { class: 'card flush scroll' }, h('table', { class: 't' }, h('thead', {}, h('tr', {}, ['What', 'Where', 'Details'].map((t) => h('th', { text: t })))),
    h('tbody', {}, items.map((it) => h('tr', {},
      h('td', {}, h('span', { class: 'tag info', text: OPEN_TITLES[it.code] || it.code })),
      h('td', {}, it.kind && it.id && rec(it.kind, it.id) ? h('a', { class: 'nm', href: hrefOf('kind', it.kind, it.id), text: nameOf(it.kind, it.id) }) : h('span', { class: 'mono small', text: it.where || '' })),
      h('td', { class: 'muted', text: it.text })))))));
  const write = (label, what, text) => h('div', { class: 'card' }, h('h3', { text: label }), h('p', { class: 'muted small', text }), actionButton({ label, generate: what }, ui));
  page.append(h('h2', { class: 'sect', text: 'Let assess write records' }), h('div', { class: 'grid3' },
    write('Write assets', 'assets', 'An asset for every element of the architecture, with all five properties. It is written once.'),
    write('Write threat scenarios', 'threats', 'One for each asset property that has none. What exists stays as it is.'),
    write('Write risks', 'risks', 'The risk of each threat scenario, with its two values. Your decisions stay.')));
  return page;
}

// ---- calculation, report, diagram, iterations, files -----------------------------------------------------------------------------
export function calc() {
  const r = S.exp.results;
  const page = h('div', { class: 'page' }, crumbs({ text: 'Calculation' }), h('div', { class: 'phead' }, h('div', { class: 'grow' }, h('h1', { text: 'Calculation' }),
    h('p', { class: 'muted', text: 'The risk of each threat scenario, before the controls and with them. Open one to see how each number came out.' }))));
  if (!r) { page.append(h('div', { class: 'alert warn', text: 'The project has errors, so nothing is calculated yet.' })); return page; }
  page.append(h('div', { class: 'card' }, h('div', { class: 'row' }, h('strong', { text: 'The item' }), chip(r.item.base, 'Before the controls'), h('span', { class: 'muted', text: 'before, decided by' }),
    r.item.baseBy ? h('a', { href: hrefOf('kind', 'damage', r.item.baseBy), class: 'cp link', text: nameOf('damage', r.item.baseBy) || r.item.baseBy }) : null,
    chip(r.item.residual, 'With the controls'), h('span', { class: 'muted', text: 'with the controls' }))));
  page.append(h('div', { class: 'card flush scroll' }, h('table', { class: 't' },
    h('thead', {}, h('tr', {}, ['Threat scenario', 'Before', 'With controls', 'Type', 'Feasibility'].map((t) => h('th', { text: t })))),
    h('tbody', {}, r.threats.map((t) => h('tr', {},
      h('td', {}, h('a', { class: 'nm', href: hrefOf('calc', t.threat), text: t.name || t.threat }), h('div', { class: 'faint small mono', text: t.threat })),
      h('td', {}, chip(t.risk && t.risk.base, 'Before the controls')), h('td', {}, chip(t.risk && t.risk.residual, 'With the controls')),
      h('td', { text: (t.risk && t.risk.type) || '' }),
      h('td', { class: 'small', text: (t.base && t.base.level ? t.base.level : '–') + ' → ' + (t.residual && t.residual.level ? t.residual.level : '–') })))))));
  return page;
}

export function explain(id) {
  const pre = h('pre', { class: 'plain', text: 'Loading…' });
  plainText('/api/explain-text?id=' + encodeURIComponent(id)).then((t) => { pre.textContent = t; });
  return h('div', { class: 'page' }, crumbs({ text: 'Calculation', href: '#/calc' }, { text: nameOf('threat', id) }),
    h('div', { class: 'phead' }, h('div', { class: 'grow' }, h('div', { class: 'label', text: 'Worksheet' }), h('h1', { text: nameOf('threat', id) }), h('div', { class: 'idline' }, h('code', { text: id }))),
      rec('threat', id) ? h('a', { class: 'btn', href: hrefOf('kind', 'threat', id) }, 'Open the record') : null, h('a', { class: 'btn', href: hrefOf('diagram', id) }, 'Attack tree')), pre);
}

// The report is shown from the other name of this server (localhost and 127.0.0.1 are different origins for a browser), so the page of
// the report cannot read anything that this page keeps. A sandbox attribute would do the same, but a browser may refuse to load a
// sandboxed frame from the local computer.
const otherHost = () => (location.hostname === 'localhost' ? '127.0.0.1' : 'localhost');
const reportURL = (more) => location.protocol + '//' + otherHost() + ':' + location.port + '/report?t=' + encodeURIComponent(tokenValue()) + (more || '');

export function reportView() {
  const frame = h('iframe', { class: 'frame', title: 'The report', src: reportURL('&v=' + Date.now()) });
  return h('div', { class: 'page wide' }, crumbs({ text: 'Report' }), h('div', { class: 'phead' }, h('div', { class: 'grow' }, h('h1', { text: 'Report' }),
    h('p', { class: 'muted', text: 'The same page that assess report writes. It is built from the files when you open it.' })),
    h('button', { class: 'btn', type: 'button', onclick: () => { frame.src = reportURL('&v=' + Date.now()); } }, 'Build again'),
    h('a', { class: 'btn', target: '_blank', rel: 'noopener', href: reportURL() }, icon('external', 15), 'Open in a new tab')), frame);
}

export function diagramView(id, ui) {
  const picture = h('div', { class: 'diagram' });
  picture.append(h('img', { alt: id ? 'The attack tree of ' + id : 'The architecture of the item',
    src: '/diagram.svg?t=' + encodeURIComponent(tokenValue()) + (id ? '&threat=' + encodeURIComponent(id) : '') + '&v=' + Date.now() }));
  const pick = h('select', { 'aria-label': 'What to draw', onchange: () => ui.go('diagram', ...(pick.value ? [pick.value] : [])) },
    h('option', { value: '', text: 'The architecture' }), [...S.threats.keys()].map((t) => h('option', { value: t, text: 'Attack tree: ' + nameOf('threat', t) })));
  pick.value = id || '';
  return h('div', { class: 'page wide' }, crumbs({ text: 'Diagram' }), h('div', { class: 'phead' }, h('div', { class: 'grow' }, h('h1', { text: 'Diagram' })), h('div', { style: 'min-width: 18rem' }, pick)), picture);
}

async function signDialog(it, ui) {
  const prefix = ((S.desc || {}).signing || {}).messagePrefix;
  const file = h('input', { type: 'file', accept: '.pem,.key,.txt', 'aria-label': 'Your private key' });
  const by = h('input', { type: 'text', 'aria-label': 'Your name', value: (it.by || [])[0] || ((S.exp.project || {}).assessors || [])[0] || '' });
  const out = h('div', {});
  const body = h('div', {},
    h('p', { class: 'muted', text: 'The page makes the signature here, in your browser, with the key that you choose. The key is not sent to the server and it is not kept. The server gets only the signature and the public key, and assess checks them against the iteration.' }),
    h('div', { class: 'field' }, h('div', { class: 'flabel' }, h('label', { text: 'Your private key' })), file,
      h('p', { class: 'doc', text: 'An ed25519 key in PKCS#8 form without a passphrase, as openssl genpkey -algorithm ed25519 writes it.' })),
    h('div', { class: 'field' }, h('div', { class: 'flabel' }, h('label', { text: 'Your name' })), by), out);
  const dlg = await ask({ title: 'Sign iteration ' + it.number, body, ok: 'Sign' });
  if (!dlg) return;
  const fail = (msg) => ask({ title: 'The iteration was not signed', noCancel: true, body: h('div', { class: 'alert err', text: msg }) });
  if (!file.files.length) { await fail('Choose the file of your private key first.'); return; }
  let made;
  try {
    made = await signIteration(await file.files[0].text(), prefix, it.hash);
  } catch (e) {
    await fail(e.message);
    return;
  } finally {
    file.value = '';
  }
  const env = await api('/api/sign', { method: 'POST', body: { iteration: it.number, by: by.value.trim(), public: made.public, signature: made.signature } });
  await ui.refresh();
  if (env.ok) toast('Signed iteration ' + it.number + '.');
  else await fail((env.diagnostics[0] || {}).message || 'The signature was not accepted.');
}

export function iterations(ui) {
  const its = S.exp.iterations || [];
  const out = h('div', {});
  const check = h('button', { class: 'btn', type: 'button', onclick: async () => {
    const env = await api('/api/verify');
    clear(out);
    put(out, h('div', { class: 'alert ' + (env.ok ? 'ok' : 'err'), text: env.ok ? 'The chain is intact.' : 'The chain is not intact.' }), said(env), diagnostics((env.diagnostics || []).slice(0, 20)));
  } }, 'Check the chain');
  const page = h('div', { class: 'page' }, crumbs({ text: 'Iterations' }), h('div', { class: 'phead' }, h('div', { class: 'grow' }, h('h1', { text: 'Iterations' }),
    h('p', { class: 'muted', text: 'Each closed iteration holds the treatment decisions of one round. They are linked by hashes, so a later change to one is found. A signature says who stands behind a round.' })), check), out);
  if (!its.length) page.append(h('div', { class: 'card' }, empty('clock', 'No iteration is closed yet', 'Close one when every risk has its decision.')));
  else page.append(h('div', { class: 'card flush scroll' }, h('table', { class: 't' },
    h('thead', {}, h('tr', {}, ['No.', 'Date', 'By', 'Note', 'Decisions', 'Hash', 'Signed by', ''].map((t) => h('th', { text: t })))),
    h('tbody', {}, its.map((i) => h('tr', {}, h('td', { class: 'num', text: i.number }), h('td', { class: 'small', text: i.date }), h('td', { text: (i.by || []).join(', ') }),
      h('td', { text: i.note || '' }), h('td', { class: 'num', text: (i.decisions || []).length }), h('td', { class: 'mono small', text: short(i.hash) }),
      h('td', {}, (i.signatures || []).length ? (i.signatures || []).map((s) => h('div', { class: 'small', title: s.key, text: s.by })) : h('span', { class: 'faint small', text: 'Not signed' })),
      h('td', {}, h('button', { class: 'btn small', type: 'button', onclick: () => signDialog(i, ui) }, icon('pen', 14), 'Sign…'))))))));
  return page;
}

// ---- the plain files ----------------------------------------------------------------------------------------------------------------
// assess.yaml, project.yaml and the policy are written as a whole. The text is checked in a copy first, as a record is: the errors have
// their place in the file, the lines that change are shown as a diff, and the page says which results would move. A change to a number of
// the policy shows which risks it moves.
let openFile = '';

// offsetOf is where a line and a column of a text start, for putting the caret on an error.
function offsetOf(text, line, column) {
  let at = 0;
  for (let i = 1; i < line; i++) { const n = text.indexOf('\n', at); if (n < 0) break; at = n + 1; }
  return Math.min(text.length, at + Math.max((column || 1) - 1, 0));
}

function fileEditor(name, ui) {
  const info = ((S.desc || {}).files || []).find((f) => f.file === name) || {};
  let was = S.exp.texts[name].hash;
  const original = S.exp.texts[name].text;
  const ta = h('textarea', { class: 'filetext mono', rows: 26, spellcheck: 'false', wrap: 'off', 'aria-label': name, oninput: () => changed() });
  ta.value = original;
  const status = h('div', { 'aria-live': 'polite' });
  const save = h('button', { class: 'btn primary', type: 'button', disabled: true }, 'Save');
  const discard = h('button', { class: 'btn', type: 'button', onclick: () => { ui.setDirty(false); ui.render(); } }, 'Discard changes');
  let seq = 0;

  const set = () => ({ apiVersion: S.apiVersion, changes: [{ op: 'write', file: name, text: ta.value, was }] });
  // an error has a line and a column of this text. A click puts the caret there.
  const errors = (list) => {
    const f = document.createDocumentFragment();
    for (const d of list) {
      f.append(h('div', { class: 'alert ' + (d.severity === 'error' ? 'err' : 'warn') }, h('span', { class: 'code', text: d.code }), d.message,
        d.line ? h('div', { class: 'where' }, h('button', { type: 'button', class: 'linkish', onclick: () => {
          const at = offsetOf(ta.value, d.line, d.column);
          ta.focus();
          ta.setSelectionRange(at, at);
          ta.scrollTop = Math.max(0, (d.line - 4) * (parseFloat(getComputedStyle(ta).lineHeight) || 20));
        } }, name + ':' + d.line + (d.column ? ':' + d.column : ''))) : null));
    }
    return f;
  };
  const clash = (env) => {
    const list = (env.result || {}).conflicts || [];
    if (!list.length) return false;
    clear(status);
    put(status, conflicts(list, {
      keep: () => { was = list[0].now; check(); },
      reload: async () => { ui.setDirty(false); await ui.refresh(); },
    }));
    return true;
  };

  const check = async () => {
    const mine = ++seq;
    clear(status);
    save.disabled = true;
    if (ta.value === original) { status.append(h('p', { class: 'muted small', text: 'No changes yet.' })); return; }
    const env = await api('/api/apply?dry=1', { method: 'POST', body: set() });
    if (mine !== seq) return;
    clear(status);
    if (clash(env)) return;
    const found = (env.diagnostics || []).filter((d) => d.severity === 'error');
    if (!env.ok) { put(status, found.length ? errors(found.slice(0, 20)) : h('div', { class: 'alert err', text: env.text || 'The file cannot be written.' })); return; }
    const r = env.result || {};
    put(status, h('div', { class: 'alert ok', text: 'The file is valid.' }), effects(r.effects), h('details', { class: 'lines', open: true }, h('summary', { text: 'The lines that change' }), diff(r.diff)));
    save.disabled = false;
  };
  const checkLater = debounce(check, 600);
  function changed() { ui.setDirty(true); clear(status); status.append(h('p', { class: 'muted small', text: 'Checking…' })); save.disabled = true; checkLater(); }

  async function doSave() {
    if (save.disabled) return;
    save.disabled = true;
    const env = await api('/api/apply', { method: 'POST', body: set() });
    if (clash(env)) return;
    if (!env.ok) { clear(status); put(status, errors((env.diagnostics || []).slice(0, 20))); return; }
    ui.setDirty(false);
    await ui.refresh();
    toast('Saved ' + name + '.', 'ok', { label: 'Undo', run: async () => {
      const undone = await api('/api/apply', { method: 'POST', body: { apiVersion: S.apiVersion, changes: [{ op: 'write', file: name, text: original, was: S.exp.texts[name].hash }] } });
      await ui.refresh();
      toast(undone.ok ? 'Undone.' : 'That could not be undone.', undone.ok ? 'ok' : 'err');
    } });
  }
  save.addEventListener('click', doSave);
  window.addEventListener('assess:save', doSave);
  window.addEventListener('assess:leave', () => window.removeEventListener('assess:save', doSave), { once: true });

  return h('div', {}, info.doc ? h('p', { class: 'muted', text: info.doc }) : null, ta, h('div', { class: 'sticky' }, status, h('div', { class: 'row' }, save, discard, h('span', { class: 'faint small', text: 'Ctrl S' }))));
}

export function files(ui) {
  const names = Object.keys(S.exp.texts || {});
  if (!names.includes(openFile)) openFile = names[0];
  const panel = h('div', {});
  const draw = () => { clear(panel); panel.append(fileEditor(openFile, ui)); };
  const pick = choice({ values: names, label: 'File', value: openFile, required: true, onChange: () => {
    if (ui.dirty() && !confirm('Leave this file without saving your changes?')) { pick.set(openFile); return; }
    ui.setDirty(false);
    openFile = pick.get();
    draw();
  } });
  draw();
  return h('div', { class: 'page wide' }, crumbs({ text: 'Files' }), h('div', { class: 'phead' }, h('div', { class: 'grow' }, h('h1', { text: 'Files' }),
    h('p', { class: 'muted', text: 'The settings of the project, as they are written. Every change is checked first, with the lines that change and the results that move. Comments stay.' }))),
    h('div', { class: 'row', style: 'margin-bottom: 12px' }, pick.node), panel);
}

// ---- a folder with no project -------------------------------------------------------------------------------------------------------
export function welcome(ui) {
  return h('div', { class: 'page' }, h('div', { class: 'card' }, empty('sparkle', 'There is no project in this folder yet',
    'Create one and assess writes what you need: the folders for the item and the analysis, a policy with the values of the standard to check, a few rules and the settings for your editor. Then the page guides you through the steps.',
    { label: 'Create a project here', run: async () => {
      const env = await api('/api/init', { method: 'POST', body: {} });
      if (!env.ok) { await ask({ title: 'The project was not created', noCancel: true, body: h('div', { class: 'alert err', text: (env.diagnostics[0] || {}).message || 'init failed' }) }); return; }
      toast('Project created.');
      await ui.refresh();
    } })));
}
