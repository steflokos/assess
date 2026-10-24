// SPDX-License-Identifier: Apache-2.0. Copyright 2026 Stefanos Flokos.
// The page of one record: the form on one side, and what the record is connected to on the other. Every change is checked with a dry
// run of assess apply first. The page shows the errors with their place in the files, the lines that would change and what the change
// does to the calculation. Only apply writes.

import { h, put, clear, plural, debounce, ask, toast, api, chip, upper, mod } from './lib.js';
import { icon, KIND_ICON } from './icons.js';
import { S, rec, nameOf, kindName, kindTitle } from './data.js';
import { recordForm, chipPicker, readOnly, inSchemaOrder, shell } from './form.js';
import { hrefOf, diagnostics, diff, effects, conflicts, crumbs, notFound } from './parts.js';

const changeSet = (changes) => ({ apiVersion: S.apiVersion, changes });

export function editor(kind, id, isNew, ui) {
  const info = S.kinds[kind];
  if (!info) return notFound('There is no such kind of record: ' + kind);
  const existing = isNew ? null : rec(kind, id);
  if (!isNew && !existing) return notFound('There is no ' + info.name + ' with the id ' + id + '.');
  const original = existing ? existing.attributes || {} : {};
  // what the page read, which a change says it expects to find. If someone else changed a value and this person decides to keep their
  // own change, the value that is there now becomes the one that is expected.
  const baseline = Object.assign({}, original);

  // ---- the id and the parent of a new record
  let idCtl = null, parentCtl = null, byHand = false;
  const top = [];
  const slug = (t) => String(t || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48).replace(/-+$/, '');
  if (isNew) {
    const taken = new Set((S.of[kind] || []).map((r) => r.id));
    if (info.idOf && info.idOf.length) {
      idCtl = chipPicker({ kinds: info.idOf, multiple: false, value: undefined, exclude: taken, placeholder: 'Choose the ' + info.idOf.join(' or ') + '…', label: 'The record this one is about', onChange: () => changed() });
      const pool = idCtl;
      idCtl = { node: pool.node, get: () => { const v = pool.get(); return v && !taken.has(v) ? v : undefined; } };
    } else {
      const input = h('input', { type: 'text', class: 'mono', placeholder: 'Made from the name', spellcheck: 'false', 'aria-label': 'Id', oninput: () => { byHand = true; changed(); } });
      idCtl = { node: input, get: () => input.value.trim() || undefined, focus: () => input.focus(), fill: (name) => {
        if (byHand) return;
        const base = slug(name);
        let id = base, n = 2;
        while (base && taken.has(id)) id = base + '-' + n++;
        input.value = id;
      } };
    }
    top.push(shell('Id', true, info.idOf && info.idOf.length
      ? 'It is the id of the ' + info.idOf.join(' or ') + ' that this record is about.'
      : 'The short name that other records use to refer to this one. It is made from the name, and you can write your own. Letters, digits, hyphens, dots and underscores.', idCtl.node));
    if (info.parents && info.parents.length) {
      parentCtl = chipPicker({ kinds: info.parents, multiple: false, value: undefined, placeholder: info.topLevel ? 'Not inside another record' : 'Choose…', label: 'Parent', onChange: () => changed() });
      top.push(shell('Written inside', !info.topLevel, 'The record that this one is part of: ' + info.parents.join(' or ') + '.', parentCtl.node));
    }
  }

  // ---- checking and saving
  const status = h('div', { 'aria-live': 'polite' });
  const save = h('button', { class: 'btn primary', type: 'button', disabled: true }, isNew ? 'Create' : 'Save');
  const discard = h('button', { class: 'btn', type: 'button', onclick: () => { ui.setDirty(false); if (isNew) ui.go('kind', kind); else ui.render(); } }, isNew ? 'Cancel' : 'Discard changes');
  let seq = 0, waiting = false;
  const form = recordForm(kind, original, () => changed());

  const build = () => {
    const { attrs, invalid } = form.changes();
    if (invalid) return { error: 'One of the fields holds text that is not valid JSON.' };
    const n = Object.keys(attrs).length;
    if (isNew) {
      const newId = idCtl.get();
      if (!newId) return { error: 'Give the new record an id.' };
      const change = { op: 'put', kind, id: newId, attributes: attrs, new: true };
      const parent = parentCtl && parentCtl.get();
      if (parent) change.parent = parent;
      return { set: changeSet([change]), id: newId, n };
    }
    if (!n) return { none: true };
    const was = Object.fromEntries(Object.keys(attrs).map((k) => [k, baseline[k] === undefined ? null : baseline[k]]));
    return { set: changeSet([{ op: 'put', kind, id, attributes: attrs, was }]), id, n, attrs };
  };

  const check = async () => {
    const mine = ++seq;
    const b = build();
    clear(status);
    save.disabled = true;
    if (b.error) { waiting = false; status.append(h('div', { class: 'alert info', text: b.error })); return; }
    if (b.none) { waiting = false; ui.setDirty(false); status.append(h('p', { class: 'muted small', text: 'No changes yet.' })); save.textContent = 'Save'; return; }
    const env = await api('/api/apply?dry=1', { method: 'POST', body: b.set });
    if (mine !== seq) return; // a newer check is on its way
    waiting = false
    clear(status);
    const errors = (env.diagnostics || []).filter((d) => d.severity === 'error');
    const clash = (env.result || {}).conflicts || [];
    if (clash.length) { showConflicts(clash); return; }
    if (!env.ok) {
      status.append(errors.length ? diagnostics(errors.slice(0, 20)) : h('div', { class: 'alert err', text: env.text || 'The change cannot be applied.' }));
      return;
    }
    const r = env.result || {};
    put(status, h('div', { class: 'alert ok', text: isNew ? 'This record can be created.' : 'The change is valid.' }), effects(r.effects),
      h('details', { class: 'lines' }, h('summary', { text: 'Show the lines that change in ' + plural((r.files || []).length, 'file') }), diff(r.diff)));
    save.textContent = isNew ? 'Create' : b.n === 1 ? 'Save 1 change' : 'Save ' + b.n + ' changes';
    save.disabled = false;
  };
  const checkLater = debounce(check, 450);
  function changed() {
    seq++; // an answer to an earlier check is not about this text any more
    waiting = true;
    if (idCtl && idCtl.fill) idCtl.fill(form.changes().attrs.name);
    ui.setDirty(true);
    clear(status);
    status.append(h('p', { class: 'muted small', text: 'Checking…' }));
    save.disabled = true;
    checkLater();
  }

  // someone else changed what this page read. The person decides: keep their own change over it, or reload and see what is there.
  function showConflicts(list) {
    clear(status);
    put(status, conflicts(list, {
      keep: () => {
        for (const c of list) if (c.attribute) baseline[c.attribute] = c.now === undefined || c.now === null ? undefined : c.now;
        check();
      },
      reload: async () => { ui.setDirty(false); await ui.refresh(); if (!rec(kind, id)) ui.go('kind', kind); },
    }));
  }

  async function doSave() {
    if (waiting) { checkLater.cancel(); await check(); } // Ctrl S while the page is still checking waits for the check
    if (save.disabled) return;
    const b = build();
    if (!b.set) return;
    save.disabled = true;
    const env = await api('/api/apply', { method: 'POST', body: b.set });
    if (((env.result || {}).conflicts || []).length) { showConflicts(env.result.conflicts); return; }
    if (!env.ok) {
      clear(status);
      status.append((env.diagnostics || []).length ? diagnostics(env.diagnostics.slice(0, 20)) : h('div', { class: 'alert err', text: env.text || 'The change was not written.' }));
      return;
    }
    ui.setDirty(false);
    await ui.refresh();
    // Undo puts the old values back, or removes what was created.
    // Undo expects to find what was just written, so that it does not undo over a change that someone made since.
    const back = isNew ? [{ op: 'delete', kind, id: b.id }]
      : [{ op: 'put', kind, id, attributes: Object.fromEntries(Object.keys(b.attrs).map((k) => [k, baseline[k] === undefined ? null : inSchemaOrder(kind, info.attributes.find((a) => a.name === k) || { name: k }, baseline[k])])),
        was: Object.fromEntries(Object.keys(b.attrs).map((k) => [k, b.attrs[k]])) }];
    toast((isNew ? 'Created ' : 'Saved ') + (nameOf(kind, b.id) || b.id) + '.', 'ok', { label: 'Undo', run: async () => {
      const undone = await api('/api/apply', { method: 'POST', body: changeSet(back) });
      await ui.refresh();
      if (undone.ok) toast('Undone.'); else toast(((undone.result || {}).conflicts || []).length ? 'Someone changed it since. It was not undone.' : 'That could not be undone.', 'err');
      if (isNew && undone.ok) ui.go('kind', kind);
    } });
    if (isNew) ui.go('kind', kind, b.id); else ui.render();
  }
  save.addEventListener('click', doSave);
  // Ctrl S saves this form, for as long as it is on the page.
  window.addEventListener('assess:save', doSave);
  window.addEventListener('assess:leave', () => window.removeEventListener('assess:save', doSave), { once: true });

  // ---- the head
  const t = S.threats.get(id);
  const risk = existing && t && (kind === 'threat' || kind === 'risk') && t.risk ? t.risk : null;
  const title = isNew ? 'New ' + info.name : nameOf(kind, id);
  const copy = !isNew ? h('button', { type: 'button', class: 'iconbtn', title: 'Copy the id', 'aria-label': 'Copy the id', onclick: async () => {
    try { await navigator.clipboard.writeText(id); toast('Id copied.'); } catch (e) { toast('The browser did not allow copying.', 'warn'); }
  } }, icon('copy', 14)) : null;
  const head = h('div', { class: 'rhead' },
    h('div', { class: 'grow' },
      h('div', { class: 'kindline' }, icon(KIND_ICON[kind] || 'circle', 16), h('span', { text: upper(info.name) })),
      h('h1', { text: title }),
      !isNew ? h('div', { class: 'idline' }, h('code', { text: id }), copy, h('span', { class: 'faint small mono', text: existing.file + ':' + existing.line })) : h('p', { class: 'muted', text: info.doc })),
    risk ? h('div', { class: 'row' }, chip(risk.base, 'Risk before the controls'), h('span', { class: 'faint', text: '→' }), chip(risk.residual, 'Risk with the controls')) : null,
    existing ? h('button', { class: 'btn danger', type: 'button', onclick: () => deleteRecord(kind, id, ui) }, icon('trash', 15), 'Delete') : null);

  // facts that assess works out are shown and not edited
  const facts = [];
  if (existing) {
    for (const a of info.attributes) {
      if (readOnly(kind, a) && original[a.name] !== undefined) {
        facts.push(h('div', { class: 'fact' }, h('span', { class: 'muted', text: upper(a.name === 'type' ? 'Type' : a.name === 'base' ? 'Risk before the controls' : a.name === 'residual' ? 'Risk with the controls' : a.name) }),
          a.name === 'base' || a.name === 'residual' ? chip(original[a.name]) : h('strong', { text: String(original[a.name]) })));
      }
    }
  }

  const main = h('div', { class: 'rmain' },
    h('div', { class: 'card' }, top, form.node),
    facts.length ? h('div', { class: 'card facts' }, h('div', { class: 'label', text: 'Written by assess' }), facts,
      h('p', { class: 'muted small', text: 'assess works these out when it writes the risks. Write the risks again after you change the attack steps.' })) : null,
    h('div', { class: 'sticky' }, status, h('div', { class: 'row' }, save, discard, h('span', { class: 'faint small', text: mod + ' S' }))));

  if (isNew) setTimeout(() => { if (idCtl && idCtl.focus) idCtl.focus(); }, 0); // the page is on the screen by then
  return h('div', { class: 'page wide' },
    crumbs({ text: kindTitle(kind), href: hrefOf('kind', kind) }, { text: isNew ? 'New' : title }),
    head,
    h('div', { class: 'rcols' }, main, existing ? context(kind, id) : null));
}

// ---- what the record is connected to ------------------------------------------------------------------------------------------------
function group(list) {
  const by = new Map();
  for (const r of list) (by.get(r.kind) || by.set(r.kind, []).get(r.kind)).push(r);
  return [...by.entries()].map(([k, items]) => h('div', { class: 'cgroup' }, h('div', { class: 'label', text: kindTitle(k) }),
    h('div', { class: 'chips' }, items.map((r) => h('a', { class: 'cp link', href: hrefOf('kind', r.kind, r.id), title: r.id + ' (' + kindName(r.kind) + ')', text: nameOf(r.kind, r.id) })))));
}

// notCalculated says why a threat scenario has no risk yet, when the reason is something this page can name.
function notCalculated(kind, id) {
  const a = (rec(kind, id) || {}).attributes || {};
  const missing = [];
  if (kind === 'threat') {
    if (!a.steps) missing.push('an attack path');
    if (!a.damages) missing.push('a damage scenario');
  }
  return 'Not calculated yet.' + (missing.length ? ' It needs ' + missing.join(' and ') + '.' : '');
}

function context(kind, id) {
  const aside = h('aside', { class: 'ctx', 'aria-label': 'Connections' });
  const t = S.threats.get(id);
  if ((kind === 'threat' || kind === 'risk') && t) {
    const lv = (o) => (o && o.level ? o.level : '–');
    aside.append(h('div', { class: 'card' }, h('div', { class: 'label', text: 'Calculation' }),
      t.risk ? h('div', { class: 'row', style: 'margin: 6px 0' }, chip(t.risk.base, 'Risk before the controls'), h('span', { class: 'muted small', text: 'before' }), chip(t.risk.residual, 'Risk with the controls'), h('span', { class: 'muted small', text: 'with controls' })) : h('p', { class: 'muted small', text: notCalculated(kind, id) }),
      h('div', { class: 'muted small', text: 'Feasibility ' + lv(t.base) + ' → ' + lv(t.residual) }),
      h('a', { class: 'more', href: hrefOf('calc', id) }, 'Show the worksheet', icon('chevronRight', 14))));
  }
  if (kind === 'threat') {
    aside.append(h('div', { class: 'card' }, h('div', { class: 'label', text: 'Attack tree' }),
      h('a', { href: hrefOf('diagram', id), class: 'pic', title: 'Open the picture' }, h('img', { alt: 'The attack tree of ' + id, src: '/diagram.svg?t=' + encodeURIComponent(S.view) + '&threat=' + encodeURIComponent(id) }))));
  }
  const uses = S.uses.get(kind + ':' + id) || [], usedBy = S.usedBy.get(kind + ':' + id) || [];
  aside.append(h('div', { class: 'card' }, h('div', { class: 'label', text: 'Uses' }), uses.length ? group(uses) : h('p', { class: 'muted small', text: 'Nothing yet.' })),
    h('div', { class: 'card' }, h('div', { class: 'label', text: 'Used by' }), usedBy.length ? group(usedBy) : h('p', { class: 'muted small', text: 'Nothing refers to it.' })));
  return aside;
}

// ---- delete -------------------------------------------------------------------------------------------------------------------------
// A delete asks assess what it would do first. A record that others use is refused, with the list of who uses it, and the person can
// then choose to delete those too.
async function deleteRecord(kind, id, ui) {
  const set = (cascade) => changeSet([Object.assign({ op: 'delete', kind, id }, cascade ? { cascade: true } : {})]);
  const problem = (env) => h('div', {}, (env.diagnostics || []).length ? diagnostics(env.diagnostics.slice(0, 10)) : h('div', { class: 'alert err', text: env.text || 'The delete was refused.' }));
  let cascade = false;
  let env = await api('/api/apply?dry=1', { method: 'POST', body: set(false) });
  if (!env.ok) {
    const blocked = (env.result || {}).blocked || [];
    if (!blocked.length) { await ask({ title: 'Cannot delete', body: problem(env), noCancel: true }); return; }
    const proceed = await ask({
      title: nameOf(kind, id) + ' is used by other records', ok: 'Show what goes with it',
      body: h('div', {}, h('p', { text: 'These records refer to it:' }),
        h('ul', {}, blocked.map((b) => h('li', {}, h('strong', { text: nameOf(b.kind, b.id) }), h('span', { class: 'muted', text: ' (' + kindName(b.kind) + '): ' + b.message }))))),
    });
    if (!proceed) return;
    cascade = true;
    env = await api('/api/apply?dry=1', { method: 'POST', body: set(true) });
    if (!env.ok) { await ask({ title: 'Cannot delete', body: problem(env), noCancel: true }); return; }
  }
  const r = env.result || {};
  const line = (d) => h('li', {}, h('strong', { text: nameOf(d.kind, d.id) }), h('span', { class: 'muted', text: ' (' + kindName(d.kind) + ')' + (d.reason ? ': ' + d.reason : '') }));
  const body = h('div', {}, h('p', { text: 'This removes:' }), h('ul', {}, (r.deleted || []).map(line)),
    (r.updated || []).length ? h('p', { text: 'And it changes:' }) : null, (r.updated || []).length ? h('ul', {}, r.updated.map(line)) : null,
    effects(r.effects), h('p', { class: 'muted small', text: 'A delete cannot be undone here. The files are in your version control.' }));
  if (!(await ask({ title: 'Delete ' + nameOf(kind, id) + '?', body, ok: 'Delete', danger: true }))) return;
  const done = await api('/api/apply', { method: 'POST', body: set(cascade) });
  if (!done.ok) { await ask({ title: 'The delete was not written', body: problem(done), noCancel: true }); return; }
  ui.setDirty(false);
  await ui.refresh();
  toast('Deleted ' + kindName(kind) + ' ' + id + '.');
  ui.go('kind', kind);
}
