// SPDX-License-Identifier: Apache-2.0. Copyright 2026 Stefanos Flokos.
// The form of a record. It is built from what describe says about each attribute, so it offers the allowed values and the ids that
// exist. It shows what is required or has a value and keeps the rest behind "Add a field". Every widget has get(), which returns the
// value that it holds, undefined when it is empty, or INVALID when what is typed cannot be used. A widget that the person has not
// touched returns what the record had, so that opening a record never looks like a change.

import { h, put, clear, uid, lines, same, firstSentence, upper } from './lib.js';
import { icon } from './icons.js';
import { S, candidates, kindOfId, nameOf, kindName, resolveAttr } from './data.js';

export const INVALID = { invalid: true };

// Names that are one word in the files and that a person reads as two or more.
// The fields that the calculation cannot do without. They are open on the form when they are empty, so that nothing is missing quietly.
const NEEDED = { threat: ['damages', 'steps'], step: ['potential'] };

// What a group of an attack path says about its parts, by the attribute that holds it.
const ROOT_TEXT = { steps: 'of these lead to the threat', preparedby: 'of these have to come first', threatenedby: 'of these can defeat the control' };

const LABELS = {
  preparedby: 'Prepared by', threatenedby: 'Threatened by', mitigatedby: 'Mitigated by', entrypoint: 'Entry point',
  roaduser: 'Road user', oem: 'OEM', knowledge: 'Knowledge of the item', window: 'Window of opportunity', time: 'Elapsed time',
  expertise: 'Specialist expertise', compromises: 'Properties lost', damages: 'Damage scenarios', steps: 'Attack path',
  assumes: 'Assumptions', potential: 'Attack potential', reduction: 'Effect on the attack potential', target: 'Where it acts',
  between: 'Between', over: 'Carried over', on: 'Applies to', check: 'Check', reference: 'References', actors: 'Threat actors',
  functions: 'Functions', properties: 'Properties', boundary: 'Boundary', environment: 'Environment',
};
export const labelOf = (name) => LABELS[name] || upper(name);

const hasValue = (v) => v !== undefined && v !== null && v !== '' && !(Array.isArray(v) && !v.length) &&
  !(typeof v === 'object' && !Array.isArray(v) && !Object.keys(v).length);

// A value that assess works out is shown, and not offered for editing: a person who changes it makes the project stale.
const readOnly = (kind, attr) => /do not edit|written by assess/i.test(attr.doc || '') || (kind === 'risk' && ['type', 'base', 'residual'].includes(attr.name));

// ---- choices ----------------------------------------------------------------------------------------------------------
// choice is a segmented control for a few values and a select for more.
export function choice({ values, label, value, required, onChange, text }) {
  const shown = text || String;
  if (values.length > 5) {
    const sel = h('select', { 'aria-label': label, onchange: () => onChange() }, h('option', { value: '', text: required ? 'Choose…' : 'Not set' }),
      values.map((v) => h('option', { value: String(v), text: shown(v) })));
    sel.value = value === undefined ? '' : String(value);
    return { node: sel, get: () => (sel.value === '' ? undefined : values.find((v) => String(v) === sel.value)), set: (v) => { sel.value = v === undefined ? '' : String(v); } };
  }
  let state = value === null ? undefined : value;
  const wrap = h('div', { class: 'seg', role: 'group', 'aria-label': label });
  const buttons = values.map((v) => h('button', { type: 'button', class: 'seg-b', text: shown(v), onclick: () => {
    state = state === v && !required ? undefined : v;
    paint();
    onChange();
  } }));
  const paint = () => buttons.forEach((b, i) => { const on = state === values[i]; b.classList.toggle('on', on); b.setAttribute('aria-pressed', String(on)); });
  buttons.forEach((b) => wrap.append(b));
  paint();
  return { node: wrap, get: () => state, set: (v) => { state = v; paint(); } };
}

// ---- text and numbers ---------------------------------------------------------------------------------------------------
function textBox(attr, value, onChange) {
  const long = /description|rationale|boundary|statement|message|check|environment/.test(attr.name) || (typeof value === 'string' && (value.includes('\n') || value.length > 80));
  const el = long ? h('textarea', { rows: Math.min(8, Math.max(2, String(value || '').split('\n').length)), oninput: () => onChange() }) : h('input', { type: 'text', oninput: () => onChange() });
  el.value = value === undefined || value === null ? '' : String(value);
  if (attr.name === 'check') el.classList.add('mono');
  return { node: el, get: () => (el.value === '' ? undefined : el.value), focus: () => el.focus() };
}

function numberBox(value, onChange) {
  const el = h('input', { type: 'number', step: 'any', oninput: () => onChange() });
  el.value = value === undefined || value === null ? '' : String(value);
  return { node: el, get: () => (el.value === '' ? undefined : Number(el.value)), focus: () => el.focus() };
}

function listBox(value, onChange) {
  const ta = h('textarea', { class: 'lines', rows: 3, spellcheck: 'false', oninput: () => onChange() });
  ta.value = (Array.isArray(value) ? value : value === undefined ? [] : [value]).join('\n');
  return { node: ta, get: () => { const l = lines(ta.value); return l.length ? l : undefined; }, focus: () => ta.focus() };
}

// ---- chips: ids with type-ahead -------------------------------------------------------------------------------------------
// chipPicker holds one id or a list of ids. A chip shows the name of the record, and its id as a tooltip. A click on it opens the
// record. Typing finds records by name or id.
export function chipPicker({ kinds, multiple, value, onChange, placeholder, label, exclude }) {
  let items = [].concat(value === undefined || value === null ? [] : value).filter((s) => typeof s === 'string');
  const pool = candidates(kinds).filter((c) => !exclude || !exclude.has(c.id));
  const popId = uid();
  const wrap = h('div', { class: 'picker' });
  const chips = h('div', { class: 'chips' });
  const input = h('input', { type: 'text', class: 'pick-in', placeholder: placeholder || 'Add…', 'aria-label': label || 'Add', autocomplete: 'off', spellcheck: 'false', role: 'combobox', 'aria-autocomplete': 'list', 'aria-expanded': 'false', 'aria-controls': popId });
  const pop = h('ul', { class: 'pop', role: 'listbox', id: popId, 'aria-label': (label || 'Suggestions'), hidden: true });
  let hit = [], at = 0, moved = false;

  const add = (id) => {
    id = id.trim();
    if (!id) return;
    if (multiple ? !items.includes(id) : true) items = multiple ? [...items, id] : [id];
    input.value = '';
    close();
    paint();
    onChange();
  };
  const remove = (id) => { items = items.filter((x) => x !== id); paint(); onChange(); };
  const close = () => { pop.hidden = true; input.setAttribute('aria-expanded', 'false'); input.removeAttribute('aria-activedescendant'); };
  const show = () => {
    const q = input.value.trim().toLowerCase();
    hit = pool.filter((c) => !items.includes(c.id) && (!q || c.name.toLowerCase().includes(q) || c.id.toLowerCase().includes(q) || kindName(c.kind).includes(q))).slice(0, 8);
    at = 0;
    moved = false;
    clear(pop);
    hit.forEach((c, i) => pop.append(h('li', { role: 'option', id: popId + '-' + i, 'aria-selected': String(i === at), class: i === at ? 'on' : '', onmousedown: (e) => { e.preventDefault(); add(c.id); } },
      h('span', { class: 'pn', text: c.name }), h('span', { class: 'pid', text: c.id }), kinds && kinds.length > 1 ? h('span', { class: 'pk', text: kindName(c.kind) }) : null)));
    if (!hit.length) pop.append(h('li', { class: 'none', text: pool.length ? 'No match' + (q ? ' for ' + q : '') : 'Type an id' }));
    pop.hidden = false;
    input.setAttribute('aria-expanded', 'true');
    if (hit.length) input.setAttribute('aria-activedescendant', popId + '-' + at);
  };
  const mark = () => {
    [...pop.children].forEach((li, i) => { li.classList.toggle('on', i === at); li.setAttribute('aria-selected', String(i === at)); });
    if (hit.length) input.setAttribute('aria-activedescendant', popId + '-' + at);
  };

  input.addEventListener('input', show);
  input.addEventListener('focus', show);
  input.addEventListener('blur', () => setTimeout(close, 120));
  input.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); if (pop.hidden) show(); moved = true; at = Math.min(at + 1, Math.max(hit.length - 1, 0)); mark(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); moved = true; at = Math.max(at - 1, 0); mark(); }
    else if (e.key === 'Enter') {
      e.preventDefault();
      const typed = input.value.trim();
      // the first suggestion is taken when something was typed or an arrow key chose one. An empty box adds nothing.
      if (hit[at] && (typed || moved)) add(hit[at].id);
      else if (typed && (!pool.length || kindOfId(typed, kinds))) add(typed);
    }
    else if (e.key === 'Escape') { close(); }
    else if (e.key === 'Backspace' && !input.value && items.length) { remove(items[items.length - 1]); }
  });

  function paint() {
    clear(chips);
    for (const id of items) {
      const k = kindOfId(id, kinds);
      chips.append(h('span', { class: 'cp' + (k ? '' : ' dangling'), title: k ? id + ' (' + kindName(k) + ')' : id + ' is not a record of this project' },
        k ? h('a', { href: '#/kind/' + encodeURIComponent(k) + '/' + encodeURIComponent(id), text: nameOf(k, id) }) : h('span', { text: id }),
        h('button', { type: 'button', class: 'cx', 'aria-label': 'Remove ' + id, onclick: () => remove(id) }, icon('x', 12))));
    }
    input.hidden = !multiple && items.length > 0;
  }
  paint();
  chips.append(input);
  wrap.append(h('div', { class: 'picker-box' }, chips), pop);
  return {
    node: wrap,
    get: () => (items.length ? (multiple ? items : items[0]) : undefined),
    focus: () => (input.hidden ? null : input.focus()),
  };
}

// ---- ratings: the five factors of an attack potential ------------------------------------------------------------------------
// A block of enums is one row of selects. The policy says how many points each value is worth, and that is shown. It is a lookup,
// and the calculation stays in assess.
function ratingRow(attr, value, onChange) {
  let touched = false;
  const cur = Object.assign({}, value || {});
  const cells = attr.attributes.map((sub) => {
    const points = S.points[sub.name] || {};
    const sel = h('select', { 'aria-label': labelOf(sub.name), onchange: () => { touched = true; paint(); onChange(); } },
      h('option', { value: '', text: 'Choose…' }), (sub.values || []).map((v) => h('option', { value: v, text: v + (v in points ? ' · ' + points[v] + ' pts' : '') })));
    sel.value = cur[sub.name] === undefined ? '' : cur[sub.name];
    const paint = () => { sel.classList.toggle('empty', sel.value === ''); };
    paint();
    sel.title = sub.doc || '';
    return { sub, sel, node: h('div', { class: 'rate' }, h('div', { class: 'rl', text: labelOf(sub.name) }), sel) };
  });
  return {
    node: h('div', { class: 'rating' }, cells.map((c) => c.node)),
    get: () => {
      if (!touched) return value;
      const out = {};
      for (const c of cells) if (c.sel.value) out[c.sub.name] = c.sel.value;
      return Object.keys(out).length ? out : undefined;
    },
  };
}

// ---- impact: stakeholders by categories ---------------------------------------------------------------------------------------
const LEVEL_CLASS = { Negligible: 'v1', Moderate: 'v2', Major: 'v3', Severe: 'v4' };

function impactGrid(kind, attr, value, onChange) {
  let touched = false;
  const state = {};
  const stakeholders = attr.attributes.map((a) => resolveAttr(kind, a));
  for (const s of stakeholders) state[s.name] = JSON.parse(JSON.stringify((value || {})[s.name] || {}));
  const shown = new Set(stakeholders.filter((s) => s.required || hasValue(state[s.name])).map((s) => s.name));
  const root = h('div', { class: 'impact' });

  const cellOf = (stk, cat) => {
    const def = resolveAttr(kind, cat);
    const levelAttr = (def.attributes || []).find((a) => a.type === 'enum') || { values: [] };
    const cur = state[stk.name][cat.name] || {};
    const sel = h('select', { 'aria-label': labelOf(stk.name) + ', ' + labelOf(cat.name) });
    put(sel, h('option', { value: '', text: 'Not rated' }), (levelAttr.values || []).map((v) => h('option', { value: v, text: v })));
    sel.value = cur.level || '';
    const why = h('textarea', { rows: 2, placeholder: 'Why this level', 'aria-label': 'Why this level', oninput: () => { touched = true; save(); onChange(); } });
    why.value = cur.rationale || '';
    const wrap = h('div', { class: 'why', hidden: true }, why);
    const toggle = h('button', { type: 'button', class: 'linkish', title: cur.rationale || '', onclick: () => { wrap.hidden = !wrap.hidden; if (!wrap.hidden) why.focus(); } }, cur.rationale ? 'Show the reason' : 'Add a reason');
    const paint = () => { sel.className = sel.value ? 'lvl ' + (LEVEL_CLASS[sel.value] || '') : 'lvl'; };
    const save = () => {
      const lvl = sel.value, rat = why.value.trim();
      if (!lvl && !rat) delete state[stk.name][cat.name];
      else state[stk.name][cat.name] = Object.assign({}, lvl ? { level: lvl } : {}, rat ? { rationale: rat } : {});
    };
    sel.addEventListener('change', () => { touched = true; paint(); save(); onChange(); });
    paint();
    return h('div', { class: 'cell' }, h('div', { class: 'cl', text: labelOf(cat.name) }), sel, toggle, wrap);
  };

  const draw = () => {
    clear(root);
    for (const s of stakeholders) {
      if (!shown.has(s.name)) continue;
      const cats = (s.attributes || []);
      root.append(h('div', { class: 'stk' },
        h('div', { class: 'stk-h' }, h('strong', { text: labelOf(s.name) }), s.required ? null : h('button', { type: 'button', class: 'linkish', onclick: () => {
          shown.delete(s.name); state[s.name] = {}; touched = true; draw(); onChange();
        } }, 'Remove')),
        h('div', { class: 'cells' }, cats.map((c) => cellOf(s, c)))));
    }
    const hidden = stakeholders.filter((s) => !shown.has(s.name));
    if (hidden.length) root.append(h('div', { class: 'row' }, hidden.map((s) => h('button', { type: 'button', class: 'btn small', onclick: () => { shown.add(s.name); touched = true; draw(); } }, icon('plus', 14), ' ' + labelOf(s.name)))));
  };
  draw();
  return {
    node: root,
    get: () => {
      if (!touched) return value;
      const out = {};
      for (const s of stakeholders) if (shown.has(s.name) && Object.keys(state[s.name] || {}).length) out[s.name] = state[s.name];
      return Object.keys(out).length ? out : undefined;
    },
  };
}

// ---- properties lost: an asset and the properties of it that are lost -----------------------------------------------------------------
function compromises(attr, value, onChange) {
  let touched = false;
  const rows = [];
  const box = h('div', { class: 'comp' });
  const addRow = (asset, props) => {
    const picker = chipPicker({ kinds: attr.refs, multiple: false, value: asset, placeholder: 'Choose an asset…', label: 'Asset', onChange: () => { touched = true; onChange(); } });
    const checks = (attr.values || []).map((p) => h('input', { type: 'checkbox', value: p, checked: (props || []).includes(p), onchange: () => { touched = true; onChange(); } }));
    const row = h('div', { class: 'comp-row' }, picker.node,
      h('div', { class: 'props' }, (attr.values || []).map((p, i) => h('label', {}, checks[i], p))),
      h('button', { type: 'button', class: 'iconbtn', 'aria-label': 'Remove this asset', onclick: () => { rows.splice(rows.indexOf(entry), 1); row.remove(); touched = true; onChange(); } }, icon('x', 14)));
    const entry = { picker, checks };
    rows.push(entry);
    box.insertBefore(row, add);
  };
  const add = h('button', { type: 'button', class: 'btn small', onclick: () => { addRow(undefined, []); touched = true; } }, icon('plus', 14), ' Add an asset');
  box.append(add);
  for (const [asset, props] of Object.entries(value || {})) addRow(asset, [].concat(props));
  return {
    node: box,
    get: () => {
      if (!touched) return value;
      const out = {};
      for (const r of rows) { const id = r.picker.get(); if (id) out[id] = r.checks.filter((c) => c.checked).map((c) => c.value); }
      return Object.keys(out).length ? out : undefined;
    },
  };
}

// ---- the attack path: and, or and the steps and threat scenarios under them ------------------------------------------------------
// tree is a value like "a", {or: ["a", "b"]} or {and: ["a", {or: ["b", "c"]}]}. The editor shows each group as a box that is "All of" or
// "Any one of" what is in it. A group of one is written as the one, which means the same.
function treeEditor(attr, value, onChange) {
  let touched = false;
  const parse = (v) => {
    if (typeof v === 'string') return { leaf: v };
    if (v && typeof v === 'object') {
      const op = Object.keys(v)[0];
      if (op === 'and' || op === 'or') return { op, kids: (v[op] || []).map(parse).filter(Boolean) };
    }
    return null;
  };
  const first = parse(value);
  const root = first && first.leaf ? { op: 'or', kids: [first] } : first || { op: 'or', kids: [] };
  const box = h('div', { class: 'treeed' });

  const changed = () => { touched = true; draw(); onChange(); };
  function addLeaf(group) {
    const picker = chipPicker({ kinds: attr.refs, multiple: false, value: undefined, placeholder: 'Add a step or a threat scenario…', label: 'Add to this group',
      onChange: () => { const id = picker.get(); if (id) { group.kids.push({ leaf: id }); changed(); } } });
    return picker.node;
  }
  function drawGroup(g, isRoot, parent) {
    const body = h('div', { class: 'tree' });
    for (const k of g.kids) {
      if (k.leaf !== undefined) {
        const kk = kindOfId(k.leaf, attr.refs);
        body.append(h('div', { class: 'leaf' }, h('span', { class: 'lt', text: kk ? kindName(kk) : 'Not found' }),
          h('span', { class: 'cp' + (kk ? '' : ' dangling'), title: k.leaf }, kk ? h('a', { href: '#/kind/' + encodeURIComponent(kk) + '/' + encodeURIComponent(k.leaf), text: nameOf(kk, k.leaf) }) : h('span', { text: k.leaf })),
          h('button', { type: 'button', class: 'iconbtn', 'aria-label': 'Remove ' + k.leaf, onclick: () => { g.kids.splice(g.kids.indexOf(k), 1); changed(); } }, icon('x', 14))));
      } else body.append(drawGroup(k, false, g));
    }
    const seg = choice({ values: ['and', 'or'], text: (v) => (v === 'and' ? 'All of' : 'Any one of'), label: 'How the parts combine', value: g.op, required: true, onChange: () => { g.op = seg.get(); touched = true; onChange(); } });
    return h('div', { class: 'grp' },
      h('div', { class: 'gh' }, seg.node, h('span', { class: 'muted', text: isRoot ? ROOT_TEXT[attr.name] || 'of these' : 'of these' }),
        isRoot ? null : h('button', { type: 'button', class: 'iconbtn', 'aria-label': 'Remove this group', onclick: () => { parent.kids.splice(parent.kids.indexOf(g), 1); changed(); } }, icon('trash', 14))),
      body,
      h('div', { class: 'tree-add' }, addLeaf(g), h('button', { type: 'button', class: 'btn small', onclick: () => { g.kids.push({ op: 'or', kids: [] }); changed(); } }, icon('plus', 14), ' Add a group')));
  }
  function draw() { clear(box); box.append(drawGroup(root, true, null)); }
  draw();

  const build = (n) => {
    if (n.leaf !== undefined) return n.leaf;
    const kids = n.kids.map(build).filter((x) => x !== undefined);
    if (!kids.length) return undefined;
    return kids.length === 1 ? kids[0] : { [n.op]: kids };
  };
  return { node: box, get: () => (touched ? build(root) : value) };
}

// ---- notes: key and value ------------------------------------------------------------------------------------------------------
function mapEditor(value, onChange) {
  const rows = h('div', { class: 'pairs' });
  const addRow = (k, v) => {
    const row = h('div', { class: 'pair' },
      h('input', { type: 'text', placeholder: 'key', 'aria-label': 'Key', value: k, oninput: () => onChange() }),
      h('input', { type: 'text', placeholder: 'value', 'aria-label': 'Value', value: v, oninput: () => onChange() }),
      h('button', { type: 'button', class: 'iconbtn', 'aria-label': 'Remove this row', onclick: () => { row.remove(); onChange(); } }, icon('x', 14)));
    rows.append(row);
  };
  for (const [k, v] of Object.entries(value || {})) addRow(k, v === null || typeof v === 'object' ? JSON.stringify(v) : String(v));
  const node = h('div', {}, rows, h('button', { type: 'button', class: 'btn small', style: 'margin-top: 6px', onclick: () => addRow('', '') }, icon('plus', 14), ' Add a row'));
  return {
    node,
    get: () => {
      const out = {};
      for (const row of rows.children) { const [k, v] = row.querySelectorAll('input'); if (k.value.trim()) out[k.value.trim()] = v.value; }
      return Object.keys(out).length ? out : undefined;
    },
  };
}

// ---- the rest, as JSON -------------------------------------------------------------------------------------------------------------
function jsonBox(value, onChange) {
  const ta = h('textarea', { class: 'json', rows: 5, spellcheck: 'false', oninput: () => onChange() });
  ta.value = value === undefined ? '' : JSON.stringify(value, null, 2);
  return {
    node: ta,
    get: () => {
      const t = ta.value.trim();
      ta.classList.remove('bad');
      if (!t) return undefined;
      try { return JSON.parse(t); } catch (e) { ta.classList.add('bad'); return INVALID; }
    },
  };
}

// ---- one attribute -------------------------------------------------------------------------------------------------------------------
const isRatings = (a) => a.type === 'block' && a.attributes && a.attributes.length >= 3 && a.attributes.every((s) => s.type === 'enum');
const isImpact = (kind, a) => a.type === 'block' && (a.attributes || []).length > 0 &&
  a.attributes.every((s) => { const r = resolveAttr(kind, s); return r.type === 'block' && (r.attributes || []).length > 0 && r.attributes.every((c) => resolveAttr(kind, c).type === 'block'); });

// widget makes the control of an attribute. A block that is not a rating or an impact is a group of the controls of its attributes.
function widget(kind, attr, value, onChange) {
  const label = labelOf(attr.name);
  switch (attr.type) {
    case 'text': return textBox(attr, value, onChange);
    case 'number': return numberBox(value, onChange);
    case 'bool': return choice({ values: [true, false], text: (v) => (v ? 'Yes' : 'No'), label, value, required: false, onChange });
    case 'enum': return choice({ values: attr.values || [], label, value, required: !!attr.required, onChange });
    case 'enums': {
      // The order in the file is kept: what stays is where it was, and what is new comes after it. A box that was not touched gives
      // back the value as it was, so that opening a record never changes it.
      let touched = false;
      const was = [].concat(value === undefined ? [] : value);
      const have = new Set(was);
      const boxes = (attr.values || []).map((v) => h('input', { type: 'checkbox', value: v, checked: have.has(v), onchange: () => { touched = true; onChange(); } }));
      return { node: h('div', { class: 'checks' }, (attr.values || []).map((v, i) => h('label', {}, boxes[i], v))),
        get: () => {
          if (!touched) return value;
          const on = boxes.filter((b) => b.checked).map((b) => b.value);
          const ordered = [...was.filter((v) => on.includes(v)), ...on.filter((v) => !was.includes(v))];
          return ordered.length ? ordered : undefined;
        } };
    }
    case 'id': return chipPicker({ kinds: attr.refs, multiple: false, value, onChange, placeholder: 'Choose…', label });
    case 'ids': return attr.refs && attr.refs.length
      ? chipPicker({ kinds: attr.refs, multiple: true, value, onChange, placeholder: 'Add…', label })
      : listBox(value, onChange);
    case 'texts': return listBox(value, onChange);
    case 'map': return mapEditor(value, onChange);
    case 'compromises': return compromises(attr, value, onChange);
    case 'tree': return treeEditor(attr, value, onChange);
    case 'block':
      if (isRatings(attr)) return ratingRow(attr, value, onChange);
      if (isImpact(kind, attr)) return impactGrid(kind, attr, value, onChange);
      if (attr.attributes && attr.attributes.length) {
        const subs = attr.attributes.map((a) => field(kind, a, (value || {})[a.name], onChange));
        return { node: h('div', { class: 'sub' }, subs.map((s) => s.node)),
          get: () => {
            const out = {};
            for (const s of subs) { const v = s.get(); if (v === INVALID) return INVALID; if (v !== undefined) out[s.attr.name] = v; }
            return Object.keys(out).length ? out : undefined;
          } };
      }
      return jsonBox(value, onChange);
    default: return jsonBox(value, onChange); // blocks, table, rows
  }
}

// shell puts a label, a small question mark for the help and a control together, as every field of the form looks.
export function shell(text, required, doc, controlNode, id) {
  const help = h('p', { class: 'doc', hidden: true, text: doc || '' });
  const q = doc ? h('button', { type: 'button', class: 'help', 'aria-label': 'What is ' + text + '?', title: 'What is this?', onclick: () => { help.hidden = !help.hidden; } }, icon('help', 15)) : null;
  return h('div', { class: 'field' }, h('div', { class: 'flabel' }, h('label', { for: id || null, text }), required ? h('span', { class: 'req', title: 'Required', text: '*' }) : null, q), help, controlNode);
}

// field is an attribute with its label and its help. The help is behind a small question mark.
export function field(kind, attr0, value, onChange, opt) {
  const attr = resolveAttr(kind, attr0);
  const id = uid();
  const control = widget(kind, attr, value, onChange);
  const help = h('p', { class: 'doc', hidden: true, text: attr.doc || '' });
  const q = attr.doc ? h('button', { type: 'button', class: 'help', 'aria-label': 'What is ' + labelOf(attr.name) + '?', title: 'What is this?', onclick: () => { help.hidden = !help.hidden; } }, icon('help', 15)) : null;
  const lab = h('label', { text: labelOf(attr.name) });
  const node = h('div', { class: 'field', 'data-name': attr.name },
    h('div', { class: 'flabel' }, lab, attr.required ? h('span', { class: 'req', title: 'Required', text: '*' }) : null, q,
      opt && opt.onRemove ? h('button', { type: 'button', class: 'iconbtn right', 'aria-label': 'Remove ' + labelOf(attr.name), title: 'Remove this field', onclick: opt.onRemove }, icon('x', 14)) : null),
    help, control.node);
  // A click on the label goes to the control when there is one control: a text box, a select. A control made of several buttons or boxes
  // is named by the label instead. If the label pointed at its first button, a click on the label would press it.
  if (control.node.matches('input,select,textarea')) {
    control.node.id = id;
    lab.setAttribute('for', id);
  } else {
    lab.id = id + '-l';
    if (!control.node.getAttribute('role')) control.node.setAttribute('role', 'group');
    control.node.setAttribute('aria-labelledby', lab.id);
  }
  const first = control.node.matches('input,select,textarea,button') ? control.node : control.node.querySelector('input,select,textarea,button');
  return { attr, node, get: control.get, focus: () => (first ? first.focus() : null) };
}

// ---- the form of a record -------------------------------------------------------------------------------------------------------------
// recordForm shows the fields that are required or have a value. The others are one click away in "Add a field", with the first
// sentence of their help.
let outside = null; // the click that closes the menu of the form that is on the page
export function recordForm(kind, original, onChange) {
  const info = S.kinds[kind];
  const defs = (info.attributes || []).filter((a) => !readOnly(kind, a));
  // notes come last
  defs.sort((a, b) => (a.name === 'notes') - (b.name === 'notes'));
  const fields = defs.map((a) => {
    const f = { def: a, shown: !!a.required || hasValue(original[a.name]) || (NEEDED[kind] || []).includes(a.name) };
    f.make = () => {
      f.f = field(kind, a, original[a.name], onChange, a.required ? null : { onRemove: () => hide(f) });
      return f.f;
    };
    return f;
  });
  const list = h('div', { class: 'fields' });
  const menuBox = h('div', { class: 'addfield' });
  const pop = h('div', { class: 'menu', hidden: true });
  const button = h('button', { type: 'button', class: 'btn', 'aria-haspopup': 'true', 'aria-expanded': 'false', onclick: () => { pop.hidden = !pop.hidden; button.setAttribute('aria-expanded', String(!pop.hidden)); } }, icon('plus', 14), ' Add a field');

  const paintMenu = () => {
    clear(pop);
    const rest = fields.filter((f) => !f.shown);
    menuBox.hidden = rest.length === 0;
    for (const f of rest) {
      pop.append(h('button', { type: 'button', class: 'menu-i', onclick: () => { pop.hidden = true; button.setAttribute('aria-expanded', 'false'); show(f); } },
        h('strong', { text: labelOf(f.def.name) }), h('span', { class: 'muted', text: firstSentence(resolveAttr(kind, f.def).doc) })));
    }
  };
  const place = (f) => {
    const nodeF = f.f ? f.f.node : f.make().node;
    const nextShown = fields.slice(fields.indexOf(f) + 1).find((x) => x.shown && x.f);
    list.insertBefore(nodeF, nextShown ? nextShown.f.node : null);
  };
  function show(f) { f.shown = true; place(f); paintMenu(); onChange(); if (f.f) f.f.focus(); }
  function hide(f) { f.shown = false; f.f.node.remove(); f.f = null; paintMenu(); onChange(); }

  for (const f of fields) if (f.shown) place(f);
  menuBox.append(button, pop);
  menuBox.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !pop.hidden) { pop.hidden = true; button.setAttribute('aria-expanded', 'false'); button.focus(); } });
  paintMenu();
  if (outside) document.removeEventListener('click', outside);
  outside = (e) => { if (!menuBox.contains(e.target)) { pop.hidden = true; button.setAttribute('aria-expanded', 'false'); } };
  document.addEventListener('click', outside);

  // changes is what the form changes in the record: the attributes that differ, and null for one that was emptied.
  const changes = () => {
    const out = {};
    let invalid = false;
    for (const f of fields) {
      const name = f.def.name;
      const cur = f.shown && f.f ? f.f.get() : undefined;
      const orig = original[name];
      if (cur === INVALID) { invalid = true; continue; }
      if (cur === undefined) { if (hasValue(orig)) out[name] = null; continue; }
      const a = resolveAttr(kind, f.def).type === 'ids' && typeof orig === 'string' ? [orig] : orig;
      if (!same(cur, a)) out[name] = inSchemaOrder(kind, f.def, cur);
    }
    return { attrs: out, invalid };
  };
  return { node: h('div', {}, list, menuBox), changes, focusFirst: () => { const f = fields.find((x) => x.shown && x.f); if (f) f.f.focus(); } };
}

export { readOnly, hasValue };

// inSchemaOrder puts the keys of a block in the order that the format lists its attributes, as people write them. A value that comes
// back from export has its keys sorted, and writing it back so would change the look of the file.
export function inSchemaOrder(kind, attr0, value) {
  const attr = resolveAttr(kind, attr0);
  if (attr.type === 'blocks' && Array.isArray(value)) return value.map((v) => inSchemaOrder(kind, Object.assign({}, attr, { type: 'block' }), v));
  if (!value || typeof value !== 'object' || Array.isArray(value) || attr.type !== 'block' || !attr.attributes) return value;
  const out = {};
  for (const sub of attr.attributes) if (sub.name in value) out[sub.name] = inSchemaOrder(kind, sub, value[sub.name]);
  for (const k of Object.keys(value)) if (!(k in out)) out[k] = value[k];
  return out;
}
