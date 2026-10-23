// SPDX-License-Identifier: Apache-2.0. Copyright 2026 Stefanos Flokos.
// What the page knows about the project: the description of the format, every record, the results, and what is worked out from them
// (names, what a record uses and what uses it, the search index and the path of the work). All of it comes from export and describe.
// Nothing is calculated here that assess calculates.

import { api, upper, plural } from './lib.js';

export const S = {
  desc: null, kinds: {}, apiVersion: 'assess/v1beta1',
  exp: null, diag: [], recs: [], of: {}, byKey: new Map(), threats: new Map(), byFile: new Map(),
  uses: new Map(), usedBy: new Map(), index: [], points: {}, open: [],
  stamp: '', view: '', fatal: '', noProject: false,
};

// load reads the format once and the project every time.
export async function load() {
  // The stamp is read first. A file that changes while the rest is read then shows as a change at the next look, and is not lost.
  const st = await api('/api/stamp');
  const [exp, desc, view] = await Promise.all([api('/api/export'), S.desc ? null : api('/api/describe'), S.view ? null : api('/api/view')]);
  if (exp.status === 401 || (desc && desc.status === 401)) { S.fatal = 'token'; return; }
  if (view && view.view) S.view = view.view;
  if (desc) {
    if (!desc.result) { S.fatal = (desc.diagnostics[0] || {}).message || 'The description of the format could not be read.'; return; }
    S.desc = desc.result;
    S.apiVersion = (desc.assess || {}).apiVersion || S.apiVersion;
    S.kinds = Object.fromEntries(S.desc.kinds.map((k) => [k.kind, k]));
  }
  S.fatal = '';
  S.exp = exp.result || { records: [] };
  S.diag = exp.diagnostics || [];
  S.noProject = S.diag.some((d) => d.code === 'no-project');
  S.recs = S.exp.records || [];
  S.open = S.exp.open || [];
  S.of = {}; S.byKey = new Map(); S.byFile = new Map();
  for (const r of S.recs) {
    (S.of[r.kind] = S.of[r.kind] || []).push(r);
    S.byKey.set(r.kind + ':' + r.id, r);
    (S.byFile.get(r.file) || S.byFile.set(r.file, []).get(r.file)).push(r);
  }
  S.threats = new Map(((S.exp.results || {}).threats || []).map((t) => [t.threat, t]));
  S.points = ((S.exp.policy || {}).feasibility || {}).points || {};
  relate();
  S.index = S.recs.map((r) => ({ kind: r.kind, id: r.id, name: nameOf(r.kind, r.id), hay: (r.id + ' ' + nameOf(r.kind, r.id) + ' ' + kindName(r.kind)).toLowerCase() }));
  S.stamp = st.stamp || '';
}

export const rec = (kind, id) => S.byKey.get(kind + ':' + id);
export const nameOf = (kind, id) => { const r = rec(kind, id); return (r && r.attributes && r.attributes.name) || id; };
export const kindName = (k) => (S.kinds[k] ? S.kinds[k].name : k);
export const kindsName = (k) => { const n = kindName(k); return /s$/.test(n) ? n : n + 's'; };
export const kindTitle = (k) => upper(kindsName(k));

// candidates lists the records of some kinds, by name, for a picker.
export function candidates(kinds) {
  const out = [];
  for (const k of kinds || []) for (const r of S.of[k] || []) out.push({ kind: k, id: r.id, name: nameOf(k, r.id) });
  return out.sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
}
// kindOfId finds the record that an id names, among the kinds that the attribute may point at.
export const kindOfId = (id, kinds) => (kinds || []).find((k) => S.byKey.has(k + ':' + id));

// recordAt finds the record that a place in a file belongs to: the last one that starts at or before the line.
export function recordAt(file, line) {
  let best = null;
  for (const r of S.byFile.get(file) || []) if (r.line <= line && (!best || r.line >= best.line)) best = r;
  return best;
}

// resolveAttr gives the attributes of a block. A block that is written like another one says so with sameAs, a path that starts at
// an attribute of the kind.
export function resolveAttr(kind, attr) {
  if (!attr.sameAs || (attr.attributes && attr.attributes.length)) return attr;
  let defs = (S.kinds[kind] || {}).attributes || [];
  let found = null;
  for (const name of attr.sameAs.split('.')) {
    found = defs.find((a) => a.name === name);
    if (!found) return attr;
    defs = found.attributes || [];
  }
  return Object.assign({}, found, { name: attr.name, doc: attr.doc || found.doc, required: attr.required, sameAs: undefined });
}

// ---- what a record uses and what uses it --------------------------------------------------------------------------------
// The ids in the attributes that point at other records. describe says which attributes do, and at which kinds.
function idsIn(attr, v) {
  switch (attr.type) {
    case 'id': return typeof v === 'string' ? [v] : [];
    case 'ids': return [].concat(v === undefined || v === null ? [] : v).filter((s) => typeof s === 'string');
    case 'compromises': return v && typeof v === 'object' ? Object.keys(v) : [];
    case 'tree': {
      const out = [];
      const walk = (n) => { if (typeof n === 'string') out.push(n); else if (Array.isArray(n)) n.forEach(walk); else if (n && typeof n === 'object') Object.values(n).forEach(walk); };
      walk(v);
      return out;
    }
    default: return [];
  }
}

function walk(kind, defs, value, out) {
  for (const a0 of defs) {
    const v = value && value[a0.name];
    if (v === undefined) continue;
    const a = resolveAttr(kind, a0);
    if (a.type === 'block') walk(kind, a.attributes || [], v, out);
    else if (a.type === 'blocks') for (const item of [].concat(v)) walk(kind, a.attributes || [], item, out);
    else for (const id of idsIn(a, v)) { const k = kindOfId(id, a.refs); if (k) out.push([k, id]); }
  }
}

function relate() {
  S.uses = new Map(); S.usedBy = new Map();
  const add = (from, to) => {
    const a = from.kind + ':' + from.id, b = to[0] + ':' + to[1];
    if (a === b) return;
    const list = S.uses.get(a) || S.uses.set(a, []).get(a);
    if (!list.some((x) => x.kind === to[0] && x.id === to[1])) list.push({ kind: to[0], id: to[1] });
    const back = S.usedBy.get(b) || S.usedBy.set(b, []).get(b);
    if (!back.some((x) => x.kind === from.kind && x.id === from.id)) back.push({ kind: from.kind, id: from.id });
  };
  for (const r of S.recs) {
    const info = S.kinds[r.kind];
    if (!info) continue;
    const out = [];
    walk(r.kind, info.attributes || [], r.attributes || {}, out);
    for (const to of out) add(r, to);
    // where it is written, and the records that it is the one of
    const parent = r.parent && kindOfId(r.parent, info.parents);
    if (parent) add(r, [parent, r.parent]);
    const of = kindOfId(r.id, info.idOf);
    if (of) add(r, [of, r.id]);
    // a threat scenario is written <asset>-<stride>
    for (const s of info.idSuffixes || []) {
      if (r.id.endsWith('-' + s) && S.byKey.has('asset:' + r.id.slice(0, -(s.length + 1)))) add(r, ['asset', r.id.slice(0, -(s.length + 1))]);
    }
  }
}

// ---- the path of the work -------------------------------------------------------------------------------------------------
// The seven steps of the README, each with a state worked out from what is in the project. The first step that is not done is the
// one to do next. A step has an action: a page to go to, or one of the commands that write records for you.
const count = (k) => (S.of[k] || []).length;
const openCount = (...codes) => S.open.filter((o) => codes.includes(o.code)).length;

export function workflow() {
  const results = !!(S.exp && S.exp.results);
  const comps = count('component'), assets = count('asset'), damages = count('damage'), threats = count('threat');
  const steps = count('step'), controls = count('control'), risks = count('risk');
  const notCalc = openCount('not-calculated', 'policy-gap');
  const undecided = openCount('no-treatment');
  const riskGaps = openCount('no-risks', 'risk-missing', 'risk-stale', 'risk-not-calculated');
  const its = (S.exp && S.exp.iterations) || [];
  const last = its[its.length - 1];
  const closed = !!last && last.inputs === (S.exp && S.exp.fingerprint);
  const hasItem = count('item') > 0;

  const list = [
    {
      title: 'Describe the item',
      done: hasItem && comps > 0,
      text: comps ? plural(comps, 'component') + ', ' + plural(count('interface'), 'interface') + ', ' + plural(count('channel'), 'channel') : 'The architecture: components, interfaces and the channels between them.',
      action: comps ? { label: 'Open the components', go: ['kind', 'component'] } : { label: 'Add a component', go: ['new', 'component'], primary: true },
    },
    {
      title: 'Identify the assets',
      done: assets > 0,
      text: assets ? plural(assets, 'asset') + ' with their properties' : 'The elements that have to be protected, and for which properties.',
      action: assets ? { label: 'Open the assets', go: ['kind', 'asset'] }
        : comps ? { label: 'Write assets for every element', generate: 'assets', primary: true } : null,
    },
    {
      title: 'Write the damage scenarios',
      done: damages > 0,
      text: damages ? plural(damages, 'damage scenario') : 'What goes wrong for the road user, the OEM or a supplier when a property is lost.',
      action: damages ? { label: 'Open the damage scenarios', go: ['kind', 'damage'] } : assets ? { label: 'Add a damage scenario', go: ['new', 'damage'], primary: true } : null,
    },
    {
      title: 'Write the threat scenarios',
      done: threats > 0,
      text: threats ? plural(threats, 'threat scenario') : 'One for each property of an asset that can be lost.',
      action: threats ? { label: 'Open the threat scenarios', go: ['kind', 'threat'] } : assets && damages ? { label: 'Write threat scenarios', generate: 'threats', primary: true } : null,
    },
    {
      title: 'Rate the attack steps and add the controls',
      done: threats > 0 && steps > 0 && results && notCalc === 0,
      text: steps ? plural(steps, 'attack step') + ', ' + plural(controls, 'control') + (notCalc ? ', ' + plural(notCalc, 'threat scenario') + ' cannot be calculated yet' : '') : 'How a threat scenario is carried out, how hard that is, and what stops it.',
      action: threats ? (notCalc ? { label: 'See what is missing', go: ['open'], primary: true } : steps ? { label: 'Open the attack steps', go: ['kind', 'step'] } : { label: 'Add an attack step', go: ['new', 'step'], primary: true }) : null,
    },
    {
      title: 'Decide the risks',
      done: risks > 0 && riskGaps === 0 && undecided === 0 && results,
      text: risks ? (risks - undecided) + ' of ' + plural(risks, 'risk') + ' have a decision' : 'The risk of each threat scenario, and what you do about it.',
      action: !results || !threats ? null
        : (risks === 0 || riskGaps > 0) ? { label: 'Write the risks', generate: 'risks', primary: true }
          : undecided > 0 ? { label: 'Decide ' + undecided + (undecided === 1 ? ' risk' : ' risks'), go: ['decisions'], primary: true }
            : { label: 'Open the decisions', go: ['decisions'] },
    },
    {
      title: 'Check, report and close the round',
      done: closed,
      text: closed ? 'Iteration ' + last.number + ' is closed and nothing changed since.' : S.open.length ? plural(S.open.length, 'item') + (S.open.length === 1 ? ' is' : ' are') + ' still open.' : 'Close the round to keep the decisions in the hash chain.',
      action: results ? (S.open.length ? { label: 'See what is open', go: ['open'] } : closed ? { label: 'Open the report', go: ['report'] } : { label: 'Close the iteration', finalize: true, primary: true }) : null,
    },
  ];
  let found = false;
  list.forEach((s, i) => {
    s.n = i + 1;
    s.state = s.done ? 'done' : !found ? 'now' : 'todo';
    if (!s.done) found = true;
  });
  return list;
}
