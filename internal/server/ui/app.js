// SPDX-License-Identifier: Apache-2.0. Copyright 2026 Stefanos Flokos.
// The web interface of assess. It shows what the commands say and writes only through `assess apply`, so a record is never
// written in a way that the command line would not write it. No framework, no build step and no text is ever put into the page as
// HTML: everything goes in as text.
'use strict';
(function () {
  // ---- small helpers -----------------------------------------------------------------------------------------------
  const $ = (sel, root) => (root || document).querySelector(sel);

  // h makes an element. Attributes starting with "on" are event listeners, the others are attributes or properties.
  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else if (k === 'style') el.style.cssText = v; // the content policy allows this, and not a style attribute
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else if (['value', 'checked', 'disabled', 'selected', 'open'].includes(k)) el[k] = v;
      else el.setAttribute(k, v === true ? '' : v);
    }
    for (const kid of kids.flat(Infinity)) {
      if (kid === null || kid === undefined || kid === false) continue;
      el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    }
    return el;
  }
  const clear = (el) => { while (el.firstChild) el.removeChild(el.firstChild); return el; };
  const plural = (n, word) => n + ' ' + word + (n === 1 ? '' : 's');
  const debounce = (fn, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };
  let counter = 0;
  const uid = () => 'f' + (++counter);
  const lines = (text) => text.split('\n').map((l) => l.trim()).filter(Boolean);
  const canon = (v) => (v && typeof v === 'object' && !Array.isArray(v)
    ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, canon(v[k])]))
    : Array.isArray(v) ? v.map(canon) : v);
  const same = (a, b) => JSON.stringify(canon(a)) === JSON.stringify(canon(b));
  const short = (hash) => String(hash || '').replace('sha256:', '').slice(0, 12);

  // ---- theme ----------------------------------------------------------------------------------------------------------
  const THEMES = ['auto', 'light', 'dark'];
  let theme = 'auto';
  try { theme = localStorage.getItem('assess-theme') || 'auto'; } catch (e) { /* no storage: stay with auto */ }
  if (!THEMES.includes(theme)) theme = 'auto';
  function paintTheme() {
    if (theme === 'auto') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', theme);
    $('#theme').textContent = 'Theme: ' + theme;
  }

  // ---- the token and the API -------------------------------------------------------------------------------------------
  // The address that assess serve prints has the token in its fragment. It is kept for this tab only, and taken out of the
  // address bar.
  let token = '';
  try { token = sessionStorage.getItem('assess-token') || ''; } catch (e) { /* no storage */ }
  const given = /[#&]t=([0-9a-f]+)/.exec(location.hash);
  if (given) {
    token = given[1];
    try { sessionStorage.setItem('assess-token', token); } catch (e) { /* no storage */ }
    history.replaceState(null, '', location.pathname + '#/');
  }

  // api calls the server and always returns a document: the JSON of a command, or one that says what went wrong.
  async function api(path, opt) {
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
    const text = await res.text();
    let doc;
    try { doc = JSON.parse(text); } catch (e) { doc = { ok: false, diagnostics: [{ severity: 'error', code: 'failed', message: text || 'HTTP ' + res.status }] }; }
    doc.status = res.status;
    return doc;
  }

  // ---- state ----------------------------------------------------------------------------------------------------------
  const S = {
    desc: null, kinds: {}, apiVersion: 'assess/v1beta1',
    exp: null, diag: [], recs: [], of: {}, byKey: new Map(), threats: new Map(), byFile: new Map(),
    stamp: '', hash: '', dirty: false, changedOnDisk: false, suppress: false, fatal: '',
  };

  async function load() {
    const [exp, desc] = await Promise.all([api('/api/export'), S.desc ? null : api('/api/describe')]);
    if (exp.status === 401 || (desc && desc.status === 401)) { S.fatal = 'token'; return; }
    if (desc) {
      if (!desc.result) { S.fatal = (desc.diagnostics[0] || {}).message || 'The description of the format could not be read.'; return; }
      S.desc = desc.result;
      S.apiVersion = (desc.assess || {}).apiVersion || S.apiVersion;
      S.kinds = Object.fromEntries(S.desc.kinds.map((k) => [k.kind, k]));
    }
    S.fatal = '';
    S.exp = exp.result || { records: [] };
    S.diag = exp.diagnostics || [];
    S.recs = S.exp.records || [];
    S.of = {}; S.byKey = new Map(); S.byFile = new Map();
    for (const r of S.recs) {
      (S.of[r.kind] = S.of[r.kind] || []).push(r);
      S.byKey.set(r.kind + ':' + r.id, r);
      (S.byFile.get(r.file) || S.byFile.set(r.file, []).get(r.file)).push(r);
    }
    S.threats = new Map(((S.exp.results || {}).threats || []).map((t) => [t.threat, t]));
    const st = await api('/api/stamp');
    S.stamp = st.stamp || '';
    S.changedOnDisk = false;
  }

  const rec = (kind, id) => S.byKey.get(kind + ':' + id);
  const idsOf = (kinds) => [...new Set((kinds || []).flatMap((k) => (S.of[k] || []).map((r) => r.id)))].sort();
  // recordAt finds the record that a place in a file belongs to: the last one that starts at or before the line.
  function recordAt(file, line) {
    let best = null;
    for (const r of S.byFile.get(file) || []) if (r.line <= line && (!best || r.line >= best.line)) best = r;
    return best;
  }
  const kindName = (k) => (S.kinds[k] ? S.kinds[k].name : k);
  const kindsName = (k) => { const n = kindName(k); return /s$/.test(n) ? n : n + 's'; };

  // ---- routing ----------------------------------------------------------------------------------------------------------
  const path = () => location.hash.replace(/^#\/?/, '').split('/').filter(Boolean).map(decodeURIComponent);
  const hrefOf = (...parts) => '#/' + parts.map(encodeURIComponent).join('/');
  const go = (...parts) => { location.hash = hrefOf(...parts); };
  window.addEventListener('hashchange', () => {
    if (S.suppress) { S.suppress = false; return; }
    if (S.dirty && !confirm('Leave this page without saving your changes?')) { S.suppress = true; location.hash = S.hash; return; }
    S.dirty = false;
    S.hash = location.hash;
    render();
  });

  // ---- pieces -----------------------------------------------------------------------------------------------------------
  const chip = (v) => h('span', { class: 'chip v' + (v === undefined || v === null ? '' : v), text: v === undefined || v === null ? '–' : v });
  const link = (text, ...parts) => h('a', { href: hrefOf(...parts) }, text);
  const where = (d) => (d.file ? d.file + (d.line ? ':' + d.line + (d.column ? ':' + d.column : '') : '') : '');

  // diagnostic is one finding: a message with where it is, linked to the record when there is one.
  function diagnostic(d) {
    const cls = d.severity === 'error' ? 'err' : 'warn';
    const real = d.file && d.file !== '<stdin>'; // a place in the change set is not a place in the project
    const at = real ? recordAt(d.file, d.line || 1) : null;
    return h('div', { class: 'alert ' + cls },
      h('span', { class: 'code', text: d.code }),
      d.message,
      real ? h('div', { class: 'where' }, at ? h('a', { href: hrefOf('kind', at.kind, at.id) }, where(d)) : where(d)) : null);
  }
  const diagnostics = (list) => { const f = document.createDocumentFragment(); list.forEach((d) => f.append(diagnostic(d))); return f; };
  // said shows what a command said for a person, when the document has it.
  const said = (env) => (env.text ? h('pre', { class: 'plain', text: env.text }) : null);

  function toast(text, kind) {
    const el = h('div', { class: 'toast alert ' + (kind || 'ok'), role: 'status', text });
    document.body.append(el);
    setTimeout(() => el.remove(), 4500);
  }

  // dialog asks a question. body is a node. It resolves to true when the person confirms.
  function ask(opt) {
    return new Promise((resolve) => {
      const dlg = h('dialog', {},
        h('h2', { text: opt.title }),
        opt.body,
        h('div', { class: 'actions' },
          opt.noCancel ? null : h('button', { class: 'btn', type: 'button', onclick: () => dlg.close('no') }, 'Cancel'),
          h('button', { class: 'btn ' + (opt.danger ? 'solid-danger' : 'primary'), type: 'button', onclick: () => dlg.close('yes') }, opt.ok || 'OK')));
      dlg.addEventListener('close', () => { const yes = dlg.returnValue === 'yes'; dlg.remove(); resolve(yes); });
      document.body.append(dlg);
      dlg.showModal();
    });
  }

  function diff(text) {
    const pre = h('pre', { class: 'diff' });
    for (const l of String(text || '').split('\n')) {
      const cls = l.startsWith('+++') || l.startsWith('---') || l.startsWith('@@') ? 'hunk' : l.startsWith('+') ? 'add' : l.startsWith('-') ? 'del' : 'ctx';
      pre.append(h('span', { class: cls, text: l + '\n' }));
    }
    return pre;
  }

  // ---- the frame: navigation and counts -----------------------------------------------------------------------------------
  function drawFrame(here) {
    const nav = clear($('#nav'));
    const item = (S.of.item || [])[0];
    $('#item').textContent = item ? ((item.attributes || {}).name || item.id) : '';
    const link1 = (label, parts, count) => {
      const on = parts.join('/') === here.slice(0, parts.length).join('/') && parts.length > 0 && here.length >= parts.length;
      return h('a', { href: hrefOf(...parts), class: on ? 'on' : '' }, label, count === undefined ? null : h('span', { class: 'n', text: count }));
    };
    nav.append(h('a', { href: '#/', class: here.length === 0 ? 'on' : '' }, 'Overview'));
    if (S.desc) {
      for (const f of S.desc.folders) {
        nav.append(h('h3', { class: 'label', text: f.folder === 'tara' ? 'TARA' : f.folder[0].toUpperCase() + f.folder.slice(1) }));
        for (const k of f.kinds) nav.append(link1(kindsName(k)[0].toUpperCase() + kindsName(k).slice(1), ['kind', k], (S.of[k] || []).length));
      }
    }
    nav.append(h('h3', { class: 'label', text: 'Work' }));
    const open = ((S.exp || {}).open || []).length;
    nav.append(link1('Open items', ['open'], open), link1('Calculation', ['calc']), link1('Report', ['report']),
      link1('Diagram', ['diagram']), link1('Iterations', ['iterations']), link1('Files', ['files']));

    const errors = S.diag.filter((d) => d.severity === 'error').length;
    const warnings = S.diag.filter((d) => d.severity === 'warning').length;
    const counts = clear($('#counts'));
    counts.append(
      h('a', { href: '#/', class: 'tag ' + (errors ? 'err' : 'ok'), title: 'Errors in the project' }, plural(errors, 'error')),
      h('a', { href: '#/', class: 'tag ' + (warnings ? 'warn' : ''), title: 'Warnings' }, plural(warnings, 'warning')),
      h('a', { href: '#/open', class: 'tag ' + (open ? 'info' : ''), title: 'What is still open' }, open + ' open'));
  }

  // ---- views ---------------------------------------------------------------------------------------------------------------
  function overview() {
    const exp = S.exp, p = exp.project || {};
    const item = (S.of.item || [])[0];
    const errors = S.diag.filter((d) => d.severity === 'error');
    const results = exp.results;
    const page = h('div', { class: 'page' });
    page.append(h('div', { class: 'head' }, h('div', { class: 'grow' }, h('h1', { text: p.name || 'Project' }),
      p.description ? h('p', { text: p.description }) : null)));

    page.append(h('div', { class: 'grid' },
      h('div', { class: 'card stat' }, h('div', { class: 'label', text: 'Records' }), h('div', { class: 'big', text: S.recs.length })),
      h('div', { class: 'card stat' }, h('div', { class: 'label', text: 'Errors' }), h('div', { class: 'big ' + (errors.length ? 'bad' : 'good'), text: errors.length })),
      h('div', { class: 'card stat' }, h('div', { class: 'label', text: 'Open items' }), h('div', { class: 'big ' + ((exp.open || []).length ? '' : 'good'), text: results ? (exp.open || []).length : '–' })),
      results ? h('div', { class: 'card stat' }, h('div', { class: 'label', text: 'Risk of the item' }),
        h('div', { class: 'row' }, h('span', { class: 'big' }, chip(results.item.base)), h('span', { class: 'muted', text: 'before the controls' })),
        h('div', { class: 'row' }, h('span', { class: 'big' }, chip(results.item.residual)), h('span', { class: 'muted', text: 'with the controls' }))) : null));

    if (!results) {
      page.append(h('div', { class: 'alert warn', text: 'The project has errors, so nothing is calculated yet. Fix the errors below. They have a place in the files.' }));
    } else {
      const count = (which) => [1, 2, 3, 4, 5].map((n) => [...S.threats.values()].filter((t) => t.risk && t.risk[which] === n).length);
      const before = count('base'), after = count('residual');
      page.append(h('div', { class: 'card' }, h('h2', { text: 'Risks by level' }),
        h('div', { class: 'bars' }, [0, 1, 2, 3, 4].map((i) => h('div', { class: 'col' }, chip(i + 1),
          h('div', { class: 'n', text: before[i] }), h('div', { class: 'faint small', text: 'before' }),
          h('div', { class: 'n', text: after[i] }), h('div', { class: 'faint small', text: 'with controls' })))),
        h('p', { class: 'muted small', style: 'margin-top: 12px', text: plural(S.threats.size, 'threat scenario') + ', one risk each.' })));
    }

    const facts = h('dl', { class: 'facts' });
    const add = (k, v) => { if (v) facts.append(h('dt', { text: k }), h('dd', { text: v })); };
    add('Item', item ? ((item.attributes || {}).name || item.id) : '');
    add('Standards', (p.standards || []).join(', '));
    add('Assessors', (p.assessors || []).join(', '));
    add('Date of the assessment', p.date);
    const its = exp.iterations || [];
    add('Iteration', its.length ? its[its.length - 1].number + ', closed ' + its[its.length - 1].date : 'none closed yet');
    if (facts.children.length) page.append(h('div', { class: 'card' }, h('h2', { text: 'Project' }), facts));

    if (S.diag.length) {
      page.append(h('div', { class: 'card' }, h('h2', { text: 'Findings' }), diagnostics(S.diag.slice(0, 100)),
        S.diag.length > 100 ? h('p', { class: 'muted small', text: '… and ' + (S.diag.length - 100) + ' more. Run assess validate for the whole list.' }) : null));
    }
    return page;
  }

  function list(kind) {
    const info = S.kinds[kind];
    if (!info) return notFound('There is no such kind of record: ' + kind);
    const rows = S.of[kind] || [];
    const body = h('tbody');
    const filter = h('input', { class: 'filter', type: 'search', placeholder: 'Filter by id or name', 'aria-label': 'Filter the list' });
    const draw = () => {
      const q = filter.value.trim().toLowerCase();
      clear(body);
      for (const r of rows) {
        const name = (r.attributes || {}).name || '';
        if (q && !(r.id.toLowerCase().includes(q) || String(name).toLowerCase().includes(q))) continue;
        body.append(h('tr', {},
          h('td', {}, h('a', { class: 'mono', href: hrefOf('kind', kind, r.id) }, r.id)),
          h('td', { text: name }),
          h('td', { class: 'nw' }, extra(kind, r)),
          h('td', { class: 'faint small mono', text: r.file + ':' + r.line }),
          h('td', { class: 'faint small mono', text: r.parent || '' })));
      }
      if (!body.children.length) body.append(h('tr', {}, h('td', { colspan: 5, class: 'empty', text: rows.length ? 'Nothing matches the filter.' : 'No ' + kindsName(kind) + ' yet.' })));
    };
    filter.addEventListener('input', draw);
    draw();
    return h('div', { class: 'page' },
      h('div', { class: 'head' },
        h('div', { class: 'grow' }, h('h1', { text: kindsName(kind)[0].toUpperCase() + kindsName(kind).slice(1) }), h('p', { text: info.doc })),
        h('a', { class: 'btn primary', href: hrefOf('new', kind) }, 'New ' + info.name)),
      h('div', { class: 'row', style: 'margin-bottom: 12px' }, filter, h('span', { class: 'muted small', text: plural(rows.length, 'record') })),
      h('div', { class: 'card scroll', style: 'padding: 0' }, h('table', { class: 't' },
        h('thead', {}, h('tr', {}, ['Id', 'Name', '', 'Where', 'Inside'].map((t) => h('th', { text: t })))), body)));
  }

  // extra is the one thing that is worth seeing in a list, besides the name.
  function extra(kind, r) {
    const a = r.attributes || {};
    if (kind === 'risk') return [chip(a.base), ' ', h('span', { class: 'faint', text: '→' }), ' ', chip(a.residual), a.treatment ? h('span', { class: 'muted small', text: '  ' + a.treatment }) : null];
    if (kind === 'threat') { const t = S.threats.get(r.id); return t && t.risk ? [chip(t.risk.base), ' ', h('span', { class: 'faint', text: '→' }), ' ', chip(t.risk.residual)] : h('span', { class: 'faint', text: 'not calculated' }); }
    return null;
  }

  function notFound(text) {
    return h('div', { class: 'page' }, h('div', { class: 'card empty' }, h('p', { text }), h('a', { class: 'btn', href: '#/' }, 'Back to the overview')));
  }

  // ---- the form of a record ------------------------------------------------------------------------------------------------
  const INVALID = { invalid: true };

  // field builds the control for one attribute from what describe says about it. get() returns the value that the control holds,
  // undefined when it is empty, or INVALID when what is typed cannot be used.
  function field(attr, value, onChange, path) {
    const id = uid();
    let control, get;
    const note = (n) => { onChange(); return n; };
    const candidates = () => idsOf(attr.refs);
    const withCurrent = (opts, cur) => (cur && !opts.includes(cur) ? [cur, ...opts] : opts);
    const jsonBox = () => {
      const ta = h('textarea', { id, class: 'json', rows: 4, spellcheck: 'false', oninput: () => note() });
      ta.value = value === undefined ? '' : JSON.stringify(value, null, 2);
      get = () => {
        const t = ta.value.trim();
        ta.classList.remove('bad');
        if (!t) return undefined;
        try { return JSON.parse(t); } catch (e) { ta.classList.add('bad'); return INVALID; }
      };
      control = ta;
    };
    switch (attr.type) {
      case 'text': {
        const long = /description|rationale|boundary|statement|note|check|message/.test(attr.name) || (typeof value === 'string' && (value.includes('\n') || value.length > 90));
        const el = long ? h('textarea', { id, rows: 3, oninput: () => note() }) : h('input', { id, type: 'text', oninput: () => note() });
        el.value = value === undefined ? '' : String(value);
        get = () => (el.value === '' ? undefined : el.value);
        control = el;
        break;
      }
      case 'number': {
        const el = h('input', { id, type: 'number', step: 'any', oninput: () => note() });
        el.value = value === undefined ? '' : String(value);
        get = () => (el.value === '' ? undefined : Number(el.value));
        control = el;
        break;
      }
      case 'bool': {
        const el = h('select', { id, onchange: () => note() }, h('option', { value: '', text: 'Not set' }), h('option', { value: 'true', text: 'true' }), h('option', { value: 'false', text: 'false' }));
        el.value = value === undefined ? '' : String(value);
        get = () => (el.value === '' ? undefined : el.value === 'true');
        control = el;
        break;
      }
      case 'enum': {
        const el = h('select', { id, onchange: () => note() }, h('option', { value: '', text: attr.required ? 'Choose…' : 'Not set' }),
          (attr.values || []).map((v) => h('option', { value: v, text: v })));
        el.value = value === undefined ? '' : String(value);
        get = () => (el.value === '' ? undefined : el.value);
        control = el;
        break;
      }
      case 'enums': {
        const have = new Set(Array.isArray(value) ? value : value === undefined ? [] : [value]);
        const boxes = (attr.values || []).map((v) => h('input', { type: 'checkbox', value: v, checked: have.has(v), onchange: () => note() }));
        control = h('div', { class: 'checks', id }, (attr.values || []).map((v, i) => h('label', {}, boxes[i], v)));
        get = () => { const on = boxes.filter((b) => b.checked).map((b) => b.value); return on.length ? on : undefined; };
        break;
      }
      case 'id': {
        const opts = candidates();
        if (!opts.length) {
          const el = h('input', { id, type: 'text', class: 'mono', oninput: () => note() });
          el.value = value === undefined ? '' : String(value);
          get = () => (el.value === '' ? undefined : el.value.trim());
          control = el;
        } else {
          const el = h('select', { id, onchange: () => note() }, h('option', { value: '', text: attr.required ? 'Choose…' : 'Not set' }),
            withCurrent(opts, value).map((v) => h('option', { value: v, text: v })));
          el.value = value === undefined ? '' : String(value);
          get = () => (el.value === '' ? undefined : el.value);
          control = el;
        }
        break;
      }
      case 'ids':
      case 'texts': {
        const ta = h('textarea', { id, class: 'lines', rows: 3, spellcheck: 'false', oninput: () => note() });
        ta.value = (Array.isArray(value) ? value : value === undefined ? [] : [value]).join('\n');
        get = () => { const l = lines(ta.value); return l.length ? l : undefined; };
        control = h('div', {}, ta);
        const opts = attr.type === 'ids' ? candidates() : [];
        if (opts.length) {
          const pick = h('select', { class: 'pick', 'aria-label': 'Add an id', onchange: () => {
            if (pick.value && !lines(ta.value).includes(pick.value)) { ta.value = (ta.value.trim() ? ta.value.trim() + '\n' : '') + pick.value; note(); }
            pick.value = '';
          } }, h('option', { value: '', text: 'Add an id…' }), opts.map((v) => h('option', { value: v, text: v })));
          control.append(pick);
        }
        break;
      }
      case 'map': {
        const rows = h('div', { class: 'pairs' });
        const addRow = (k, v) => {
          const row = h('div', { class: 'pair' },
            h('input', { type: 'text', placeholder: 'key', 'aria-label': 'Key', value: k, oninput: () => note() }),
            h('input', { type: 'text', placeholder: 'value', 'aria-label': 'Value', value: v, oninput: () => note() }),
            h('button', { class: 'btn', type: 'button', 'aria-label': 'Remove this row', onclick: () => { row.remove(); note(); } }, '×'));
          rows.append(row);
        };
        for (const [k, v] of Object.entries(value || {})) addRow(k, v === null || typeof v === 'object' ? JSON.stringify(v) : String(v));
        control = h('div', { id }, rows, h('button', { class: 'btn', type: 'button', style: 'margin-top: 6px', onclick: () => addRow('', '') }, 'Add a row'));
        get = () => {
          const out = {};
          for (const row of rows.children) { const [k, v] = row.querySelectorAll('input'); if (k.value.trim()) out[k.value.trim()] = v.value; }
          return Object.keys(out).length ? out : undefined;
        };
        break;
      }
      case 'block': {
        if (!attr.attributes || !attr.attributes.length) { jsonBox(); break; }
        const subs = attr.attributes.map((a) => field(a, (value || {})[a.name], onChange, path + '.' + a.name));
        const fs = h('fieldset', { class: 'block' }, h('legend', { text: attr.name }), subs.map((s) => s.node));
        get = () => {
          const out = {};
          for (const s of subs) { const v = s.get(); if (v === INVALID) return INVALID; if (v !== undefined) out[s.attr.name] = v; }
          return Object.keys(out).length ? out : undefined;
        };
        return { attr, node: fs, get };
      }
      default: // tree, blocks, compromises, table, rows: written as JSON
        jsonBox();
    }
    const node = h('div', { class: 'field' },
      h('label', { for: id }, attr.name, attr.required ? h('span', { class: 'req', title: 'Required', text: '*' }) : null, h('span', { class: 'type', text: attr.type })),
      attr.doc ? h('p', { class: 'doc', text: attr.doc }) : null, control);
    return { attr, node, get };
  }

  // changesOf works out what the form changes: the attributes that differ from what the record has, and null for one that was emptied.
  function changesOf(fields, original) {
    const out = {};
    let invalid = false;
    for (const f of fields) {
      const cur = f.get();
      const orig = original[f.attr.name];
      if (cur === INVALID) { invalid = true; continue; }
      if (cur === undefined) { if (orig !== undefined && orig !== null) out[f.attr.name] = null; continue; }
      const a = f.attr.type === 'ids' && typeof orig === 'string' ? [orig] : orig;
      if (!same(cur, a)) out[f.attr.name] = cur;
    }
    return { attrs: out, invalid };
  }

  const changeSet = (changes) => ({ apiVersion: S.apiVersion, changes });

  // ---- the editor of a record ---------------------------------------------------------------------------------------------------
  function editor(kind, id, isNew) {
    const info = S.kinds[kind];
    if (!info) return notFound('There is no such kind of record: ' + kind);
    const existing = isNew ? null : rec(kind, id);
    if (!isNew && !existing) return notFound('There is no ' + info.name + ' with the id ' + id + '.');
    const original = existing ? existing.attributes || {} : {};

    // the id and the parent, for a new record
    let idCtl = null, parentCtl = null;
    const top = [];
    if (isNew) {
      const taken = new Set((S.of[kind] || []).map((r) => r.id));
      if (info.idOf && info.idOf.length) {
        const options = idsOf(info.idOf).filter((v) => !taken.has(v));
        idCtl = h('select', { id: 'new-id', onchange: () => changed() }, h('option', { value: '', text: 'Choose…' }), options.map((v) => h('option', { value: v, text: v })));
      } else {
        idCtl = h('input', { id: 'new-id', type: 'text', class: 'mono', placeholder: info.heading.replace(/^\S+\s/, ''), oninput: () => changed(), spellcheck: 'false' });
      }
      top.push(h('div', { class: 'field' }, h('label', { for: 'new-id' }, 'id', h('span', { class: 'req', text: '*' }), h('span', { class: 'type', text: info.heading })),
        h('p', { class: 'doc', text: info.idOf && info.idOf.length ? 'The id is the id of the ' + info.idOf.join(' or ') + ' that this record is about.' : 'Lower case words with hyphens.' }), idCtl));
      if (info.parents && info.parents.length) {
        const options = idsOf(info.parents);
        parentCtl = h('select', { id: 'new-parent', onchange: () => changed() }, h('option', { value: '', text: info.topLevel ? 'Not inside another record' : 'Choose…' }), options.map((v) => h('option', { value: v, text: v })));
        top.push(h('div', { class: 'field' }, h('label', { for: 'new-parent' }, 'parent', info.topLevel ? null : h('span', { class: 'req', text: '*' })),
          h('p', { class: 'doc', text: 'The record that this one is written inside: ' + info.parents.join(' or ') + '.' }), parentCtl));
      }
    }

    const status = h('div', { 'aria-live': 'polite' });
    const save = h('button', { class: 'btn primary', type: 'button', disabled: true }, 'Save');
    const revert = h('button', { class: 'btn', type: 'button', onclick: () => { S.dirty = false; render(); } }, 'Discard changes');
    let seq = 0;

    const fields = info.attributes.map((a) => field(a, original[a.name], () => changed(), a.name));
    const build = () => {
      const { attrs, invalid } = changesOf(fields, original);
      if (invalid) return { error: 'One of the fields holds text that is not valid JSON.' };
      if (isNew) {
        const newId = idCtl.value.trim();
        if (!newId) return { error: 'Give the new record an id.' };
        const change = { op: 'put', kind, id: newId, attributes: attrs };
        if (parentCtl && parentCtl.value) change.parent = parentCtl.value;
        return { set: changeSet([change]), id: newId };
      }
      if (!Object.keys(attrs).length) return { none: true };
      return { set: changeSet([{ op: 'put', kind, id, attributes: attrs }]), id };
    };

    const check = async () => {
      const mine = ++seq;
      const b = build();
      clear(status);
      save.disabled = true;
      if (b.error) { status.append(h('div', { class: 'alert info', text: b.error })); return; }
      if (b.none) { status.append(h('p', { class: 'muted small', text: 'No changes yet.' })); return; }
      const env = await api('/api/apply?dry=1', { method: 'POST', body: b.set });
      if (mine !== seq) return; // a newer check is on its way
      clear(status);
      const errors = (env.diagnostics || []).filter((d) => d.severity === 'error');
      if (!env.ok) {
        status.append(errors.length ? diagnostics(errors.slice(0, 20)) : h('div', { class: 'alert err', text: env.text || 'The change cannot be applied.' }));
        return;
      }
      const r = env.result || {};
      status.append(h('div', { class: 'alert ok', text: 'The change is valid. It touches ' + plural((r.files || []).length, 'file') + '.' }), diff(r.diff));
      save.disabled = false;
    };
    const checkLater = debounce(check, 450);
    function changed() { S.dirty = true; clear(status); status.append(h('p', { class: 'muted small', text: 'Checking…' })); save.disabled = true; checkLater(); }

    save.addEventListener('click', async () => {
      const b = build();
      if (!b.set) return;
      save.disabled = true;
      const env = await api('/api/apply', { method: 'POST', body: b.set });
      if (!env.ok) { clear(status); status.append(diagnostics((env.diagnostics || []).slice(0, 20))); if (!env.diagnostics || !env.diagnostics.length) status.append(h('div', { class: 'alert err', text: env.text || 'The change was not written.' })); return; }
      S.dirty = false;
      await load();
      toast('Saved ' + info.name + ' ' + b.id + '.');
      if (isNew) go('kind', kind, b.id); else render();
    });

    const head = h('div', { class: 'head' },
      h('div', { class: 'grow' },
        h('div', { class: 'label', text: info.name }),
        h('h1', { class: 'mono', style: 'font-size: 1.3rem', text: isNew ? 'New ' + info.name : id }),
        existing ? h('p', { class: 'mono small' }, existing.file + ':' + existing.line) : h('p', { text: info.doc })),
      existing ? h('div', { class: 'row' },
        S.of.threat && kind === 'threat' ? h('a', { class: 'btn', href: hrefOf('calc', id) }, 'Calculation') : null,
        h('button', { class: 'btn danger', type: 'button', onclick: () => deleteRecord(kind, id) }, 'Delete')) : null);

    return h('div', { class: 'page' }, head,
      h('div', { class: 'card' }, top, fields.map((f) => f.node)),
      h('div', { class: 'sticky' }, status, h('div', { class: 'row' }, save, revert, h('a', { class: 'btn', href: hrefOf('kind', kind) }, 'Back to the list'))));
  }

  // deleteRecord asks assess what a delete would do, before it does it. A record that others use is refused, with the list of who uses
  // it, and the person can then choose to delete those too.
  async function deleteRecord(kind, id) {
    const set = (cascade) => changeSet([Object.assign({ op: 'delete', kind, id }, cascade ? { cascade: true } : {})]);
    const problem = (env) => h('div', {}, (env.diagnostics || []).length ? diagnostics(env.diagnostics.slice(0, 10)) : h('div', { class: 'alert err', text: env.text || 'The delete was refused.' }));
    let cascade = false;
    let env = await api('/api/apply?dry=1', { method: 'POST', body: set(false) });
    if (!env.ok) {
      const blocked = (env.result || {}).blocked || [];
      if (!blocked.length) { await ask({ title: 'Cannot delete', body: problem(env), noCancel: true }); return; }
      const proceed = await ask({
        title: id + ' is used by other records', ok: 'Show what a delete with them removes',
        body: h('div', {}, h('p', { text: 'These records refer to it:' }),
          h('ul', {}, blocked.map((b) => h('li', {}, h('code', { text: b.kind + ' ' + b.id }), ' ', h('span', { class: 'muted', text: b.message }))))),
      });
      if (!proceed) return;
      cascade = true;
      env = await api('/api/apply?dry=1', { method: 'POST', body: set(true) });
      if (!env.ok) { await ask({ title: 'Cannot delete', body: problem(env), noCancel: true }); return; }
    }
    const r = env.result || {};
    const body = h('div', {}, h('p', { text: 'This removes:' }),
      h('ul', {}, (r.deleted || []).map((d) => h('li', {}, h('code', { text: d.kind + ' ' + d.id }), d.reason ? h('span', { class: 'muted', text: '  ' + d.reason }) : null))),
      (r.updated || []).length ? h('p', { text: 'And it changes:' }) : null,
      (r.updated || []).length ? h('ul', {}, r.updated.map((u) => h('li', {}, h('code', { text: u.kind + ' ' + u.id }), u.reason ? h('span', { class: 'muted', text: '  ' + u.reason }) : null))) : null);
    if (!(await ask({ title: 'Delete ' + kind + ' ' + id + '?', body, ok: 'Delete', danger: true }))) return;
    const done = await api('/api/apply', { method: 'POST', body: set(cascade) });
    if (!done.ok) { await ask({ title: 'The delete was not written', body: problem(done), noCancel: true }); return; }
    S.dirty = false;
    await load();
    toast('Deleted ' + kind + ' ' + id + '.');
    go('kind', kind);
  }

  // ---- open items, and the work that assess does for you -----------------------------------------------------------------
  function openItems() {
    const items = (S.exp || {}).open || [];
    const page = h('div', { class: 'page' }, h('div', { class: 'head' }, h('div', { class: 'grow' }, h('h1', { text: 'Open items' }),
      h('p', { text: 'What is not calculated, what has no decision yet and what the rules found. It is the same list as in the report.' }))));
    if (!S.exp.results) page.append(h('div', { class: 'alert warn', text: 'The project has errors, so the list is not there yet. See the findings in the overview.' }));
    else if (!items.length) page.append(h('div', { class: 'alert ok', text: 'Nothing is open.' }));
    else page.append(h('div', { class: 'card scroll', style: 'padding: 0' }, h('table', { class: 't' },
      h('thead', {}, h('tr', {}, ['Code', 'Where', 'What'].map((t) => h('th', { text: t })))),
      h('tbody', {}, items.map((it) => h('tr', {},
        h('td', {}, h('span', { class: 'tag info', text: it.code })),
        h('td', {}, it.kind && it.id && rec(it.kind, it.id) ? h('a', { class: 'mono', href: hrefOf('kind', it.kind, it.id) }, it.where || it.kind + ' ' + it.id) : h('span', { class: 'mono', text: it.where || '' })),
        h('td', { text: it.text })))))));

    const action = (title, what, text, force) => h('div', { class: 'card' }, h('h3', { text: title }), h('p', { class: 'muted', text }),
      h('button', { class: 'btn', type: 'button', onclick: async (e) => {
        e.target.disabled = true;
        const env = await api('/api/generate?what=' + what + (force ? '&force=1' : ''), { method: 'POST', body: {} });
        e.target.disabled = false;
        await load();
        render();
        toast(env.text || (env.ok ? 'Done.' : (env.diagnostics[0] || {}).message || 'It did not work.'), env.ok ? 'ok' : 'err');
      } }, title));
    page.append(h('h2', { text: 'Let assess write records', style: 'margin: 24px 0 12px' }),
      h('div', { class: 'grid' },
        action('Write assets', 'assets', 'An asset for every element of the architecture, with all five properties. It is written once. Remove what does not apply.'),
        action('Write threat scenarios', 'threats', 'One threat scenario for each asset property that has none. What exists stays as it is.'),
        action('Write risks', 'risks', 'The risk of each threat scenario, with its two values. The decisions that you wrote stay.')));
    page.append(h('div', { class: 'card' }, h('h3', { text: 'Close an iteration' }),
      h('p', { class: 'muted', text: 'Closes the treatment decisions in the hash chain. It is refused while anything is open. A signature is added on the command line, with your private key.' }),
      h('button', { class: 'btn primary', type: 'button', onclick: finalizeDialog }, 'Close iteration…')));
    return page;
  }

  async function finalizeDialog() {
    const assessors = ((S.exp.project || {}).assessors || []).join(', ');
    const note = h('textarea', { rows: 2, 'aria-label': 'What this iteration was', placeholder: 'What this iteration was, in a sentence' });
    const by = h('input', { type: 'text', 'aria-label': 'Who closes it', placeholder: assessors || 'Names, separated by commas' });
    const out = h('div', {});
    const body = h('div', {}, h('div', { class: 'field' }, h('label', {}, 'Note'), note), h('div', { class: 'field' }, h('label', {}, 'By'), by,
      h('p', { class: 'doc', text: 'Leave it empty to use the assessors of project.yaml.' })), out);
    const payload = () => ({ note: note.value.trim(), by: by.value.split(',').map((s) => s.trim()).filter(Boolean) });
    const preview = h('button', { class: 'btn', type: 'button', onclick: async () => {
      const env = await api('/api/finalize?dry=1', { method: 'POST', body: payload() });
      clear(out);
      out.append(env.ok ? h('div', { class: 'alert ok', text: 'This is what would be closed:' }) : h('div', { class: 'alert warn', text: 'It cannot be closed yet:' }), said(env), diagnostics((env.diagnostics || []).slice(0, 10)));
    } }, 'Preview');
    body.append(h('div', { class: 'row' }, preview));
    if (!(await ask({ title: 'Close iteration', body, ok: 'Close iteration' }))) return;
    const env = await api('/api/finalize', { method: 'POST', body: payload() });
    await load();
    render();
    if (env.ok) toast('Iteration closed.');
    else await ask({ title: 'The iteration was not closed', noCancel: true, body: h('div', {}, said(env), diagnostics((env.diagnostics || []).slice(0, 10))) });
  }

  // ---- calculation, report, diagram, iterations, files -------------------------------------------------------------------------
  function calc() {
    const r = S.exp.results;
    const page = h('div', { class: 'page' }, h('div', { class: 'head' }, h('div', { class: 'grow' }, h('h1', { text: 'Calculation' }),
      h('p', { text: 'The risk of each threat scenario, before the controls and with them. Open one to see how each number came out.' }))));
    if (!r) { page.append(h('div', { class: 'alert warn', text: 'The project has errors, so nothing is calculated yet.' })); return page; }
    page.append(h('div', { class: 'card' }, h('div', { class: 'row' }, h('strong', { text: 'The item' }), chip(r.item.base), h('span', { class: 'muted', text: 'before, decided by' }),
      r.item.baseBy ? h('code', { text: r.item.baseBy }) : null, chip(r.item.residual), h('span', { class: 'muted', text: 'with the controls' }))));
    page.append(h('div', { class: 'card scroll', style: 'padding: 0' }, h('table', { class: 't' },
      h('thead', {}, h('tr', {}, ['Threat scenario', 'Before', 'With controls', 'Type', 'Feasibility'].map((t) => h('th', { text: t })))),
      h('tbody', {}, r.threats.map((t) => h('tr', {},
        h('td', {}, h('a', { class: 'mono', href: hrefOf('calc', t.threat) }, t.threat), h('div', { class: 'muted small', text: t.name })),
        h('td', {}, chip(t.risk && t.risk.base)),
        h('td', {}, chip(t.risk && t.risk.residual)),
        h('td', { text: (t.risk && t.risk.type) || '' }),
        h('td', { class: 'small', text: (t.base && t.base.level ? t.base.level : '–') + ' → ' + (t.residual && t.residual.level ? t.residual.level : '–') })))))));
    return page;
  }

  function explain(id) {
    const pre = h('pre', { class: 'plain', text: 'Loading…' });
    fetch('/api/explain-text?id=' + encodeURIComponent(id), { headers: { 'X-Assess-Token': token }, cache: 'no-store' })
      .then((r) => r.text()).then((t) => { pre.textContent = t; }).catch(() => { pre.textContent = 'The server does not answer.'; });
    return h('div', { class: 'page' }, h('div', { class: 'head' }, h('div', { class: 'grow' }, h('div', { class: 'label', text: 'Worksheet' }), h('h1', { class: 'mono', style: 'font-size: 1.3rem', text: id })),
      rec('threat', id) ? h('a', { class: 'btn', href: hrefOf('kind', 'threat', id) }, 'Open the record') : null,
      h('a', { class: 'btn', href: hrefOf('diagram', id) }, 'Attack tree'), h('a', { class: 'btn', href: '#/calc' }, 'Back')), pre);
  }

  // The report is shown from the other name of this server (localhost and 127.0.0.1 are different origins for a browser), so the
  // page of the report cannot read anything that this page keeps. A sandbox attribute would do the same, but a browser may
  // refuse to load a sandboxed frame from the local computer.
  const otherHost = () => (location.hostname === 'localhost' ? '127.0.0.1' : 'localhost');
  const reportURL = (more) => location.protocol + '//' + otherHost() + ':' + location.port + '/report?t=' + encodeURIComponent(token) + (more || '');

  function reportView() {
    const frame = h('iframe', { class: 'frame', title: 'The report', src: reportURL('&v=' + Date.now()) });
    return h('div', { class: 'page', style: 'max-width: none' }, h('div', { class: 'head' }, h('div', { class: 'grow' }, h('h1', { text: 'Report' }),
      h('p', { text: 'The same page that assess report writes. It is built from the files when you open it.' })),
      h('button', { class: 'btn', type: 'button', onclick: () => { frame.src = reportURL('&v=' + Date.now()); } }, 'Build again'),
      h('a', { class: 'btn', target: '_blank', rel: 'noopener', href: reportURL() }, 'Open in a new tab')), frame);
  }

  function diagramView(id) {
    const picture = h('div', { class: 'diagram' });
    const draw = (threat) => {
      clear(picture);
      picture.append(h('img', { alt: threat ? 'The attack tree of ' + threat : 'The architecture of the item',
        src: '/diagram.svg?t=' + encodeURIComponent(token) + (threat ? '&threat=' + encodeURIComponent(threat) : '') + '&v=' + Date.now() }));
    };
    const pick = h('select', { 'aria-label': 'What to draw', onchange: () => go('diagram', ...(pick.value ? [pick.value] : [])) },
      h('option', { value: '', text: 'The architecture' }), [...S.threats.keys()].map((t) => h('option', { value: t, text: 'Attack tree: ' + t })));
    pick.value = id || '';
    draw(id);
    return h('div', { class: 'page', style: 'max-width: none' }, h('div', { class: 'head' }, h('div', { class: 'grow' }, h('h1', { text: 'Diagram' })),
      h('div', { style: 'min-width: 18rem' }, pick)), picture);
  }

  function iterations() {
    const its = (S.exp || {}).iterations || [];
    const out = h('div', {});
    const check = h('button', { class: 'btn', type: 'button', onclick: async () => {
      const env = await api('/api/verify');
      clear(out);
      out.append(h('div', { class: 'alert ' + (env.ok ? 'ok' : 'err'), text: env.ok ? 'The chain is intact.' : 'The chain is not intact.' }), said(env), diagnostics((env.diagnostics || []).slice(0, 20)));
    } }, 'Check the chain');
    const page = h('div', { class: 'page' }, h('div', { class: 'head' }, h('div', { class: 'grow' }, h('h1', { text: 'Iterations' }),
      h('p', { text: 'Each closed iteration holds the treatment decisions of one round. They are linked by hashes, so a later change to one is found.' })), check), out);
    if (!its.length) page.append(h('div', { class: 'card empty', text: 'No iteration is closed yet. Close one when every risk has its decision.' }));
    else page.append(h('div', { class: 'card scroll', style: 'padding: 0' }, h('table', { class: 't' },
      h('thead', {}, h('tr', {}, ['No.', 'Date', 'By', 'Note', 'Decisions', 'Hash', 'Signatures'].map((t) => h('th', { text: t })))),
      h('tbody', {}, its.map((i) => h('tr', {}, h('td', { class: 'num', text: i.number }), h('td', { class: 'small', text: i.date }), h('td', { text: (i.by || []).join(', ') }),
        h('td', { text: i.note || '' }), h('td', { class: 'num', text: (i.decisions || []).length }), h('td', { class: 'mono small', text: short(i.hash) }),
        h('td', { class: 'num', text: (i.signatures || []).length })))))));
    return page;
  }

  function files() {
    const exp = S.exp;
    const block = (title, value) => h('div', { class: 'card' }, h('h2', { text: title }), value && Object.keys(value).length ? h('pre', { class: 'plain', text: JSON.stringify(value, null, 2) }) : h('p', { class: 'muted', text: 'Nothing is written there.' }));
    return h('div', { class: 'page' }, h('div', { class: 'head' }, h('div', { class: 'grow' }, h('h1', { text: 'Files' }),
      h('p', { text: 'These files hold settings and are not records. Change them in your editor. The page shows them as they are.' }))),
      block('assess.yaml', exp.config), block('project.yaml', exp.project), block(exp.policyFile || 'policy.yaml', exp.policy));
  }

  // banner tells a person who is editing that the files changed on disk. The form stays as it is.
  function banner() {
    const main = $('#main');
    if ($('#changed')) return;
    main.prepend(h('div', { id: 'changed', class: 'alert warn row', style: 'margin: 0 0 16px' }, 'The files changed on disk while you were editing.',
      h('button', { class: 'btn', type: 'button', onclick: async () => { S.dirty = false; await load(); render(); } }, 'Reload and discard my changes')));
  }

  // ---- drawing the page ---------------------------------------------------------------------------------------------------------
  function render() {
    const parts = path();
    const main = clear($('#main'));
    if (S.fatal) {
      drawFrame(['none']);
      main.append(h('div', { class: 'page' }, h('div', { class: 'card empty' },
        h('h2', { text: S.fatal === 'token' ? 'This page needs the address that assess serve printed' : 'Something went wrong' }),
        h('p', { text: S.fatal === 'token' ? 'The address has a token at its end. Copy the whole line from the terminal into the address bar.' : S.fatal }))));
      return;
    }
    drawFrame(parts);
    const page = h('div', {});
    let view;
    const [a, b, c] = parts;
    if (!a) view = overview();
    else if (a === 'kind' && b && c) view = editor(b, c, false);
    else if (a === 'kind' && b) view = list(b);
    else if (a === 'new' && b) view = editor(b, '', true);
    else if (a === 'open') view = openItems();
    else if (a === 'calc') view = b ? explain(b) : calc();
    else if (a === 'report') view = reportView();
    else if (a === 'diagram') view = diagramView(b);
    else if (a === 'iterations') view = iterations();
    else if (a === 'files') view = files();
    else view = notFound('There is no such page.');
    page.append(view);
    main.append(page);
    main.scrollTop = 0;
  }

  // ---- start ------------------------------------------------------------------------------------------------------------------------
  async function start() {
    paintTheme();
    $('#theme').addEventListener('click', () => {
      theme = THEMES[(THEMES.indexOf(theme) + 1) % THEMES.length];
      try { localStorage.setItem('assess-theme', theme); } catch (e) { /* no storage */ }
      paintTheme();
    });
    S.hash = location.hash;
    if (!token) { S.fatal = 'token'; render(); return; }
    await load();
    render();
    // The files may change under the page: an editor, or a command. A change is noticed within a few seconds. A form with
    // unsaved changes is not replaced. The person is told instead.
    setInterval(async () => {
      if (document.hidden || S.fatal) return;
      const st = await api('/api/stamp');
      if (!st.stamp || st.stamp === S.stamp) return;
      if (S.dirty) { S.changedOnDisk = true; banner(); return; }
      await load();
      render();
    }, 2000);
  }
  start();
})();
