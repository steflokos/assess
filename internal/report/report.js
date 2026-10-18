// SPDX-License-Identifier: Apache-2.0. Copyright 2026 Stefanos Flokos.
// The conveniences of the report: a filter for the tables, a theme switch, the place you are in the
// table of contents and links that open what they point into. The page reads the same without this
// script, which the page allows to run and to do nothing else (see the policy in its head).
// A page template may leave out the bar or the contents: every feature checks that its part is there.
(() => {
  const root = document.documentElement;
  root.classList.add('js');
  const $ = (selector, within = document) => within.querySelector(selector);
  const $$ = (selector, within = document) => Array.from(within.querySelectorAll(selector));

  // The theme is set before the page is drawn, so that a chosen theme does not flash.
  const THEMES = ['auto', 'light', 'dark'];
  const STORE = 'assess-report-theme';
  let theme = 'auto';
  try { theme = localStorage.getItem(STORE) || 'auto'; } catch (e) { /* no storage: stay with auto */ }
  if (!THEMES.includes(theme)) theme = 'auto';
  const paintTheme = () => (theme === 'auto' ? root.removeAttribute('data-theme') : root.setAttribute('data-theme', theme));
  paintTheme();

  document.addEventListener('DOMContentLoaded', () => {
    const filter = $('#filter');
    const hits = $('#hits');
    let run = () => {}; // applies the filter; set below when the page has one

    // ---- theme
    const button = $('#theme');
    if (button) {
      const label = () => { button.textContent = 'Theme: ' + theme; };
      button.hidden = false;
      label();
      button.addEventListener('click', () => {
        theme = THEMES[(THEMES.indexOf(theme) + 1) % THEMES.length];
        paintTheme();
        label();
        try { localStorage.setItem(STORE, theme); } catch (e) { /* not kept */ }
      });
    }

    // ---- filter: a row stays when it holds every word typed, in any of its cells. A derivation
    // worksheet is matched by its title and what no row matches is hidden with its heading.
    if (filter) {
      let rows = null; // everything that can be filtered, with its text, read the first time it is needed
      const collect = () => rows || (rows = [
        ...$$('.tablewrap').flatMap((wrap) => $$('tbody tr', wrap).map((el) => ({ el, wrap, text: el.textContent.toLowerCase() }))),
        ...$$('section.part details[id]').map((el) => ({ el, wrap: null, text: $('summary', el).textContent.toLowerCase() })),
      ]);
      run = () => {
        const words = filter.value.toLowerCase().split(/\s+/).filter(Boolean);
        const all = collect();
        const shown = new Map();
        let total = 0;
        for (const r of all) {
          const match = words.every((w) => r.text.includes(w));
          if (r.el.hidden === match) r.el.hidden = !match;
          if (match) { total++; if (r.wrap) shown.set(r.wrap, (shown.get(r.wrap) || 0) + 1); }
        }
        for (const wrap of $$('.tablewrap')) wrap.classList.toggle('nomatch', words.length > 0 && !shown.get(wrap));
        root.classList.toggle('filtering', words.length > 0);
        if (hits) hits.textContent = words.length ? total + ' of ' + all.length + ' shown' : '';
      };
      let timer = 0;
      filter.hidden = false;
      filter.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(run, 150); });
      document.addEventListener('keydown', (e) => {
        const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);
        if (e.key === '/' && !typing && !e.metaKey && !e.ctrlKey && !e.altKey) {
          e.preventDefault();
          filter.focus();
          filter.select();
        } else if (e.key === 'Escape' && document.activeElement === filter) {
          filter.value = '';
          run();
          filter.blur();
        }
      });
    }

    // ---- links open what they point into: a section that is folded, or a row the filter hides
    const reveal = (id) => {
      let el = null;
      try { el = document.getElementById(decodeURIComponent(id)); } catch (e) { /* not an id */ }
      if (!el) return null;
      if (filter && filter.value) { // a target the filter hides: show everything again
        const section = el.closest('section');
        if (el.closest('[hidden], .nomatch') || (section && getComputedStyle(section).display === 'none')) { filter.value = ''; run(); }
      }
      for (let d = el.closest('details'); d; d = d.parentElement && d.parentElement.closest('details')) d.open = true;
      return el;
    };
    document.addEventListener('click', (e) => {
      const a = e.target.closest && e.target.closest('a[href^="#"]');
      if (a) reveal(a.getAttribute('href').slice(1));
    });
    window.addEventListener('hashchange', () => reveal(location.hash.slice(1)));
    if (location.hash.length > 1) {
      const el = reveal(location.hash.slice(1));
      if (el) el.scrollIntoView();
    }

    // ---- the table of contents: where you are and it folds on a narrow screen
    const nav = $('.toc');
    const toc = nav && $('details', nav);
    // below 1180 px the contents are a card at the top, folded; from 1180 px they are the sidebar, always open
    const narrow = matchMedia('(max-width: 1179px)');
    const fold = () => { if (toc) toc.open = !narrow.matches; };
    fold();
    narrow.addEventListener('change', fold);
    const heads = $$('section.part > h2, section.part > h3');
    if (nav && heads.length) {
      const links = new Map($$('a', nav).map((a) => [a.getAttribute('href').slice(1), a]));
      let here = '';
      let queued = false;
      const spy = () => {
        queued = false;
        let current = heads[0];
        const line = Math.max(140, window.innerHeight * 0.3); // a heading counts once it is this far down
        for (const h of heads) {
          if (h.getBoundingClientRect().top > line) break;
          current = h;
        }
        const id = current ? current.parentElement.id : '';
        if (id === here) return;
        here = id;
        $$('.on, .here', nav).forEach((x) => x.classList.remove('on', 'here'));
        const a = links.get(id);
        if (!a) return;
        a.classList.add('here');
        for (let li = a.closest('li'); li; li = li.parentElement.closest('li')) li.classList.add('on');
        const r = a.getBoundingClientRect();
        const n = nav.getBoundingClientRect();
        if (r.top < n.top + 48) nav.scrollTop -= n.top + 48 - r.top;
        else if (r.bottom > n.bottom - 24) nav.scrollTop += r.bottom - n.bottom + 24;
      };
      window.addEventListener('scroll', () => { if (!queued) { queued = true; requestAnimationFrame(spy); } }, { passive: true });
      spy();
    }

    // ---- a table that needs more room than the page has scrolls sideways, instead of squeezing its columns.
    // A character is half the font size of the table (the .5em in report.css).
    const wraps = $$('.tablewrap');
    const unit = wraps.length ? parseFloat(getComputedStyle($('table', wraps[0])).fontSize) / 2 : 0;
    const fit = () => {
      for (const wrap of wraps) {
        wrap.classList.toggle('scroll', wrap.clientWidth < (parseFloat(wrap.style.getPropertyValue('--need')) || 0) * unit);
      }
    };
    let resizing = 0;
    window.addEventListener('resize', () => { clearTimeout(resizing); resizing = setTimeout(() => { fit(); fold(); }, 100); });
    if (wraps.length) fit();

    // ---- a picture too wide for the page can be shown at its own size
    for (const zoom of $$('.zoom')) {
      zoom.hidden = false;
      zoom.addEventListener('click', () => {
        zoom.textContent = zoom.closest('figure').classList.toggle('actual') ? 'Fit to width' : 'Actual size';
      });
    }
  });
})();
