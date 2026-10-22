// SPDX-License-Identifier: Apache-2.0. Copyright 2026 Stefanos Flokos.
// A few small icons, drawn for assess. Each one is lines on a 24 by 24 grid, in the color of the text around it. A path that has
// several parts is written with | between them.

const PATHS = {
  home: 'M3 11l9-8 9 8|M5 10v10h5v-6h4v6h5V10',
  box: 'M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3z|M12 12l8-4.5|M12 12v9|M12 12L4 7.5',
  flag: 'M5 21V4|M5 4h12l-2 4 2 4H5',
  bolt: 'M13 3L5 14h6l-1 7 8-11h-6l1-7z',
  chip: 'M7 7h10v10H7z|M10 3v4|M14 3v4|M10 17v4|M14 17v4|M3 10h4|M3 14h4|M17 10h4|M17 14h4',
  plug: 'M9 3v5|M15 3v5|M6 8h12v4a6 6 0 0 1-12 0V8z|M12 18v3',
  link: 'M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1|M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1',
  data: 'M4 6c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3z|M4 6v6c0 1.7 3.6 3 8 3s8-1.3 8-3V6|M4 12v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6',
  function: 'M5 5h14|M5 12h9|M5 19h14|M17 9l3 3-3 3',
  shield: 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6l8-3z',
  alert: 'M12 4l9 16H3L12 4z|M12 10v4|M12 17.5h.01',
  target: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z|M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z|M12 12h.01',
  layers: 'M12 3l9 5-9 5-9-5 9-5z|M3 13l9 5 9-5|M3 17.5l9 5 9-5',
  lock: 'M6 11h12v9H6z|M8 11V8a4 4 0 0 1 8 0v3|M12 15v2',
  scale: 'M12 3v18|M5 7h14|M5 7l-3 7a3 3 0 0 0 6 0L5 7z|M19 7l-3 7a3 3 0 0 0 6 0l-3-7z',
  check: 'M5 12.5l4.5 4.5L19 7',
  circle: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z',
  checkCircle: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z|M8 12.5l3 3 5-6',
  list: 'M8 6h13|M8 12h13|M8 18h13|M3.5 6h.01|M3.5 12h.01|M3.5 18h.01',
  chart: 'M4 20V10|M10 20V4|M16 20v-7|M22 20H2',
  page: 'M6 3h9l4 4v14H6V3z|M14 3v5h5|M9 13h6|M9 17h6',
  image: 'M4 5h16v14H4V5z|M4 16l5-5 4 4 3-3 4 4|M9 9.5h.01',
  clock: 'M12 7v5l3 2|M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0z',
  folder: 'M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z',
  rules: 'M4 6h16|M4 12h10|M4 18h6|M17 14l2 2 3-4',
  search: 'M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14z|M21 21l-4.5-4.5',
  plus: 'M12 5v14|M5 12h14',
  trash: 'M4 7h16|M10 11v6|M14 11v6|M6 7l1 13h10l1-13|M9 7V4h6v3',
  x: 'M6 6l12 12|M18 6L6 18',
  help: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z|M9.6 9.2a2.5 2.5 0 1 1 3.6 2.2c-.8.4-1.2 1-1.2 1.8|M12 16.8h.01',
  chevron: 'M6 9l6 6 6-6',
  chevronRight: 'M9 6l6 6-6 6',
  undo: 'M9 14L4 9l5-5|M4 9h10a6 6 0 0 1 0 12h-3',
  pen: 'M4 20l4-1 11-11-3-3L5 16l-1 4z',
  external: 'M14 4h6v6|M20 4l-9 9|M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5',
  sun: 'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z|M12 2v2|M12 20v2|M2 12h2|M20 12h2|M5 5l1.5 1.5|M17.5 17.5L19 19|M19 5l-1.5 1.5|M6.5 17.5L5 19',
  moon: 'M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z',
  copy: 'M9 9h11v11H9z|M5 15V5h10',
  sparkle: 'M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8L12 3z',
};

const NS = 'http://www.w3.org/2000/svg';

export function icon(name, size) {
  const svg = document.createElementNS(NS, 'svg');
  const s = String(size || 18);
  for (const [k, v] of Object.entries({ viewBox: '0 0 24 24', width: s, height: s, fill: 'none', stroke: 'currentColor', 'stroke-width': '1.8', 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true', focusable: 'false' })) svg.setAttribute(k, v);
  svg.setAttribute('class', 'icon');
  for (const d of (PATHS[name] || PATHS.circle).split('|')) {
    const p = document.createElementNS(NS, 'path');
    p.setAttribute('d', d);
    svg.append(p);
  }
  return svg;
}

// the icon of each kind of record
export const KIND_ICON = {
  item: 'box', assumption: 'flag', function: 'function', component: 'chip', interface: 'plug', channel: 'link', data: 'data',
  asset: 'shield', damage: 'alert', threat: 'target', step: 'layers', control: 'lock', risk: 'scale', rule: 'rules',
};
