/**
 * Navigation icons.
 *
 * Inline SVG rather than an icon package: the enclave has no internet, so every dependency
 * has to be vendored and carried, and a handful of line glyphs is not worth that. They draw
 * on `currentColor`, so a link's hover and active states color the icon without a second
 * rule for each.
 *
 * Each glyph says what its screen is about — a shield for findings, a chip for reverse
 * engineering, a scroll for the audit trail — because in a sidebar the icon is what gets
 * recognized before the label is read.
 */
const base = {
  viewBox: "0 0 24 24",
  fill: "none",
  strokeWidth: 1.7,
  strokeLinecap: "round",
  strokeLinejoin: "round",
  "aria-hidden": true,
  focusable: false,
};

export const IconDashboard = () => (
  <svg {...base}><rect x="3" y="3" width="7" height="8" rx="1.5" /><rect x="14" y="3" width="7" height="5" rx="1.5" /><rect x="14" y="11" width="7" height="10" rx="1.5" /><rect x="3" y="14" width="7" height="7" rx="1.5" /></svg>
);

// A case file: investigations group everything collected in one engagement.
export const IconInvestigations = () => (
  <svg {...base}><path d="M3 7a2 2 0 0 1 2-2h4l2 2.5h8a2 2 0 0 1 2 2V17a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z" /><path d="M3 11h18" /></svg>
);

export const IconHosts = () => (
  <svg {...base}><rect x="3" y="4" width="18" height="7" rx="1.5" /><rect x="3" y="13" width="18" height="7" rx="1.5" /><path d="M7 7.5h.01M7 16.5h.01" /></svg>
);

// A shield: findings are what the platform asserts about a host.
export const IconFindings = () => (
  <svg {...base}><path d="M12 3l7 3v5.5c0 4.4-2.9 8.3-7 9.5-4.1-1.2-7-5.1-7-9.5V6Z" /><path d="M9.2 12.2l2 2 3.6-3.9" /></svg>
);

// Linked nodes: the multi-host picture.
export const IconCorrelation = () => (
  <svg {...base}><circle cx="6" cy="7" r="2.4" /><circle cx="18" cy="7" r="2.4" /><circle cx="12" cy="18" r="2.4" /><path d="M7.9 8.6 10.6 16M16.1 8.6 13.4 16M8.4 7h7.2" /></svg>
);

// A chip under inspection: carved regions opened on the isolated workstation.
export const IconReversing = () => (
  <svg {...base}><rect x="7" y="7" width="10" height="10" rx="1.6" /><path d="M10 3v3M14 3v3M10 18v3M14 18v3M3 10h3M3 14h3M18 10h3M18 14h3" /></svg>
);

export const IconSearch = () => (
  <svg {...base}><circle cx="11" cy="11" r="6.5" /><path d="m20 20-3.6-3.6" /></svg>
);

// A sealed scroll: the append-only, hash-chained ledger.
export const IconAudit = () => (
  <svg {...base}><path d="M7 3h10a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Z" /><path d="M9 8h6M9 12h6M9 16h3" /></svg>
);

export const IconUsers = () => (
  <svg {...base}><circle cx="9" cy="8" r="3.2" /><path d="M3.5 19c.6-3.1 2.9-4.8 5.5-4.8s4.9 1.7 5.5 4.8" /><path d="M16 5.2a3.2 3.2 0 0 1 0 5.9M17.6 14.6c2 .6 3.4 2.2 3.9 4.4" /></svg>
);

// A pulse: platform health is measured live, never cached.
export const IconHealth = () => (
  <svg {...base}><path d="M3 12h4l2.5-6 4 12L16 12h5" /></svg>
);

// Stacked blocks: the parts the platform is built from, each reporting its own resources.
export const IconComponents = () => (
  <svg {...base}>
    <rect x="3" y="3" width="7" height="7" rx="1" />
    <rect x="14" y="3" width="7" height="7" rx="1" />
    <rect x="3" y="14" width="7" height="7" rx="1" />
    <rect x="14" y="14" width="7" height="7" rx="1" />
  </svg>
);

// A baton passing between two hands: the shift changes, the work does not stop.
export const IconHandover = () => (
  <svg {...base}><path d="M4 14a3 3 0 0 1 3-3h3" /><path d="m9 8 3 3-3 3" /><path d="M20 10a3 3 0 0 1-3 3h-3" /><path d="M6.5 19.5h11" /></svg>
);

// A bell: what is waiting for you specifically, as distinct from what happened on a case.
export const IconBell = () => (
  <svg {...base}><path d="M18 9a6 6 0 1 0-12 0c0 5-2 6-2 6h16s-2-1-2-6Z" /><path d="M10.3 19a2 2 0 0 0 3.4 0" /></svg>
);
