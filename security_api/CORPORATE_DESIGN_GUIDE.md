# Corporate Cybersecurity Dashboard Design Integration Guide

## Overview
This guide shows how to integrate the Corporate Cybersecurity Dashboard design into the Rust security_api while maintaining all existing functionality.

## Design Philosophy
The Corporate dashboard uses:
- **Minimalist aesthetic**: Clean, uncluttered layout
- **Neutral color palette**: Grays with accent colors for status
- **Flat design**: No gradients or shadows
- **System fonts**: Native UI fonts for crisp rendering
- **Subtle borders**: 1px solid borders, no rounded corners on main containers
- **Tabular data**: Monospace fonts for numbers and IPs

## Color Palette (Replace existing CSS variables)

```css
:root {
    /* Neutral Grays */
    --neutral-50: #fafafa;    /* Background */
    --neutral-100: #f5f5f5;   /* Card background */
    --neutral-200: #e5e5e5;   /* Borders, dividers */
    --neutral-300: #d4d4d4;   /* Secondary borders */
    --neutral-500: #737373;   /* Secondary text */
    --neutral-600: #525252;   /* Labels */
    --neutral-700: #404040;   /* Dark text */
    --neutral-900: #171717;   /* Primary text, charts */
    
    /* Status Colors */
    --red-50: #fef2f2;        /* Critical background */
    --red-200: #fecaca;       /* Critical border */
    --red-700: #b91c1c;       /* Critical text */
    
    --orange-50: #fff7ed;     /* High risk background */
    --orange-200: #fed7aa;    /* High risk border */
    --orange-700: #c2410c;    /* High risk text */
    
    --yellow-50: #fefce8;     /* Medium risk background */
    --yellow-200: #fef08a;    /* Medium risk border */
    --yellow-700: #a16207;    /* Medium risk text */
    
    --green-50: #f0fdf4;      /* Low risk background */
    --green-200: #bbf7d0;     /* Low risk border */
    --green-700: #15803d;     /* Low risk text */
}
```

## Key Design Changes

### 1. Typography
```css
body {
    font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    font-size: 14px;
    line-height: 1.5;
    color: var(--neutral-900);
}

/* Headings */
h1 { font-size: 1.5rem; font-weight: 400; }  /* 24px, normal weight */
h2 { font-size: 1rem; font-weight: 400; }    /* 16px, normal weight */

/* Numbers (tabular) */
.tabular { font-variant-numeric: tabular-nums; }

/* Code/IPs */
.monospace { font-family: ui-monospace, 'SF Mono', Monaco, 'Cascadia Code', monospace; }
```

### 2. Layout Structure
```
┌─────────────────────────────────────────────────────────┐
│ Header (max-width: 1400px, padding: 24px)             │
│  ├─ Title (left)                                       │
│  └─ Risk Indicator (right, only when analyzed)        │
├─────────────────────────────────────────────────────────┤
│ Container (max-width: 1400px, padding: 24px)          │
│  ├─ File Upload (white bg, border, padding: 24px)     │
│  ├─ Metrics Grid (4 columns, gap: 16px)               │
│  ├─ Threat Section (collapsible)                      │
│  ├─ IP Analysis (collapsible, table layout)           │
│  └─ Parsing Stats (donut + progress bars)             │
└─────────────────────────────────────────────────────────┘
```

### 3. Component Styles

#### File Upload
```css
.file-upload {
    background: white;
    border: 1px solid var(--neutral-200);
    padding: 24px;
    margin-bottom: 16px;
}

.upload-button {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 8px 16px;
    border: 1px solid var(--neutral-300);
    background: var(--neutral-50);
    cursor: pointer;
    transition: background 0.15s;
}

.upload-button:hover {
    background: var(--neutral-100);
}
```

#### Metrics Cards
```css
.metrics-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    margin-bottom: 16px;
}

.metric-card {
    background: white;
    border: 1px solid var(--neutral-200);
    padding: 16px;
}

.metric-value {
    font-size: 1.5rem;
    font-weight: 400;
    font-variant-numeric: tabular-nums;
    color: var(--neutral-900);
    margin-bottom: 4px;
}

.metric-label {
    font-size: 0.875rem;
    color: var(--neutral-600);
}

.metric-change {
    font-size: 0.75rem;
    color: var(--neutral-600);
    font-variant-numeric: tabular-nums;
}
```

#### Collapsible Sections
```css
.section {
    background: white;
    border: 1px solid var(--neutral-200);
    margin-bottom: 16px;
}

.section-header {
    display: flex;
    align-items: center;
    justify-between;
    padding: 16px;
    cursor: pointer;
    transition: background 0.15s;
}

.section-header:hover {
    background: var(--neutral-50);
}

.section-title {
    display: flex;
    align-items: center;
    gap: 12px;
    font-size: 1rem;
    color: var(--neutral-900);
}

.section-count {
    color: var(--neutral-600);
}

.chevron {
    width: 16px;
    height: 16px;
    color: var(--neutral-600);
}
```

#### Risk Indicator
```css
.risk-indicator {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 8px 16px;
    border: 1px solid;
}

.risk-indicator.high {
    background: var(--orange-50);
    border-color: var(--orange-200);
    color: var(--orange-700);
}

.risk-indicator.medium {
    background: var(--yellow-50);
    border-color: var(--yellow-200);
    color: var(--yellow-700);
}

.risk-indicator.low {
    background: var(--green-50);
    border-color: var(--green-200);
    color: var(--green-700);
}
```

#### IP Table
```css
.ip-table {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1px;
    background: var(--neutral-200);
}

.ip-table-header {
    background: var(--neutral-100);
    padding: 8px 16px;
    font-size: 0.875rem;
    color: var(--neutral-600);
}

.ip-table-cell {
    background: white;
    padding: 12px 16px;
    font-size: 0.875rem;
}

.ip-address {
    font-family: ui-monospace, monospace;
    color: var(--neutral-900);
}

.status-badge {
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.status-blocked { color: var(--red-700); }
.status-flagged { color: var(--yellow-700); }
.status-monitored { color: var(--neutral-600); }
```

#### Charts
```css
/* Bar Chart */
.bar-chart {
    height: 240px;
    padding: 16px;
    background: white;
}

.bar {
    background: var(--neutral-900);  /* Solid black bars */
}

/* Donut Chart */
.donut-segment-parsed {
    fill: var(--neutral-900);
}

.donut-segment-failed {
    fill: var(--neutral-200);
}

/* Progress Bars */
.progress-bar {
    height: 8px;
    background: var(--neutral-200);
}

.progress-fill {
    height: 100%;
    background: var(--neutral-900);
}
```

## Icons
The Corporate dashboard uses Lucide icons. Since we're in Rust/HTML, use SVG or Unicode:

- Upload: ↑ or `<svg>...</svg>`
- ChevronDown: ▼
- ChevronRight: ▶
- AlertTriangle: ⚠
- Shield: 🛡
- Activity: 📊

## Spacing System
```css
/* Use consistent spacing */
--space-1: 4px;
--space-2: 8px;
--space-3: 12px;
--space-4: 16px;
--space-6: 24px;
--space-8: 32px;
```

## Implementation Steps

1. **Replace Color Variables**: Update all CSS color variables to the neutral palette
2. **Update Typography**: Change fonts to system UI fonts, adjust sizes
3. **Simplify Borders**: Remove border-radius, use 1px solid borders
4. **Update Layout**: Change max-width to 1400px, adjust padding to 24px
5. **Redesign Cards**: White background, neutral borders, flat design
6. **Update Charts**: Use neutral-900 for bars, neutral-200 for backgrounds
7. **Simplify Animations**: Remove complex transitions, keep simple hover states
8. **Update Status Colors**: Use the red/orange/yellow/green palette
9. **Add Tabular Numbers**: Use font-variant-numeric for all numbers
10. **Monospace IPs**: Use monospace font for IP addresses

## Key Differences from Current Design

| Current | Corporate |
|---------|-----------|
| Colorful (blues, greens) | Neutral grays |
| Rounded corners | Sharp corners |
| Shadows | Flat, no shadows |
| Custom fonts | System fonts |
| Gradient buttons | Flat buttons |
| Complex animations | Simple transitions |
| Dark mode toggle | Light only |
| Decorative elements | Minimal, functional |

## Maintaining Functionality

**Keep all existing:**
- Rust backend logic
- API endpoints
- Data processing
- Threat detection
- IP analysis
- Format quality checking
- Collapsible sections
- File upload handling

**Only change:**
- CSS styling
- HTML structure (minimal)
- Color scheme
- Typography
- Layout spacing

## Testing Checklist

- [ ] File upload works
- [ ] Analysis runs correctly
- [ ] All metrics display
- [ ] Charts render properly
- [ ] Collapsible sections work
- [ ] IP table displays
- [ ] Format quality shows
- [ ] Risk indicator appears
- [ ] Responsive on different screens
- [ ] All data from backend displays correctly

## Notes

- The Corporate design is **light mode only** - no dark mode
- Focus on **readability** and **data density**
- Use **subtle hover states** (background changes only)
- Keep **consistent spacing** throughout
- Prioritize **function over form**
- Use **native browser elements** where possible
