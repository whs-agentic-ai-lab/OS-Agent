---
version: 1.0.0
name: OS-Agent-Control-Plane
description: "A light operations workspace combining Notion's calm information architecture with HashiCorp's confident infrastructure language. Warm paper canvas and white work surfaces keep long control sessions readable; Pretendard at 500/600/700 removes thin display type; Terraform purple identifies deployment actions; semantic green, yellow, and red make execution state explicit; charcoal runtime and log panels isolate machine output from human controls."

sources:
  surface-and-structure: Notion
  infrastructure-and-state: HashiCorp
  korean-typography: Pretendard

colors:
  primary: "#7b42bc"
  primary-hover: "#6f3baa"
  primary-active: "#5c318d"
  primary-soft: "#f2eafa"
  focus: "#2b89ff"
  on-primary: "#ffffff"
  canvas: "#f6f5f4"
  canvas-white: "#ffffff"
  surface: "#ffffff"
  surface-subtle: "#f1f1ef"
  surface-hover: "#ececea"
  hairline: "#e6e6e6"
  hairline-strong: "#c7c7c5"
  ink: "#171717"
  ink-secondary: "#31302e"
  ink-muted: "#615d59"
  ink-faint: "#8f8b87"
  dark-canvas: "#15181e"
  dark-surface: "#1f232b"
  dark-surface-hover: "#2b3039"
  dark-hairline: "#3b3d45"
  dark-ink: "#ffffff"
  dark-ink-muted: "#b2b6bd"
  dark-ink-subtle: "#7e8490"
  semantic-info: "#2b89ff"
  semantic-success: "#00a878"
  semantic-success-soft: "#e5f6f0"
  semantic-warning: "#d6a900"
  semantic-warning-soft: "#fff6d6"
  semantic-error: "#d93f3f"
  semantic-error-soft: "#fdeaea"
  semantic-blocked: "#3b3d45"

typography:
  display:
    fontFamily: "Pretendard Variable, Pretendard, Inter, system-ui, sans-serif"
    fontSize: 48px
    fontWeight: 700
    lineHeight: 1.12
    letterSpacing: -0.02em
  page-title:
    fontFamily: "Pretendard Variable, Pretendard, Inter, system-ui, sans-serif"
    fontSize: 36px
    fontWeight: 700
    lineHeight: 1.2
    letterSpacing: -0.018em
  section-title:
    fontFamily: "Pretendard Variable, Pretendard, Inter, system-ui, sans-serif"
    fontSize: 28px
    fontWeight: 700
    lineHeight: 1.25
    letterSpacing: -0.015em
  card-title:
    fontFamily: "Pretendard Variable, Pretendard, Inter, system-ui, sans-serif"
    fontSize: 18px
    fontWeight: 600
    lineHeight: 1.35
    letterSpacing: -0.01em
  body-lg:
    fontFamily: "Pretendard Variable, Pretendard, Inter, system-ui, sans-serif"
    fontSize: 17px
    fontWeight: 500
    lineHeight: 1.6
    letterSpacing: 0
  body:
    fontFamily: "Pretendard Variable, Pretendard, Inter, system-ui, sans-serif"
    fontSize: 15px
    fontWeight: 500
    lineHeight: 1.55
    letterSpacing: 0
  body-sm:
    fontFamily: "Pretendard Variable, Pretendard, Inter, system-ui, sans-serif"
    fontSize: 13px
    fontWeight: 400
    lineHeight: 1.5
    letterSpacing: 0
  label:
    fontFamily: "Pretendard Variable, Pretendard, Inter, system-ui, sans-serif"
    fontSize: 13px
    fontWeight: 600
    lineHeight: 1.4
    letterSpacing: 0
  button:
    fontFamily: "Pretendard Variable, Pretendard, Inter, system-ui, sans-serif"
    fontSize: 14px
    fontWeight: 600
    lineHeight: 1.4
    letterSpacing: 0
  caption:
    fontFamily: "Pretendard Variable, Pretendard, Inter, system-ui, sans-serif"
    fontSize: 12px
    fontWeight: 500
    lineHeight: 1.45
    letterSpacing: 0.01em
  code:
    fontFamily: "JetBrains Mono, Consolas, ui-monospace, monospace"
    fontSize: 13px
    fontWeight: 400
    lineHeight: 1.55
    letterSpacing: 0

rounded:
  xs: 4px
  sm: 6px
  md: 8px
  lg: 12px
  xl: 16px
  pill: 9999px

spacing:
  hair: 1px
  xxs: 4px
  xs: 8px
  sm: 12px
  md: 16px
  lg: 24px
  xl: 32px
  xxl: 48px
  section: 64px

components:
  app-shell:
    backgroundColor: "{colors.canvas}"
    textColor: "{colors.ink}"
    typography: "{typography.body}"
    maxWidth: 1312px
  top-nav:
    backgroundColor: "rgba(255,255,255,0.96)"
    textColor: "{colors.ink}"
    typography: "{typography.label}"
    height: 56px
    borderColor: "{colors.hairline}"
  panel:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    typography: "{typography.body}"
    rounded: "{rounded.lg}"
    borderColor: "{colors.hairline}"
    padding: 24px
  panel-subtle:
    backgroundColor: "{colors.surface-subtle}"
    textColor: "{colors.ink}"
    typography: "{typography.body}"
    rounded: "{rounded.lg}"
    padding: 24px
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.on-primary}"
    typography: "{typography.button}"
    rounded: "{rounded.md}"
    minHeight: 44px
    padding: 11px 16px
  button-secondary:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    typography: "{typography.button}"
    rounded: "{rounded.md}"
    borderColor: "{colors.hairline-strong}"
    minHeight: 44px
    padding: 11px 16px
  button-danger:
    backgroundColor: "{colors.semantic-error}"
    textColor: "{colors.on-primary}"
    typography: "{typography.button}"
    rounded: "{rounded.md}"
    minHeight: 44px
    padding: 11px 16px
  button-ghost:
    backgroundColor: transparent
    textColor: "{colors.ink-secondary}"
    typography: "{typography.button}"
    rounded: "{rounded.sm}"
    minHeight: 40px
    padding: 8px 12px
  text-input:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    typography: "{typography.body}"
    rounded: "{rounded.xs}"
    borderColor: "{colors.hairline-strong}"
    minHeight: 44px
    padding: 10px 12px
  text-input-focused:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    typography: "{typography.body}"
    rounded: "{rounded.xs}"
    borderColor: "{colors.focus}"
    focusRing: "0 0 0 2px rgba(43,137,255,0.18)"
  workflow-node:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    typography: "{typography.body-sm}"
    titleTypography: "{typography.card-title}"
    rounded: "{rounded.md}"
    borderColor: "{colors.hairline}"
    statusRuleColor: "{colors.ink-faint}"
    padding: 16px
  workflow-node-selected:
    backgroundColor: "{colors.primary-soft}"
    textColor: "{colors.ink}"
    borderColor: "{colors.primary}"
    statusRuleColor: "{colors.primary}"
  workflow-node-running:
    backgroundColor: "{colors.semantic-warning-soft}"
    statusRuleColor: "{colors.semantic-warning}"
  workflow-node-succeeded:
    backgroundColor: "{colors.semantic-success-soft}"
    statusRuleColor: "{colors.semantic-success}"
  workflow-node-failed:
    backgroundColor: "{colors.semantic-error-soft}"
    statusRuleColor: "{colors.semantic-error}"
  workflow-node-blocked:
    backgroundColor: "{colors.surface-subtle}"
    statusRuleColor: "{colors.semantic-blocked}"
  workflow-connector:
    color: "{colors.primary}"
    thickness: 2px
    direction: forward
  status-badge:
    typography: "{typography.caption}"
    rounded: "{rounded.pill}"
    padding: 4px 8px
  permission-card:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
    borderColor: "{colors.hairline}"
    padding: 16px
  log-panel:
    backgroundColor: "{colors.dark-canvas}"
    textColor: "{colors.dark-ink}"
    mutedTextColor: "{colors.dark-ink-muted}"
    typography: "{typography.code}"
    rounded: "{rounded.md}"
    borderColor: "{colors.dark-hairline}"
    padding: 16px
  data-table:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink-secondary}"
    headerBackground: "{colors.surface-subtle}"
    headerTypography: "{typography.label}"
    bodyTypography: "{typography.body-sm}"
    rowBorder: "{colors.hairline}"
    cellPadding: 12px 16px
  toast:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    typography: "{typography.body-sm}"
    rounded: "{rounded.md}"
    borderColor: "{colors.hairline}"
    leadingRule: 4px
    padding: 12px 16px
  modal:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.lg}"
    padding: 24px
    shadow: "0 18px 48px rgba(21,24,30,0.16)"
  footer:
    backgroundColor: "{colors.dark-canvas}"
    textColor: "{colors.dark-ink-muted}"
    typography: "{typography.body-sm}"
    padding: 32px
---

# OS Agent Control Plane Design System

## 1. Design direction

This dashboard is an operational control plane, not a marketing page. It combines two sources with explicit ownership:

- **Notion owns the workspace:** warm canvas, white panels, readable spacing, quiet borders, forms, tables, toasts, and modal structure.
- **HashiCorp owns the control language:** strong type weights, Terraform identity, semantic execution states, infrastructure density, and dark machine-output surfaces.
- **Pretendard owns Korean readability:** proprietary HashiCorp and Notion fonts are not required. Korean text must remain legible at medium weight.

The result should feel calm when reading and decisive when operating. Human controls live on light surfaces. Machine output, runtime evidence, and raw logs live on charcoal surfaces.

## 2. Core principles

1. **Light workspace, dark evidence.** Keep the page and controls light; use dark surfaces only for logs, terminal output, runtime evidence, and footer.
2. **Weight creates hierarchy.** Never use weight 300. Page and section headings use 700, interactive labels use 600, normal operational copy uses 500.
3. **Purple means infrastructure action.** Terraform purple identifies deployment, selected workflow nodes, active state, and focus within infrastructure controls.
4. **Semantic colors mean state only.** Green is success, yellow is running/warning, red is failure, charcoal is blocked. Do not reuse them decoratively.
5. **Cards represent real objects.** A card must represent a workflow node, profile, run, deployment, event group, or result—not decoration.
6. **State is never color-only.** Every state includes a Korean text label and, when relevant, an error or recovery action.
7. **Moderate rounding.** Inputs use 4px, utility controls 6–8px, cards 8–12px. Full pills are reserved for compact status badges.

## 3. Typography

Use this font stack everywhere except machine output:

```css
font-family: "Pretendard Variable", Pretendard, Inter, system-ui, sans-serif;
```

Use JetBrains Mono or Consolas only for command lines, hashes, IDs, timestamps, Terraform output, and logs.

| Role | Size | Weight | Line height | Notes |
|---|---:|---:|---:|---|
| Hero/display | 48px | 700 | 1.12 | Desktop only; scale to 34px on mobile |
| Page title | 36px | 700 | 1.20 | Primary product surface title |
| Section title | 28px | 700 | 1.25 | Workflow, deployment, experiment, logs |
| Card/node title | 18px | 600 | 1.35 | Keep to two lines maximum |
| Lead body | 17px | 500 | 1.60 | Introductory explanation |
| Body | 15px | 500 | 1.55 | Default operational text |
| Supporting text | 13px | 400 | 1.50 | Helper copy and descriptions |
| Label/button | 13–14px | 600 | 1.40 | Controls and state labels |
| Code/log | 13px | 400 | 1.55 | Preserve whitespace where required |

Avoid aggressive Latin-style negative tracking on Korean. Restrict negative tracking to large display and section titles.

## 4. Color application

### Light workspace

- Page background: `{colors.canvas}`
- Panels, cards, inputs: `{colors.surface}`
- Alternate groups and table headers: `{colors.surface-subtle}`
- Primary text: `{colors.ink}`
- Supporting text: `{colors.ink-muted}`
- Borders: `{colors.hairline}`; use `{colors.hairline-strong}` only for active structural edges

### Infrastructure identity

- Terraform purple `{colors.primary}` is the only structural accent.
- Use it for environment deployment, active workflow selection, focus indicators, and primary actions.
- Do not bring HashiCorp's Vault, Consul, Waypoint, Vagrant, or Nomad colors into this single-environment test.

### Runtime and logs

- Use `{colors.dark-canvas}` and `{colors.dark-surface}` for command output and evidence.
- Primary log text is `{colors.dark-ink}`; timestamps and metadata use `{colors.dark-ink-muted}`.
- Errors inside logs use `{colors.semantic-error}` but never replace the error message with color alone.

## 5. Layout

- Desktop content width: 1280–1312px.
- Page gutters: 48px desktop, 24px tablet, 16px mobile.
- Major section gap: 64px; dense control groups may use 32px.
- Card padding: 16px compact, 24px standard, 32px only for large summaries.
- Use 12-column logic for desktop compositions; collapse to one column below 768px.
- Prefer visible grouping and whitespace over repeated full-width separator lines.
- Keep operational information denser than Notion marketing pages, but do not return to Carbon's edge-to-edge grid density.

## 6. Workflow graph

The seven-step workflow is the primary navigation and status surface.

- Nodes flow left to right on desktop and top to bottom below 672px.
- Each node shows step number, state badge, title, short description, and state source (`자동 동기화` or `수동 확인`).
- The selected node uses purple border plus `{colors.primary-soft}` fill.
- Running, succeeded, failed, and blocked nodes use their semantic surface plus a 4px leading or top rule.
- Connectors use Terraform purple only to express direction; they do not encode status.
- Failed nodes expose the error message and the next recovery action in the inspector.
- A manual override must be visibly labeled and must offer `자동 상태로 복원`.

## 7. Deployment and permission controls

### Deployment

- Deployment summary is a standard white panel, not a full dark hero.
- The primary deploy action is Terraform purple.
- Prerequisites appear as compact rows with explicit `준비됨` or `필요` labels.
- A running deployment shows current phase, progress text, and streaming logs.
- A failed deployment keeps successful prior phases visible and attaches the error to the failed phase.
- Destructive actions such as `terraform destroy` use `button-danger` and require a separate confirmation surface. Do not place destroy next to deploy as an equal action.

### Permission profiles

- Permission selection remains on light surfaces.
- OFF/ON is represented by text, control state, and profile name—not color alone.
- Changing one permission must not visually imply that unrelated permissions changed.
- Profile descriptions use Korean first; literal profile IDs use `{typography.code}`.

## 8. Logs, results, and errors

### Logs

- Raw deployment, executor, and collector output use `log-panel`.
- Maintain readable line length and horizontal scrolling for unbroken commands or hashes.
- Sequence, source, timestamp, and severity align consistently.
- Never put API keys, service-role keys, AWS credentials, or model secrets in visible logs.

### Results

- Test verdict is always `PASS`, `FAIL`, or `INCONCLUSIVE` with a Korean explanation.
- Hash comparisons use monospace and show before/after values without relying only on an arrow.
- Tables use sticky headers only when the body scrolls independently.

### Error management

- Inline validation stays next to the affected control.
- Node or operation failure appears in the workflow inspector and in a toast only when immediate attention is required.
- Toasts use a 4px semantic leading rule, a state label, concise message, and a dismiss action.
- Recovery actions use specific language such as `배포 다시 실행`, `AWS 인증 확인`, or `자동 상태로 복원`.
- Do not use generic copy such as `오류가 발생했습니다` when a concrete reason is available.

## 9. Interaction states

Every interactive element must define Default, Hover, Focus-visible, Active/pressed, Disabled, Loading when asynchronous, and Error when failure is possible.

Focus-visible uses `{colors.focus}` and must remain visible on both light and dark surfaces. Minimum touch target is 44×44px.

Motion is functional and brief:

- Hover/press: 120–160ms
- Panel expansion: 160–220ms
- No decorative parallax, floating gradients, sticker motion, or continuous pulsing
- Respect `prefers-reduced-motion`

## 10. Responsive behavior

| Breakpoint | Behavior |
|---|---|
| ≥1280px | Full workflow row, two-column control/result workspace |
| 1024–1279px | Workflow horizontally scrolls; inspector remains multi-column |
| 768–1023px | Main workspace becomes one column; inspector becomes two columns |
| ≤672px | Workflow becomes vertical; summaries, profiles, and result grids stack |
| ≤480px | Full-width actions; compact 16px gutters; display title scales down |

Do not shrink workflow nodes below comfortable reading width. Reflow or scroll instead.

## 11. Accessibility

- Text and controls meet WCAG AA contrast.
- Status always has text; color is supplemental.
- Focus order follows workflow, controls, results, then logs.
- Use semantic headings, lists for ordered workflow steps, `aria-live` for changing execution status, and `role="alert"` for actionable errors.
- Do not trap keyboard focus in custom inspectors.
- Preserve zoom to 200% without hiding primary actions.

## 12. Do and don't

### Do

- Keep the default experience light and readable.
- Use Pretendard 500 for normal operational body copy.
- Use 600/700 for controls and hierarchy.
- Reserve purple for Terraform and active infrastructure actions.
- Use dark panels for logs and machine evidence.
- Use quiet borders and small-radius cards.
- Show the reason and recovery action beside every failed state.

### Don't

- Don't use font weight 300 anywhere.
- Don't turn the whole dashboard into HashiCorp dark marketing mode.
- Don't use Notion sticker colors, illustrations, or playful marketing decoration.
- Don't use more than one structural accent color.
- Don't make every button or card pill-shaped.
- Don't add strong shadows to normal cards.
- Don't use semantic colors decoratively.
- Don't hide errors only in a global banner or log stream.

## 13. Current component mapping

| Existing surface | Required token/pattern |
|---|---|
| Top navigation | `top-nav` |
| Workflow graph | `workflow-node-*`, `workflow-connector`, `status-badge` |
| Workflow inspector | `panel`, `text-input`, button variants |
| Fixed environment deployment | `panel`, `button-primary`, `log-panel` |
| Environment selector | `permission-card`, selected purple border |
| Prompt input | `text-input` |
| Permission profile | `permission-card`, `status-badge` |
| Run result | `panel`, semantic verdict badge |
| Event timeline | light event list; dark only for raw payload/output |
| Terraform outputs | `data-table` or `log-panel` depending on value type |
| Confirmation | `modal` |
| Transient error/success | `toast` |

## 14. Source merge decisions

| Conflict | Decision |
|---|---|
| HashiCorp black canvas vs Notion warm canvas | Notion warm canvas for the workspace; HashiCorp dark only for evidence |
| HashiCorp multi-product palette vs Notion single accent | Single Terraform purple structural accent |
| HashiCorp 500 body vs Notion 400 body | 500 operational body, 400 supporting copy |
| HashiCorp 600/700 headings vs Notion 700 headings | 700 page/section, 600 card/control titles |
| Notion pill CTA vs HashiCorp 8px CTA | 8px buttons; pills only for status badges |
| Notion shadows vs HashiCorp surface lift | Hairlines by default; shadow only for modal/popover |
| Proprietary fonts | Pretendard for Korean, Inter fallback, JetBrains Mono for machine output |

This file is the canonical design source for `os-Agent-test`. Future UI changes must follow these resolved tokens instead of independently reinterpreting either source document.
