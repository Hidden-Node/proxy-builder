# AGENTS.md — agent conventions for this repo

> Zero-context brief: read this first in every agent session. AGENTS.md rots
> fast: any gate/convention change must update it in the same commit.

## 1. What this is

Zero-dependency static app: `index.html` + `script.js` + `style.css` +
`pure.js`. No `package.json` (until plan 021 lands), no build step, no
framework. Classic `<script>` global scope; `pure.js` loads first
(`index.html:791` before `index.html:792`).

File map: `pure.js` = DOM/network-free helpers (Node-testable) · `script.js`
= UI wiring · `tests/pure.test.js` = unit tests · `README.md` + `README-fa.md`
= bilingual docs (always updated together) · `plans/` + `plans/README.md`
index = plan workflow and decision log.

## 2. Verification gates (repo root, Windows PowerShell)

```powershell
node --check pure.js
node --check script.js
node --test tests/pure.test.js
```

FILE form only: bare `node --test tests/` fails on this Node build —
environmental quirk, NOT a test failure. All three gates must exit 0.

Browser matrix (human): open `index.html` via `file://`, exercise the
touched tab(s). Live-browser console checks may be skipped only with a
documented static-trace substitution (precedent: plans 002/004).

`Copied!` grep gate stays at 2 until plan 018 lands (then 1) — plan 018
moves the success morph into the shared helper.

## 3. Where code goes

- `pure.js` header rule (`pure.js:1-6`): future pure helpers MUST go there,
  with tests in `tests/pure.test.js`. Test stack: `node:test` +
  `node:assert/strict`; pattern file is `tests/pure.test.js`.
- Bilingual discipline: every user-facing/feature change updates BOTH
  `README.md` and `README-fa.md`. Preset/scheme additions touch `pure.js` +
  tests + `index.html` + both READMEs (the plan-011 consistency test enforces
  the HTML half).
- Decision log lives in `plans/README.md` ("Findings considered and
  rejected" + "Deferred follow-ups") — check it before proposing VMess bulk
  enhancement, user-editable ECH presets, or a god-file split.
- Feature/preset changes update BOTH `README.md` and `README-fa.md` in the same commit (plan 011's consistency test enforces the HTML half only).

## 4. Plan workflow

- Read the whole plan before acting; run every verification command listed.
- Every plan needs machine-checkable done criteria + STOP conditions
  (exemplar: `plans/001-test-baseline.md`). On any STOP: stop and report,
  do not improvise.
- Update your plan's status row in `plans/README.md` when done (unless the
  dispatcher says they own the index).
- Branches: `advisor/NNN-slug`. Commits, conventional-ish: `fix(scope):`,
  `test(tests):`, `sec(scope):`, `refactor(scope):`, `feat(scope):`,
  `docs(...)`. Never push or open a PR without instruction.

## 5. Do not re-litigate (web-verified, settled)

- Xray `echConfigList` accepts fixed-base64 AND `domain+resolver` forms —
  verbatim passthrough stays.
- `flow: xtls-rprx-vision` is valid on VLESS outbounds.
- Clipboard API is secure-context-only — hence the `copyTextWithFeedback`
  fallback contract (`script.js:3075`).
- Rejected ideas live in `plans/README.md` ("Findings considered and
  rejected") — do not re-propose without new evidence.
