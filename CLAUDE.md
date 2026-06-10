# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

X-Auth is a marketing site for an identity security product (risk-based authentication, authorization, and risk intelligence) built by XentraNET. It is a **single-file static site** — `public/index.html` contains all HTML, CSS, and no JavaScript beyond inline code snippets shown as marketing content.

## Local Development

No build step. Open `public/index.html` directly in a browser, or serve locally:

```bash
firebase serve --only hosting   # serves public/ at http://localhost:5000
```

## Deployment

Hosted on **Firebase Hosting** (project: `xauth-2026`). The `public/` directory is the served root. `firebase.json` rewrites all paths to `/index.html` (SPA-style fallback), so any new HTML files added under `public/` are only reachable if they're linked from the single-page app.

```bash
# Deploy manually (requires Firebase CLI)
firebase deploy --only hosting
```

**CI/CD**: GitHub Actions auto-deploys on push to `main` (live) and on pull requests (preview channel). The workflows reference `npm ci && npm run build` — there is currently no `package.json`, so those steps will fail if triggered. If a build step becomes necessary, a `package.json` must be added.

## Architecture

The entire site lives in one file: `public/index.html`.

- **No framework, no bundler** — raw HTML/CSS with inline `<style>`.
- **Fonts**: Inter (body) + JetBrains Mono (monospace/code) loaded from Google Fonts.
- **Design system** defined via CSS custom properties in `:root` — accent green `#00e096`, dark background `#09090b`, warn amber `#f0b429`, danger red `#f04040`.
- **Layout**: CSS Grid throughout; responsive breakpoints at 960px (single-column) and 720px (mobile).

### Page sections (in order)

| ID / anchor | Section |
|---|---|
| *(header)* | Sticky nav |
| *(hero)* | Headline + terminal code snippet |
| *(stats-band)* | Threat / Solution / ROI stats |
| `#problem` | "Don't Scare Your Customers Away" |
| `#how-it-works` | Risk tier cards (Low / Medium / High) |
| *(no id)* | Intelligence Engine — 4 signal cards |
| `#services` | Core services — AuthN / AuthZ / Risk |
| *(no id)* | Compliance & Trust (badges) |
| `#pricing` | Pricing plans (Developer / Growth / Enterprise) |
| *(footer)* | Footer |

## Content References

- `REQUIREMENTS.md` — original product/design requirements (target audience, visual aesthetic, section goals).
- `CONTENT_GUIDE.md` — approved copy, headlines, CTAs, and keyword lists for each section.
- `ARCHITECTURE.md` — backend platform architecture requirements. Defines four Go microservices (transaction-service, risk-service, authentication-service, authenticator-service), domain model, REST API contracts, risk scoring pipeline, data stores, deployment topology, and compliance certification mapping (SOC 2, ISO 27001, GDPR, HIPAA, PCI DSS). This is the source of truth for all backend implementation.
- `*.drawio` (repo root) — architecture diagrams referenced by `ARCHITECTURE.md`: `x-auth-system.drawio` (full-platform overview, both products), C4 model views `x-auth-c1-context.drawio` / `x-auth-c2-container.drawio` / `x-auth-c3-component-broker.drawio`, service topology `x-auth-apps-services.drawio`, and flow diagrams `oidc-transaction-integration.drawio`, `high-risk-stepup-flow.drawio`, `submit-payment-stepup-flow.drawio`.

When editing copy, cross-reference `CONTENT_GUIDE.md` to stay consistent with approved messaging.
When implementing backend services, follow the contracts and patterns defined in `ARCHITECTURE.md`.
