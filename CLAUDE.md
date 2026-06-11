# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

X-Auth is a marketing site for an identity security product (risk-based authentication, authorization, and risk intelligence) built by XentraNET. It is a **single-file static site** — `public/index.html` contains all HTML, CSS, and two small inline scripts: a mailto-based contact form handler and a three.js (loaded from CDN) hero background animation. Both are progressive enhancements — the page must remain fully usable without them.

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

**CI/CD**: GitHub Actions auto-deploys on push to `main` (live) and on pull requests (preview channel). There is no build step — the workflows deploy `public/` as-is (the repo's `package.json` is a stub whose `build` script is a no-op echo). If a build step becomes necessary, put it in `package.json` and restore an `npm ci && npm run build` step to the hosting workflows.

### Backend services (Cloud Run)

The 8 Go services deploy to GCP Cloud Run (stage 1; GKE per ARCHITECTURE.md Appendix B is the end state). Infrastructure is Terraform in `deploy/terraform/` (Cloud SQL PG16, Memorystore Redis, Secret Manager, VPC + connector, 8 services + 8 migration jobs) — see `deploy/terraform/README.md` for bootstrap, WIF setup, and the deliberate stage-1 deviations from ARCHITECTURE.md (no mesh mTLS; internal-only ingress instead). Image rollout is owned by `.github/workflows/deploy-services.yml`: build → push to Artifact Registry → run `migrate-<svc>` jobs → `gcloud run services update` → smoke-check. Terraform ignores image changes; never set images via Terraform.

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
