-- authentication-service — per-tenant mDL-enrollment opt-in.
--
-- The OIDC social leg can show a first-time end user an optional mDL-enrollment
-- interstitial before continuing to the app. Gate it per tenant, default OFF, so
-- an integrator never gets an unexpected extra screen — the owner opts in from
-- their dashboard.

ALTER TABLE tenants
    ADD COLUMN mdl_enroll_enabled BOOLEAN NOT NULL DEFAULT false;
