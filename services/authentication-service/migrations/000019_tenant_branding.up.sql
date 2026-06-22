-- authentication-service — per-tenant branding for the hosted end-user pages.
--
-- The hosted /login chooser, phone-login screens, and step-up verification pages
-- render on X-Auth's default dark theme. These columns let a workspace owner
-- override the look for their own end users: a logo shown above the card and an
-- accent + background colour the pages derive their scheme from. All default to
-- empty so a tenant that configures nothing keeps the standard theme unchanged.

ALTER TABLE tenants
    ADD COLUMN brand_logo_url TEXT NOT NULL DEFAULT '',
    ADD COLUMN brand_color    TEXT NOT NULL DEFAULT '',
    ADD COLUMN brand_bg_color TEXT NOT NULL DEFAULT '';
