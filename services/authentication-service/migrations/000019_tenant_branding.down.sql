ALTER TABLE tenants
    DROP COLUMN IF EXISTS brand_logo_url,
    DROP COLUMN IF EXISTS brand_color,
    DROP COLUMN IF EXISTS brand_bg_color;
