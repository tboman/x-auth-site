-- authentication-service — staff (internal admin console) accounts + roles.
--
-- The /admin console authenticates XentraNET staff via Google (dedicated
-- ten_admin tenant) and authorises them by role. ADMIN_EMAILS seed the
-- `administrator` role on boot; ROOT_EMAILS (break-glass) get every role and are
-- reactivated on boot. These tables back that seed and the per-request
-- authorisation in currentAdmin(): GetStaffUserByEmail + GetStaffUserRoles.
--
-- Without these tables the boot seed's INSERTs silently fail (errors are
-- best-effort) and currentAdmin() errors on the staff lookup, clearing the
-- cookie and bouncing every staff sign-in back to the login page — even though
-- the Google callback (which only checks the email allowlist) logs admin_login.
--
-- No FK on staff_user_roles.staff_user_id (consistent with the schema's
-- deliberate no-FK stance — see 000009); (staff_user_id, role) is the natural
-- primary key and is the conflict target for AddStaffUserRole's
-- ON CONFLICT DO NOTHING.

CREATE TABLE IF NOT EXISTS staff_users (
    id           TEXT PRIMARY KEY,
    email        TEXT NOT NULL UNIQUE,
    display_name TEXT,
    active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS staff_user_roles (
    staff_user_id TEXT NOT NULL,
    role          TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (staff_user_id, role)
);

-- A staff member's roles, oldest-first (GetStaffUserRoles ORDER BY created_at).
CREATE INDEX IF NOT EXISTS idx_staff_user_roles_user
    ON staff_user_roles (staff_user_id, created_at);
