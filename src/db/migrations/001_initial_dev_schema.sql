CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- 1. CONTROL PLANE: Developers, Sessions, Applications & Environments
-- ============================================================================

CREATE TABLE IF NOT EXISTS developers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    email VARCHAR(255) NOT NULL,
    password_hash TEXT NOT NULL,
    account_status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (
        account_status IN (
            'active',
            'disabled',
            'suspended',
            'deleted'
        )
    ),
    deleted_at TIMESTAMPTZ,
    deletion_scheduled_for TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_developers_deleted_consistency CHECK (
        (
            account_status = 'deleted'
            AND deleted_at IS NOT NULL
            AND deletion_scheduled_for IS NOT NULL
        )
        OR (
            account_status <> 'deleted'
            AND deleted_at IS NULL
            AND deletion_scheduled_for IS NULL
        )
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_developers_email_lower ON developers (lower(email));

CREATE INDEX IF NOT EXISTS idx_developers_status ON developers (account_status);

CREATE INDEX IF NOT EXISTS idx_developers_deletion_due ON developers (deletion_scheduled_for)
WHERE
    account_status = 'deleted'
    AND deletion_scheduled_for IS NOT NULL;

CREATE TABLE IF NOT EXISTS developer_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    developer_id UUID NOT NULL REFERENCES developers (id) ON DELETE CASCADE,
    family_id UUID NOT NULL,
    refresh_token_hash TEXT NOT NULL,
    user_agent TEXT,
    ip_address VARCHAR(45),
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_reason VARCHAR(60),
    last_active_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_developer_sessions_dev_active ON developer_sessions (
    developer_id,
    is_revoked,
    expires_at
);

CREATE INDEX IF NOT EXISTS idx_developer_sessions_family ON developer_sessions (family_id);

CREATE TABLE IF NOT EXISTS applications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    developer_id UUID NOT NULL REFERENCES developers (id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    slug VARCHAR(100) NOT NULL,
    description TEXT,
    deleted_at TIMESTAMPTZ, -- Supports safe soft-deletion of applications
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (developer_id, slug),
    UNIQUE (id, developer_id)
);

CREATE INDEX IF NOT EXISTS idx_applications_developer_active ON applications (developer_id)
WHERE
    deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS app_environments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    application_id UUID NOT NULL REFERENCES applications (id) ON DELETE CASCADE,
    env_type VARCHAR(20) NOT NULL CHECK (
        env_type IN ('development', 'production')
    ),
    publishable_key VARCHAR(64) UNIQUE NOT NULL,
    secret_key_hash TEXT NOT NULL,
    secret_key_prefix VARCHAR(16) NOT NULL, -- e.g. 'sk_live_9f8a...' for dashboard display
    allowed_origins TEXT [] NOT NULL DEFAULT '{}',
    redirect_uris TEXT [] NOT NULL DEFAULT '{}',
    auth_config JSONB NOT NULL DEFAULT '{
        "methods": {
            "password": true,
            "email_otp": true,
            "magic_link": true,
            "passkeys": true,
            "oauth": {
                "google": false,
                "github": false,
                "facebook": false
            }
        },
        "username": {
            "enabled": true,
            "required": false,
            "cooldown_days": 30
        },
        "mfa": {
            "policy": "optional",
            "allowed_methods": ["totp", "email_otp", "backup_code"]
        },
        "session": {
            "access_token_ttl_sec": 900,
            "refresh_token_ttl_sec": 604800
        }
    }',
    oauth_credentials JSONB NOT NULL DEFAULT '{}', -- Encrypted client_id/secret per provider
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (application_id, env_type),
    UNIQUE (application_id, id)
);