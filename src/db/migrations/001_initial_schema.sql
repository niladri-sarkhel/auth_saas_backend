CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- 1. CONTROL PLANE: Developers, Sessions, Applications & Environments
-- ============================================================================

CREATE TABLE IF NOT EXISTS developers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name VARCHAR(120) NOT NULL,
    is_verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS developer_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    developer_id UUID NOT NULL REFERENCES developers (id) ON DELETE CASCADE,
    refresh_token_hash TEXT NOT NULL,
    user_agent TEXT,
    ip_address VARCHAR(45),
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS applications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    developer_id UUID NOT NULL REFERENCES developers (id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    slug VARCHAR(100) NOT NULL,
    description TEXT,
    deleted_at TIMESTAMPTZ, -- Supports safe soft-deletion of applications
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (developer_id, slug)
);

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
            "cooldown_days": 90
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
    UNIQUE (application_id, env_type)
);

-- ============================================================================
-- 2. DATA PLANE: Core End-Users & 90-Day Username History
-- ============================================================================

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    application_id UUID NOT NULL REFERENCES applications (id) ON DELETE CASCADE,
    env_id UUID NOT NULL REFERENCES app_environments (id) ON DELETE CASCADE,
    username VARCHAR(50),
    username_changed_at TIMESTAMPTZ,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    display_name VARCHAR(120),
    profile_picture TEXT,
    hashed_password TEXT,
    account_status VARCHAR(30) NOT NULL DEFAULT 'pending_verification' CHECK (
        account_status IN (
            'active',
            'disabled',
            'suspended',
            'deleted',
            'pending_verification'
        )
    ),
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    verified_badge BOOLEAN NOT NULL DEFAULT FALSE,
    public_metadata JSONB NOT NULL DEFAULT '{}',
    private_metadata JSONB NOT NULL DEFAULT '{}',
    last_active_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    account_created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Case-insensitive unique username per environment
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_env_username ON users (env_id, lower(username))
WHERE
    username IS NOT NULL
    AND deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_users_env_status ON users (env_id, account_status);

CREATE TABLE IF NOT EXISTS username_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    env_id UUID NOT NULL REFERENCES app_environments (id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    old_username VARCHAR(50) NOT NULL,
    reserved_until TIMESTAMPTZ NOT NULL, -- Enforces 90-day hold & powers /oldname redirects
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_username_history_lookup ON username_history (
    env_id,
    lower(old_username),
    reserved_until DESC
);

-- ============================================================================
-- 3. PUBLIC USER PROFILE (1-to-1 with users)
-- ============================================================================

CREATE TABLE IF NOT EXISTS user_profiles (
    user_id UUID PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    env_id UUID NOT NULL REFERENCES app_environments (id) ON DELETE CASCADE,
    cover_picture TEXT,
    designation VARCHAR(120),
    about TEXT,
    pronouns VARCHAR(50),
    contact_number VARCHAR(30),
    contact_number_verified BOOLEAN NOT NULL DEFAULT FALSE,
    contact_email VARCHAR(255),
    portfolio_link TEXT,
    profile_url TEXT,
    social_links JSONB NOT NULL DEFAULT '[]' CHECK (
        jsonb_typeof(social_links) = 'array'
        AND jsonb_array_length(social_links) <= 10
    ),
    date_of_birth DATE,
    state VARCHAR(100),
    country VARCHAR(100),
    locale VARCHAR(20) NOT NULL DEFAULT 'en',
    timezone VARCHAR(64) NOT NULL DEFAULT 'UTC',
    activity_status VARCHAR(200), -- Short text + emoji, max 200 chars
    profile_visibility VARCHAR(10) NOT NULL DEFAULT 'public' CHECK (
        profile_visibility IN ('public', 'private')
    ),
    accent_color VARCHAR(20),
    theme_preference VARCHAR(20) NOT NULL DEFAULT 'system' CHECK (
        theme_preference IN ('light', 'dark', 'system')
    ),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_user_profiles_env_contact_number ON user_profiles (env_id, contact_number)
WHERE
    contact_number IS NOT NULL;

-- ============================================================================
-- 4. PRIVATE CREDENTIALS: Emails, Sessions, MFA, Passkeys & OAuth
-- ============================================================================

CREATE TABLE IF NOT EXISTS user_emails (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    env_id UUID NOT NULL REFERENCES app_environments (id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    email_type VARCHAR(20) NOT NULL DEFAULT 'primary' CHECK (
        email_type IN (
            'primary',
            'secondary',
            'recovery'
        )
    ),
    is_verified BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Email must be unique per environment
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_emails_env_email ON user_emails (env_id, lower(email));

-- Enforces max 1 primary, max 1 secondary, and max 1 recovery email per user
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_emails_one_per_type ON user_emails (user_id, email_type);

CREATE TABLE IF NOT EXISTS user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    env_id UUID NOT NULL REFERENCES app_environments (id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    family_id UUID NOT NULL, -- Token family for reuse detection
    refresh_token_hash TEXT NOT NULL,
    device_name VARCHAR(120),
    browser VARCHAR(100),
    os VARCHAR(100),
    ip_address VARCHAR(45),
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_reason VARCHAR(60), -- e.g. 'user_signout', 'token_reuse_detected', 'password_reset'
    last_active_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_user_sessions_user_active ON user_sessions (
    user_id,
    is_revoked,
    expires_at
);

CREATE INDEX IF NOT EXISTS idx_user_sessions_family ON user_sessions (family_id);

CREATE TABLE IF NOT EXISTS user_mfa_methods (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    method_type VARCHAR(20) NOT NULL CHECK (
        method_type IN ('totp', 'backup_code')
    ),
    device_label VARCHAR(100),
    secret_or_hash TEXT NOT NULL,
    is_used BOOLEAN NOT NULL DEFAULT FALSE,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_user_mfa_user ON user_mfa_methods (user_id, method_type);

CREATE TABLE IF NOT EXISTS user_passkeys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    env_id UUID NOT NULL REFERENCES app_environments (id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    credential_id TEXT UNIQUE NOT NULL,
    public_key BYTEA NOT NULL,
    counter BIGINT NOT NULL DEFAULT 0,
    transports TEXT [] DEFAULT '{}',
    device_name VARCHAR(120),
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_user_passkeys_user ON user_passkeys (user_id);

CREATE TABLE IF NOT EXISTS user_oauth_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    env_id UUID NOT NULL REFERENCES app_environments (id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    provider VARCHAR(30) NOT NULL CHECK (
        provider IN (
            'google',
            'github',
            'facebook'
        )
    ),
    provider_user_id VARCHAR(255) NOT NULL,
    provider_email VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (
        env_id,
        provider,
        provider_user_id
    )
);

-- ============================================================================
-- 5. LOGIN HISTORY, AUDIT LOGS & SECURITY NOTIFICATIONS
-- ============================================================================

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    env_id UUID NOT NULL REFERENCES app_environments (id) ON DELETE CASCADE,
    user_id UUID REFERENCES users (id) ON DELETE SET NULL,
    actor_type VARCHAR(20) NOT NULL DEFAULT 'user' CHECK (
        actor_type IN ('user', 'developer', 'system')
    ),
    event_type VARCHAR(60) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'success' CHECK (
        status IN ('success', 'failure')
    ),
    ip_address VARCHAR(45),
    user_agent TEXT,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user_time ON audit_logs (user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_logs_env_time ON audit_logs (env_id, created_at DESC);

CREATE TABLE IF NOT EXISTS security_notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    title VARCHAR(150) NOT NULL,
    message TEXT NOT NULL,
    channel VARCHAR(20) NOT NULL DEFAULT 'both' CHECK (
        channel IN ('in_app', 'email', 'both')
    ),
    is_read BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_security_notifications_user_unread ON security_notifications (
    user_id,
    is_read,
    created_at DESC
);