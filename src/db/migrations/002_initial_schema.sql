-- ============================================================================
-- 1. CORE USER IDENTITY, LIFECYCLE & AUTH STATE
-- ============================================================================
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    application_id UUID NOT NULL REFERENCES applications (id) ON DELETE CASCADE,
    env_id UUID NOT NULL REFERENCES app_environments (id) ON DELETE CASCADE,
    username VARCHAR(50),
    username_changed_at TIMESTAMPTZ,
    hashed_password TEXT,
    account_status VARCHAR(30) NOT NULL DEFAULT 'pending_verification' CHECK (
        account_status IN (
            'pending_verification',
            'active',
            'disabled',
            'suspended',
            'deleted'
        )
    ),
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    public_metadata JSONB NOT NULL DEFAULT '{}',
    private_metadata JSONB NOT NULL DEFAULT '{}',
    last_active_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    deletion_scheduled_for TIMESTAMPTZ,
    account_created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_users_app_env FOREIGN KEY (application_id, env_id) REFERENCES app_environments (application_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_users_deleted_consistency CHECK (
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

-- Case-insensitive unique username per environment
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_env_username ON users (env_id, lower(username))
WHERE
    username IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_users_env_status ON users (env_id, account_status);

CREATE INDEX IF NOT EXISTS idx_users_deletion_due ON users (deletion_scheduled_for)
WHERE
    account_status = 'deleted'
    AND deletion_scheduled_for IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_users_env_last_active ON users (env_id, last_active_at DESC);

-- ============================================================================
-- 2. USERNAME HISTORY (30-DAY COOLDOWN, RECLAIM & REDIRECTS)
-- ============================================================================
CREATE TABLE IF NOT EXISTS username_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    env_id UUID NOT NULL REFERENCES app_environments (id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    old_username VARCHAR(50) NOT NULL,
    new_username VARCHAR(50),
    reserved_until TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_username_history_lookup ON username_history (
    env_id,
    lower(old_username),
    reserved_until DESC
);

CREATE INDEX IF NOT EXISTS idx_username_history_user ON username_history (user_id, created_at DESC);

-- ============================================================================
-- 3. PUBLIC USER PROFILE (1-TO-1 WITH USERS)
-- ============================================================================
CREATE TABLE IF NOT EXISTS user_profiles (
    user_id UUID PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    env_id UUID NOT NULL REFERENCES app_environments (id) ON DELETE CASCADE,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    display_name VARCHAR(120),
    profile_picture TEXT,
    cover_picture TEXT,
    designation VARCHAR(120),
    about TEXT,
    pronouns VARCHAR(50),
    date_of_birth DATE,
    state VARCHAR(100),
    country VARCHAR(100),
    locale VARCHAR(20) NOT NULL DEFAULT 'en',
    timezone VARCHAR(64) NOT NULL DEFAULT 'UTC',
    contact_number VARCHAR(30),
    contact_number_verified BOOLEAN NOT NULL DEFAULT FALSE,
    contact_number_verified_at TIMESTAMPTZ,
    contact_email VARCHAR(255),
    portfolio_link TEXT,
    profile_url TEXT,
    social_links JSONB NOT NULL DEFAULT '[]' CHECK (
        jsonb_typeof(social_links) = 'array'
        AND jsonb_array_length(social_links) <= 10
    ),
    activity_status VARCHAR(200) CHECK (
        activity_status IS NULL
        OR char_length(activity_status) <= 200
    ),
    profile_visibility VARCHAR(10) NOT NULL DEFAULT 'public' CHECK (
        profile_visibility IN ('public', 'private')
    ),
    verified_badge BOOLEAN NOT NULL DEFAULT FALSE,
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
-- 4. EMAILS, SESSIONS, MFA, RECOVERY, PASSKEYS & OAUTH
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

CREATE UNIQUE INDEX IF NOT EXISTS idx_user_emails_env_email ON user_emails (env_id, lower(email));

CREATE UNIQUE INDEX IF NOT EXISTS idx_user_emails_one_per_type ON user_emails (user_id, email_type);

CREATE TABLE IF NOT EXISTS user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    env_id UUID NOT NULL REFERENCES app_environments (id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    family_id UUID NOT NULL,
    refresh_token_hash TEXT NOT NULL,
    device_name VARCHAR(120),
    browser VARCHAR(100),
    os VARCHAR(100),
    ip_address VARCHAR(45),
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_reason VARCHAR(60),
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
    env_id UUID NOT NULL REFERENCES app_environments (id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    method_type VARCHAR(20) NOT NULL CHECK (
        method_type IN (
            'totp',
            'email_otp',
            'backup_code'
        )
    ),
    device_label VARCHAR(100),
    secret_or_hash TEXT,
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    is_used BOOLEAN NOT NULL DEFAULT FALSE,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_user_mfa_user ON user_mfa_methods (user_id, method_type);

CREATE TABLE IF NOT EXISTS user_recovery_methods (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    env_id UUID NOT NULL REFERENCES app_environments (id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    recovery_type VARCHAR(30) NOT NULL CHECK (
        recovery_type IN (
            'recovery_email',
            'backup_codes',
            'mfa_challenge'
        )
    ),
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    configured_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    UNIQUE (user_id, recovery_type)
);

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
-- 5. AUDIT LOGS & SECURITY NOTIFICATIONS
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
    env_id UUID NOT NULL REFERENCES app_environments (id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    title VARCHAR(150) NOT NULL,
    message TEXT NOT NULL,
    channel VARCHAR(20) NOT NULL DEFAULT 'both' CHECK (
        channel IN ('in_app', 'email', 'both')
    ),
    is_read BOOLEAN NOT NULL DEFAULT FALSE,
    read_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_security_notifications_user_unread ON security_notifications (
    user_id,
    is_read,
    created_at DESC
);