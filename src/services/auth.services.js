// src/services/auth.services.js
import crypto from "node:crypto";
import bcrypt from "bcrypt";
import { pool, redis, env } from "#config";
import {
    signAccessToken,
    generateRefreshToken,
    hashToken,
    generateOTP,
} from "#utils";
import { MAIL_PURPOSES, MAIL_SUBJECTS } from "#constants";
import { MailService } from "./email.services.js";
import {
    BadRequestError,
    UnauthorizedError,
    ForbiddenError,
    NotFoundError,
    ConflictError,
    TooManyRequestsError,
} from "#errors";

const DEFAULT_DUMMY_HASH =
    "$2b$12$C6UzMDM.H6dfI/f/IKcEeO9u6M6p2r9x8H5v2lY1yP6x8b4p2q1W.";
const REFRESH_TTL_SEC = Number(env.REFRESH_TTL_SECONDS || 7 * 24 * 60 * 60);

function parseUserAgent(ua = "") {
    const browser = /Edg/i.test(ua)
        ? "Edge"
        : /Chrome/i.test(ua)
            ? "Chrome"
            : /Firefox/i.test(ua)
                ? "Firefox"
                : /Safari/i.test(ua)
                    ? "Safari"
                    : "Unknown";

    const os = /Windows/i.test(ua)
        ? "Windows"
        : /Android/i.test(ua)
            ? "Android"
            : /iPhone|iPad/i.test(ua)
                ? "iOS"
                : /Mac OS/i.test(ua)
                    ? "macOS"
                    : /Linux/i.test(ua)
                        ? "Linux"
                        : "Unknown";

    return { browser, os, deviceName: `${browser} on ${os}` };
}

async function logAudit(
    db,
    { envId, userId = null, eventType, status = "success", ip, ua, metadata = {} }
) {
    await db.query(
        `INSERT INTO audit_logs (env_id, user_id, actor_type, event_type, status, ip_address, user_agent, metadata)
     VALUES ($1, $2, 'user', $3, $4, $5, $6, $7)`,
        [
            envId,
            userId,
            eventType,
            status,
            ip || null,
            ua || null,
            JSON.stringify(metadata),
        ]
    );
}

// ============================================================================
// 1. SIGNUP
// ============================================================================
export async function signupUser({ tenant, payload, ip, userAgent }) {
    const { email, password, username, first_name, last_name } = payload;

    if (!tenant.auth_config?.methods?.password) {
        throw new ForbiddenError({
            message: "Password signup is disabled for this application",
        });
    }

    if (tenant.auth_config?.username?.required && !username) {
        throw new BadRequestError({
            message: "Username is required for this application",
        });
    }

    const client = await pool.connect();
    try {
        await client.query("BEGIN");

        // 1. Check email uniqueness inside this environment
        const existingEmail = await client.query(
            `SELECT 1 FROM user_emails WHERE env_id = $1 AND lower(email) = lower($2)`,
            [tenant.env_id, email]
        );
        if (existingEmail.rows.length > 0) {
            throw new ConflictError({
                message: "An account with this email already exists",
            });
        }

        // 2. Check active username + 90-day cooldown hold
        if (username) {
            const existingUsername = await client.query(
                `SELECT 1 FROM users WHERE env_id = $1 AND lower(username) = lower($2) AND deleted_at IS NULL`,
                [tenant.env_id, username]
            );
            if (existingUsername.rows.length > 0) {
                throw new ConflictError({
                    message: "Username is already taken",
                });
            }

            const reservedUsername = await client.query(
                `SELECT 1 FROM username_history
         WHERE env_id = $1 AND lower(old_username) = lower($2) AND reserved_until > NOW()`,
                [tenant.env_id, username]
            );
            if (reservedUsername.rows.length > 0) {
                throw new ConflictError({
                    message: "Username is temporarily reserved",
                });
            }
        }

        // 3. Create user, profile, and primary email
        const hashedPassword = await bcrypt.hash(password, 12);
        const displayName =
            [first_name, last_name].filter(Boolean).join(" ") ||
            username ||
            email.split("@")[0];

        const userRes = await client.query(
            `INSERT INTO users (
         application_id, env_id, username, first_name, last_name, display_name, hashed_password, account_status
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending_verification')
       RETURNING id, username, first_name, last_name, display_name, account_status, account_created_at`,
            [
                tenant.application_id,
                tenant.env_id,
                username || null,
                first_name || null,
                last_name || null,
                displayName,
                hashedPassword,
            ]
        );
        const user = userRes.rows[0];

        await client.query(
            `INSERT INTO user_profiles (user_id, env_id) VALUES ($1, $2)`,
            [user.id, tenant.env_id]
        );

        await client.query(
            `INSERT INTO user_emails (env_id, user_id, email, email_type, is_verified)
       VALUES ($1, $2, $3, 'primary', false)`,
            [tenant.env_id, user.id, email]
        );

        await logAudit(client, {
            envId: tenant.env_id,
            userId: user.id,
            eventType: "signup.created",
            ip,
            ua: userAgent,
            metadata: { email },
        });

        await client.query("COMMIT");

        // 4. Store hashed 6-digit OTP in Redis & send email via Mailpit
        const otp = generateOTP();
        const otpKey = `otp:verify:${tenant.env_id}:${email.toLowerCase()}`;
        await redis.set(
            otpKey,
            hashToken(otp),
            "EX",
            Number(env.OTP_TTL_SECONDS || 300)
        );

        const otpExpiryMinutes = Number(env.OTP_TTL_SECONDS || 300) / 60;
        await MailService.sendEmail(
            email,
            otp,
            MAIL_SUBJECTS.ACCOUNT_REGISTRATION,
            MAIL_PURPOSES.ACCOUNT_REGISTRATION,
            otpExpiryMinutes
        );

        return {
            user: { ...user, email },
            message:
                "Account created. Please check your email for the 6-digit verification code.",
        };
    } catch (err) {
        await client.query("ROLLBACK");
        throw err;
    } finally {
        client.release();
    }
}

// ============================================================================
// 2. VERIFY EMAIL
// ============================================================================
export async function verifyUserEmail({ tenant, email, otp, ip, userAgent }) {
    const otpKey = `otp:verify:${tenant.env_id}:${email.toLowerCase()}`;
    const storedHash = await redis.get(otpKey);

    if (!storedHash || storedHash !== hashToken(otp)) {
        throw new BadRequestError({
            message: "Invalid or expired verification code",
        });
    }

    const client = await pool.connect();
    try {
        await client.query("BEGIN");

        const emailRes = await client.query(
            `UPDATE user_emails
       SET is_verified = true, verified_at = NOW()
       WHERE env_id = $1 AND lower(email) = lower($2)
       RETURNING user_id, email`,
            [tenant.env_id, email]
        );

        if (emailRes.rows.length === 0) {
            throw new NotFoundError({ message: "Account not found" });
        }

        const { user_id: userId } = emailRes.rows[0];

        await client.query(
            `UPDATE users
       SET account_status = 'active', updated_at = NOW()
       WHERE id = $1 AND account_status = 'pending_verification'`,
            [userId]
        );

        await logAudit(client, {
            envId: tenant.env_id,
            userId,
            eventType: "email.verified",
            ip,
            ua: userAgent,
            metadata: { email },
        });

        await client.query("COMMIT");
        await redis.del(otpKey);

        return { message: "Email verified successfully. You can now sign in." };
    } catch (err) {
        await client.query("ROLLBACK");
        throw err;
    } finally {
        client.release();
    }
}

// ============================================================================
// 3. SIGNIN (Identifier-First: Email or Case-Insensitive Username)
// ============================================================================
export async function signinUser({
    tenant,
    identifier,
    password,
    ip,
    userAgent,
}) {
    if (!tenant.auth_config?.methods?.password) {
        throw new ForbiddenError({
            message: "Password sign-in is disabled for this application",
        });
    }

    // Progressive exponential delay check on repeated failed attempts
    const failKey = `login_fail:${tenant.env_id}:${identifier.toLowerCase()}`;
    const failCount = Number((await redis.get(failKey)) || 0);
    if (failCount >= 5) {
        const ttl = await redis.ttl(failKey);
        throw new TooManyRequestsError({
            message: `Too many failed attempts. Please try again in ${Math.max(ttl, 1)} seconds.`,
        });
    }

    // Look up user by primary/secondary email OR username within this environment
    const { rows } = await pool.query(
        `SELECT DISTINCT u.id, u.application_id, u.env_id, u.username, u.first_name, u.last_name,
            u.display_name, u.hashed_password, u.account_status, u.mfa_enabled,
            pe.email AS primary_email, pe.is_verified AS primary_email_verified
     FROM users u
     JOIN user_emails pe ON pe.user_id = u.id AND pe.email_type = 'primary'
     LEFT JOIN user_emails any_e ON any_e.user_id = u.id AND any_e.email_type IN ('primary', 'secondary')
     WHERE u.env_id = $1
       AND u.deleted_at IS NULL
       AND (lower(u.username) = lower($2) OR lower(any_e.email) = lower($2))
     LIMIT 1`,
        [tenant.env_id, identifier]
    );

    const user = rows[0];
    const passwordValid = await bcrypt.compare(
        password,
        user?.hashed_password || env.DUMMY_PASSWORD_HASH || DEFAULT_DUMMY_HASH
    );

    if (!user || !user.hashed_password || !passwordValid) {
        const nextFails = await redis.incr(failKey);
        const backoffSeconds = Math.min(Math.pow(2, nextFails) * 5, 900); // Exponential up to 15m
        await redis.expire(failKey, backoffSeconds);

        await logAudit(pool, {
            envId: tenant.env_id,
            userId: user?.id || null,
            eventType: "signin.failed",
            status: "failure",
            ip,
            ua: userAgent,
            metadata: { identifier },
        });

        throw new UnauthorizedError({ message: "Invalid credentials" });
    }

    if (
        user.account_status === "pending_verification" ||
        !user.primary_email_verified
    ) {
        throw new ForbiddenError({
            message: "Please verify your email address before signing in",
        });
    }

    if (user.account_status !== "active") {
        throw new ForbiddenError({
            message: `Account is ${user.account_status}`,
        });
    }

    // Clear failure counter on valid login
    await redis.del(failKey);

    const { rawToken, tokenHash } = generateRefreshToken();
    const familyId = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + REFRESH_TTL_SEC * 1000);
    const { browser, os, deviceName } = parseUserAgent(userAgent);

    const sessionRes = await pool.query(
        `INSERT INTO user_sessions (
       env_id, user_id, family_id, refresh_token_hash, device_name, browser, os, ip_address, expires_at
     )
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
     RETURNING id`,
        [
            tenant.env_id,
            user.id,
            familyId,
            tokenHash,
            deviceName,
            browser,
            os,
            ip || null,
            expiresAt,
        ]
    );
    const sessionId = sessionRes.rows[0].id;

    await pool.query(`UPDATE users SET last_active_at = NOW() WHERE id = $1`, [
        user.id,
    ]);

    await logAudit(pool, {
        envId: tenant.env_id,
        userId: user.id,
        eventType: "signin.success",
        ip,
        ua: userAgent,
        metadata: { sessionId, deviceName },
    });

    const accessToken = await signAccessToken({
        userId: user.id,
        sessionId,
        envId: tenant.env_id,
        applicationId: tenant.application_id,
        email: user.primary_email,
    });

    return {
        accessToken,
        refreshToken: rawToken,
        user: {
            id: user.id,
            email: user.primary_email,
            username: user.username,
            first_name: user.first_name,
            last_name: user.last_name,
            display_name: user.display_name,
        },
    };
}

// ============================================================================
// 4. REFRESH TOKEN ROTATION + REUSE DETECTION
// ============================================================================
export async function rotateRefreshToken({
    tenant,
    rawRefreshToken,
    ip,
    userAgent,
}) {
    if (!rawRefreshToken) {
        throw new UnauthorizedError({ message: "Missing refresh token" });
    }

    const incomingHash = hashToken(rawRefreshToken);

    const client = await pool.connect();
    try {
        await client.query("BEGIN");

        const { rows } = await client.query(
            `SELECT s.*, u.account_status, u.application_id, pe.email AS primary_email
       FROM user_sessions s
       JOIN users u ON u.id = s.user_id
       JOIN user_emails pe ON pe.user_id = u.id AND pe.email_type = 'primary'
       WHERE s.env_id = $1 AND s.refresh_token_hash = $2
       FOR UPDATE OF s`,
            [tenant.env_id, incomingHash]
        );

        const session = rows[0];
        if (!session) {
            await client.query("ROLLBACK");
            throw new UnauthorizedError({ message: "Invalid refresh token" });
        }

        // REUSE DETECTION: If this token was ALREADY rotated/revoked, compromise is assumed!
        if (session.is_revoked) {
            await client.query(
                `UPDATE user_sessions
         SET is_revoked = true, revoked_reason = 'token_reuse_detected'
         WHERE family_id = $1 AND is_revoked = false`,
                [session.family_id]
            );

            await logAudit(client, {
                envId: tenant.env_id,
                userId: session.user_id,
                eventType: "session.reuse_detected",
                status: "failure",
                ip,
                ua: userAgent,
                metadata: {
                    familyId: session.family_id,
                    compromisedSessionId: session.id,
                },
            });

            await client.query("COMMIT");
            throw new UnauthorizedError({
                message: "Refresh token reuse detected. All sessions in family revoked.",
            });
        }

        if (
            new Date(session.expires_at) <= new Date() ||
            session.account_status !== "active"
        ) {
            await client.query(
                `UPDATE user_sessions SET is_revoked = true, revoked_reason = 'expired' WHERE id = $1`,
                [session.id]
            );
            await client.query("COMMIT");
            throw new UnauthorizedError({
                message: "Session expired or account inactive",
            });
        }

        // Revoke the used refresh token
        await client.query(
            `UPDATE user_sessions SET is_revoked = true, revoked_reason = 'rotated' WHERE id = $1`,
            [session.id]
        );

        // Issue a replacement refresh token inside the SAME family_id
        const { rawToken: nextRawToken, tokenHash: nextTokenHash } =
            generateRefreshToken();
        const expiresAt = new Date(Date.now() + REFRESH_TTL_SEC * 1000);
        const { browser, os, deviceName } = parseUserAgent(userAgent);

        const nextSessionRes = await client.query(
            `INSERT INTO user_sessions (
         env_id, user_id, family_id, refresh_token_hash, device_name, browser, os, ip_address, expires_at
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING id`,
            [
                tenant.env_id,
                session.user_id,
                session.family_id,
                nextTokenHash,
                deviceName,
                browser,
                os,
                ip || null,
                expiresAt,
            ]
        );
        const nextSessionId = nextSessionRes.rows[0].id;

        await client.query(`UPDATE users SET last_active_at = NOW() WHERE id = $1`, [
            session.user_id,
        ]);
        await client.query("COMMIT");

        const accessToken = await signAccessToken({
            userId: session.user_id,
            sessionId: nextSessionId,
            envId: tenant.env_id,
            applicationId: session.application_id,
            email: session.primary_email,
        });

        return { accessToken, refreshToken: nextRawToken };
    } catch (err) {
        if (client) {
            try {
                await client.query("ROLLBACK");
            } catch { }
        }
        throw err;
    } finally {
        client.release();
    }
}

// ============================================================================
// 5. SIGNOUT
// ============================================================================
export async function signoutUser({ tenant, rawRefreshToken, ip, userAgent }) {
    if (!rawRefreshToken) return;

    const tokenHash = hashToken(rawRefreshToken);
    const { rows } = await pool.query(
        `UPDATE user_sessions
     SET is_revoked = true, revoked_reason = 'user_signout'
     WHERE env_id = $1 AND refresh_token_hash = $2 AND is_revoked = false
     RETURNING id, user_id`,
        [tenant.env_id, tokenHash]
    );

    if (rows[0]) {
        await logAudit(pool, {
            envId: tenant.env_id,
            userId: rows[0].user_id,
            eventType: "signout",
            ip,
            ua: userAgent,
            metadata: { sessionId: rows[0].id },
        });
    }
}

// ============================================================================
// 6. RESEND-OTP
// ============================================================================
export async function resendVerificationOtp({ tenant, email }) {
    const { rows } = await pool.query(
        `SELECT u.id, u.account_status, ue.is_verified
     FROM users u
     JOIN user_emails ue ON ue.user_id = u.id AND ue.email_type = 'primary'
     WHERE u.env_id = $1 AND lower(ue.email) = lower($2) AND u.deleted_at IS NULL`,
        [tenant.env_id, email]
    );

    // Generic response prevents email enumeration even if email doesn't exist
    const genericResponse = {
        message:
            "If an unverified account exists for this email, a new verification code has been sent.",
    };

    const user = rows[0];
    if (!user || user.is_verified || user.account_status !== "pending_verification") {
        return genericResponse;
    }

    // Cooldown guard (60s) to prevent OTP spam
    const cooldownKey = `otp:cooldown:${tenant.env_id}:${email.toLowerCase()}`;
    if (await redis.get(cooldownKey)) {
        throw new TooManyRequestsError({
            message: "Please wait 60 seconds before requesting another code",
        });
    }

    const otp = generateOTP();
    const otpKey = `otp:verify:${tenant.env_id}:${email.toLowerCase()}`;
    await redis.set(
        otpKey,
        hashToken(otp),
        "EX",
        Number(env.OTP_TTL_SECONDS || 300)
    );
    await redis.set(cooldownKey, "1", "EX", 60);

    const otpExpiryMinutes = Number(env.OTP_TTL_SECONDS || 300) / 60;
    await MailService.sendEmail(
        email,
        otp,
        MAIL_SUBJECTS.ACCOUNT_REGISTRATION,
        MAIL_PURPOSES.ACCOUNT_REGISTRATION,
        otpExpiryMinutes
    );

    return genericResponse;
}