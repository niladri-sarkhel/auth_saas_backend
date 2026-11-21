import crypto from "node:crypto";
import bcrypt from "bcrypt";
import { SignJWT, jwtVerify } from "jose";

import { env, pool, redis } from "#config";
import {
    BadRequestError,
    ConflictError,
    ExpiredSessionError,
    ForbiddenError,
    TooManyRequestsError,
    UnauthorizedError,
} from "#errors";
import { MailService } from "#services";
import {
    generateOTP,
    generateRefreshToken,
    hashToken,
    logger,
} from "#utils";

const BCRYPT_ROUNDS = 12;
const OTP_TTL_SEC = env.OTP_TTL_SECONDS || 300;
const REFRESH_TTL_SEC = env.REFRESH_TTL_SECONDS || 604800;
const ACCESS_TOKEN_TTL = "15m";
const CHALLENGE_TTL_SEC = 300;
const MAX_OTP_ATTEMPTS = 5;
const MAX_FAILED_LOGINS = 5;
const LOGIN_LOCK_TTL_SEC = 900; // 15 minutes

const devAccessSecret = new TextEncoder().encode(env.JWT_SECRET);

export class DevAuthServicesClass {
    _normalizeEmail = (email) => email.trim().toLowerCase();

    _otpHash = (otp) =>
        crypto.createHash("sha256").update(String(otp)).digest("hex");

    _pendingSignupKey = (email) => `dev:signup:pending:${this._normalizeEmail(email)}`;
    _signinChallengeKey = (challengeId) => `dev:signin:challenge:${challengeId}`;
    _resetOtpKey = (email) => `dev:reset:otp:${this._normalizeEmail(email)}`;
    _failedLoginKey = (email) => `dev:login:failed:${this._normalizeEmail(email)}`;
    _resendCooldownKey = (purpose, email) =>
        `dev:otp:cooldown:${purpose}:${this._normalizeEmail(email)}`;

    _signDevAccessToken = async ({ developerId, sessionId, email }) => {
        return new SignJWT({
            sid: sessionId,
            email,
            scope: "dev",
        })
            .setProtectedHeader({ alg: "HS256" })
            .setSubject(developerId)
            .setIssuedAt()
            .setIssuer(env.APP_NAME || "auth_saas")
            .setAudience("dev_control_plane")
            .setExpirationTime(ACCESS_TOKEN_TTL)
            .sign(devAccessSecret);
    };

    verifyDevAccessToken = async (token) => {
        const { payload } = await jwtVerify(token, devAccessSecret, {
            issuer: env.APP_NAME || "auth_saas",
            audience: "dev_control_plane",
        });

        if (!payload?.sub || payload.scope !== "dev") {
            throw new UnauthorizedError({
                message: "Invalid developer access token scope",
            });
        }

        return payload;
    };

    _ensureCanAuthenticate = (dev) => {
        if (!dev) {
            throw new UnauthorizedError({ message: "Invalid email or password" });
        }

        if (dev.account_status === "deleted") {
            throw new ForbiddenError({
                message:
                    "Account is scheduled for deletion. Cancel deletion to restore access.",
            });
        }

        if (dev.account_status !== "active") {
            throw new ForbiddenError({
                message: `Developer account is ${dev.account_status}`,
            });
        }
    };

    _checkLoginLockout = async (email) => {
        const key = this._failedLoginKey(email);
        const attempts = Number((await redis.get(key)) || 0);
        if (attempts >= MAX_FAILED_LOGINS) {
            const ttl = await redis.ttl(key);
            throw new TooManyRequestsError({
                message: "Too many failed login attempts. Try again later.",
                errors: [ttl > 0 ? `Retry after ${ttl} seconds` : "Account temporarily locked"],
            });
        }
    };

    _recordFailedLogin = async (email) => {
        const key = this._failedLoginKey(email);
        const attempts = await redis.incr(key);
        if (attempts === 1) {
            await redis.expire(key, LOGIN_LOCK_TTL_SEC);
        }
    };

    _clearFailedLogin = async (email) => {
        await redis.del(this._failedLoginKey(email));
    };

    _enforceResendCooldown = async (purpose, email, cooldownSec = 60) => {
        const key = this._resendCooldownKey(purpose, email);
        const ttl = await redis.ttl(key);
        if (ttl > 0) {
            throw new TooManyRequestsError({
                message: `Please wait ${ttl} seconds before requesting another OTP`,
            });
        }
        await redis.set(key, "1", "EX", cooldownSec);
    };

    _createSessionAndTokens = async ({
        developerId,
        email,
        userAgent = null,
        ipAddress = null,
        familyId = null,
    }) => {
        const resolvedFamilyId = familyId || crypto.randomUUID();
        const { rawToken, tokenHash } = generateRefreshToken();
        const expiresAt = new Date(Date.now() + REFRESH_TTL_SEC * 1000);

        const { rows } = await pool.query(
            `INSERT INTO developer_sessions (
                developer_id,
                family_id,
                refresh_token_hash,
                user_agent,
                ip_address,
                expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, family_id, expires_at`,
            [developerId, resolvedFamilyId, tokenHash, userAgent, ipAddress, expiresAt],
        );

        const session = rows[0];
        const accessToken = await this._signDevAccessToken({
            developerId,
            sessionId: session.id,
            email,
        });

        return {
            accessToken,
            refreshToken: rawToken,
            sessionId: session.id,
            familyId: session.family_id,
            expiresAt: session.expires_at,
        };
    };

    _revokeAllDeveloperSessions = async (developerId, reason = "security_change") => {
        await pool.query(
            `UPDATE developer_sessions
             SET is_revoked = TRUE, revoked_reason = $2
             WHERE developer_id = $1 AND is_revoked = FALSE`,
            [developerId, reason],
        );
    };

    // =========================================================================
    // 1. SIGNUP (Email + Password + OTP; DB row created ONLY after OTP verified)
    // =========================================================================

    requestSignupOtp = async ({ email, password }) => {
        const normalizedEmail = this._normalizeEmail(email);

        // Prevent duplicate registration if already in developers table
        const existing = await pool.query(
            `SELECT id, account_status FROM developers WHERE lower(email) = $1 LIMIT 1`,
            [normalizedEmail],
        );
        if (existing.rows.length > 0) {
            throw new ConflictError({
                message: "An account with this email already exists",
            });
        }

        await this._enforceResendCooldown("signup", normalizedEmail, 60);

        const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
        const otp = generateOTP({ length: 6, asString: true });

        const payload = {
            email: normalizedEmail,
            passwordHash,
            otpHash: this._otpHash(otp),
            attempts: 0,
        };

        await redis.set(
            this._pendingSignupKey(normalizedEmail),
            JSON.stringify(payload),
            "EX",
            OTP_TTL_SEC,
        );

        await MailService.sendEmail({
            to: normalizedEmail,
            otp,
            subject: `Verify your ${env.APP_NAME || "Developer"} account`,
            purposeText: "complete your developer account registration",
            expiryMinutes: Math.ceil(OTP_TTL_SEC / 60),
        });

        return {
            email: normalizedEmail,
            expiresInSeconds: OTP_TTL_SEC,
            message: "Verification OTP sent to your email address",
        };
    };

    verifySignupOtp = async ({ email, otp, userAgent = null, ipAddress = null }) => {
        const normalizedEmail = this._normalizeEmail(email);
        const key = this._pendingSignupKey(normalizedEmail);
        const raw = await redis.get(key);

        if (!raw) {
            throw new ExpiredSessionError({
                message: "Signup OTP has expired or was not requested",
            });
        }

        const pending = JSON.parse(raw);

        if (pending.attempts >= MAX_OTP_ATTEMPTS) {
            await redis.del(key);
            throw new TooManyRequestsError({
                message: "Maximum OTP verification attempts exceeded. Please request a new OTP.",
            });
        }

        if (this._otpHash(otp) !== pending.otpHash) {
            pending.attempts += 1;
            const ttl = await redis.ttl(key);
            if (ttl > 0) {
                await redis.set(key, JSON.stringify(pending), "EX", ttl);
            }
            throw new BadRequestError({
                message: "Invalid verification OTP",
            });
        }

        const client = await pool.connect();
        try {
            await client.query("BEGIN");

            const dupCheck = await client.query(
                `SELECT id FROM developers WHERE lower(email) = $1 LIMIT 1`,
                [normalizedEmail],
            );
            if (dupCheck.rows.length > 0) {
                await client.query("ROLLBACK");
                await redis.del(key);
                throw new ConflictError({
                    message: "An account with this email already exists",
                });
            }

            const { rows } = await client.query(
                `INSERT INTO developers (email, password_hash, account_status)
                 VALUES ($1, $2, 'active')
                 RETURNING id, email, account_status, created_at`,
                [normalizedEmail, pending.passwordHash],
            );

            await client.query("COMMIT");
            await redis.del(key);

            const developer = rows[0];
            const tokens = await this._createSessionAndTokens({
                developerId: developer.id,
                email: developer.email,
                userAgent,
                ipAddress,
            });

            return {
                developer: {
                    id: developer.id,
                    email: developer.email,
                    accountStatus: developer.account_status,
                    createdAt: developer.created_at,
                },
                ...tokens,
            };
        } catch (err) {
            await client.query("ROLLBACK");
            throw err;
        } finally {
            client.release();
        }
    };

    // =========================================================================
    // 2. SIGNIN (Email + Password -> Sends OTP + Returns Challenge; then Verify OTP)
    // =========================================================================

    signin = async ({ email, password }) => {
        const normalizedEmail = this._normalizeEmail(email);
        await this._checkLoginLockout(normalizedEmail);

        const { rows } = await pool.query(
            `SELECT id, email, password_hash, account_status
             FROM developers
             WHERE lower(email) = $1
             LIMIT 1`,
            [normalizedEmail],
        );

        const dev = rows[0];
        const hashToCompare = dev?.password_hash || env.DUMMY_PASSWORD_HASH;
        const passwordValid = await bcrypt.compare(password, hashToCompare);

        if (!dev || !passwordValid) {
            await this._recordFailedLogin(normalizedEmail);
            throw new UnauthorizedError({
                message: "Invalid email or password",
            });
        }

        this._ensureCanAuthenticate(dev);
        await this._clearFailedLogin(normalizedEmail);

        const challengeId = crypto.randomUUID();
        const otp = generateOTP({ length: 6, asString: true });

        const challengeData = {
            developerId: dev.id,
            email: dev.email,
            otpHash: this._otpHash(otp),
            attempts: 0,
        };

        await redis.set(
            this._signinChallengeKey(challengeId),
            JSON.stringify(challengeData),
            "EX",
            CHALLENGE_TTL_SEC,
        );

        await MailService.sendEmail({
            to: dev.email,
            otp,
            subject: `Your ${env.APP_NAME || "Developer"} sign-in OTP`,
            purposeText: "complete your developer account sign-in",
            expiryMinutes: Math.ceil(CHALLENGE_TTL_SEC / 60),
        });

        return {
            requiresOtp: true,
            challengeId,
            expiresInSeconds: CHALLENGE_TTL_SEC,
            message: "OTP sent to your registered email address",
        };
    };

    verifySigninOtp = async ({
        challengeId,
        otp,
        userAgent = null,
        ipAddress = null,
    }) => {
        const key = this._signinChallengeKey(challengeId);
        const raw = await redis.get(key);

        if (!raw) {
            throw new ExpiredSessionError({
                message: "Sign-in OTP challenge has expired or is invalid",
            });
        }

        const challenge = JSON.parse(raw);

        if (challenge.attempts >= MAX_OTP_ATTEMPTS) {
            await redis.del(key);
            throw new TooManyRequestsError({
                message: "Too many invalid OTP attempts. Please sign in again.",
            });
        }

        if (this._otpHash(otp) !== challenge.otpHash) {
            challenge.attempts += 1;
            const ttl = await redis.ttl(key);
            if (ttl > 0) {
                await redis.set(key, JSON.stringify(challenge), "EX", ttl);
            }
            throw new BadRequestError({
                message: "Invalid sign-in OTP",
            });
        }

        const { rows } = await pool.query(
            `SELECT id, email, account_status
             FROM developers
             WHERE id = $1
             LIMIT 1`,
            [challenge.developerId],
        );

        const dev = rows[0];
        this._ensureCanAuthenticate(dev);

        await redis.del(key);

        const tokens = await this._createSessionAndTokens({
            developerId: dev.id,
            email: dev.email,
            userAgent,
            ipAddress,
        });

        return {
            developer: {
                id: dev.id,
                email: dev.email,
                accountStatus: dev.account_status,
            },
            ...tokens,
        };
    };

    // =========================================================================
    // 3. TOKEN REFRESH (Rotation + Reuse Detection) & SIGNOUT
    // =========================================================================

    refresh = async ({ refreshToken, userAgent = null, ipAddress = null }) => {
        if (!refreshToken) {
            throw new UnauthorizedError({ message: "Refresh token is required" });
        }

        const tokenHash = hashToken(refreshToken);

        const { rows } = await pool.query(
            `SELECT s.id, s.developer_id, s.family_id, s.is_revoked, s.expires_at,
                    d.email, d.account_status
             FROM developer_sessions s
             JOIN developers d ON d.id = s.developer_id
             WHERE s.refresh_token_hash = $1
             LIMIT 1`,
            [tokenHash],
        );

        const session = rows[0];

        if (!session) {
            throw new UnauthorizedError({ message: "Invalid refresh token" });
        }

        // Refresh token reuse detection: if a revoked token is presented, revoke its entire family
        if (session.is_revoked) {
            logger.warn(
                { developerId: session.developer_id, familyId: session.family_id },
                "Developer refresh token reuse detected; revoking token family",
            );
            await pool.query(
                `UPDATE developer_sessions
                 SET is_revoked = TRUE, revoked_reason = 'refresh_token_reuse'
                 WHERE family_id = $1 AND is_revoked = FALSE`,
                [session.family_id],
            );
            throw new UnauthorizedError({
                message: "Refresh token reuse detected. Session family revoked.",
            });
        }

        if (new Date(session.expires_at) <= new Date()) {
            await pool.query(
                `UPDATE developer_sessions
                 SET is_revoked = TRUE, revoked_reason = 'expired'
                 WHERE id = $1`,
                [session.id],
            );
            throw new UnauthorizedError({ message: "Refresh token has expired" });
        }

        this._ensureCanAuthenticate({
            id: session.developer_id,
            account_status: session.account_status,
        });

        const client = await pool.connect();
        try {
            await client.query("BEGIN");

            await client.query(
                `UPDATE developer_sessions
                 SET is_revoked = TRUE, revoked_reason = 'rotated'
                 WHERE id = $1`,
                [session.id],
            );

            const nextTokens = await this._createSessionAndTokens({
                developerId: session.developer_id,
                email: session.email,
                userAgent,
                ipAddress,
                familyId: session.family_id,
            });

            await client.query("COMMIT");
            return nextTokens;
        } catch (err) {
            await client.query("ROLLBACK");
            throw err;
        } finally {
            client.release();
        }
    };

    signout = async ({ refreshToken }) => {
        if (!refreshToken) {
            return { message: "Signed out" };
        }

        const tokenHash = hashToken(refreshToken);
        await pool.query(
            `UPDATE developer_sessions
             SET is_revoked = TRUE, revoked_reason = 'signed_out'
             WHERE refresh_token_hash = $1 AND is_revoked = FALSE`,
            [tokenHash],
        );

        return { message: "Signed out successfully" };
    };

    // =========================================================================
    // 4. FORGOT PASSWORD & RESET PASSWORD (OTP + Session Invalidation)
    // =========================================================================

    forgotPassword = async ({ email }) => {
        const normalizedEmail = this._normalizeEmail(email);

        const { rows } = await pool.query(
            `SELECT id, email, account_status
             FROM developers
             WHERE lower(email) = $1
             LIMIT 1`,
            [normalizedEmail],
        );

        const dev = rows[0];
        if (dev && dev.account_status === "active") {
            const cooldownKey = this._resendCooldownKey("forgot_password", dev.email);
            const ttl = await redis.ttl(cooldownKey);

            if (ttl <= 0) {
                await redis.set(cooldownKey, "1", "EX", 60);
                const otp = generateOTP({ length: 6, asString: true });

                await redis.set(
                    this._resetOtpKey(dev.email),
                    JSON.stringify({
                        developerId: dev.id,
                        otpHash: this._otpHash(otp),
                        attempts: 0,
                    }),
                    "EX",
                    OTP_TTL_SEC,
                );

                await MailService.sendEmail({
                    to: dev.email,
                    otp,
                    subject: `Reset your ${env.APP_NAME || "Developer"} password`,
                    purposeText: "reset your developer account password",
                    expiryMinutes: Math.ceil(OTP_TTL_SEC / 60),
                });
            }
        }

        // Generic response prevents account enumeration
        return {
            message:
                "If an active account exists with that email, a password reset OTP has been sent.",
        };
    };

    resetPassword = async ({ email, otp, newPassword }) => {
        const normalizedEmail = this._normalizeEmail(email);
        const key = this._resetOtpKey(normalizedEmail);
        const raw = await redis.get(key);

        if (!raw) {
            throw new ExpiredSessionError({
                message: "Password reset OTP has expired or is invalid",
            });
        }

        const resetState = JSON.parse(raw);

        if (resetState.attempts >= MAX_OTP_ATTEMPTS) {
            await redis.del(key);
            throw new TooManyRequestsError({
                message: "Too many failed OTP attempts. Request a new reset OTP.",
            });
        }

        if (this._otpHash(otp) !== resetState.otpHash) {
            resetState.attempts += 1;
            const ttl = await redis.ttl(key);
            if (ttl > 0) {
                await redis.set(key, JSON.stringify(resetState), "EX", ttl);
            }
            throw new BadRequestError({ message: "Invalid reset OTP" });
        }

        const passwordHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);

        const client = await pool.connect();
        try {
            await client.query("BEGIN");

            const { rows } = await client.query(
                `UPDATE developers
                 SET password_hash = $2, updated_at = NOW()
                 WHERE id = $1 AND account_status = 'active'
                 RETURNING id`,
                [resetState.developerId, passwordHash],
            );

            if (rows.length === 0) {
                await client.query("ROLLBACK");
                await redis.del(key);
                throw new ForbiddenError({
                    message: "Account is not eligible for password reset",
                });
            }

            await client.query(
                `UPDATE developer_sessions
                 SET is_revoked = TRUE, revoked_reason = 'password_reset'
                 WHERE developer_id = $1 AND is_revoked = FALSE`,
                [resetState.developerId],
            );

            await client.query("COMMIT");
            await redis.del(key);
            await this._clearFailedLogin(normalizedEmail);

            return {
                message:
                    "Password reset successful. All active sessions have been signed out.",
            };
        } catch (err) {
            await client.query("ROLLBACK");
            throw err;
        } finally {
            client.release();
        }
    };

    // =========================================================================
    // 5. RESEND OTP (Signup or Sign-in Challenge)
    // =========================================================================

    resendOtp = async ({ purpose, email, challengeId }) => {
        if (purpose === "signup") {
            const normalizedEmail = this._normalizeEmail(email);
            const key = this._pendingSignupKey(normalizedEmail);
            const raw = await redis.get(key);
            if (!raw) {
                throw new ExpiredSessionError({
                    message: "No pending signup found. Please start signup again.",
                });
            }

            await this._enforceResendCooldown("signup", normalizedEmail, 60);

            const pending = JSON.parse(raw);
            const otp = generateOTP({ length: 6, asString: true });
            pending.otpHash = this._otpHash(otp);
            pending.attempts = 0;

            await redis.set(key, JSON.stringify(pending), "EX", OTP_TTL_SEC);

            await MailService.sendEmail({
                to: normalizedEmail,
                otp,
                subject: `Verify your ${env.APP_NAME || "Developer"} account`,
                purposeText: "complete your developer account registration",
                expiryMinutes: Math.ceil(OTP_TTL_SEC / 60),
            });

            return {
                expiresInSeconds: OTP_TTL_SEC,
                message: "Signup OTP resent",
            };
        }

        if (purpose === "signin") {
            const key = this._signinChallengeKey(challengeId);
            const raw = await redis.get(key);
            if (!raw) {
                throw new ExpiredSessionError({
                    message: "Sign-in challenge expired. Please sign in again.",
                });
            }

            const challenge = JSON.parse(raw);
            await this._enforceResendCooldown("signin", challenge.email, 60);

            const otp = generateOTP({ length: 6, asString: true });
            challenge.otpHash = this._otpHash(otp);
            challenge.attempts = 0;

            const ttl = await redis.ttl(key);
            await redis.set(
                key,
                JSON.stringify(challenge),
                "EX",
                ttl > 0 ? ttl : CHALLENGE_TTL_SEC,
            );

            await MailService.sendEmail({
                to: challenge.email,
                otp,
                subject: `Your ${env.APP_NAME || "Developer"} sign-in OTP`,
                purposeText: "complete your developer account sign-in",
                expiryMinutes: Math.ceil(CHALLENGE_TTL_SEC / 60),
            });

            return {
                expiresInSeconds: ttl > 0 ? ttl : CHALLENGE_TTL_SEC,
                message: "Sign-in OTP resent",
            };
        }

        throw new BadRequestError({
            message: "Unsupported OTP resend purpose",
        });
    };
}

export const devAuthServices = new DevAuthServicesClass();