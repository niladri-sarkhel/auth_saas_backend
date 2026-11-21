import { env } from "#config";
import { BadRequestError } from "#errors";
import { devAuthServices } from "#services";
import { logger } from "#utils";

const REFRESH_COOKIE_NAME = env.REFRESH_COOKIE_NAME || "dev_refresh_token";
const REFRESH_TTL_SEC = env.REFRESH_TTL_SECONDS || 604800;

export class DevAuthControllersClass {
    _getClientMeta = (req) => ({
        userAgent: req.headers["user-agent"] || null,
        ipAddress:
            req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
            req.ip ||
            req.socket?.remoteAddress ||
            null,
    });

    _setRefreshCookie = (res, refreshToken, expiresAt) => {
        const isProd = env.NODE_ENV === "production";
        const maxAgeMs = expiresAt
            ? Math.max(0, new Date(expiresAt).getTime() - Date.now())
            : REFRESH_TTL_SEC * 1000;

        res.cookie(REFRESH_COOKIE_NAME, refreshToken, {
            httpOnly: true,
            secure: isProd,
            sameSite: isProd ? "strict" : "lax",
            path: `${env.API_PREFIX || "/api/v1"}/dev/auth`,
            maxAge: maxAgeMs,
        });
    };

    _clearRefreshCookie = (res) => {
        const isProd = env.NODE_ENV === "production";
        res.clearCookie(REFRESH_COOKIE_NAME, {
            httpOnly: true,
            secure: isProd,
            sameSite: isProd ? "strict" : "lax",
            path: `${env.API_PREFIX || "/api/v1"}/dev/auth`,
        });
    };

    _extractRefreshToken = (req) =>
        req.cookies?.[REFRESH_COOKIE_NAME] || req.body?.refreshToken || null;

    // =========================================================================
    // 1. SIGNUP (Request OTP -> Verify OTP)
    // =========================================================================

    requestSignupOtp = async (req, res, next) => {
        try {
            const { email, password } = req.body ?? {};
            if (!email || !password) {
                throw new BadRequestError({
                    message: "Email and password are required",
                });
            }

            const result = await devAuthServices.requestSignupOtp({
                email,
                password,
            });

            return res.status(200).json({
                success: true,
                data: result,
                error: null,
            });
        } catch (err) {
            return next(err);
        }
    };

    verifySignupOtp = async (req, res, next) => {
        try {
            const { email, otp } = req.body ?? {};
            if (!email || !otp) {
                throw new BadRequestError({
                    message: "Email and OTP are required",
                });
            }

            const { userAgent, ipAddress } = this._getClientMeta(req);
            const result = await devAuthServices.verifySignupOtp({
                email,
                otp,
                userAgent,
                ipAddress,
            });

            if (result.refreshToken) {
                this._setRefreshCookie(res, result.refreshToken, result.expiresAt);
            }

            return res.status(201).json({
                success: true,
                data: {
                    developer: result.developer,
                    accessToken: result.accessToken,
                    refreshToken: result.refreshToken,
                    sessionId: result.sessionId,
                    expiresAt: result.expiresAt,
                },
                error: null,
            });
        } catch (err) {
            return next(err);
        }
    };

    // =========================================================================
    // 2. SIGNIN (Email + Password -> OTP Challenge; then Verify OTP)
    // =========================================================================

    signin = async (req, res, next) => {
        try {
            const { email, password } = req.body ?? {};
            if (!email || !password) {
                throw new BadRequestError({
                    message: "Email and password are required",
                });
            }

            const result = await devAuthServices.signin({ email, password });

            return res.status(200).json({
                success: true,
                data: result,
                error: null,
            });
        } catch (err) {
            return next(err);
        }
    };

    verifySigninOtp = async (req, res, next) => {
        try {
            const { challengeId, otp } = req.body ?? {};
            if (!challengeId || !otp) {
                throw new BadRequestError({
                    message: "Challenge ID and OTP are required",
                });
            }

            const { userAgent, ipAddress } = this._getClientMeta(req);
            const result = await devAuthServices.verifySigninOtp({
                challengeId,
                otp,
                userAgent,
                ipAddress,
            });

            if (result.refreshToken) {
                this._setRefreshCookie(res, result.refreshToken, result.expiresAt);
            }

            return res.status(200).json({
                success: true,
                data: {
                    developer: result.developer,
                    accessToken: result.accessToken,
                    refreshToken: result.refreshToken,
                    sessionId: result.sessionId,
                    expiresAt: result.expiresAt,
                },
                error: null,
            });
        } catch (err) {
            return next(err);
        }
    };

    // =========================================================================
    // 3. REFRESH & SIGNOUT
    // =========================================================================

    refresh = async (req, res, next) => {
        try {
            const refreshToken = this._extractRefreshToken(req);
            const { userAgent, ipAddress } = this._getClientMeta(req);

            const tokens = await devAuthServices.refresh({
                refreshToken,
                userAgent,
                ipAddress,
            });

            if (tokens.refreshToken) {
                this._setRefreshCookie(res, tokens.refreshToken, tokens.expiresAt);
            }

            return res.status(200).json({
                success: true,
                data: {
                    accessToken: tokens.accessToken,
                    refreshToken: tokens.refreshToken,
                    sessionId: tokens.sessionId,
                    expiresAt: tokens.expiresAt,
                },
                error: null,
            });
        } catch (err) {
            logger.debug({ err }, "Developer token refresh failed");
            return next(err);
        }
    };

    signout = async (req, res, next) => {
        try {
            const refreshToken = this._extractRefreshToken(req);
            const result = await devAuthServices.signout({ refreshToken });

            this._clearRefreshCookie(res);

            return res.status(200).json({
                success: true,
                data: result,
                error: null,
            });
        } catch (err) {
            return next(err);
        }
    };

    // =========================================================================
    // 4. FORGOT PASSWORD & RESET PASSWORD
    // =========================================================================

    forgotPassword = async (req, res, next) => {
        try {
            const { email } = req.body ?? {};
            if (!email) {
                throw new BadRequestError({
                    message: "Email is required",
                });
            }

            const result = await devAuthServices.forgotPassword({ email });

            return res.status(200).json({
                success: true,
                data: result,
                error: null,
            });
        } catch (err) {
            return next(err);
        }
    };

    resetPassword = async (req, res, next) => {
        try {
            const { email, otp, newPassword } = req.body ?? {};
            if (!email || !otp || !newPassword) {
                throw new BadRequestError({
                    message: "Email, OTP, and new password are required",
                });
            }

            const result = await devAuthServices.resetPassword({
                email,
                otp,
                newPassword,
            });

            this._clearRefreshCookie(res);

            return res.status(200).json({
                success: true,
                data: result,
                error: null,
            });
        } catch (err) {
            return next(err);
        }
    };

    // =========================================================================
    // 5. RESEND OTP
    // =========================================================================

    resendOtp = async (req, res, next) => {
        try {
            const { purpose, email, challengeId } = req.body ?? {};
            if (!purpose) {
                throw new BadRequestError({
                    message: "OTP resend purpose is required",
                });
            }

            const result = await devAuthServices.resendOtp({
                purpose,
                email,
                challengeId,
            });

            return res.status(200).json({
                success: true,
                data: result,
                error: null,
            });
        } catch (err) {
            return next(err);
        }
    };
}

export const devAuthControllers = new DevAuthControllersClass();