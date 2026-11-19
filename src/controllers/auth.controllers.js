// src/controllers/auth.controllers.js
import { env } from "#config";
import {
    signupSchema,
    verifyEmailSchema,
    signinSchema,
    resendOtpSchema,
} from "#validators";
import {
    signupUser,
    verifyUserEmail,
    signinUser,
    rotateRefreshToken,
    signoutUser,
    resendVerificationOtp,
} from "#services";

const REFRESH_COOKIE_NAME = "refresh_token";
const REFRESH_MAX_AGE_MS =
    Number(env.REFRESH_TTL_SECONDS || 7 * 24 * 60 * 60) * 1000;

function getCookieOptions() {
    const isProd = env.NODE_ENV === "production";
    return {
        httpOnly: true,
        secure: isProd,
        sameSite: isProd ? "none" : "lax",
        path: `${env.API_PREFIX}/auth`,
        maxAge: REFRESH_MAX_AGE_MS,
    };
}

function getClearCookieOptions() {
    const { maxAge, ...clearOpts } = getCookieOptions();
    return clearOpts;
}

function validate(schema, body) {
    const { error, value } = schema.validate(body, {
        abortEarly: false,
        stripUnknown: true,
    });
    if (error) throw error;
    return value;
}

export async function signup(req, res, next) {
    try {
        const payload = validate(signupSchema, req.body);
        const result = await signupUser({
            tenant: req.tenant,
            payload,
            ip: req.ip,
            userAgent: req.headers["user-agent"],
        });
        return res.status(201).json({ success: true, data: result });
    } catch (err) {
        next(err);
    }
}

export async function verifyEmail(req, res, next) {
    try {
        const { email, otp } = validate(verifyEmailSchema, req.body);
        const result = await verifyUserEmail({
            tenant: req.tenant,
            email,
            otp,
            ip: req.ip,
            userAgent: req.headers["user-agent"],
        });
        return res.status(200).json({ success: true, data: result });
    } catch (err) {
        next(err);
    }
}

export async function signin(req, res, next) {
    try {
        const { identifier, password } = validate(signinSchema, req.body);
        const result = await signinUser({
            tenant: req.tenant,
            identifier,
            password,
            ip: req.ip,
            userAgent: req.headers["user-agent"],
        });

        res.cookie(REFRESH_COOKIE_NAME, result.refreshToken, getCookieOptions());

        return res.status(200).json({
            success: true,
            data: {
                access_token: result.accessToken,
                token_type: "Bearer",
                expires_in: 900,
                user: result.user,
            },
        });
    } catch (err) {
        next(err);
    }
}

export async function refresh(req, res, next) {
    try {
        const rawRefreshToken = req.cookies?.[REFRESH_COOKIE_NAME];
        const result = await rotateRefreshToken({
            tenant: req.tenant,
            rawRefreshToken,
            ip: req.ip,
            userAgent: req.headers["user-agent"],
        });

        res.cookie(REFRESH_COOKIE_NAME, result.refreshToken, getCookieOptions());

        return res.status(200).json({
            success: true,
            data: {
                access_token: result.accessToken,
                token_type: "Bearer",
                expires_in: 900,
            },
        });
    } catch (err) {
        res.clearCookie(REFRESH_COOKIE_NAME, getClearCookieOptions());
        next(err);
    }
}

export async function signout(req, res, next) {
    try {
        const rawRefreshToken = req.cookies?.[REFRESH_COOKIE_NAME];
        await signoutUser({
            tenant: req.tenant,
            rawRefreshToken,
            ip: req.ip,
            userAgent: req.headers["user-agent"],
        });

        res.clearCookie(REFRESH_COOKIE_NAME, getClearCookieOptions());
        return res
            .status(200)
            .json({ success: true, data: { message: "Signed out successfully" } });
    } catch (err) {
        next(err);
    }
}

export async function resendOtp(req, res, next) {
    try {
        const { email } = validate(resendOtpSchema, req.body);
        const result = await resendVerificationOtp({ tenant: req.tenant, email });
        return res.status(200).json({ success: true, data: result });
    } catch (err) {
        next(err);
    }
}