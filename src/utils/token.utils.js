// src/utils/token.utils.js
import crypto from 'node:crypto';
import { SignJWT, jwtVerify, generateKeyPair, exportJWK } from 'jose';

// In production, load PEM keys from env/secrets manager so restarts don't rotate keys unexpectedly
let keyPairPromise = generateKeyPair('RS256');
const KEY_ID = 'auth-saas-key-1';

export async function getPublicJWKS() {
    const { publicKey } = await keyPairPromise;
    const jwk = await exportJWK(publicKey);
    return {
        keys: [{ ...jwk, kid: KEY_ID, alg: 'RS256', use: 'sig' }],
    };
}

export async function signAccessToken({ userId, sessionId, envId, applicationId, email }) {
    const { privateKey } = await keyPairPromise;
    return new SignJWT({
        sid: sessionId,
        env_id: envId,
        app_id: applicationId,
        email,
    })
        .setProtectedHeader({ alg: 'RS256', kid: KEY_ID })
        .setSubject(userId)
        .setIssuedAt()
        .setIssuer('auth_saas')
        .setAudience(applicationId)
        .setExpirationTime('15m')
        .sign(privateKey);
}

export async function verifyAccessToken(token) {
    const { publicKey } = await keyPairPromise;
    const { payload } = await jwtVerify(token, publicKey, { issuer: 'auth_saas' });
    return payload;
}

export function generateRefreshToken() {
    const rawToken = crypto.randomBytes(48).toString('base64url');
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    return { rawToken, tokenHash };
}

export function hashToken(rawToken) {
    return crypto.createHash('sha256').update(rawToken).digest('hex');
}