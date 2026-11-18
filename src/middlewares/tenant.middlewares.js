// src/middlewares/tenant.middleware.js

import { pool, redis } from '#config';

export async function resolveTenant(req, res, next) {
    try {
        const publishableKey = req.headers['x-publishable-key'];
        if (!publishableKey || typeof publishableKey !== 'string') {
            return res.status(401).json({ error: 'Missing x-publishable-key header' });
        }

        const cacheKey = `tenant:pk:${publishableKey}`;
        let tenant = null;

        const cached = await redis.get(cacheKey);
        if (cached) {
            tenant = JSON.parse(cached);
        } else {
            const { rows } = await pool.query(
                `SELECT ae.id AS env_id, ae.application_id, ae.env_type,
                ae.allowed_origins, ae.redirect_uris, ae.auth_config
         FROM app_environments ae
         JOIN applications a ON a.id = ae.application_id
         WHERE ae.publishable_key = $1 AND a.deleted_at IS NULL`,
                [publishableKey]
            );

            if (rows.length === 0) {
                return res.status(401).json({ error: 'Invalid publishable key' });
            }

            tenant = rows[0];
            await redis.set(cacheKey, JSON.stringify(tenant), 'EX', 300);
        }

        // Origin validation (when browser sends Origin header)
        const origin = req.headers.origin;
        if (origin && tenant.allowed_origins.length > 0 && !tenant.allowed_origins.includes(origin)) {
            return res.status(403).json({ error: 'Origin not allowed for this application' });
        }

        req.tenant = tenant;
        next();
    } catch (err) {
        next(err);
    }
}