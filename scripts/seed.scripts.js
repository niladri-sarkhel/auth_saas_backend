// scripts/seed.js

import bcrypt from 'bcrypt';
import crypto from 'node:crypto';
import { pool } from '#config'; // adjust to your pg pool export

async function seed() {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const devHash = await bcrypt.hash('DevPass123!', 12);
        const devRes = await client.query(
            `INSERT INTO developers (email, password_hash, name, is_verified)
       VALUES ($1, $2, $3, true)
       ON CONFLICT (email) DO UPDATE SET name = EXCLUDED.name
       RETURNING id`,
            ['dev@local.test', devHash, 'Local Developer']
        );
        const developerId = devRes.rows[0].id;

        const appRes = await client.query(
            `INSERT INTO applications (developer_id, name, slug, description)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (developer_id, slug) DO UPDATE SET name = EXCLUDED.name
       RETURNING id`,
            [developerId, 'Test Client App', 'test-client-app', 'Local development tenant']
        );
        const applicationId = appRes.rows[0].id;

        const rawSecret = 'sk_test_local_01';
        const secretHash = crypto.createHash('sha256').update(rawSecret).digest('hex');

        await client.query(
            `INSERT INTO app_environments (
         application_id, env_type, publishable_key, secret_key_hash, secret_key_prefix, allowed_origins
       )
       VALUES ($1, 'development', $2, $3, $4, $5)
       ON CONFLICT (application_id, env_type) DO UPDATE
       SET publishable_key = EXCLUDED.publishable_key,
           secret_key_hash = EXCLUDED.secret_key_hash`,
            [
                applicationId,
                'pk_test_local_01',
                secretHash,
                'sk_test_local_',
                ['http://localhost:3000', 'http://localhost:5173'],
            ]
        );

        await client.query('COMMIT');
        console.log('✅ Seeded test tenant: pk_test_local_01 / sk_test_local_01');
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('❌ Seed failed:', err);
    } finally {
        client.release();
        await pool.end();
    }
}

seed();