// src/config/redis.config.js
import Redis from "ioredis";
import { env } from "./env.config.js";
import { logger } from "#utils";

export const redis = new Redis({
    host: env.REDIS_HOST,
    port: Number(env.REDIS_PORT),
    password: env.REDIS_PASSWORD || undefined,
    maxRetriesPerRequest: 3,
    enableReadyCheck: true,
    lazyConnect: true,
    retryStrategy(times) {
        if (times > 10) {
            logger.error("Redis retry limit reached, giving up");
            return null;
        }
        const delay = Math.min(times * 200, 3000);
        return delay;
    },
});

redis.on("connect", () => {
    logger.info("⏳ Connecting to Redis...");
});

redis.on("ready", () => {
    logger.info("✅ Redis connected successfully");
});

redis.on("error", (err) => {
    logger.error({ err }, "Redis connection error");
});

redis.on("close", () => {
    logger.warn("Redis connection closed");
});

export async function connectRedis() {
    if (redis.status === "wait") {
        await redis.connect();
    }
}

export async function disconnectRedis() {
    if (redis.status !== "end") {
        await redis.quit();
    }
}