// app.js

import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import helmet from "helmet";

import { env } from "#config";
import { apiV1Router } from "#routes";
import { handleReqErrors, NotFoundError } from "#errors";
import { requestLogger, getPublicJWKS } from "#utils";


console.log(env);

export const app = express();
app
    .use(helmet())
    .use(cors())
    .use(requestLogger)
    .use(express.json())
    .use(express.urlencoded({ extended: true }))
    .use(cookieParser())
    // Standard root-level JWKS discovery endpoint (cached by client SDKs/backends)
    .get("/.well-known/jwks.json", async (_req, res, next) => {
        try {
            const jwks = await getPublicJWKS();
            res.set("Cache-Control", "public, max-age=3600");
            return res.status(200).json(jwks);
        } catch (err) {
            next(err);
        }
    })
    .use("/api/v1", apiV1Router)
    .use((req, _res, next) => {
        next(
            new NotFoundError({
                message: `Route [${req.method}] ${req.path} not found`,
            }),
        );
    })
    .use(handleReqErrors);
