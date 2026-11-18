// app.js

import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";

import { env } from "#config";
import { apiV1Router } from "#routes";
import { handleReqErrors, NotFoundError } from "#errors";
import { requestLogger } from "#utils";


// console.log(env);

export const app = express();
app
    .use(cors())
    .use(requestLogger)
    .use(express.json())
    .use(express.urlencoded({ extended: true }))
    .use(cookieParser())
    .use(env.API_PREFIX, apiV1Router)
    .use((req, _res, next) => {
        next(
            new NotFoundError({
                message: `Route [${req.method}] ${req.path} not found`,
            }),
        );
    })
    .use(handleReqErrors);
