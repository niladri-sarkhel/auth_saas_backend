// src/routes/api.v1.router.js

import express from "express";

import { testRouter } from "./test.routes.js";
import { authRouter } from "./auth.routes.js";
import { devRouter } from "./dev_routes/index.js";

export const apiV1Router = express.Router();
apiV1Router.use("/test", testRouter);
apiV1Router.use("/auth", authRouter);
apiV1Router.use("/dev", devRouter);