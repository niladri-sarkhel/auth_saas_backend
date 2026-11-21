// src/routes/dev_routes/index.js

import express from "express";

import { testRouter } from "./test.routes.js";
import { authRouter } from "./auth.routes.js";
// import { meRouter } from "./me.routes.js";
// import { appsRouter } from "./apps.routes.js";

export const devRouter = express.Router();
devRouter.use("/test", testRouter);
devRouter.use("/auth", authRouter);
// devRouter.use("/me", meRouter);
// devRouter.use("/apps", appsRouter);