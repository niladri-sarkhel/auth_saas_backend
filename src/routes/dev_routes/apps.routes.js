// src/routes/dev_routes/apps.routes.js

import { Router } from "express";
import { resolveTenant } from "#middlewares";
import { signup, verifyEmail, signin, refresh, signout, resendOtp } from "#controllers";

export const appsRouter = Router();

appsRouter.use(resolveTenant);

appsRouter.post("/", getDevProfile);

appsRouter.get("/", getDevProfile);
appsRouter.get("/:appId", getDevProfile);

appsRouter.patch("/:appId/environments/:envId", getDevProfile);

appsRouter.post("/:appId/environments/:envId/rotate-secret", getDevProfile);