// src/routes/dev_routes/me.routes.js

import { Router } from "express";
import { resolveTenant } from "#middlewares";
import { signup, verifyEmail, signin, refresh, signout, resendOtp } from "#controllers";

export const meRouter = Router();

meRouter.use(resolveTenant);

meRouter.get("/", getDevProfile);

meRouter.post("/email/request-otp", signup);
meRouter.post("/email/verify-current-otp", signup);
meRouter.post("/email/request-new-otp", signup);
meRouter.post("/email/verify-new-otp", signup);

meRouter.post("/password/request-otp", signup);
meRouter.post("/password/update", signup);

meRouter.post("/delete", getDevProfile);
meRouter.post("/delete/cancel", getDevProfile);

meRouter.post("/resend-otp", resendOtp);