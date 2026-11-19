// src/routes/auth.routes.js
import { Router } from "express";
import { resolveTenant } from "#middlewares";
import { signup, verifyEmail, signin, refresh, signout, resendOtp } from "#controllers";

export const authRouter = Router();

authRouter.use(resolveTenant);

authRouter.post("/signup", signup);
authRouter.post("/verify-email", verifyEmail);
authRouter.post("/signin", signin);
authRouter.post("/refresh", refresh);
authRouter.post("/signout", signout);
authRouter.post("/resend-otp", resendOtp);
