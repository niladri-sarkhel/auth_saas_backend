// src/routes/dev_routes/auth.routes.js

import { Router } from "express";
import { devAuthControllers } from "#controllers";

export const authRouter = Router();

authRouter.post("/signup/request-otp", devAuthControllers.requestSignupOtp);
authRouter.post("/signup/verify-otp", devAuthControllers.verifySignupOtp);

authRouter.post("/signin/request-otp", devAuthControllers.signin);
authRouter.post("/signin/verify-otp", devAuthControllers.verifySigninOtp);

authRouter.post("/refresh", devAuthControllers.refresh);

authRouter.post("/signout", devAuthControllers.signout);

authRouter.post("/forgot-password", devAuthControllers.forgotPassword);
authRouter.post("/reset-password", devAuthControllers.resetPassword);

authRouter.post("/resend-otp", devAuthControllers.resendOtp);
