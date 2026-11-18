// src/routes/auth.routes.js
import { Router } from "express";
import { resolveTenant } from "#middlewares";
import * as authController from "#controllers";

export const authRouter = Router();

authRouter.use(resolveTenant);

// authRouter.post("/signup", authController.signup);
// authRouter.post("/verify-email", authController.verifyEmail);
// authRouter.post("/signin", authController.signin);
// authRouter.post("/refresh", authController.refresh);
// authRouter.post("/signout", authController.signout);