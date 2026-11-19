// src/validators/auth.validators.js

import Joi from "joi";

const usernameRule = Joi.string()
    .trim()
    .min(3)
    .max(30)
    .pattern(/^[a-zA-Z0-9_]+$/)
    .messages({
        "string.pattern.base": "Username can only contain letters, numbers, and underscores",
    });

export const signupSchema = Joi.object({
    email: Joi.string().trim().lowercase().email().max(255).required(),
    password: Joi.string().min(8).max(128).required(),
    username: usernameRule.optional(),
    first_name: Joi.string().trim().max(100).optional(),
    last_name: Joi.string().trim().max(100).optional(),
});

export const verifyEmailSchema = Joi.object({
    email: Joi.string().trim().lowercase().email().required(),
    otp: Joi.string().trim().length(6).pattern(/^\d+$/).required(),
});

export const signinSchema = Joi.object({
    identifier: Joi.string().trim().min(3).max(255).required(), // Accepts email OR username
    password: Joi.string().min(1).max(128).required(),
});

export const resendOtpSchema = Joi.object({
    email: Joi.string().trim().lowercase().email().required(),
});