import nodemailer from "nodemailer";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { env } from "#config";
import { logger } from "#utils";
import { MailServiceError, MailTemplateError } from "#errors";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export class MailServiceClass {
    _transporter = nodemailer.createTransport({
        host: env.SMTP_HOST,
        port: env.SMTP_PORT,
        secure: env.SMTP_SECURE,
        auth: {
            user: env.SMTP_USER,
            pass: env.SMTP_PASS,
        },
    });

    _fromAddress = env.SMTP_FROM;
    _templatePath = path.join(__dirname, "../templates/email-template.html");
    _cachedHtml = null;

    _loadTemplate = async () => {
        if (this._cachedHtml) return this._cachedHtml;
        try {
            this._cachedHtml = await fs.readFile(this._templatePath, "utf8");
            return this._cachedHtml;
        } catch (error) {
            throw new MailTemplateError({
                message: "Critical: Mail infrastructure layout missing.",
                errors: [error.message],
            });
        }
    };

    sendEmail = async (to, otp, subject, purposeText, expiryMinutes = 5) => {
        let recipient = to;
        let mailOtp = otp;
        let mailSubject = subject;
        let mailPurpose = purposeText;
        let mailExpiryMinutes = expiryMinutes;
        let customHtml = null;

        if (typeof to === "object" && to !== null) {
            recipient = to.to;
            mailOtp = to.otp;
            mailSubject = to.subject;
            mailPurpose = to.purposeText;
            mailExpiryMinutes = to.expiryMinutes ?? 5;
            customHtml = to.html;
        }

        const appName = env.APP_NAME || "Global Marketplace";
        const currentYear = new Date().getFullYear().toString();
        const expirationDuration = `${mailExpiryMinutes} mins`;

        // 1. Calculate future expiration time using your target timezone
        const expiryDate = new Date(Date.now() + mailExpiryMinutes * 60 * 1000);
        const expirationTime = expiryDate.toLocaleTimeString("en-US", {
            timeZone: "Asia/Kolkata", // <-- Forces IST instead of UTC
            hour: "numeric",
            minute: "2-digit",
            hour12: true,
        }).toLowerCase(); // e.g., "2:27 p.m."

        let htmlToSend = customHtml;
        if (!htmlToSend) {
            const rawTemplate = await this._loadTemplate();

            // Replace all dynamic placeholders safely across the template
            htmlToSend = rawTemplate
                .replaceAll("{{APP_NAME}}", appName)
                .replaceAll("{{OTP}}", mailOtp ?? "")
                .replaceAll("{{PURPOSE_TEXT}}", mailPurpose ?? "")
                .replaceAll("{{EXPIRATION_DURATION}}", expirationDuration)
                .replaceAll("{{EXPIRATION_TIME}}", expirationTime)
                .replaceAll("{{CURRENT_YEAR}}", currentYear);
        }

        try {
            const deliveryReceipt = await this._transporter.sendMail({
                from: this._fromAddress,
                to: recipient,
                subject: mailSubject,
                html: htmlToSend,
            });

            logger.info(
                `✅ Outbound email delivered to: ${recipient} | Expires at: ${expirationTime} [ID: ${deliveryReceipt.messageId}]`,
            );

            return true;
        } catch (error) {
            throw new MailServiceError({
                message: "Unable to complete security authentication message transmission.",
                errors: [error.message],
            });
        }
    };
}

export const MailService = new MailServiceClass();