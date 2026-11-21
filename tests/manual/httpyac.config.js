// httpyac.config.js
async function extractEmailOTP(url = "http://localhost:8025/api/v1/message/latest") {
    const res = await fetch(url);
    if (!res.ok) {
        throw new Error(`Mailpit request failed: ${res.status}`);
    }

    const data = await res.json();
    const match = data?.Text?.match(/verification code is (\d{6})/i);
    if (!match) {
        throw new Error("Verification code not found in latest email");
    }

    return match[1];
}

// Make available in JS script blocks ({{ ... }}) as well as variable hooks
globalThis.extractEmailOTP = extractEmailOTP;

export default {
    cookieJarEnabled: true,
    configureHooks(api) {
        api.hooks.provideVariables.addHook("extractEmailOTP", async () => ({
            extractEmailOTP,
        }));
    },
};