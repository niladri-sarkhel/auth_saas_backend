# user profile data
## public
- first_name, last_name
- display_name
- profile_picture, cover_picture
- username (public, Unique per app)
- designation
- about / bio
- location : state, country (locale & timezone)
- account_created_at : System-generated
- contact_number
- contact_email
- portfolio_link
- social_links : max 10 
- profile_url
- date_of_birth : optional
- pronouns : optional
- account_status : active / disabled / suspended / deleted
- activity_status : short text, supports emoji, max length of text 200.
- last_active : time stamp (minutes/hours ago, or if >= 24 hours, last active on DD/MM/YYYY)
- profile_visibility : public / private
- verified_badge
- accent_color
- theme_preference
- public_metadata (JSONB)

## private
- immutable id (UUID) & application_id (UUID)
- primary_email : max 1
- secondary_email : max 1
- recovery_email : max 1
- hashed_password
- MFA status
- Authenticator devices
- Passkeys
- Backup codes
- Active sessions
- Login history
- Connected accounts
- Recovery methods
- Security notifications
- private_metadata (JSONB)

# signup
- create account with unique email and password
- email is immediately verified by email based OTP / magic link
- or signup using social providers like google, github, facebook : continue with google / github
- once email is verified (via otp or social provider), create a unique (per application) public username : optional or mandatory based on the client application 
- or signup using passkey : instead of typing a password, the user enters their email or username and clicks "Create a passkey." Their device (phone, laptop, or password manager) generates a cryptographic public/private key pair, prompts for biometrics or a device PIN, and sends the public key to your server to create the account.
- user can later add phone numebr (unique per application) later once signed up in the user profile section. initially phone number is not required to signup. then the user can verify the added phone number using email based otp (i cant afford sms based subscription, so i will be using free email based otps). 

# signin
- simple (email / username / phone number) + password based, no otp
- or simple (email / username / phone number) + otp, no password required
- or simple (email / username / phone number) + magic link, no password required
- or standard (email / username / phone number) + password then otp sent to the email, fist the password is requierd, then if the password matches an otp is sent to the email.
- or signin using social providers like google, github, facebook : continue with google / github
- or signin using authenticator apps using TOTP.
- or signin using passkeys.
- or signin using backup codes.

# signout & centralized session management
- List all active sessions with proper Device information (Browser, OS, IP where available)
- Identify current device/session
- Revoke individual sessions
- revoke(signout) current session.
- Revoke all sessions except the current one.
- Revoke all sessions.
- complete signin history logs

# user profile management
- updating email / phone number / password keeps the current session active, revoke all other sessions immediately, and rotate the current session's token. For voluntary password updates in settings, the user gets a checkbox that is checked by default: ☑️ "Sign out of all other devices"
- updating username does not revoke any session, but it has itw own rules : 
    - the username can be changed once in every 90 days
    - usernames needs to be case insensitive 
    - Temporary Hold / Cooldown (90 days): Place the old username in a reserved/locked state for 90 days so only the original owner can reclaim it if they change their mind, preventing bots from instantly sniping famous handles.
    - Profile Redirects vs. Hard Release: During that hold period (or permanently, like GitHub), either show a "Username changed" notice or redirect /oldname to /newname until the cooldown expires.
- user can enable / disable MFA

# account recovery
- MFA based forget password, reset password
- Global Session Invalidation: Automatically revoke all active sessions and refresh tokens the moment a password is changed so an attacker who already stole a session gets kicked out. 
- Security Notifications: Send a confirmation email to the user's address notifying them that their password was just changed.
- No Account Enumeration: Always show a generic message like "If that email exists, a reset link has been sent" with consistent response times so attackers cannot probe which emails are registered.

# account security & abuse protection
- Password hashing: Use a suitable password hashing algorithm
- Token verification: use the hybrid approach, use short-lived JWT access tokens (e.g., 15 minutes) paired with Refresh Token Rotation (invalidating old refresh tokens upon use and detecting token reuse).
- Account lockout: use progressive delays (exponential backoff) or CAPTCHA challenges rather than hard lockouts, which attackers can exploit to lock out legitimate users (Denial of Service).
- Email enumeration protection: Avoid exposing registered accounts
- Audit events: Record security-sensitive actions
- Secure cookies: HttpOnly, Secure, SameSite
- CSRF protection: Protect cookie-based authentication
- Rate limiting: Prevent abuse and brute-force attacks
- Login attempt tracking: Detect repeated failed attempts
- Origin validation: Restrict unauthorized application origins

# Developer dashboard and application management
- Developer registration : Developers can create accounts
- Application registration : Create and manage applications
- Application credentials : Unique credentials per application
- Environment separation : Development and production
- Allowed origins : Configure permitted domains
- Redirect URLs : Configure OAuth callback URLs
- Auth method configuration : Enable/disable login methods
- MFA configuration : Configure supported MFA methods
- User management : View and manage application users
- Session management : View and revoke application sessions
- Application deletion : Delete an application safely

# integration APIs
- authentication APIs
- User and session APIs
- javascript sdk 