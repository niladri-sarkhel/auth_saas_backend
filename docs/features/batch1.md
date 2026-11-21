### batch1 features 
#### everything (refresh + access token), emailOTP based

- dev profile will have email and password only, and only one email, no contact number, no displayname, no username, no firstname, lastname, not even secondary eamil, atleast for version-1 of the app.
- so a developer will have only 2 credential : email + password
- Developer signup/signin, create app, and get development/production environment keys + allowed origins / redirect URIs

##### dev features
- signup : unique email + password, otp verfied, (email wont be registered to db unless otp is verified)
- signin : emails + password + otp (can't signin without otp)
- signout : (revoke current session/refresh token)
- Token refresh : (refresh token rotation + reuse detection) & current-user (/me) check
- otp based email and password update : 
    - email update : 
        1. change email requst is sent by dev. 
        2. an otp is sent to the existing email. 
        3. dev sends the otp to the server, then the otp is verified, 
        4. if verification is successful then a short session of 10mins is opened for the dev to change email.
        5. dev gives new email and sends a email add request. 
        6. an verification otp is sent to the new email. 
        7. dev sends the otp from the new email for email verification.
        8. if the verification is successful then the email is changed successfully, and the email change session expires due to successful email change.
        9. if 10mins deadline is reached then the email change session is also expired, then the dev needs to start the process from the beginning. 
        5. all devices are logged out, the dev needs to signin from the beginning.
    - password update : 
        1. dev gives old password.
        2. if password matches an otp is sent to email. 
        3. dev sends the otp along with the new password.
        4. if otp is matched password is changed successfully.
        5. all devices are logged out, the dev needs to signin from the beginning.
- delete account : (enters 30-day 'deleted' state and blocks access, dev can revoke the deletion process if they want)
- get own profile only, all dev account will be private only, there is no need to have a public dev account
- otp based forget-password + reset-password (invalidates active sessions)
- standard Abuse Protection: Progressive backoff/CAPTCHA challenges, login attempt tracking, and password hashing/verification policies etc.

##### dev features
- signup
- signin 
- signout
- delete account
- get own profile
- get other public profiles
- otp based forget-password + reset-password
- standard Abuse Protection: Progressive backoff/CAPTCHA challenges, login attempt tracking, and password hashing/verification policies etc.