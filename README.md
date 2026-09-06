# JWT Recon

A lightweight CLI tool for **JWT discovery, decoding, analysis, tampering, and authentication testing** during authorized web security assessments.
```
JWT  recon • decode • analyze • tamper
```

## What it does

- Logs in automatically and pulls the JWT out of the response
- Searches cookies, headers, response bodies, and redirect hops for tokens
- Decodes headers/payloads and flags common security issues
- Tests username impersonation after login
- Tampers claims and headers, including the classic `alg=none` trick
- Falls back to replaying a raw Burp/DevTools request if auto-login can't find the form

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/jwt-recon.git
cd jwt-recon
python3 jwt.py
```

## Main Menu

```
1  Login & extract JWT   (authenticate and inspect tokens)
2  Decode & analyze JWT  (inspect a token you already have)
3  Tamper JWT            (modify claims or headers)
4  Quit
```

![Main menu and login run](images/jwt-1.png)

---

## 1. Login & Extract JWT

Give it a login URL and credentials:

```
Site URL (login page): https://target.example/login
Login using: 1) Username  2) Email
Username: wiener
Password: peter
```

It handles the rest on its own: detects the password form (hidden CSRF fields included), falls back to common field names if it can't, tries both form and JSON submission, and follows redirects while keeping the session alive.

```
[+] Success on attempt 1/50
[*] Status: 200
```

![JWT found and decoded](images/jwt-2.png)

### JWT Discovery

It checks cookies, headers, response body, and every hop in the redirect chain, since a token sometimes only shows up on an intermediate `302`.

```
✓ JWT found  [cookies, headers]

Header
{ "kid": "...", "alg": "RS256" }

Payload
{ "iss": "portswigger", "exp": 1787841031, "sub": "wiener" }
```


### Username Impersonation Test

![Impersonation test results](images/jwt-3.png)

Once it has a JWT, it offers to tamper the username claim and test if the server actually checks it:

```
=== Test user impersonation via tampered JWT ===
Tamper the username claim (e.g. brxzyy -> admin) and test if it's accepted? [y/N]:
```

It auto-detects the likely claim (`sub`, `username`, `user`, `name`, `preferred_username`), sends the tampered token back the same way the original arrived (same cookie or `Authorization` header), and swaps the username into the target URL if it appears there. Then it tries two variants, original signature kept and `alg=none` with the signature stripped, and reports each as `ACCEPTED`, `MAYBE`, `REJECTED`, or `ERROR`.

```
[*] Auto-testing 2 tamper variants...
  [+] Original signature kept: ACCEPTED (status 200)
  [+] alg=none, signature stripped: ACCEPTED (status 200)
```

`MAYBE` means the response looked promising but the new username wasn't confirmed in the body, so it's worth a manual check.

---

## 2. Decode & Analyze JWT

Already have a token? Paste it in:

```
Paste JWT: eyJhbGciOiJSUzI1NiIs...
```

You get the raw token, header, payload, a signature preview, and findings like:

```
● [WARN] No 'exp' claim - token may never expire.
● [INFO] Privilege-related claim found: role = user
● [WARN] Header contains 'kid' = ...
```

Checks include `alg=none`, missing or expired `exp`, privilege-related claims, `kid`/`jku`/`x5u` injection risk, and signs of algorithm confusion.

---

## 3. Tamper JWT

```
Paste JWT to tamper:

1. Set alg to 'none' and strip signature
2. Edit a claim in the payload
3. Edit a header field
4. Re-encode as-is
```

It hands back the modified token, ready to test.

> A modified JWT isn't automatically valid. Whether the server accepts it depends on how it actually validates signatures.

---

## Request Replay

If auto-login can't find the form, replay a raw request exported from Burp Suite or browser DevTools instead:

```
Provide a raw request file (req.txt, e.g. saved from Burp/DevTools) to replay instead? [y/N]:
Path to req.txt: ./req.txt
```

It reads the method, host, headers, body, cookies, and form/JSON payload straight from the file.
