#!/usr/bin/env python3
"""Log into Rauthy the way the login page does (session -> PoW -> authorize -> token).

Usage: rv_login.py <api_url> <email> <password> <out_session.json>
Writes {"cookie", "csrf", "access_token", "id_token", "code"} so `rv api` can call the
admin API with the same session cookie + x-csrf-token the browser UI uses.
Prints each step and its HTTP status; exits non-zero on the first failure.
"""
import base64, hashlib, http.client, json, secrets, sys, urllib.parse


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def solve_pow(challenge: str) -> str:
    # spow v1: "1:<difficulty>:<exp>:<salt>:<challenge>:" + counter, sha256 must start
    # with <difficulty> zero bits (see spow::pow::Pow::work).
    difficulty = int(challenge[2:4])
    counter = 0
    while True:
        h = int.from_bytes(hashlib.sha256(f"{challenge}{counter}".encode()).digest(), "big")
        if h >> (256 - difficulty) == 0:
            return f"{challenge}{counter}"
        counter += 1


def req(conn, method, path, body=None, headers=None, form=False):
    headers = dict(headers or {})
    data = None
    if body is not None:
        if form:
            data = urllib.parse.urlencode(body)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            data = json.dumps(body)
            headers["Content-Type"] = "application/json"
    conn.request(method, path, body=data, headers=headers)
    res = conn.getresponse()
    raw = res.read()
    print(f"HTTP {res.status} {method} {path}", file=sys.stderr)
    return res, raw


def main():
    api, email, password, out = sys.argv[1:5]
    u = urllib.parse.urlparse(api)
    conn = http.client.HTTPConnection(u.hostname, u.port)
    base = u.path.rstrip("/")
    redirect_uri = f"{api.rstrip('/')}/oidc/callback"

    res, raw = req(conn, "POST", f"{base}/oidc/session")
    if res.status not in (200, 201):
        sys.exit(f"session init failed: {raw[:300]!r}")
    cookie = res.getheader("Set-Cookie").split(";", 1)[0]
    csrf = json.loads(raw)["csrf_token"]

    res, raw = req(conn, "POST", f"{base}/pow")
    pow_solved = solve_pow(raw.decode())

    verifier = b64url(secrets.token_bytes(48))
    challenge = b64url(hashlib.sha256(verifier.encode()).digest())
    login = {
        "email": email, "password": password, "pow": pow_solved,
        "client_id": "rauthy", "redirect_uri": redirect_uri,
        "nonce": b64url(secrets.token_bytes(12)),
        "code_challenge": challenge, "code_challenge_method": "S256",
    }
    hdr = {"Cookie": cookie, "x-csrf-token": csrf}
    query = urllib.parse.urlencode({
        "client_id": "rauthy", "redirect_uri": redirect_uri, "response_type": "code",
        "code_challenge": challenge, "code_challenge_method": "S256",
    })
    res, raw = req(conn, "POST", f"{base}/oidc/authorize?{query}", login, hdr)
    if res.status != 202:
        sys.exit(f"login failed ({res.status}): {raw[:300]!r}")
    loc = urllib.parse.urlparse(res.getheader("Location"))
    code = urllib.parse.parse_qs(loc.query)["code"][0]

    res, raw = req(conn, "POST", f"{base}/oidc/token", {
        "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
        "client_id": "rauthy", "code_verifier": verifier,
    }, form=True)
    if res.status != 200:
        sys.exit(f"token exchange failed ({res.status}): {raw[:300]!r}")
    ts = json.loads(raw)

    with open(out, "w") as f:
        json.dump({"email": email, "cookie": cookie, "csrf": csrf, "code": code,
                   "access_token": ts["access_token"], "id_token": ts.get("id_token")}, f)
    print(f"logged in as {email}; session saved to {out}")


if __name__ == "__main__":
    main()
