# Easy Cookie-Auth Nginx Proxy
[![Docker Image Size (latest)](https://img.shields.io/docker/image-size/mon4d/nginx-cookie-auth/latest)](https://hub.docker.com/r/mon4d/nginx-cookie-auth)
[![Docker Hub](https://img.shields.io/badge/Docker%20Hub-View%20Image-blue?logo=docker)](https://hub.docker.com/r/mon4d/nginx-cookie-auth)

A simple, secure, and lightweight reverse proxy that adds a robust authentication layer in front of any web application. This image is designed to be placed behind an existing reverse proxy (like Traefik, Caddy, or another Nginx instance) that handles SSL/TLS termination.

## Overview

This Docker image provides an Nginx-based reverse proxy that protects your backend services with a simple but effective authentication mechanism. Instead of relying on the browser to send an `Authorization` header with every request, it uses a secure, `HttpOnly` cookie. This means users log in once with their username and password, and are then authenticated for all subsequent requests until the cookie expires. It's an ideal solution for adding a quick and secure authentication gate to internal tools, dashboards, or any web service that is less trusted or lacks its own user management.

## How It Works

The authentication flow is designed to be both secure and user-friendly:

1.  **First Visit:** When a user first accesses the protected application, the proxy detects they don't have a valid authentication cookie.
2.  **HTTP Basic Auth:** The proxy challenges the user with an HTTP Basic Authentication prompt, requesting a username and password.
3.  **Set Secure Cookie:** Upon successful validation of the credentials against the configured `.htpasswd` entry, the proxy sets a secure, `HttpOnly` cookie in the user's browser. This cookie contains a secret token known only to the proxy.
4.  **Authenticated Access:** On all subsequent requests, the browser automatically sends the cookie. The proxy validates the cookie's token. If it's valid, the user is granted access without needing to log in again.
5.  **Seamless Experience:** The user remains logged in for 7 days, after which the cookie expires and they will be prompted to log in again.

This method is more secure than standard Basic Auth for web UIs because the user's credentials are only transmitted once during the initial login.

## Features

*   **Efficient Cookie-Based Auth:** Log in once and stay authenticated for 7 days.
*   **Security Hardened:**
    *   Runs as an unprivileged `nginx` user.
    *   Sets secure headers by default: `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and a configurable `Content-Security-Policy`.
    *   Uses secure cookie flags: `HttpOnly`, `Secure`, and `SameSite=Strict`.
    *   Configurable timeouts and buffer sizes to improve resilience.
*   **Highly Configurable:** All key parameters are easily configured with environment variables.
*   **Lightweight & Performant:** Built on the official `nginxinc/nginx-unprivileged:stable-alpine` image for a minimal footprint.
*   **WebSocket Support:** Seamlessly proxies WebSocket connections (`Upgrade` headers).

## Limitations and Security Considerations

It is important to understand what this image does *not* do:

*   **No SSL/TLS Termination:** This proxy does not handle HTTPS. It is **designed to run behind another reverse proxy** (e.g., Traefik, Caddy) that terminates SSL. The `Secure` flag on the cookie requires the connection to the user's browser to be HTTPS.
*   **Single Shared Cookie:** The proxy uses one secret token (`SCA_TOKEN`) for all users. This means every user who successfully logs in receives a cookie with the same value. This is ideal for a single user or a small group of trusted users sharing credentials (e.g., for a home lab). It does not provide per-user sessions.
*   **No Session Invalidation:** If an attacker steals a valid authentication cookie, they can use it to access the application until the cookie expires (after 7 days) or the `SCA_TOKEN` is changed on the server. There is no mechanism to remotely log out a specific session.

## Quick Start (`docker-compose`)

This example shows how to place the `nginx-cookie-auth` proxy in front of a web application within a Docker network.

Save this as `docker-compose.yml`:

```yaml
version: '3.8'

services:
  nginx-cookie-auth:
    image: mon4d/nginx-cookie-auth:latest
    container_name: nginx-cookie-auth
    restart: unless-stopped
    # By design, ports are not exposed to the host.
    # Access should be managed by your main reverse proxy (e.g. Traefik, Caddy, or another Nginx instance).
    # For quick testing, you can uncomment the ports section below.
    # ports:
    #   - "8080:8080"
    environment:
      # --- Required ---
      # Generate with: htpasswd -nbB testuser testpassword
      - HTPASSWD=testuser:$$apr1$$D7q61h1b$$C8v6bB5gYJGpMRwIu.oud/
      # Generate with: openssl rand -hex 32
      - SCA_TOKEN=_a_very_secret_and_long_random_string_change_me_
      
      # --- Target Service ---
      # If on the same docker network, use the container-name and port.
      - FORWARD_HOST=webapp
      - FORWARD_PORT=80
      
      # --- Optional Hardening ---
      # - CLIENT_MAX_BODY_SIZE=32m
      # - MAX_BUFFER_SIZE=16k
      # - TIMEOUT=60
      # - CONTENT_SECURITY_POLICY="default-src 'self'; frame-ancestors 'self'; form-action 'self';"
    depends_on:
      - webapp

  # Example web app to be protected:
  webapp:
    image: nginxdemos/hello:plain-text
    container_name: webapp
    restart: unless-stopped

```

**To run this stack:**

1.  Generate and replace the `HTPASSWD` and `SCA_TOKEN` values in the file.
2.  Start the services: `docker-compose up -d`.
3.  **Recommended Setup:** Configure your main reverse proxy (e.g. Traefik, Caddy, or another Nginx instance) to forward traffic for your desired domain to `http://nginx-cookie-auth:8080`.
4.  **For Quick Local Testing:** If you don't have a main reverse proxy, uncomment the `ports` section in `docker-compose.yml` and run `docker-compose up -d` again. You can then access the service at `http://localhost:8080` (though you will see browser warnings about the `Secure` cookie flag on an insecure connection).

## Generating Credentials

You must provide two secret values for the proxy to operate.

#### HTPASSWD

This variable holds the username and hashed password. Use `htpasswd` to generate it.

```bash
# The -n flag prints to stdout, -b runs in batch mode, -B uses bcrypt (recommended)
htpasswd -nbB myuser mypassword123
# Output: myuser:$2y$05$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Copy the entire output string and use it as the value for the `HTPASSWD` environment variable.

#### SCA_TOKEN

This is the secret value for the authentication cookie. It should be a long, random string.

```bash
openssl rand -hex 32
# Output: a1b7c3d9e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1
```

## Future Roadmap

This image is designed for simplicity. I encourage you to review the source code on my **[GitHub page](https://github.com/mon4d/nginx-cookie-auth)** to see how everything fits together.

Future enhancements may include:

*   **Configurable Cookie Lifetime:** An environment variable (`SCA_TOKEN_MAX_AGE`) to allow customization of the cookie's expiration time, which is currently hardcoded to 7 days.
*   **Per-User Sessions:** A more advanced (and complex) implementation could generate unique session tokens for each user, allowing for individual session invalidation.

## Configuration

All configuration is managed via environment variables.

| Variable                  | Description                                                                                             | Default Value            |
| ------------------------- | ------------------------------------------------------------------------------------------------------- | ------------------------ |
| `HTPASSWD`                | **(Required)** The htpasswd entry for authentication. Format: `user:hashed_password`.                   | `(none)`                 |
| `SCA_TOKEN`               | **(Required)** The secret token for the authentication cookie. Should be a long, random string.         | `(none)`                 |
| `FORWARD_HOST`            | The hostname or container name of the upstream service to proxy requests to.                            | `web`                    |
| `FORWARD_PORT`            | The port of the upstream service.                                                                       | `80`                     |
| `CLIENT_MAX_BODY_SIZE`    | The maximum allowed size of the client request body. Useful for file uploads.                           | `256m`                   |
| `TIMEOUT`                 | A general timeout in seconds for proxy, send, and client operations.                                    | `60`                     |
| `MAX_BUFFER_SIZE`         | The buffer size for client request body and headers.                                                    | `16k`                    |
| `CONTENT_SECURITY_POLICY` | The `Content-Security-Policy` header value. Set to `""` to disable. A sane default is recommended.      | `""` (empty)             |

## Inspired by

*   [https://github.com/beevelop/docker-nginx-basic-auth](https://github.com/beevelop/docker-nginx-basic-auth)
*   [https://gist.github.com/eatnumber1/92e94086dafc7194077df4a6b45b2b75](https://gist.github.com/eatnumber1/92e94086dafc7194077df4a6b45b2b75)
