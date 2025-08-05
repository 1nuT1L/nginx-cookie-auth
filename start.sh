#!/bin/sh
set -e # Exit immediately if a command exits with a non-zero status.

# --- Security Checks ---
# Check for required environment variables
if [ -z "$HTPASSWD" ] || [ -z "$SCA_TOKEN" ]; then
  echo "FATAL: HTPASSWD and SCA_TOKEN environment variables must be set."
  exit 1
fi

# Create htpasswd file
echo "${HTPASSWD}" > /etc/nginx/.htpasswd

# Calculated value for keepalive_timeout
KEEPALIVE_VALUE=$(($TIMEOUT + 5))
export TIMEOUT_KEEPALIVE_CALC=${KEEPALIVE_VALUE}

# Substitute environment variables in the nginx config template
VARS_TO_SUBSTITUTE="\
  \${FORWARD_HOST} \
  \${FORWARD_PORT} \
  \${SCA_TOKEN} \
  \${CLIENT_MAX_BODY_SIZE} \
  \${CONTENT_SECURITY_POLICY} \
  \${TIMEOUT} \
  \${MAX_BUFFER_SIZE} \
  \${TIMEOUT_KEEPALIVE_CALC}"
envsubst "${VARS_TO_SUBSTITUTE}" < /etc/nginx/conf.d/default.conf.template > /etc/nginx/conf.d/default.conf

echo "--- Nginx configuration generated ---"
echo "Max Client Body Size: ${CLIENT_MAX_BODY_SIZE}"
echo "Max Buffer Size: ${MAX_BUFFER_SIZE}"
echo "Timeout: ${TIMEOUT}s"
echo "Keepalive Timeout: ${TIMEOUT_KEEPALIVE_CALC}s"
echo "Content Security Policy: ${CONTENT_SECURITY_POLICY}"
echo "------------------------------------"

# Start nginx
nginx -g 'daemon off;'
