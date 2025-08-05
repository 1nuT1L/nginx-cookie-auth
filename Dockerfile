# Using the official nginx image
FROM nginxinc/nginx-unprivileged:stable-alpine

#Not sure why I would need the following yet:
#USER root
#ARG DOCROOT=/usr/share/nginx/html
#COPY --chown=nobody:nobody . ${DOCROOT}
#RUN find ${DOCROOT} -type d -print0 | xargs -0 chmod 755 && \
#    find ${DOCROOT} -type f -print0 | xargs -0 chmod 644 && \
#    chmod 755 ${DOCROOT}

USER root

# Install gettext for envsubst
# RUN apk add --no-cache gettext

# Copy nginx configuration and startup script
COPY default.conf.template /etc/nginx/conf.d/default.conf.template
COPY start.sh /start.sh

# Make start script executable
RUN chmod +x /start.sh

USER nginx

# Expose port 8080
EXPOSE 8080

# Set default environment variables
ENV FORWARD_HOST=web
ENV FORWARD_PORT=80
# ENV HTPASSWD='foo:$apr1$odHl5EJN$KbxMfo86Qdve2FH4owePn.'
# ENV SCA_TOKEN=a_very_secret_token

# --- CONFIGURABLE HARDENING SETTINGS ---
# Generous default to allow big uploads (tweak according to your web-app)
ENV CLIENT_MAX_BODY_SIZE=256m
# In seconds
ENV TIMEOUT=60
ENV MAX_BUFFER_SIZE=16k
ENV CONTENT_SECURITY_POLICY=""

# Set the entrypoint
ENTRYPOINT ["/start.sh"]
