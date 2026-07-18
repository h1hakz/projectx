# Deliberately vulnerable Dockerfile for IaC (Trivy) demo
FROM node:18-alpine

# Run as root (bad practice)
USER root

# Install packages without verification
RUN apk add --no-cache curl wget && \
    curl -fsSL https://example.com/script.sh | bash

# Copy sensitive files into image
COPY SSRF/workshop-secrets.env /app/.env

WORKDIR /app

# Expose dangerous ports
EXPOSE 22 3306 27017

# Run with unnecessary privileges
CMD ["node", "server.js"]
