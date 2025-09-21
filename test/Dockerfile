# Vulnerable Dockerfile example for Trivy demo

# 1. Use an outdated, vulnerable base image
FROM ubuntu:16.04

# 2. Install packages with known CVEs and without version pinning
RUN apt-get update && \
    apt-get install -y \
    openssl \
    apache2 \
    libssl1.0.0 \
    wget \
    curl \
    vim \
    && rm -rf /var/lib/apt/lists/*

# 3. Run as root (bad practice)
USER root

# 4. Expose port
EXPOSE 80

# 5. Start apache2 in foreground
CMD ["/usr/sbin/apache2ctl", "-D", "FOREGROUND"]
