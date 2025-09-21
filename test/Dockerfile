# vulnerable Dockerfile for Trivy testing
FROM ubuntu:16.04

# Install outdated packages with known vulnerabilities
RUN apt-get update && \
    apt-get install -y \
    curl=7.47.0-1ubuntu2.19 \
    openssl=1.0.2g-1ubuntu4.20 \
    sudo=1.8.16-0ubuntu1.10 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Add a dummy app
RUN echo "This is a vulnerable test image" > /app.txt
