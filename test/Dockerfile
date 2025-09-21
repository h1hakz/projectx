# Use an old, known-vulnerable base image
FROM ubuntu:18.04

# Install a specific vulnerable version of a package, for example, curl
# This version of curl has multiple known vulnerabilities.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl=7.58.0-2ubuntu3.8 \
    && rm -rf /var/lib/apt/lists/*

CMD ["bash"]
