FROM mcr.microsoft.com/devcontainers/python:1-3.12-bookworm

# The upstream Python dev-container image currently carries a Yarn APT source
# whose signing key is unavailable during feature installation. VulnHunter does
# not use Yarn, so remove that source before the SSH feature runs apt-get update.
USER root
RUN rm -f \
    /etc/apt/sources.list.d/yarn.list \
    /etc/apt/sources.list.d/yarn.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl iproute2 unzip \
    && rm -rf /var/lib/apt/lists/*
