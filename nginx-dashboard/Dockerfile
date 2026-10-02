FROM node:22-alpine

# Install git and openssh-client (for HTTPS and SSH repo access)
RUN apk add --no-cache git openssh-client tzdata

WORKDIR /app

# Version info — injected at build time by CI
ARG APP_VERSION="dev"
ARG APP_REVISION=""
ARG APP_CREATED=""

# OCI standard labels
LABEL org.opencontainers.image.version="${APP_VERSION}"
LABEL org.opencontainers.image.revision="${APP_REVISION}"
LABEL org.opencontainers.image.created="${APP_CREATED}"
LABEL org.opencontainers.image.title="nginx-reverse-proxy-dashboard"
LABEL org.opencontainers.image.source="https://forge.rdr-it.com/Dockerfiles/nginx-reverse-proxy-dashboard"

# Version visible at runtime — read directly by lib/config.js (VERSION),
# which is what the dashboard displays (header badge, window.DASHBOARD_VERSION,
# GET /api/status) and compares against DASHBOARD_VERSION_URL below.
ENV APP_VERSION=${APP_VERSION}

# Fix (audit report, Basse/Analyzer, "aucune variable TZ dans les Dockerfiles
# et le compose" — applies to the whole suite, not just the analyzer): local
# wall-clock time shows up in several places here too (backup/export
# filenames stamped with a local time, the digest's scheduled send time,
# GoAccess's own report). `tzdata` is installed unconditionally above so any
# IANA zone name resolves; `TZ` itself defaults to empty (UTC, the previous
# implicit behavior — nothing changes for an operator who does not set it)
# and is meant to be overridden per deployment, e.g.
# `environment: TZ=Europe/Paris` in docker-compose.yml — see README.md.
ARG TZ=""
ENV TZ=${TZ}

# ─── Version check URLs ───────────────────────────────────────────────────────
# Plain-text files containing the latest version string (e.g. "11.0.0")
# Set at build time via --build-arg, overridable at runtime via .env
ARG DASHBOARD_VERSION_URL=""
ARG NGINX_VERSION_URL=""
ENV DASHBOARD_VERSION_URL=${DASHBOARD_VERSION_URL}
ENV NGINX_VERSION_URL=${NGINX_VERSION_URL}

# ─── Reference configuration sync ─────────────────────────────────────────────
# Forgejo/Gitea repository dedicated to the reference conf/sites/snippets/streams
# files (see the "Sync fichiers de reference" section of the README). Baked in
# here so a built image ships with a working default source, same as the
# version-check URLs above; still overridable at runtime via .env.
ARG SYNC_REF_URL=""
ENV SYNC_REF_URL=${SYNC_REF_URL}

# ─── Changelog (page Systeme) ──────────────────────────────────────────────────
# Raw URL of this project's CHANGELOG.md (e.g. a raw.githubusercontent.com,
# Forgejo/Gitea "raw" link) — powers the "Changelog" button on the System
# page (v12.41.0, retour utilisateur). Not baked into the image (it lives in
# the repo, next to the code, and changes on every version) — fetched live,
# same override rule as DASHBOARD_VERSION_URL/SYNC_REF_URL above: set here at
# build time, still overridable at runtime via .env.
ARG CHANGELOG_URL=""
ENV CHANGELOG_URL=${CHANGELOG_URL}

# ─── Message important / alertes distantes (page Systeme) ──────────────────────
# Raw URL of a Markdown file of "important messages" (planned maintenance, an
# ongoing incident, an announcement...) — v12.45.0, retour utilisateur. Same
# override rule as CHANGELOG_URL above: settable at build time, still
# overridable at runtime via .env. Empty by default: no outbound request, no
# possible alert until an operator sets it. ALERTING_ENABLE is a SEPARATE
# opt-in switch (also overridable via config/features.yml) — an operator can
# bake this URL into a shared base image and still have each instance decide
# for itself whether to actually poll it, without touching the URL.
ARG ALERTING_URL=""
ENV ALERTING_URL=${ALERTING_URL}
ARG ALERTING_ENABLE=""
ENV ALERTING_ENABLE=${ALERTING_ENABLE}
ARG ALERTING_POLL_INTERVAL_MIN="60"
ENV ALERTING_POLL_INTERVAL_MIN=${ALERTING_POLL_INTERVAL_MIN}

# ─── Analyzer default image ────────────────────────────────────────────────────
# Default container_image used for the analyzer when analyzer.yml doesn't set
# one. Unlike the other managed containers (certbot, geoipupdate, error-pages),
# which all point at a public third-party image, the analyzer is this
# project's own image (nginx-analyzer/) — set at build time to match wherever
# you push your own build, still overridable at runtime via .env.
ARG ANALYZER_DEFAULT_IMAGE="forge.rdr-it.com/dockerfiles/nginx-analyzer:latest"
ENV ANALYZER_DEFAULT_IMAGE=${ANALYZER_DEFAULT_IMAGE}
# Conteneur du challenge navigateur (v12.63.0) : image maison nginx-challenge et
# image Anubis. Memes regles que ci-dessus : fixables au build, surchargeables a
# l'execution, et config/challenge.yml (container_image) reste prioritaire.
ARG CHALLENGE_DEFAULT_IMAGE="forge.rdr-it.com/dockerfiles/nginx-challenge:latest"
ENV CHALLENGE_DEFAULT_IMAGE=${CHALLENGE_DEFAULT_IMAGE}
ARG ANUBIS_DEFAULT_IMAGE="ghcr.io/techarohq/anubis:latest"
ENV ANUBIS_DEFAULT_IMAGE=${ANUBIS_DEFAULT_IMAGE}

# ─── Branding ─────────────────────────────────────────────────────────────────
ARG BRANDING_KOFI=""
ARG BRANDING_KOFI_LABEL="Support on Ko-fi"
ARG BRANDING_SITE=""
ARG BRANDING_SITE_LABEL=""
ARG BRANDING_REPO=""
ARG BRANDING_REPO_LABEL="Source repository"
ARG BRANDING_DOC=""
ARG BRANDING_DOC_LABEL="Documentation"

ENV BRANDING_KOFI=${BRANDING_KOFI}
ENV BRANDING_KOFI_LABEL=${BRANDING_KOFI_LABEL}
ENV BRANDING_SITE=${BRANDING_SITE}
ENV BRANDING_SITE_LABEL=${BRANDING_SITE_LABEL}
ENV BRANDING_REPO=${BRANDING_REPO}
ENV BRANDING_REPO_LABEL=${BRANDING_REPO_LABEL}
ENV BRANDING_DOC=${BRANDING_DOC}
ENV BRANDING_DOC_LABEL=${BRANDING_DOC_LABEL}

COPY server.js .
COPY lib/      lib/
COPY features/ features/
COPY public/   public/
EXPOSE 3000
CMD ["node", "server.js"]
