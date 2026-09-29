FROM node:22-alpine

WORKDIR /app

ARG APP_VERSION="dev"
ARG APP_REVISION=""
ARG APP_CREATED=""

LABEL org.opencontainers.image.version="${APP_VERSION}"
LABEL org.opencontainers.image.revision="${APP_REVISION}"
LABEL org.opencontainers.image.created="${APP_CREATED}"
LABEL org.opencontainers.image.title="nginx-analyzer"

ENV APP_VERSION=${APP_VERSION}

# Fix (audit report, Basse/Analyzer, "aucune variable TZ dans les Dockerfiles
# et le compose"): two things in this service read the *local* wall-clock
# time of the process, not UTC — ModSecurity's default audit-log timestamp
# has no timezone of its own (lib/parse-waf.js's parseTimestamp() relies on
# the runtime's local zone to interpret it), and the weekly volumetric
# baseline (lib/baseline.js's hourOfWeek()) buckets by local hour-of-week on
# purpose, so it tracks human daily/weekly rhythm correctly across a DST
# change instead of drifting by an hour for months. Neither works as intended
# with no TZ set (a bare `node:alpine` container defaults to UTC) unless the
# operator's actual local zone is configured — and an IANA zone name only
# resolves at all once the `tzdata` package backing it exists in the image.
# `TZ` defaults to empty here (UTC, the previous *implicit* behavior, so
# nothing changes for an operator who does not set it) and is meant to be
# overridden per deployment, e.g. `environment: TZ=Europe/Paris` in
# docker-compose.yml — see README.md.
RUN apk add --no-cache tzdata
ARG TZ=""
ENV TZ=${TZ}

COPY server.js .
COPY lib/ lib/

# L API n'est jamais publiee : elle n'est jointe que par le dashboard sur le
# reseau Docker interne.
EXPOSE 9100

# node:sqlite est marque experimental et emet un avertissement a chaque
# demarrage ; il est stable et utilise a dessein.
CMD ["node", "--no-warnings", "server.js"]
