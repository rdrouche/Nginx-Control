# nginx-challenge - page de vérification navigateur (preuve de travail) + cookie signé.
# Image minimale, binaire statique sans CGO, aucune dépendance externe.
#
# Build :   docker build -t nginx-challenge --build-arg APP_VERSION=12.63.0 .

FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/challenge ./cmd/challenge

FROM alpine:3.21
ARG APP_VERSION="dev"
LABEL org.opencontainers.image.version="${APP_VERSION}"
LABEL org.opencontainers.image.title="nginx-challenge"
ENV APP_VERSION=${APP_VERSION}

# Reglages par defaut, fixables au build (--build-arg) ET surchargeables a
# l'execution (-e / environment: / config/challenge.yml du dashboard), comme les
# autres integrations. NC_SECRET n'a volontairement PAS d'ARG : un secret passe
# en --build-arg reste lisible dans l'historique de l'image. Fournissez-le a
# l'execution (NC_SECRET ou NC_SECRET_FILE) ; sans lui un secret aleatoire est
# tire a chaque demarrage.
ARG NC_BIND=":8080"
ARG NC_DIFFICULTY_BITS="16"
ARG NC_COOKIE_HOURS="24"
ARG NC_TOKEN_SECONDS="300"
ARG NC_COOKIE_NAME="nc_chal"
ARG NC_BIND_IP="true"
ARG NC_COOKIE_SECURE="true"
ARG NC_RATE_PER_MIN="30"
ARG NC_LANG="auto"
ARG NC_GOODBOTS="true"
ARG NC_GOODBOTS_EXTRA=""
ENV NC_BIND=${NC_BIND} \
    NC_DIFFICULTY_BITS=${NC_DIFFICULTY_BITS} \
    NC_COOKIE_HOURS=${NC_COOKIE_HOURS} \
    NC_TOKEN_SECONDS=${NC_TOKEN_SECONDS} \
    NC_COOKIE_NAME=${NC_COOKIE_NAME} \
    NC_BIND_IP=${NC_BIND_IP} \
    NC_COOKIE_SECURE=${NC_COOKIE_SECURE} \
    NC_RATE_PER_MIN=${NC_RATE_PER_MIN} \
    NC_LANG=${NC_LANG} \
    NC_GOODBOTS=${NC_GOODBOTS} \
    NC_GOODBOTS_EXTRA=${NC_GOODBOTS_EXTRA}
COPY --from=build /out/challenge /usr/local/bin/challenge
RUN adduser -D -H -u 10001 nc && mkdir /data && chown 10001 /data
# Secret de signature : si NC_SECRET est absent, il est genere une fois et conserve ici
# (monter un volume sur /data pour qu il survive a la recreation du conteneur).
ENV NC_SECRET_FILE=/data/secret
VOLUME /data
USER 10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD wget -qO- "http://127.0.0.1:${NC_BIND##*:}/healthz" >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/challenge"]
