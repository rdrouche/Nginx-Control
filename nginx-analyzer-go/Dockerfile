# nginx-analyzer (portage Go) - image finale minimale, binaire statique sans CGO.
#
# Build :   docker build -t nginx-analyzer-go --build-arg APP_VERSION=12.52.0 .
# Remplace l'image Node de ../nginx-analyzer : meme API HTTP (port 9100), memes
# variables d'environnement, meme format de base SQLite - voir README.md.

FROM golang:1.24-alpine AS build
WORKDIR /src
# Couche de dependances separee : un changement de code ne re-telecharge rien.
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
# -trimpath : builds reproductibles ; -s -w : sans table de symboles/DWARF (binaire plus petit).
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/analyzer ./cmd/analyzer

FROM alpine:3.21

ARG APP_VERSION="dev"
ARG APP_REVISION=""
ARG APP_CREATED=""
LABEL org.opencontainers.image.version="${APP_VERSION}"
LABEL org.opencontainers.image.revision="${APP_REVISION}"
LABEL org.opencontainers.image.created="${APP_CREATED}"
LABEL org.opencontainers.image.title="nginx-analyzer"

ENV APP_VERSION=${APP_VERSION}

# TZ : voir nginx-analyzer/Dockerfile - la baseline volumetrique et l'horodatage
# WAF sans fuseau utilisent l'heure LOCALE du process. La base des fuseaux est
# embarquee dans le binaire (time/tzdata) : pas besoin du paquet tzdata ici.
# Vide par defaut (= UTC, comme avant) ; a surcharger par deploiement, ex.
# `environment: TZ=Europe/Paris`.
ARG TZ=""
ENV TZ=${TZ}

# GOGC : voir cmd/analyzer/main.go (defaut 40, RAM/CPU). GOMEMLIMIT (plafond
# souple, ex. 256MiB) peut etre ajoute au besoin, sans imposer de defaut ici.

COPY --from=build /out/analyzer /usr/local/bin/analyzer

# Comme l'image Node, tourne en root : la base SQLite deja presente dans le
# volume monte (creee par l'ancienne image) appartient a root ; passer a un
# utilisateur non-root sans migrer les permissions du volume casserait la
# reprise de l'historique. L'API n'est jamais publiee (reseau Docker interne
# uniquement, protegee en plus par ANALYZER_TOKEN quand le dashboard la gere).
EXPOSE 9100

ENTRYPOINT ["/usr/local/bin/analyzer"]
