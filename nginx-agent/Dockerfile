# nginx-control-agent — image de reference pour deployer l agent Go
# (Partie 2 "avance" du document de conception) sur un hote Docker distant.
# Build multi-etapes : compilation Go dans une image complete, binaire
# statique copie seul dans une image minimale de diffusion. Meme discipline
# "zero dependance" que le reste du projet — go.mod n a aucun require tiers,
# donc rien d autre qu un compilateur Go n est necessaire pour construire.

# ─── Etape 1 : compilation ─────────────────────────────────────────────────
FROM golang:1.24-alpine AS build
WORKDIR /src

# go.mod/go.sum d abord pour profiter du cache Docker sur les couches
# suivantes (ce module n a pas de go.sum, aucune dependance tierce a
# telecharger, mais on garde l ordre habituel par coherence/evolutivite).
COPY go.mod ./
COPY *.go ./

# CGO_ENABLED=0 : binaire statique, condition necessaire pour tourner sur
# l image de diffusion minimale ci-dessous (scratch, sans libc).
# -ldflags "-s -w" : retire les symboles de debug, image plus legere.
ARG APP_VERSION="dev"
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w -X main.buildVersion=${APP_VERSION}" \
      -o /out/nginx-control-agent .

# ─── Etape 2 : diffusion ───────────────────────────────────────────────────
# scratch : rien d autre que le binaire lui-meme dans l image finale. Un
# binaire Go statique (CGO_ENABLED=0) n a besoin de rien d autre pour
# s executer, ce qui est le point de zero-dependance de ce projet pousse au
# bout (surface d attaque minimale, image de quelques Mo).
FROM scratch

# Certificats CA : necessaires pour que l agent puisse verifier le certificat
# TLS du dashboard (https://..., sauf --insecure-skip-verify) — scratch n en
# fournit aucun par lui-meme, on les recupere de l etape de build (paquet
# ca-certificates d Alpine).
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/nginx-control-agent /nginx-control-agent

ARG APP_VERSION="dev"
ARG APP_REVISION=""
ARG APP_CREATED=""
LABEL org.opencontainers.image.version="${APP_VERSION}"
LABEL org.opencontainers.image.revision="${APP_REVISION}"
LABEL org.opencontainers.image.created="${APP_CREATED}"
LABEL org.opencontainers.image.title="nginx-control-agent"
LABEL org.opencontainers.image.description="Agent Docker distant (Partie 2) pour nginx-reverse-proxy-dashboard"
LABEL org.opencontainers.image.source="https://forge.rdr-it.com/Dockerfiles/nginx-reverse-proxy-dashboard"

# ─── Configuration runtime (ENV) ────────────────────────────────────────────
# Toutes les options en ligne de commande de l agent (voir README.md, section
# "Options") sont exposees ici comme variables d environnement : l entrypoint
# ci-dessous les retraduit en flags. Une image construite une seule fois peut
# ainsi etre reutilisee telle quelle pour n importe quel hote/operateur, en ne
# changeant que le fichier .env du deploiement (voir compose.yml + sample.env
# dans ce meme dossier) — jamais besoin de reconstruire l image pour changer
# une adresse ou un intervalle.
#
# Obligatoire :
ENV DASHBOARD_URL=""
# Optionnelles (memes defauts que les flags CLI, voir main.go) :
ENV AGENT_HOSTNAME=""
ENV AGENT_FINGERPRINT=""
ENV STATE_FILE="/data/nginx-control-agent-state.json"
ENV TOKEN_FILE="/data/token"
ENV TOKEN=""
ENV DOCKER_SOCKET="/var/run/docker.sock"
ENV POLL_INTERVAL="30s"
ENV INSECURE_SKIP_VERIFY="false"
ENV TUNNEL_ENABLE="true"
# Mode relay (port unique/double, v12.20.0) — voir README.md :
ENV RELAY_HTTP_LISTEN=""
ENV RELAY_HTTP_ADVERTISE=""
ENV RELAY_HTTPS_LISTEN=""
ENV RELAY_HTTPS_ADVERTISE=""
ENV RELAY_HTTPS_CERT=""
ENV RELAY_HTTPS_KEY=""
# Cote AVAL du relais (agent -> backend Docker local) — independant du cote
# AMONT choisi ci-dessus (nginx -> agent). Voir README.md, "Chaines de
# schemas supportees".
ENV RELAY_BACKEND_INSECURE_SKIP_VERIFY="false"
# Multi-master (v12.21.0) — voir README.md, "Multi-master". Quand renseigne,
# remplace DASHBOARD_URL/STATE_FILE/TOKEN(_FILE) ci-dessus par une LISTE de
# cibles independantes lue dans ce fichier JSON (a monter en volume, ex. sous
# /data avec le reste de l etat persistant).
ENV TARGETS_FILE=""

# /data : etat persistant (agentId + jeton, si --token-file est laisse a sa
# valeur par defaut plus haut) — a monter en volume, voir compose.yml.
VOLUME ["/data"]

# Pas de shell disponible sur scratch (pas de /bin/sh) pour traduire les ENV
# en flags via un entrypoint.sh classique : c est le binaire LUI-MEME qui
# relit chaque variable d environnement documentee ci-dessus comme defaut de
# son propre flag correspondant (voir envOr()/envOrBool()/envOrDuration()
# dans main.go) avant d appliquer flag.Parse(). Un flag explicite sur la
# ligne de commande (CMD ci-dessous n en passe aucun par defaut) resterait
# prioritaire si jamais l un des deux etait fourni.
ENTRYPOINT ["/nginx-control-agent"]
