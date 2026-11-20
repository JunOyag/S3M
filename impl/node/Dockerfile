# Image officielle du Nœud S3m (deploiement.packaging).
# Construction, depuis la racine du dépôt :
#   docker build -f impl/node/Dockerfile -t s3m-node impl
# Première exécution (phrase de récupération + configuration dans /data) :
#   docker run --rm -v p2p-node:/data s3m-node init /data
# Démarrage (réseau de l'hôte : l'API du dashboard n'écoute que 127.0.0.1) :
#   docker run -d --name p2p-node --network host -v p2p-node:/data s3m-node
# L'URL du dashboard (jeton dans le fragment) s'affiche dans `docker logs p2p-node`.

FROM rust:1-bookworm AS build
RUN apt-get update -qq && apt-get install -y -qq cmake libgmp-dev libclang-dev >/dev/null
WORKDIR /src
COPY core core
COPY protocol protocol
COPY node node
RUN cd node && cargo build --release --locked --features vdf --bin s3m-node

FROM debian:bookworm-slim
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends libgmp10 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --home /data --uid 10001 p2p && mkdir -p /data && chown p2p /data
COPY --from=build /src/node/target/release/s3m-node /usr/local/bin/s3m-node
USER p2p
VOLUME /data
EXPOSE 4001 4002
ENTRYPOINT ["s3m-node"]
CMD ["/data/node.json"]
