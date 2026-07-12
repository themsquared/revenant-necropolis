# Lean image for the standalone Necropolis directory (the horde's muster point).
# Build context is THIS repo; the shared revenant-net crate is fetched as a git
# dependency at build time (hence git + ca-certificates in the build stage).
FROM rust:1-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release --bin necropolis

FROM debian:stable-slim
RUN useradd -m revenant && mkdir -p /data && chown revenant /data
COPY --from=build /src/target/release/necropolis /usr/local/bin/necropolis
USER revenant
ENV PORT=8080 NECROPOLIS_DB=/data/necropolis.db
EXPOSE 8080
CMD ["necropolis"]
