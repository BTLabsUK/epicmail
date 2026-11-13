# Static musl build, scratch runtime.
#   docker build -t epicbox-relay .
#   docker run -d --name relay -p 127.0.0.1:3423:3423 \
#     -v relay-data:/data -v ./relay.toml:/etc/epicbox-relay/relay.toml:ro epicbox-relay
# The config must set server.listen = "0.0.0.0:3423" and store.path = "/data/epicbox-relay.db".
# No HEALTHCHECK: scratch has no shell or curl. Check from outside, see docs/operating.md.

FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev build-base
WORKDIR /src
ENV RUSTFLAGS="-C target-feature=+crt-static"
# Cache dependencies first.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src/bin && echo 'fn main() {}' > src/main.rs && echo '' > src/lib.rs \
    && echo 'fn main() {}' > src/bin/sigdiff-gen.rs \
    && cargo build --release --target x86_64-unknown-linux-musl --locked || true
COPY src ./src
RUN touch src/main.rs src/lib.rs \
    && cargo build --release --locked --target x86_64-unknown-linux-musl --bin epicbox-relay \
    && mkdir /data-skel \
    && cp target/x86_64-unknown-linux-musl/release/epicbox-relay /epicbox-relay

FROM scratch
COPY --from=build /epicbox-relay /usr/local/bin/epicbox-relay
COPY --from=build --chown=65532:65532 /data-skel /data
COPY packaging/relay.example.toml /etc/epicbox-relay/relay.example.toml
USER 65532:65532
VOLUME ["/data"]
EXPOSE 3423
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/epicbox-relay"]
CMD ["serve", "--config", "/etc/epicbox-relay/relay.toml"]
