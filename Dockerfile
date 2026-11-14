# Static musl build, scratch runtime.
#   docker build -t epicmail .
#   docker run -d --name relay -p 127.0.0.1:3423:3423 \
#     -v relay-data:/data -v ./epicmail.toml:/etc/epicmail/epicmail.toml:ro epicmail
# The config must set server.listen = "0.0.0.0:3423" and store.path = "/data/epicmail.db".
# No HEALTHCHECK: scratch has no shell or curl. Check from outside, see docs/operating.md.

FROM rust:1.100-alpine AS build
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
    && cargo build --release --locked --target x86_64-unknown-linux-musl --bin epicmail \
    && mkdir /data-skel \
    && cp target/x86_64-unknown-linux-musl/release/epicmail /epicmail

FROM scratch
COPY --from=build /epicmail /usr/local/bin/epicmail
COPY --from=build --chown=65532:65532 /data-skel /data
COPY packaging/epicmail.example.toml /etc/epicmail/epicmail.example.toml
USER 65532:65532
VOLUME ["/data"]
EXPOSE 3423
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/epicmail"]
CMD ["serve", "--config", "/etc/epicmail/epicmail.toml"]
