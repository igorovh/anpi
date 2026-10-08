FROM rust:1-bookworm AS build
WORKDIR /src
# Build dependencies first so source edits reuse the cached layer.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && touch src/lib.rs \
    && cargo build --release --locked && rm -rf src
COPY migrations migrations
COPY templates templates
COPY static static
COPY src src
RUN touch src/main.rs src/lib.rs && cargo build --release --locked \
    && mkdir -p /out/data && cp target/release/anpi /out/anpi

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /out/anpi /anpi
COPY --from=build --chown=65532:65532 /out/data /data
ENV ANPI_DATA_DIR=/data \
    ANPI_BIND=0.0.0.0:3000
VOLUME /data
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["/anpi", "healthcheck"]
ENTRYPOINT ["/anpi"]
