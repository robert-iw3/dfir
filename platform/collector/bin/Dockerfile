# Build container for the field collector.
#
# The binary is built HERE and extracted; this image is never deployed to an endpoint. A
# flagged workstation has no container runtime — that is the whole reason this track exists —
# so the deliverable is the static artifact, not an image.
#
# Stages:
#   toolchain -> deps -> lock       Cargo.lock, exported to the host
#                     -> check      typecheck and lint, produces no artifact
#                     -> build -> artifact    the binary, exported to the host
#
# RUST_VERSION must match [toolchain].channel in rust-toolchain.toml. build.sh passes it from
# that file so the two cannot drift; the toolchain stage asserts it for a direct `podman build`.
ARG RUST_VERSION=1.97.1
ARG ALPINE_VERSION=3.24

FROM docker.io/library/rust:${RUST_VERSION}-alpine${ALPINE_VERSION} AS toolchain

# musl-dev provides the static libc, gcc builds the compression crate's C sources, file backs
# the static-linkage gate. No dynamic linker ends up in the artifact.
RUN apk add --no-cache musl-dev pkgconfig file

WORKDIR /src

# rustup reads this and resolves the pinned channel, target and components for every cargo
# invocation below. Its own layer, so a source change never re-resolves the toolchain.
COPY rust-toolchain.toml ./
RUN rustup show

# The pin is only worth something if it is the toolchain actually in use.
RUN PINNED="$(sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' rust-toolchain.toml)" \
 && rustc --version | grep -q "^rustc ${PINNED} " \
 || { echo "FATAL: toolchain is not the pinned channel: $(rustc --version)" >&2; exit 1; }

# Edition 2024 is a hard requirement of this crate, and a toolchain that predates it rejects the
# manifest with an error that reads like a syntax problem. Prove it up front.
RUN printf 'pub fn probe() {}\n' > /tmp/edition.rs \
 && rustc --edition 2024 --crate-type lib --emit=metadata -o /tmp/edition.rmeta /tmp/edition.rs \
 && rm -f /tmp/edition.rs /tmp/edition.rmeta

# --- dependencies ---------------------------------------------------------------------------
# Resolved before the source is copied, so editing a .rs file does not re-fetch the world.
FROM toolchain AS deps
ARG CARGO_LOCKED=""
COPY Cargo.toml Cargo.lock* ./
RUN mkdir -p src && printf 'fn main() {}\n' > src/main.rs \
 && cargo fetch ${CARGO_LOCKED} --target x86_64-unknown-linux-musl \
 && rm -rf src

# A committed lockfile is what makes the recorded artifact hash mean anything; without it an
# upstream release silently changes the binary. `build.sh --lock` exports this to the host.
FROM scratch AS lock
COPY --from=deps /src/Cargo.lock /Cargo.lock

# --- typecheck and lint ---------------------------------------------------------------------
# Ordered so the first failure is the useful one: type errors, then lints, then formatting.
FROM deps AS check
ARG CARGO_LOCKED=""
COPY src ./src
RUN cargo check ${CARGO_LOCKED} --release --target x86_64-unknown-linux-musl --all-targets
RUN cargo clippy ${CARGO_LOCKED} --release --target x86_64-unknown-linux-musl --all-targets -- -D warnings
RUN cargo fmt --check

# --- artifact -------------------------------------------------------------------------------
FROM deps AS build
ARG CARGO_LOCKED=""
COPY src ./src

# --release for size and speed; the target triple is what makes it static. Symbols are dropped
# by the release profile, so there is no separate strip step to keep in sync.
RUN cargo build ${CARGO_LOCKED} --release --target x86_64-unknown-linux-musl

# Refuse to produce a dynamically linked artifact. A collector that needs a loader on the
# endpoint is exactly what this track exists to avoid, and the failure would otherwise surface
# on a suspect host in the middle of an incident.
RUN file target/x86_64-unknown-linux-musl/release/ir-collect | grep -q 'statically linked' \
 || { echo 'FATAL: artifact is not statically linked' >&2; exit 1; }

# Nothing runs from this stage; it exists so `podman build --target artifact -o` can export the
# binary to the host without a container ever being started.
FROM scratch AS artifact
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/ir-collect /ir-collect
