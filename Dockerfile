# Nadina: image CLI penandatanganan dan verifikasi software release.
# Platform: linux/amd64 (wajib) dan linux/arm64.
#
# Build  : docker build -t nadina .
# Pakai  : docker run --rm --network none --user "$(id -u):$(id -g)" \
#            -v "$PWD:/work" -w /work nadina <subcommand> ...

ARG ELIXIR_IMAGE=elixir:1.20-otp-29-alpine

# ---- tahap build: kompilasi menjadi escript tunggal ----
FROM ${ELIXIR_IMAGE} AS build
ENV MIX_ENV=prod
WORKDIR /src
COPY mix.exs ./
COPY lib ./lib
RUN mix escript.build

# ---- tahap akhir: runtime minimal, non-root ----
FROM ${ELIXIR_IMAGE}
# UID/GID dapat ditimpa saat run lewat --user. HOME diarahkan ke /tmp agar
# runtime Erlang tetap dapat menulis walau UID acak tidak punya home.
RUN adduser -D -u 10001 nadina
ENV HOME=/tmp \
    LANG=C.UTF-8 \
    ERL_AFLAGS="-noshell"
COPY --from=build /src/nadina /usr/local/bin/nadina
USER 10001:10001
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/nadina"]
