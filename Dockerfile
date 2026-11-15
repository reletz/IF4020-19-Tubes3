# Nadina: image CLI penandatanganan dan verifikasi software release.
# Platform: linux/amd64 (wajib) dan linux/arm64.
#
# Build  : docker build -t nadina .
# Pakai  : docker run --rm --network none --user "$(id -u):$(id -g)" \
#            -v "$PWD:/work" -w /work nadina <subcommand> ...

ARG ELIXIR_IMAGE=elixir:1.20-otp-29-alpine
ARG RUNTIME_IMAGE=alpine:3.24

# ---- tahap build: mix release (ERTS ikut dibundel) ----
FROM ${ELIXIR_IMAGE} AS build
ENV MIX_ENV=prod
WORKDIR /src
# Hex dibutuhkan mix untuk membaca spesifikasi dependensi. ex_doc hanya untuk
# dev sehingga tidak diunduh maupun masuk ke image.
RUN mix local.hex --force
COPY mix.exs mix.lock ./
COPY lib ./lib
RUN mix release nadina --path /opt/nadina

# ---- tahap akhir: runtime minimal, non-root ----
FROM ${RUNTIME_IMAGE}
# Pustaka native untuk ERTS: libstdc++, ncurses, OpenSSL (crypto), dan lksctp (agar stderr bersih).
RUN apk add --no-cache libstdc++ ncurses-libs openssl lksctp-tools \
 && adduser -D -u 10001 nadina \
 && printf '#!/bin/sh\nexec /opt/nadina/bin/nadina eval "Nadina.CLI.main(System.argv())" "$@"\n' \
      > /usr/local/bin/nadina \
 && chmod 0755 /usr/local/bin/nadina
COPY --from=build /opt/nadina /opt/nadina
# UID/GID dapat ditimpa saat run lewat --user. HOME dan RELEASE_TMP diarahkan ke
# /tmp agar tetap dapat ditulis oleh UID acak. Tanpa distribusi Erlang.
ENV HOME=/tmp \
    RELEASE_TMP=/tmp \
    RELEASE_DISTRIBUTION=none \
    LANG=C.UTF-8
USER 10001:10001
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/nadina"]
