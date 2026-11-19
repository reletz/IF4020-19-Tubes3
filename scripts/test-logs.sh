#!/usr/bin/env bash
# Menjalankan seluruh kelompok pengujian dan menyimpan keluarannya ke docs/log/*.txt.
# Setiap berkas memuat baris perintah, waktu UTC, keluaran yang sudah disanitasi, dan
# baris terakhir "exit: N". Skrip tetap lanjut bila satu langkah gagal dan keluar non-zero
# di akhir bila ada langkah yang gagal. Benchmark (12) hanya berjalan bila BENCH=1.
set -o pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo"
out=docs/log
mkdir -p "$out"
export MIX_ANSI_ENABLED=false

# Ganti path absolut dengan lokasi relatif dan hilangkan kode warna ANSI.
sanitize() {
  sed -e 's/\x1b\[[0-9;]*[A-Za-z]//g' \
      -e "s#$repo#.#g" \
      -e "s#$HOME#~#g"
}

failed=0
run() {
  local name=$1; shift
  local file="$out/$name.txt"
  echo "[$name] $*"
  {
    echo "# $name"
    echo "# tanggal: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# perintah: $*"
    "$@" 2>&1
    echo "exit: $?"
  } | sanitize > "$file"
  local rc
  rc=$(tail -1 "$file" | sed 's/^exit: //')
  if [ "$rc" != "0" ]; then
    failed=$((failed + 1))
    echo "  gagal (exit $rc), lihat $file"
  fi
}

# Versi image Elixir Alpine yang sama dengan job test-alpine di ci.yml.
ELIXIR_IMAGE=$(sed -n 's/^  ELIXIR_IMAGE: //p' .github/workflows/ci.yml)

run 00-env bash -c '
  echo "commit: $(git rev-parse --short HEAD)"
  uname -srm
  elixir --version | tail -1
  erl -noshell -eval "io:format(\"OTP ~s\n\", [erlang:system_info(otp_release)]), halt()."
  openssl version
  docker --version 2>/dev/null || echo "docker: tidak tersedia"
'
run 01-format mix format --check-formatted
run 02-compile mix compile --force --warnings-as-errors
run 03-credo mix credo
run 04-dialyzer mix dialyzer
run 05-test-all mix test --trace
run 06-test-u-scenarios mix test test/cli_test.exs test/u_scenarios --trace
run 07-test-vector mix test test/profile test/profile_test.exs test/keys_test.exs --trace
run 08-test-property mix test test/property --trace
run 09-test-interop mix test test/interop --trace
run 10-test-sbom mix test test/sbom_test.exs --trace
run 11-test-alpine docker run --rm -v "$repo:/src:ro" "$ELIXIR_IMAGE" sh -c '
  set -eu
  mkdir /tmp/work
  cp -r /src/mix.exs /src/mix.lock /src/lib /src/test /src/config /tmp/work/ 2>/dev/null || cp -r /src/mix.exs /src/mix.lock /src/lib /src/test /tmp/work/
  cd /tmp/work
  mix local.hex --force >/dev/null
  mix local.rebar --force >/dev/null
  mix deps.get >/dev/null
  MIX_ENV=test mix test --trace
'
if [ "${BENCH:-0}" = "1" ]; then
  run 12-benchmark bash bench/run.sh
fi

echo "selesai: $failed langkah gagal"
[ "$failed" -eq 0 ]
