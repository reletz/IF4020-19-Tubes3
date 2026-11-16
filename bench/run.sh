#!/usr/bin/env bash
# Menjalankan bench/bench.exs di dalam image nadina. Hasil: docs/report/data/benchmark/*.csv
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo"
image=nadina:bench

# Git Bash: matikan konversi path POSIX dan pakai path Windows untuk bind mount.
export MSYS_NO_PATHCONV=1
mount_src=$repo
if pwd -W >/dev/null 2>&1; then mount_src=$(pwd -W); fi

if [ -z "${BENCH_HOST_OS:-}" ]; then
  if command -v powershell.exe >/dev/null 2>&1; then
    BENCH_HOST_OS=$(powershell.exe -NoProfile -Command \
      '$o = Get-CimInstance Win32_OperatingSystem; "$($o.Caption) $($o.Version)"' | tr -d '\r')
  else
    BENCH_HOST_OS=$(uname -srm)
  fi
fi

docker build -t "$image" .

# Direktori data harus bisa ditulis oleh user image (10001).
mkdir -p docs/report/data/benchmark
docker run --rm --network none \
  -v "$mount_src:/work" -w /work \
  -e BENCH_RUNS -e BENCH_WARMUP -e BENCH_KEYGEN \
  -e "BENCH_HOST_OS=$BENCH_HOST_OS" \
  -e "BENCH_GIT_COMMIT=$(git rev-parse --short HEAD)" \
  --entrypoint /opt/nadina/bin/nadina \
  "$image" eval 'Code.eval_file("bench/bench.exs")'
