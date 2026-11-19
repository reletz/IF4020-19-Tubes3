# Nadina

Kakas penandatanganan dan verifikasi software release (RSA-PSS, ECDSA P-256, Ed25519) untuk pipeline CI/CD. Tugas 3 IF4020 Kriptografi.

Spesifikasi tugas: [docs/spek.md](docs/spek.md). Laporan: [docs/report](docs/report).

## Dependensi

Program hanya bergantung pada pustaka bawaan OTP dan Elixir: `crypto`, `public_key`, dan modul `JSON`.
Dependensi pengembangan tidak masuk ke rilis maupun image.

| Dependensi | Versi | Peran | Dokumentasi |
|---|---|---|---|
| Elixir | 1.20 | Bahasa dan modul `JSON` | https://hexdocs.pm/elixir |
| Erlang/OTP | 29 | Runtime, `crypto`, `public_key` | https://www.erlang.org/doc |
| OpenSSL | paket Alpine 3.24 | Backend kriptografi OTP | https://docs.openssl.org |
| ExDoc | 0.40.4 | Dokumentasi API (dev) | https://hexdocs.pm/ex_doc |
| Credo | 1.7.19 | Analisis gaya kode (dev, test) | https://hexdocs.pm/credo |
| Dialyxir | 1.4.9 | Antarmuka Dialyzer (dev, test) | https://hexdocs.pm/dialyxir |
| StreamData | 1.4.0 | Property test (dev, test) | https://hexdocs.pm/stream_data |

Versi dependensi dikunci dalam `mix.lock`.

## Penggunaan

Image: `reletz/nadina`. Jalankan dengan `--network none` dan UID pengguna, dengan direktori kerja di-mount.

```
docker run --rm --network none --user "$(id -u):$(id -g)" -v "$PWD:/work" -w /work \
  reletz/nadina:0.1.0 keygen -algorithm ed25519 -out keys/publisher
docker run --rm --network none --user "$(id -u):$(id -g)" -v "$PWD:/work" -w /work \
  reletz/nadina:0.1.0 trust add -key keys/publisher.pub.pem -package contoh-app -store trust.json
docker run --rm --network none --user "$(id -u):$(id -g)" -v "$PWD:/work" -w /work \
  reletz/nadina:0.1.0 sign -file contoh-app.zip -package contoh-app -version 1.0.0 \
  -key keys/publisher.key.pem -out release.json
docker run --rm --network none --user "$(id -u):$(id -g)" -v "$PWD:/work" -w /work \
  reletz/nadina:0.1.0 verify -file contoh-app.zip -bundle release.json \
  -trust-store trust.json -package contoh-app -version 1.0.0 -json
```

Subperintah lengkap: `keygen`, `sign`, `verify`, `trust add|list|remove`, dan `sbom bind|extract|sign|verify`.
Opsi `-help` dan `-version` menampilkan petunjuk dan nomor versi. Exit code: 0 berhasil, 1 verifikasi ditolak,
2 kesalahan pemakaian, I/O, atau lingkungan.

## Image container (versi, tag, digest)

| Versi | Tag | Digest index | Platform |
|---|---|---|---|
| 0.1.0 | `reletz/nadina:0.1.0`, `sha-<commit>` | `sha256:590e50e5e5e23f6f8ca58c4dd3d6b90218dfcc5a5c89eef53bf893e27aaaba72` | linux/amd64, linux/arm64 |

Pipeline mengunci image berdasarkan digest, bukan tag, sehingga referensi yang dipakai pemakai sebagai berikut:

```
reletz/nadina@sha256:590e50e5e5e23f6f8ca58c4dd3d6b90218dfcc5a5c89eef53bf893e27aaaba72
```

Tag `edge` mengikuti commit terbaru di `main` dan bisa berubah. Gunakan digest untuk rilis.

## Pengujian

Seluruh pengujian dijalankan dan disimpan ke `docs/log/` dengan:

```
./scripts/test-logs.sh
```

Skrip menjalankan format, compile dengan `--warnings-as-errors`, credo, dialyzer, seluruh tes, serta tes di dalam
image Elixir Alpine. Benchmark (`bench/run.sh`) dijalankan terpisah dan keluarannya disimpan di `docs/log/12-benchmark.txt`.

Hasil dan penjelasan setiap kelompok tes ada di bab Pengujian laporan (`docs/report/sections/bab5-pengujian.tex`).
Bukti pipeline pemakai (C01 sampai C05) ada di `docs/ci-evidence/`.
