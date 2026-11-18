# Bukti pengujian CI/CD

Setiap run `pipeline-demo` mengunggah artifact `out/`. Salin artifact ke direktori
skenario di bawah ini, lalu isi tabel. Jangan menyimpan secret atau kunci privat.

| Skenario | Profil | Run | Digest image | Exit | Status | Marker |
|---|---|---|---|---|---|---|
| C01 | rsa-pss-sha256 |  |  |  |  |  |
| C01 | ecdsa-p256-sha256 |  |  |  |  |  |
| C01 | ed25519 |  |  |  |  |  |
| C02 | ecdsa-p256-sha256 |  |  |  |  |  |
| C03 | ecdsa-p256-sha256 |  |  |  |  |  |
| C04 | ecdsa-p256-sha256 |  |  |  |  |  |
| C05 | ed25519 |  |  |  |  |  |

Berkas yang disimpan per skenario:

- `verification.json`: keluaran `verify --json`.
- `artifact.sha256` atau `tampered.sha256`: hash artefak sebelum/sesudah perubahan.
- `image.txt`: referensi image beserta digest.
- `run-url.txt`: tautan workflow run.
- `deployed.txt`: bukti marker deploy (hanya C01).
- `marker-status.txt`: bukti marker tidak dibuat (C02-C04).
- `uid.txt`, `gid.txt`, `version.txt`: bukti eksekusi C05.

C01 dijalankan untuk tiga profil. C02-C04 cukup satu profil. C05 sekali.
