# Bukti pengujian CI/CD

Bukti diambil dari pipeline pemakai di repo
`AnmategraKMITB/Anmategra-APP` memakai image
`docker.io/reletz/nadina@sha256:590e50e5e5e23f6f8ca58c4dd3d6b90218dfcc5a5c89eef53bf893e27aaaba72`
(tag `0.1.0`, multi-arch `linux/amd64` dan `linux/arm64`).

## Ringkasan

| Skenario | Profil | Run | Exit | Status | SBOM | Marker |
|---|---|---|---|---|---|---|
| C01 | rsa-pss-sha256 | [44480652005](https://github.com/AnmategraKMITB/Anmategra-APP/actions/runs/44480652005) | 0 | `OK` | `OK` | ada |
| C01 | ecdsa-p256-sha256 | [44480962135](https://github.com/AnmategraKMITB/Anmategra-APP/actions/runs/44480962135) | 0 | `OK` | `OK` | ada |
| C01 | ed25519 | [44480632370](https://github.com/AnmategraKMITB/Anmategra-APP/actions/runs/44480632370) | 0 | `OK` | `OK` | ada |
| C02 | ecdsa-p256-sha256 | [44481623084](https://github.com/AnmategraKMITB/Anmategra-APP/actions/runs/44481623084) | 1 | `ARTIFACT_MISMATCH` | - | tidak ada |
| C03 | ecdsa-p256-sha256 | [44481623084](https://github.com/AnmategraKMITB/Anmategra-APP/actions/runs/44481623084) | 1 | `KEY_NOT_TRUSTED` | - | tidak ada |
| C04 | ecdsa-p256-sha256 | [44481623084](https://github.com/AnmategraKMITB/Anmategra-APP/actions/runs/44481623084) | 2 | `INPUT_ERROR` | - | tidak ada |
| C05 | ed25519 | [44481623084](https://github.com/AnmategraKMITB/Anmategra-APP/actions/runs/44481623084) | 0 | `OK` | - | tidak ada |

C01 dijalankan pada `develop` commit
`e02e087b8910fa08cb09f5fae40f0c83b4406a96`. C02-C05 dijalankan pada commit
`38e9caae88920fd67088db9b6915baa7d3479c8e` (kemudian di-merge ke `develop`
sebagai `a6f4b33`).

C05 tidak membuat marker deploy karena bukan tahap deploy; yang diuji adalah
eksekusi CLI dengan UID/GID runner, tanpa TTY, dan `--network none`.

## Isi direktori

Setiap direktori skenario memuat:

- `verification.json`: keluaran `verify --json`.
- `sbom-verification.json`: keluaran `sbom verify --json` (C01).
- `artifact.sha256` dan `tampered.sha256`: hash artefak sebelum/sesudah perubahan.
- `deployed.txt`: bukti marker deploy (C01).
- `marker-status.txt`: bukti marker tidak dibuat (C02-C04).
- `uid.txt`, `gid.txt`, `version.txt`: bukti eksekusi C05.
- `image.txt`: referensi image beserta digest.
- `run-url.txt`: tautan workflow run.
- `head-sha.txt`: commit yang dijalankan.
- `run.log`: log job yang sudah dibersihkan dari escape ANSI. GitHub Actions
  menyamarkan nilai secret sebagai `***`; pencarian `PRIVATE KEY` dan token pada
  direktori ini tidak menemukan apa pun.

Snapshot konfigurasi yang dipakai ada di `workflows/`, dan snapshot trust store
ada di `trust/`.
