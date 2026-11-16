# Pipeline demo

Workflow `.github/workflows/pipeline-demo.yml` menjalankan C01-C05 memakai image
`reletz/nadina` yang dikunci berdasarkan digest. Artefak yang ditandatangani adalah
`anmategra-<versi>.zip` yang dibentuk dari `ci/fixtures/anmategra`.

## Kunci demo

Tiga pasangan kunci demo (satu per profil) dibuat di luar repo. Kunci privat disimpan
sebagai secret environment GitHub `nadina-demo`, kunci publik di `ci/keys/` dan
`ci/trust.json`.

Fingerprint demo:

- `rsa-pss-sha256`: `7187459c6be4d98eddeeb82ec35056d6351226960c6686848492a1bcabfd01a0`
- `ecdsa-p256-sha256`: `9d38b598fdd918a0a281959087a02e28e96118db5f03aebd820b9fa469c7449d`
- `ed25519`: `0b677cf14dc46e4256bdb771119fa5af2d461d84902870feca5cf0c5e3dbddda`

Set secret dari berkas kunci privat:

```sh
gh secret set NADINA_DEMO_KEY_RSA_PSS --env nadina-demo < rsa-pss-sha256.key.pem
gh secret set NADINA_DEMO_KEY_ECDSA_P256 --env nadina-demo < ecdsa-p256-sha256.key.pem
gh secret set NADINA_DEMO_KEY_ED25519 --env nadina-demo < ed25519.key.pem
```

Environment `nadina-demo` sengaja terpisah dari kredensial produksi. Workflow tidak
pernah membuat atau mengubah `ci/trust.json`.

## Menjalankan

```sh
gh variable set NADINA_DIGEST --body "reletz/nadina@sha256:<digest>"
gh workflow run pipeline-demo.yml -f scenario=all -f version=1.0.0
```

`scenario` dapat diisi `all`, `c01`, `c02`, `c03`, `c04`, atau `c05`. Input `image`
boleh diisi eksplisit; nilainya harus memuat `@sha256:`.

## Bukti

Setiap job mengunggah `out/` sebagai artifact. Salin isi artifact ke
`docs/ci-evidence/<skenario>/` dan isi tabel di `docs/ci-evidence/README.md` setelah
run selesai.
