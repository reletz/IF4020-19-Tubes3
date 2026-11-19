# Nadina v0.1.0 - API Reference

## Modules

- [Nadina](Nadina.md): Nadina: penandatanganan dan verifikasi software release (RSA-PSS, ECDSA P-256, Ed25519).
- [Nadina.Artifact](Nadina.Artifact.md): Pembacaan artefak: ukuran dan SHA-256 dari byte berkas.
- [Nadina.Bundle](Nadina.Bundle.md): Bundle tanda tangan (spek Tabel 2.4): byte manifest M dan tanda tangan, keduanya Base64.
- [Nadina.CLI](Nadina.CLI.md): Antarmuka baris perintah (spek Tabel 2.7): keygen, sign, verify, dan trust.
- [Nadina.JSONOut](Nadina.JSONOut.md): Penulis JSON kecil untuk keluaran program (hasil verifikasi dan trust store).
- [Nadina.Keys](Nadina.Keys.md): Pembangkitan kunci, pemuatan PEM (PKCS8 dan SPKI), dan fingerprint (Tabel 2.5).
- [Nadina.Manifest](Nadina.Manifest.md): Release manifest (spek Tabel 2.3): pembentukan, serialisasi canonical, dan parse strict.
- [Nadina.SBOM](Nadina.SBOM.md): Pengikatan SBOM ke artefak rilis (bonus spek 2.10).
- [Nadina.Sign](Nadina.Sign.md): Alur penandatanganan: baca artefak, bentuk manifest, tandatangani byte manifest, tulis
bundle.
- [Nadina.StrictJSON](Nadina.StrictJSON.md): Parser JSON strict (RFC 8259) untuk manifest, bundle, dan trust store.
- [Nadina.Trust](Nadina.Trust.md): Pengelolaan trust store (spek Tabel 2.6) dengan penulisan atomik.
- [Nadina.Trust.Entry](Nadina.Trust.Entry.md): Satu entri kunci pada trust store.
- [Nadina.Verify](Nadina.Verify.md): Tujuh langkah pemeriksaan verifikasi dan hasil JSON (spek Tabel 2.8 sampai 2.10).

- Profil
  - [Nadina.Profile](Nadina.Profile.md): Behaviour untuk profil algoritma tanda tangan (Tabel 2.1 spesifikasi).
  - [Nadina.Profile.EcdsaP256](Nadina.Profile.EcdsaP256.md): Profil ecdsa-p256-sha256, yaitu ECDSA pada kurva NIST P-256 (secp256r1) dengan SHA-256.
  - [Nadina.Profile.Ed25519](Nadina.Profile.Ed25519.md): Profil ed25519, yaitu PureEdDSA sesuai RFC 8032 pada kurva Ed25519.
  - [Nadina.Profile.RsaPss](Nadina.Profile.RsaPss.md): Profil rsa-pss-sha256, yaitu RSASSA-PSS (RFC 8017 bagian 8.1) dengan kunci RSA
3072 bit dan e = 65537.

