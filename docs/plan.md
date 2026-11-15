# rencana proyek: nadina

tools buat nandatanganin dan verifikasi software release (rsa-pss, ecdsa p-256, ed25519) utk pipeline ci/cd.

---

## 0. ringkasan

cli yg niru alur cosign, alurnya kira-kira gini.

```
artefak (zip) -> manifest (json canonical) -> tanda tangan -> bundle (json)
                  verify: trust store + bundle + artefak -> status + exit code
```

- kunci dibikin lewat cli (keygen). kunci privat ga pernah masuk repo atau bundle. kunci publik masuk trust store (trust add).
- program dikemas jd image container yg ditarik sm pipeline pemakai, bukan dibangun dari source di runner.
- pipeline pemakai pertama adalah anmategra (artefak yg di-sign adalah rilis .zip).

yg ga dikerjain yaitu transparency log, layanan sertifikat, integrasi registry artefak (opsional di spek), deteksi malware, dan signing image container.

---

## 1. yang udah disepakatin

| hal | keputusan | catatan |
|---|---|---|
| bahasa | elixir 1.20 / otp 29 | kripto bawaan otp (:crypto, :public_key), tanpa dependensi kripto luar. udah dibuktiin lewat spike/. |
| nama program | nadina | dari nayaka, dita, nau. executable nadina, app :nadina. |
| repo kode | reletz/IF4020-19-Tubes3 | branch main. |
| registry | docker hub, reletz/nadina | satu registry aja biar digest-nya tunggal. |
| token | 2 token | push (read and write) sm pull (read-only). menyusul. |
| platform image | linux/amd64 + linux/arm64, satu tag multi-arch | amd64 wajib (spek), arm64 tambahan. base alpine. |
| pin image | pake digest, bukan tag | digest manifest index. tag latest ga dipake. |
| trust store | di repo pemakai (anmategra), ci/trust.json | hash dikunci di konfigurasi, perubahan lewat review. |
| artefak yg di-sign | rilis .zip anmategra | dibikin sekali, terus dipake ulang sm job sign dan verify. |
| pemindai | trivy | gerbang build, gagal kalo ada temuan high atau critical. |
| base image | elixir:1.20-otp-29-alpine | ada utk amd64 dan arm64. spike udah dijalanin di amd64 (alpine 3.24, openssl 3.5, uid acak, --network none) dan hasilnya sama kayak debian. arm64 belum dijalanin. |

---

## 2. arsitektur

### 2.1 modul (lib/nadina/)

| modul | detail |
|---|---|
| strict_json | parser json strict, nolak duplicate key, null, field tambahan, tipe salah (boolean bukan integer), dan trailing data. |
| manifest | validasi field (regex tabel 2.3), serialisasi canonical, batas 16 kib. |
| bundle | parse bundle (batas 64 kib), base64 strict (decode, encode ulang, bandingin). |
| keys | keygen, load pem (pkcs8/spki), validasi tipe dan parameter, fingerprint hex(sha256(der spki)). |
| profile/* | Nadina.Profile (behaviour) + rsa_pss, ecdsa_p256, ed25519. |
| trust | trust store (validasi, add/list/remove, tulis atomik). |
| verify | tujuh pemeriksaan berurutan (tabel 2.8), hasil json (tabel 2.9). |
| cli | dispatch subcommand, --help, --version, exit code (0/1/2). |

satu-satunya tempat yg manggil api kripto otp cuma profile/* sm keys. modul lain ga nyentuh kripto.

### 2.2 alur sign
1. validasi argumen (paket, versi, kunci, path keluaran). kalo gagal i/o atau input, exit 2.
2. baca artefak sbg byte (streaming utk hash), itung ukuran sm sha-256. artefak ga dijalanin dan ga diekstrak.
3. muat kunci privat, cek profil, itung keyid.
4. bentuk manifest, serialisasi canonical jd byte M.
5. signature = Sign(key, M) sesuai profil. sha-256 diterapin tepat sekali (rsa, ecdsa). ed25519 nerima M langsung.
6. tulis bundle (schema, manifest_b64, signature_b64) tanpa nimpa berkas yg udah ada kecuali ada opsi eksplisit.

### 2.3 alur verify (berhenti di kegagalan pertama)

| no | status kalo gagal | pemeriksaan |
|---|---|---|
| 1 | INPUT_ERROR (exit 2) | opsi lengkap, semua berkas bisa dibaca. |
| 2 | FORMAT_ERROR | struktur, tipe, ukuran, serialisasi canonical bundle, manifest, trust store. base64 valid. |
| 3 | UNSUPPORTED_ALGORITHM | algorithm salah satu dari tiga profil. |
| 4 | KEY_NOT_TRUSTED | keyid ada di trust store, profil sama sm manifest, kunci diizinin utk paket yg diharapin. |
| 5 | INVALID_SIGNATURE | tanda tangan sah atas byte manifest yg tersimpan (bukan hasil format ulang). |
| 6 | METADATA_MISMATCH | paket, versi, dan nama artefak (basename) sama persis sm masukan. |
| 7 | ARTIFACT_MISMATCH | ukuran dan sha-256 artefak sama sm manifest. |
| 8 | OK | semua lolos (exit 0). |

catatan, trust store rusak atau kunci di dalamnya ga sesuai (tipe, parameter, fingerprint) hasilnya FORMAT_ERROR. kunci valid tp profilnya beda hasilnya KEY_NOT_TRUSTED. exit code 0 artinya ok, 1 verifikasi ditolak, 2 salah pemakaian / i/o / lingkungan.

### 2.4 profil algoritma

| profil | rincian | keluaran |
|---|---|---|
| rsa-pss-sha256 | rsa 3072, e=65537, rsassa-pss, sha-256, mgf1-sha-256, salt 32 byte | 384 byte |
| ecdsa-p256-sha256 | p-256, sha-256, nonce dari csprng | 64 byte (r\|s, tiap nilai 32 byte big-endian) |
| ed25519 | pureeddsa (rfc 8032), tanpa pre-hash dan tanpa context | 64 byte |

hasil spike (otp 29, udah dicek silang sm openssl) nunjukin ketiganya sesuai. ecdsa butuh konversi der ke r|s (padding nol buat r/s yg pendek). spki ed25519 tanpa field parameter.

---

## 3. desain keamanan (kripto)

- pembangkitan acak pake csprng otp (:crypto) buat kunci, salt pss, dan nonce ecdsa. ga ada seed tetap kecuali utk test vector.
- kunci privat cuma dibaca dari berkas (bukan argumen atau env), dibikin dgn izin 0600, ga dicatat di log, ga masuk bundle. nimpa cuma boleh pake opsi eksplisit (--force).
- fail-closed, semua gagal berarti ditolak. ga nyoba kunci, profil, atau trust store lain.
- verifikasi atas byte asli, tanda tangan dicek di byte manifest dari bundle sebelum diformat ulang. cek canonical dilakuin dgn parse strict, serialisasi ulang, terus bandingin byte-for-byte.
- batas ukuran dicek sebelum parsing (manifest 16 kib, bundle 64 kib). artefak di-hash streaming.
- di trust store, kunci cuma valid utk paket yg diizinin. store kosong ga percaya siapa pun. ga pernah di-update otomatis dari bundle. penulisan atomik (file sementara terus rename).
- analisis yg masuk laporan mencakup kebocoran kunci privat, reuse nonce ecdsa, salah parameter (misal double hashing, salt salah), kunci publik dari sumber ga tepercaya, kompromi kunci (dicabut lewat trust remove), dan rollback attack (rancangan ini ga nyegah, butuh trusted state kayak versi terendah yg diterima atau metadata bertimestamp ala tuf).

---

## 4. devops

### 4.1 repo nadina (reletz/IF4020-19-Tubes3)

ci.yml (push dan pr) isinya begini.
1. mix format --check-formatted, credo, dialyzer.
2. mix test (unit, test vector, property test).
3. build image uji, jalanin test kripto di dalam image alpine (musl dan openssl-nya beda sm debian).
4. trivy atas image, gagal kalo ada high/critical.

release.yml (push ke main dan tag v*, cuma setelah ci.yml lulus) isinya begini.
1. build multi-arch (docker buildx, amd64 + arm64), base image dikunci per digest.
2. trivy, terus push ke docker hub pake token push.
3. main dpt tag edge dan sha-<commit>, tag v* dpt tag versi.
4. tulis digest manifest index sbg output job dan ringkasan run. digest ini dicatat di readme (tabel versi, tag repo, digest).

aturan umumnya, izin workflow dibikin minimal (contents: read), action dikunci per sha, ga ada secret utk pr dari fork, concurrency buat batalin run lama di pr, dan branch protection di main (ci wajib lulus, review wajib).

### 4.2 image
- multi-stage, build mix release, stage akhir alpine.
- user non-root, harus tetep jalan pake --user <uid>:<gid> acak dan --network none.
- release dikonfigurasi tanpa distribusi erlang (RELEASE_DISTRIBUTION=none) dan direktori sementara yg bisa ditulis.
- entrypoint nerusin stdout, stderr, dan exit code asli. stdout di-flush sebelum System.halt/1.
- ga ada kunci di layer, log, atau artefak build. .dockerignore nolak *.key.pem.

### 4.3 pipeline pemakai (repo anmategra)

workflow terpisah nadina-release.yml, pemicunya workflow_dispatch dan tag v* (ga ikut ci harian), langkahnya begini.
1. build anmategra-<versi>.zip sekali (misal pake git archive --format=zip), upload sbg artefak.
2. tarik image pake docker pull reletz/nadina@sha256:<digest> (login pake token pull kalo perlu).
3. sign pake nadina sign dgn kunci privat dari secret ke berkas sementara (izin terbatas, dihapus abis dipake).
4. verify pake nadina verify --json dgn ci/trust.json. tahap ini ga nerima kunci privat.
5. deploy simulasi pake file penanda. tahap ini wajib needs ke verify, tanpa continue-on-error.

aturannya, kunci demo khusus utk pengujian (satu per profil). secret ada di github environment khusus, terpisah dari kredensial produksi. ci/trust.json dilindungi branch protection dan CODEOWNERS. trust store ga dibikin atau diubah otomatis sm workflow. artefak ga dibangun ulang setelah verifikasi.

### 4.4 skenario c01-c05
dijalanin di runner github-hosted bersih (linux/amd64). tiap skenario pake direktori keluaran bersih, ngecek exit code asli dari proses verify, dan nyimpen log (tanpa rahasia), json keluaran, sm bukti ada atau ga adanya file penanda. link workflow run dan salinan hasil disimpen di repo nadina (docs/ci-evidence/).

---

## 5. strategi pengujian

| lapisan | isi |
|---|---|
| unit | tiap modul, termasuk kasus batas (manifest 16 kib, bundle 64 kib, base64 ga canonical). |
| test vector | rfc 8032 (ed25519), vektor ecdsa dan rsa-pss dari sumber publik (misal wycheproof) kalo cocok sm profil. |
| property | round trip serialisasi, parser strict nolak varian cacat, sign terus verify selalu ok. |
| skenario u01-u14 | satu berkas uji per skenario (masukan, hasil yg diharapin, hasil aktual, perintah jalanin). u01 dan u14 utk tiga algoritma, u02-u13 minimal satu profil. |
| interop | openssl (alat uji doang, ga dipake di kode) utk tiga profil. cosign opsional sbg pembanding ecdsa kalo formatnya memungkinkan. |
| integrasi | c01-c05 di pipeline anmategra. |

semuanya jalan otomatis di ci.yml, kecuali c01-c05 yg jalan di pipeline pemakai.

---

## 6. benchmark

- minimal 3 artefak ukuran beragam, berkas sama utk tiga algoritma.
- 5 kali pemanasan, minimal 30 kali ukur, waktu pake jam monotonik (:erlang.monotonic_time).
- yg diukur adalah keygen (5 pasang, median), hash artefak, sign/verify atas manifest (median dan p95), end-to-end sign/verify (median dan p95, termasuk boot beam), ukuran kunci der, tanda tangan, dan bundle.
- persentil pake nearest-rank, ceil(0.95 * n) di data terurut.
- laporan nyantumin hardware, os, versi elixir/otp, dan library. kalo lingkungannya beda-beda, semuanya dicantumin.

---

## 7. laporan (latex)

struktur ngikutin Tugas2/docs/report (main.tex, preamble.tex, sections/, figures/, data/, build/).
bagiannya pendahuluan dan ruang lingkup, rancangan, implementasi per algoritma (library, versi, parameter, link dokumentasi), pengujian u01-u14 dan interop, integrasi ci/cd (c01-c05), benchmark, analisis keamanan, penutup. data benchmark disimpen sbg berkas di data/ dan dipake langsung sm grafik.

---

## 8. pembagian tugas

prinsipnya rata (beban kira-kira sama) dan tiap orang punya porsi kripto, condong ke spesialisasi.

### nau
- kripto, profil ecdsa p-256 (konversi der dan r\|s, padding, nanganin r/s di luar domain) dan analisis nonce (u14)
- kripto, test vector ecdsa p-256 (misal wycheproof) dan uji nilai r/s di luar domain
- kripto, keys (keygen, pem pkcs8/spki, fingerprint, validasi parameter, izin berkas, --force)
- interop sm openssl utk tiga profil
- dockerfile multi-arch alpine, release.yml, push docker hub, trivy, digest
- ci.yml (format, credo, dialyzer, test)
- branch protection, secret, environment, CODEOWNERS, kebijakan supply chain
- pemindaian secret (gitleaks), dependabot, penguncian action per sha
- laporan (analisis keamanan dan bagian ci/cd)

### nayaka
- kripto, profil ed25519 (rfc 8032, format kunci rfc 8410, test vector)
- kripto, trust (validasi store, kecocokan fingerprint dan spki, add/list/remove idempoten, tulis atomik)
- cli (subcommand, --help, --version, exit code, perintah non-interaktif)
- sign (alur penandatanganan)
- nadina-release.yml di anmategra, build zip, deploy simulasi, secret demo
- c01-c05 beserta bukti (docs/ci-evidence/)
- pengujian u06, u07, u12 (trust)
- laporan (integrasi anmategra dan trust store)

### dita
- kripto, profil rsa-pss (salt 32, mgf1-sha-256, ga ada double hashing, test vector)
- kripto, verify (tujuh langkah, urutan status, hasil json, ecdsa r\|s di luar domain)
- strict_json
- manifest (validasi field, canonical, batas ukuran)
- bundle (base64 strict, batas ukuran)
- pengujian u01-u05, u08-u11, u13, u14 dan property test
- benchmark (skrip, pengukuran, data)
- laporan (rancangan, pengujian, benchmark, perakitan)

---

## 9. urutan kerja

| fase | isi | siapa utama |
|---|---|---|
| 0 | kerangka repo, spike kripto (udah kelar) | semua |
| 1 | behaviour Profile, strict_json, manifest, bundle, keys, tiga profil | dita, nau, nayaka |
| 2 | sign, verify, trust, cli, dockerfile, ci.yml, spike di arm64 | nayaka, dita, nau |
| 3 | image terbit (digest pertama), u01-u14, interop | semua |
| 4 | pipeline anmategra dan c01-c05 | nayaka, nau |
| 5 | benchmark, analisis keamanan, laporan | dita, nau, nayaka |
| 6 | rilis (tag, digest, readme dgn tabel versi-tag-digest, cek akhir ke spek) | semua |

image harus terbit secepet mungkin (akhir fase 3) krn pipeline anmategra bergantung ke situ.

---

## 10. definisi selesai

- semua perintah di tabel 2.7 jalan, tanpa interaksi pengguna atau tty.
- u01-u14 dan interop lulus pake bukti. c01-c05 lulus pake link workflow run dan salinan hasil.
- image reletz/nadina publik, multi-arch, bisa diambil tanpa kredensial. digest dan pemetaan versi tercatat di readme.
- readme isinya dependensi (versi dan link dokumentasi), cara pake, dan cara jalanin pengujian.
- laporan latex lengkap (termasuk benchmark dan analisis keamanan).
- ga ada kunci privat di repo, image, layer, atau log.

---

## 11. bonus

### 11.1 api documentation (+3)

pake ex_doc, tiap orang ngedokumentasiin fungsi yg dia tulis sendiri secara inline (@moduledoc, @doc, @spec, doctest), mirip doxygen, terus mix docs bikin html statis yg di-host lewat github pages dari ci. ex_doc dipasang only: :dev jadi ga masuk image, tp tetep dicantumin di readme.

ntar nitip dita buat rapiin

### 11.2 signed sbom (+7)

sbom itu daftar komponen/dependensi penyusun sebuah rilis (nama, versi, hash, lisensi) dalam json (cyclonedx). di sini sbom ditandatangani sbg artefak terpisah dan diikat ke artefak rilis lewat sha-256.

yg dibikin ada beberapa hal.
- sbom.json utk zip anmategra, dihasilin kakas luar (trivy atau cyclonedx npm, dicek dulu mana yg bisa) dari dependensi npm. hash sha-256 zip dicantumin di metadata.component.hashes, kalo kakasnya ga bisa ya disisipin step kecil sebelum ditandatangani.
- sbom ditandatangani pake manifest dan bundle yg sama (artifact.name = nama berkas sbom). jadi tiap rilis punya dua bundle, satu buat zip dan satu buat sbom.
- subcommand tambahan (nama bebas, ini usulan) ada tiga.
  - sbom sign, validasi sbom (json valid, ada hash artefak rilis), terus tandatangani kayak sign biasa.
  - sbom verify, verifikasi bundle sbom, alurnya sama persis sm verify (status sama).
  - sbom check, verifikasi kedua bundle, terus cocokin hash artefak di sbom sm hash di manifest bundle rilis dan hash berkas zip aslinya. status tambahan SBOM_MISMATCH (exit 1) kalo ga cocok.
- aturan baca hash, komponen utama sbom harus punya tepat satu hash sha-256 dan namanya sama dgn nama artefak. kalo ga, format error.

cara develop kita.
1. modul baru lib/nadina/sbom.ex (parse strict sbom, ambil hash, cocokin). sign dan verify yg udah ada dipake ulang, ga nulis ulang alur kripto.
2. nambah subcommand di cli, tabel parameter dan keluarannya didokumentasiin (spek minta ini).
3. tambah step di nadina-release.yml, yaitu generate sbom, sbom sign, sbom check, baru deploy simulasi (tetep needs ke verify).
4. pengujian wajib ngecover (a) ubah satu byte isi sbom, (b) ganti artefak rilis (nama dan ukuran sama, isi beda), (c) sbom valid tp ngerujuk hash lain, (d) sbom tanpa hash. hasilnya dicatat di laporan.
5. laporan, bagian implementasi sbom dan hasil uji.

pembagian sbom.
- nau megang modul sbom, subcommand sbom di cli, pengujian a-d, analisis keamanan sbom, dan bagian laporan sbom.
- nayaka megang bagian yg nyerempet anmategra, yaitu generate sbom dari dependensi anmategra (trivy atau cyclonedx npm), step sbom di nadina-release.yml, dan bukti ci-nya.

pembagian api docs, dita fokus rapiin (setup ex_doc, halaman tambahan cli/format, cek konsistensi dokumentasi semua modul, deploy github pages). nau dan nayaka tetep ngedokumentasiin fungsi yg mereka tulis sendiri.
