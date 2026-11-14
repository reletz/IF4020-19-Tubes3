0̷1̶—̶L̶ątar̵B̴ela̸ka̵ņg̴
Tugas 3 IF4020-Kriptografi
2026/2027
←Kembali ke Daftar Isi Halaman 5 dari 47 Program Studi Teknik Informatika
Sekolah Teknik Elektro dan Informatika
Institut Teknologi Bandung
Chapter 3: Penandatanganan dan 
Verifikasi Software Release
2 November 2026
Tugas 3 IF4020-Kriptografi
2026/2027
←Kembali ke Daftar Isi Halaman 6 dari 47 Program Studi Teknik Informatika
Sekolah Teknik Elektro dan Informatika
Institut Teknologi Bandung
Chapter 3: Penandatanganan dan 
Verifikasi Software Release
2 November 2026
Tugas 3 IF4020-Kriptografi
2026/2027
←Kembali ke Daftar Isi Halaman 7 dari 47 Program Studi Teknik Informatika
Sekolah Teknik Elektro dan Informatika
Institut Teknologi Bandung
Chapter 3: Penandatanganan dan 
Verifikasi Software Release
2 November 2026
Tugas 3 IF4020-Kriptografi
2026/2027
←Kembali ke Daftar Isi Halaman 8 dari 47 Program Studi Teknik Informatika
Sekolah Teknik Elektro dan Informatika
Institut Teknologi Bandung
Chapter 3: Penandatanganan dan 
Verifikasi Software Release
2 November 2026
02̷—̷Sp̧es̸if̧įka̶si T̴u̸g̴as̶
Program yang dirancang harus dapat melakukan proses penandatanganan dan verifikasi
rilis perangkat lunak (software release) menggunakan algoritma RSA, ECDSA, dan EdDSA.
Program ditujukan untuk digunakan sebagai kakas pada pipeline CI/CD. Program
didistribusikan sebagai image container yang dapat diambil dari registry, kemudian
dijalankan untuk menandatangani artefak hasil build dan memverifikasinya sebelum
publikasi atau deployment. Program wajib menyediakan pembangkitan pasangan kunci,
pembentukan release manifest, dan pengelolaan kunci publik tepercaya. Pengujian dan
analisis dilakukan pada ketiga algoritma untuk membandingkan kebenaran hasil, keamanan
sistem, dan performa program.
Program yang dibuat mengadaptasi alur penandatanganan berkas pada Sigstore Cosign.
Berkas rilis yang akan ditandatangani selanjutnya disebut artefak. Informasi mengenai
artefak, seperti nama paket, versi, ukuran berkas, dan nilai hash, disimpan dalam release
manifest. Tanda tangan digital diberikan pada manifest tersebut, kemudian manifest dan
tanda tangannya disimpan dalam satu berkas yang disebut bundle.
Gambar 2.1 Skema penandatanganan artefak dan pembentukan bundle
Tugas 3 IF4020-Kriptografi
2026/2027
←Kembali ke Daftar Isi Halaman 9 dari 47 Program Studi Teknik Informatika
Sekolah Teknik Elektro dan Informatika
Institut Teknologi Bandung
Chapter 3: Penandatanganan dan 
Verifikasi Software Release
2 November 2026
Proses verifikasi dilakukan menggunakan daftar kunci publik tepercaya (trust store) yang
dikelola oleh pengguna. Tanda tangan digital digunakan untuk memeriksa keaslian dan
integritas data, bukan untuk menentukan apakah suatu perangkat lunak bebas dari malware
atau kerentanan. Kepercayaan terhadap identitas penerbit ditentukan melalui pemeriksaan
kunci publik yang digunakan.
2.1 Algoritma Tanda Tangan Digital
Anda harus mengimplementasikan ketiga algoritma tanda tangan digital dengan parameter
yang ditentukan pada Tabel 2.1. Nama profil pada tabel digunakan sebagai nilai algorithm
pada release manifest dan masukan program.
Tabel 2.1 Profil algoritma yang wajib didukung
Profil Ketentuan Tanda Tangan
rsa-pss-sha256 Kunci: RSA 3072 bit, eksponen publik 65537.
Skema: RSASSA-PSS dengan SHA-256 dan
MGF1-SHA-256.
Salt: 32 byte.
384 byte.
ecdsa-p256-sha2
56
Kurva: NIST P-256 / secp256r1.
Hash: SHA-256.
Nonce: dari CSPRNG atau dibangkitkan
secara deterministik sesuai RFC 6979.
64 byte.
Format: r | s.
Setiap nilai berupa 32
byte big-endian.
ed25519 Varian: Ed25519 (PureEdDSA), sesuai RFC
8032.
Masukan: pesan asli, tanpa pre-hash
64 byte. Encoding
standar Ed25519.
Tugas 3 IF4020-Kriptografi
2026/2027
←Kembali ke Daftar Isi Halaman 10 dari 47 Program Studi Teknik Informatika
Sekolah Teknik Elektro dan Informatika
Institut Teknologi Bandung
Chapter 3: Penandatanganan dan 
Verifikasi Software Release
2 November 2026
eksternal dan tanpa context.
Ketentuan Implementasi Algoritma:
● Implementasi ketiga algoritma boleh menggunakan pustaka kriptografi (library).
Pustaka yang digunakan, versi, dan pengaturan parameternya wajib dijelaskan pada
README maupun laporan, disertai tautan dokumentasi.
● Pembangkitan pasangan kunci, salt RSA-PSS, dan nonce ECDSA wajib menggunakan
sumber bilangan acak yang aman secara kriptografis. Khusus ECDSA, penggunaan
nonce deterministik sesuai RFC 6979 diperbolehkan. Penggunaan seed tetap hanya
diperbolehkan untuk pengujian dengan test vector.
● Implementasi RSA wajib menggunakan skema RSASSA-PSS. Penggunaan textbook
RSA atau operasi enkripsi RSA sebagai pengganti tanda tangan tidak diperbolehkan.
● Implementasi EdDSA wajib menggunakan varian Ed25519 sesuai Tabel 2.1.
Penggunaan Ed25519ph sebagai pengganti Ed25519 tidak diperbolehkan.
● Apabila pustaka ECDSA menghasilkan tanda tangan dalam format ASN.1 DER,
program wajib mengubahnya ke format r | s sebelum menyimpannya dalam
bundle.
● Normalisasi low-S pada ECDSA tidak diwajibkan. Verifier boleh menerima tanda
tangan non-low-S selama tanda tangan valid menurut ECDSA P-256 dan
encoding r | s memenuhi ketentuan.
● Penandatanganan dilakukan terhadap byte manifest pada Bagian 2.3. Pada RSA dan
ECDSA, SHA-256 diterapkan satu kali terhadap byte manifest. Penggunaan API
pustaka harus disesuaikan agar tidak terjadi double hashing.
Tugas 3 IF4020-Kriptografi
2026/2027
←Kembali ke Daftar Isi Halaman 11 dari 47 Program Studi Teknik Informatika
Sekolah Teknik Elektro dan Informatika
Institut Teknologi Bandung
Chapter 3: Penandatanganan dan 
Verifikasi Software Release
2 November 2026
2.2 Implementasi Program
Anda harus mengimplementasikan proses pembangkitan kunci, penandatanganan, dan
verifikasi dalam suatu program. Komponen masukan dan keluaran program yang diperlukan
dapat dilihat pada Tabel 2.2.
Tabel 2.2 Ringkasan masukan dan keluaran program
Komponen Keterangan
Berkas Masukan (Input) Satu berkas teks atau biner yang diperlakukan sebagai
artefak. Isi berkas dibaca sebagai byte tanpa
normalisasi.
Metadata Rilis (Release
Metadata)
Nama paket dan versi rilis. Nilai yang diharapkan saat
verifikasi diberikan secara eksplisit oleh pengguna.
Kunci Privat (Private Key) Digunakan untuk menandatangani manifest dan tidak
disertakan dalam bundle.
Kunci Publik (Public Key) dan
Trust Store
Kunci publik penerbit beserta daftar paket yang boleh
ditandatanganinya. Digunakan untuk memeriksa
kepercayaan pada saat verifikasi.
Bundle Berkas JSON yang memuat byte manifest dan tanda
tangan digital. Keduanya disimpan sebagai string
Base64.
Keluaran (Output) Berkas kunci, bundle, atau hasil verifikasi, sesuai
perintah yang dijalankan. Hasil verifikasi menyertakan
status dan penjelasan singkat.
Ketentuan Implementasi Program:
● Bahasa pemrograman dibebaskan.
● Program wajib dapat dijalankan sebagai container pada runner Linux amd64.
Dukungan eksekusi langsung pada Windows, Linux, atau platform lain dapat
disediakan sebagai tambahan.
Tugas 3 IF4020-Kriptografi
2026/2027
←Kembali ke Daftar Isi Halaman 12 dari 47 Program Studi Teknik Informatika
Sekolah Teknik Elektro dan Informatika
Institut Teknologi Bandung
Chapter 3: Penandatanganan dan 
Verifikasi Software Release
2 November 2026
● Program wajib menyediakan antarmuka CLI dengan ketentuan pada Bagian 2.6.
Penggunaan GUI atau antarmuka web bersifat opsional.
● Pembentukan manifest, pengelolaan trust store, validasi masukan, dan alur
penandatanganan serta verifikasi wajib diimplementasikan sendiri. Program tidak
boleh menggunakan Cosign, OpenSSL CLI, atau aplikasi penandatanganan lainnya
sebagai pengganti implementasi tersebut.
● Penggunaan pustaka untuk operasi kriptografi, fungsi hash, encoding, pengolahan
JSON, dan pembuatan antarmuka diperbolehkan. Seluruh dependensi yang
digunakan wajib dicantumkan pada README.
● Program wajib mendukung penandatanganan dan verifikasi berkas secara lokal.
Integrasi registry penyimpanan artefak, layanan sertifikat, dan transparency log
bersifat opsional.
● Image program wajib dipublikasikan pada registry container dan dapat digunakan
oleh pipeline sesuai ketentuan pada Bagian 2.9.
● Berikan nama program Anda dengan nama yang unik dan kreatif.
2.3 Format Release Manifest
Program wajib membentuk release manifest dalam format JSON dengan struktur yang
ditentukan pada Tabel 2.3. Seluruh field pada tabel wajib disertakan. Program wajib menolak
manifest yang memiliki field tambahan, field dengan nama yang sama, nilai null, atau tipe
data yang tidak sesuai.
Deteksi field dengan nama yang sama wajib dilakukan sebelum atau selama parsing. Parser
JSON yang secara diam-diam mempertahankan salah satu nilai duplicate field tanpa
melaporkan duplikasi tidak memenuhi ketentuan ini.
Tugas 3 IF4020-Kriptografi
2026/2027
←Kembali ke Daftar Isi Halaman 13 dari 47 Program Studi Teknik Informatika
Sekolah Teknik Elektro dan Informatika
Institut Teknologi Bandung
Chapter 3: Penandatanganan dan 
Verifikasi Software Release
2 November 2026
Tabel 2.3 Struktur release manifest
Field Tipe Ketentuan
schema string Nilai tetap minisign-manifest/v1.
package string Nama paket.
Pola: [a-z0-9][a-z0-9._-]{0,63}.
version string Versi rilis.
Pola: [A-Za-z0-9][A-Za-z0-9._+-]{0,63}. Format semantic
version tidak diwajibkan (tetapi dianjurkan).
algorithm string Nama profil algoritma sesuai Tabel 2.1.
keyid string Fingerprint kunci publik sesuai Bagian 2.4. Ditulis sebagai
64 karakter heksadesimal dengan huruf kecil.
artifact object Memuat tepat tiga field: name, size, dan sha256.
artifact.name string Nama berkas tanpa direktori.
Pola: [A-Za-z0-9][A-Za-z0-9._-]{0,127}.
artifact.size integer Ukuran artefak dalam byte.
Rentang: 0–9007199254740991. Nilai boolean tidak
diterima sebagai integer.
artifact.sha256 string SHA-256 dari byte artefak. Ditulis sebagai 64 karakter
heksadesimal dengan huruf kecil.
Batas maksimum 9007199254740991 (2^53 - 1) digunakan untuk menjaga
interoperabilitas dengan implementasi JSON yang merepresentasikan bilangan
menggunakan IEEE-754 binary64.
Ketentuan Serialisasi Manifest:
● Manifest disimpan menggunakan UTF-8 tanpa Byte Order Mark (BOM), tanpa spasi di
luar string, dan tanpa karakter baris baru, termasuk pada akhir berkas. Ukuran
manifest maksimum adalah 16 KiB.
Tugas 3 IF4020-Kriptografi
2026/2027
←Kembali ke Daftar Isi Halaman 14 dari 47 Program Studi Teknik Informatika
Sekolah Teknik Elektro dan Informatika
Institut Teknologi Bandung
Chapter 3: Penandatanganan dan 
Verifikasi Software Release
2 November 2026
● Urutan field pada manifest adalah schema, package, version, algorithm, keyid, dan
artifact. Urutan field pada objek artifact adalah name, size, dan sha256.
● Seluruh string menggunakan karakter ASCII sesuai ketentuan setiap field. Karakter
ditulis secara langsung, tanpa escape \uXXXX. Bilangan bulat ditulis dalam bentuk
desimal tanpa tanda plus, pecahan, eksponen, atau angka nol di depan bilangan,
kecuali untuk nilai 0.
● Program wajib memeriksa kesesuaian serialisasi manifest pada saat verifikasi.
Tanda tangan diverifikasi menggunakan byte manifest yang tersimpan dalam bundle.
Manifest tidak boleh diformat ulang sebelum tanda tangannya diperiksa.
● Pemeriksaan canonical serialization boleh dilakukan dengan melakukan parsing
manifest secara strict, membentuk kembali serialisasi canonical sesuai ketentuan di
atas, lalu membandingkan hasilnya secara byte-for-byte dengan byte manifest asli.
Ketentuan serialisasi tersebut berlaku untuk manifest yang ditandatangani. Urutan field dan
penggunaan white space pada JSON bundle dibebaskan selama tidak mengubah isi manifest
dan tanda tangan yang disimpan di dalamnya.
Tugas 3 IF4020-Kriptografi
2026/2027
←Kembali ke Daftar Isi Halaman 15 dari 47 Program Studi Teknik Informatika
Sekolah Teknik Elektro dan Informatika
Institut Teknologi Bandung
Chapter 3: Penandatanganan dan 
Verifikasi Software Release
2 November 2026
Contoh Manifest dan Pesan yang Ditandatangani
Contoh struktur manifest dapat dilihat di bawah ini. Penulisan dengan indentasi hanya
digunakan untuk memperjelas struktur data. Sebelum ditandatangani, manifest wajib
diserialisasi sesuai ketentuan sebelumnya. Nilai keyid dan sha256 pada contoh harus
diganti dengan hasil perhitungan program.
{
"schema": "minisign-manifest/v1",
"package": "contoh-app",
"version": "1.0.0",
"algorithm": "ed25519",
"keyid": "<64 karakter heksadesimal lowercase>",
"artifact": {
"name": "contoh-app.zip",
"size": 1048576,
"sha256": "<64 karakter heksadesimal lowercase>"
}
}
Misalkan M merupakan byte hasil serialisasi manifest. Proses penandatanganan dan
verifikasi dilakukan sebagai berikut:
M = UTF8(serialize_manifest(manifest))
signature = Sign(private_key, M)
signature_valid = Verify(public_key, M, signature)
Fungsi Sign dan Verify menggunakan algoritma beserta parameter pada Tabel 2.1. Nilai
artifact.sha256 digunakan untuk memeriksa integritas artefak, sedangkan pesan yang
Tugas 3 IF4020-Kriptografi
2026/2027
←Kembali ke Daftar Isi Halaman 16 dari 47 Program Studi Teknik Informatika
Sekolah Teknik Elektro dan Informatika
Institut Teknologi Bandung
Chapter 3: Penandatanganan dan 
Verifikasi Software Release
2 November 2026
ditandatangani adalah seluruh byte manifest M. Dengan demikian, nama paket, versi,
algoritma, identitas kunci, dan informasi artefak turut dilindungi oleh tanda tangan digital.
Pada Ed25519, byte manifest diberikan secara langsung kepada pustaka tanpa proses
hashing tambahan. Fungsi hash yang menjadi bagian dari algoritma Ed25519 dijalankan oleh
pustaka yang digunakan.
Pseudocode Penandatanganan Rilis
Pseudocode berikut memperjelas pembentukan manifest dan bundle. Nama fungsi bersifat
ilustratif dan dapat disesuaikan dengan bahasa serta pustaka yang digunakan. Pemeriksaan
masukan mencakup metadata, tipe dan parameter kunci, nama berkas, serta izin penulisan
keluaran. Kegagalan masukan atau I/O pada proses penandatanganan menghasilkan exit
code 2.
Fungsi Manifest membentuk field sesuai Tabel 2.3 dengan urutan argumen paket, versi,
profil, fingerprint, nama artefak, ukuran, dan hash. Fungsi Bundle membentuk struktur pada
Tugas 3 IF4020-Kriptografi
2026/2027
←Kembali ke Daftar Isi Halaman 17 dari 47 Program Studi Teknik Informatika
Sekolah Teknik Elektro dan Informatika
Institut Teknologi Bandung
Chapter 3: Penandatanganan dan 
Verifikasi Software Release
2 November 2026
Tabel 2.4. Kedua fungsi mengisi nilai schema yang ditentukan. Notasi |𝐴| menyatakan
panjang byte, sedangkan Hex menghasilkan heksadesimal dengan huruf kecil.
Operasi Sign𝑎 menggunakan pustaka sesuai profil pada Tabel 2.1:
● RSA-PSS: tandatangani M menggunakan SHA-256, MGF1-SHA-256, dan salt
sepanjang 32 byte. SHA-256 atas M diterapkan tepat satu kali.
● ECDSA P-256: tandatangani M dengan SHA-256 yang diterapkan tepat satu kali.
Peroleh nilai r dan s, lalu gabungkan sebagai r | s, masing-masing 32 byte
big-endian. Jika keluaran pustaka berupa DER, lakukan decode terlebih dahulu.
● Ed25519: berikan M secara langsung kepada operasi Ed25519, tanpa hashing
eksternal.
2.4 Format Bundle dan Berkas Kunci
Manifest beserta tanda tangan digital disimpan dalam satu berkas bundle dengan format
JSON. Bundle menggunakan UTF-8 tanpa BOM dan memiliki ukuran maksimum 64 KiB.
Struktur bundle yang diperlukan dapat dilihat pada Tabel 2.4. Program wajib menolak bundle
yang memiliki field tambahan atau field dengan nama yang sama. Kunci privat tidak boleh
disertakan dalam bundle.
Tabel 2.4 Struktur bundle tanda tangan
Field Tipe Ketentuan
schema string Nilai tetap minisign-bundle/v1.
manifest_b64 string Byte manifest M yang dikodekan menggunakan Base64
standar RFC 4648, dengan padding jika diperlukan.
Tugas 3 IF4020-Kriptografi
2026/2027
←Kembali ke Daftar Isi Halaman 18 dari 47 Program Studi Teknik Informatika
Sekolah Teknik Elektro dan Informatika
Institut Teknologi Bandung
Chapter 3: Penandatanganan dan 
Verifikasi Software Release
2 November 2026
signature_b64 string Byte tanda tangan sesuai Tabel 2.1 yang dikodekan
menggunakan Base64 standar RFC 4648, dengan padding
jika diperlukan.
Encoding Base64 wajib mengikuti RFC 4648 dengan alfabet A–Z, a–z, 0–9, +, dan /, serta
padding = apabila diperlukan. Penggunaan white space di dalam string Base64 tidak
diperbolehkan. Program wajib menolak karakter, padding, dan encoding yang tidak sesuai.
Pemeriksaan encoding dapat dilakukan dengan decode dan encode ulang, kemudian
membandingkan hasilnya dengan string masukan.
Kunci disimpan menggunakan format standar pada Tabel 2.5 agar dapat diuji dengan
pustaka atau kakas eksternal.
Tabel 2.5 Format berkas kunci
Komponen Ketentuan
Kunci Privat (Private Key) PKCS8 dalam PEM, dengan label PRIVATE KEY.
Dukungan PKCS8 terenkripsi bersifat opsional.
Kunci Publik (Public Key) SubjectPublicKeyInfo (SPKI) dalam PEM, dengan label
PUBLIC KEY.
RSA Modulus tepat 3072 bit dan eksponen publik 65537.
Identitas algoritma pada SPKI menggunakan
rsaEncryption.
ECDSA Kurva P-256 diidentifikasi melalui named-curve OID. Titik
publik pada SPKI menggunakan encoding SEC1
uncompressed.
ED25519 Encoding kunci mengikuti RFC 8410. Field parameter
pada AlgorithmIdentifier harus tidak disertakan.
Fingerprint / keyid Perhitungan: hex_lower(SHA256(DER_SPKI)).
Tugas 3 IF4020-Kriptografi
2026/2027
←Kembali ke Daftar Isi Halaman 19 dari 47 Program Studi Teknik Informatika
Sekolah Teknik Elektro dan Informatika
Institut Teknologi Bandung
Chapter 3: Penandatanganan dan 
Verifikasi Software Release
2 November 2026
Di mana DER_SPKI adalah byte SPKI dalam DER standar
yang diperoleh dari ekspor ulang kunci publik.
Tipe dan parameter kunci wajib sesuai dengan profil algoritma. Perbedaan line ending atau
pemenggalan PEM tidak boleh mengubah keyid. Isi kunci privat tidak boleh dicatat pada log
atau disertakan dalam bundle. Penimpaan berkas kunci privat memerlukan opsi eksplisit
pengguna.
2.5 Pengelolaan Trust Store
Program wajib menyediakan pengelolaan daftar kunci publik tepercaya (trust store) dalam
format JSON. Trust store disimpan secara terpisah dari artefak dan bundle. Sebelum
menambahkan kunci, pengguna perlu memeriksa fingerprint kunci publik melalui sumber
yang dipercaya. Struktur trust store yang diperlukan dapat dilihat pada Tabel 2.6.
Tabel 2.6 Struktur trust store
Field Tipe Ketentuan
schema string Nilai tetap minisign-trust/v1.
keys array Daftar entri kunci. Daftar boleh kosong, tetapi setiap
entri harus memiliki keyid yang unik.
keys[].keyid string Fingerprint kunci publik pada Tabel 2.5.
keys[].algorithm string Nama profil algoritma sesuai Tabel 2.1. Profil harus
sesuai dengan tipe dan parameter kunci.
keys[].public_key_pem string Isi kunci publik dalam PEM SPKI. Nilai field memuat
teks PEM secara langsung, bukan path berkas.
keys[].packages array of
string
Nama paket yang diizinkan untuk kunci tersebut.
Daftar tidak boleh kosong, memuat duplikat, atau
Tugas 3 IF4020-Kriptografi
2026/2027
←Kembali ke Daftar Isi Halaman 20 dari 47 Program Studi Teknik Informatika
Sekolah Teknik Elektro dan Informatika
Institut Teknologi Bandung
Chapter 3: Penandatanganan dan 
Verifikasi Software Release
2 November 2026
menggunakan wildcard.
Ketentuan Pengelolaan Trust Store:
● Seluruh field pada tabel wajib disertakan. Program wajib memeriksa tipe data,
keunikan nama field, dan kesesuaian fingerprint dengan kunci publik yang disimpan.
Field tambahan tidak diperbolehkan.
● Proses verifikasi hanya boleh menggunakan kunci yang tercantum dalam trust store
dan memiliki izin untuk paket yang diperiksa. Trust store yang kosong tidak
memberikan kepercayaan kepada kunci mana pun.
● Perintah trust add wajib menampilkan fingerprint, algoritma, dan nama paket yang
diberikan izin. Apabila kunci yang sama ditambahkan untuk paket lain, program wajib
memperbarui daftar paket pada entri yang sudah ada. Apabila pasangan keyid dan
nama paket yang sama telah tersedia pada trust store, perintah trust add bersifat
idempoten.
● Perintah trust remove menghapus entri kunci berdasarkan keyid. Setelah kunci
dihapus, verifikasi menggunakan kunci tersebut wajib ditolak.
● Kegagalan penyimpanan trust store tidak boleh merusak berkas sebelumnya. Apabila
trust store tidak dapat dibaca atau tidak sesuai format, program wajib menghentikan
proses verifikasi. Sebagai contoh, implementasi dapat menuliskan perubahan ke
temporary file pada direktori yang sama, memastikan penulisan selesai, kemudian
melakukan rename atau replace terhadap trust store sebelumnya.
Kepercayaan terhadap kunci ditentukan berdasarkan isi trust store pada saat verifikasi.
Pemeriksaan riwayat keabsahan kunci, timestamp, dan identitas berbasis sertifikat bersifat
opsional. Trust store tidak boleh diperbarui secara otomatis berdasarkan kunci atau
informasi dari bundle.
Tugas 3 IF4020-Kriptografi
2026/2027
←Kembali ke Daftar Isi Halaman 21 dari 47 Program Studi Teknik Informatika
Sekolah Teknik Elektro dan Informatika
Institut Teknologi Bandung
Chapter 3: Penandatanganan dan 
Verifikasi Software Release
2 November 2026
2.6 Antarmuka Program
Program wajib menyediakan perintah CLI dengan parameter masukan dan keluaran yang
ditentukan pada Tabel 2.7. Nama executable dibebaskan (minisign digunakan sebagai
contoh pada spesifikasi ini). Seluruh parameter pada tabel wajib disediakan, kecuali
parameter yang dinyatakan opsional. Parameter path mengacu pada berkas atau direktori
lokal.
Tabel 2.7 Subcommand dan parameter CLI
Perintah Parameter Keluaran
keygen -algorithm <profil>
-out <prefix>
<prefix>.key.pem
<prefix>.pub.pem
Fingerprint kunci publik.
sign -file <path>
-package <nama> –-version <versi>
-key <private.pem> -out
<bundle.json>
Bundle pada path -out.
Profil ditentukan dari kunci
privat.
verify -file <path> -bundle
<bundle.json>
-trust-store <trust.json>
-package <nama> -version <versi>
-json (opsional)
Hasil verifikasi. Opsi
-json mengikuti Tabel
2.9.
trust add -key <public.pem> -package <nama>
-store <trust.json>
Izin paket untuk kunci
publik. Trust store dibuat
jika belum tersedia.
Tugas 3 IF4020-Kriptografi
2026/2027
←Kembali ke Daftar Isi Halaman 22 dari 47 Program Studi Teknik Informatika
Sekolah Teknik Elektro dan Informatika
Institut Teknologi Bandung
Chapter 3: Penandatanganan dan 
Verifikasi Software Release
2 November 2026
trust list -store <trust.json> Daftar fingerprint, profil, dan
paket yang diizinkan.
trust remove -keyid <fingerprints>
-store <trust.json>
Entri kunci dihapus. Jika
keyid tidak ditemukan:
exit code 2.
Program wajib menyediakan opsi -help dan -version untuk petunjuk penggunaan dan
nomor versi program. Isi artefak tidak boleh diubah selama proses penandatanganan
maupun verifikasi. Nilai artifact.name diambil dari nama berkas masukan tanpa direktori
(basename) dan wajib diperiksa pada saat verifikasi. Apabila nama berkas diubah, manifest
perlu dibentuk dan ditandatangani kembali. Pemeriksaan artefak dilakukan dengan
membaca byte berkas, tanpa menjalankan atau mengekstrak isinya.
Contoh Penggunaan (shell POSIX)
minisign keygen --algorithm ed25519 --out keys/publisher
minisign trust add --key keys/publisher.pub.pem \
--package contoh-app --store trust.json
minisign sign --file contoh-app.zip --package contoh-app \
--version 1.0.0 --key keys/publisher.key.pem --out release.json
minisign verify --file contoh-app.zip --bundle release.json \
--trust-store trust.json --package contoh-app \
--version 1.0.0 --json
2.7 Alur dan Hasil Verifikasi
Program wajib memeriksa kesesuaian format berkas, kepercayaan terhadap kunci,
keabsahan tanda tangan, serta kesesuaian metadata dan isi artefak. Urutan pemeriksaan
beserta status keluaran yang diperlukan dapat dilihat pada Tabel 2.8. Proses verifikasi
dinyatakan berhasil apabila seluruh pemeriksaan terpenuhi.
Tugas 3 IF4020-Kriptografi
2026/2027
←Kembali ke Daftar Isi Halaman 23 dari 47 Program Studi Teknik Informatika
Sekolah Teknik Elektro dan Informatika
Institut Teknologi Bandung
Chapter 3: Penandatanganan dan 
Verifikasi Software Release
2 November 2026
Gambar 2.2 Skema verifikasi bundle dengan kunci yang dipercaya
Tabel 2.8 Urutan pemeriksaan dan status verifikasi
No
.
Status jika gagal Pemeriksaan
1 INPUT_ERROR Opsi wajib telah diberikan dan seluruh
berkas masukan dapat dibaca. Kegagalan
pemakaian, I/O, atau lingkungan
menghasilkan status ini.
2 FORMAT_ERROR Struktur, tipe data, ukuran, dan serialisasi
bundle, manifest, serta trust store sesuai
ketentuan. Encoding Base64 juga harus
valid. Dukungan profil diperiksa pada
langkah 3.
3 UNSUPPORTED_ALGORITHM Nilai algorithm adalah salah satu profil
pada Tabel 2.1. Nilai string yang tidak
dikenal menghasilkan status ini.
4 KEY_NOT_TRUSTED Trust store memuat keyid yang diminta.
Profil kunci sesuai dengan manifest dan
kunci diizinkan untuk paket yang
diharapkan pengguna.
5 INVALID_SIGNATURE Tanda tangan atas byte manifest sah
menurut profil dan kunci publik tepercaya.
Tugas 3 IF4020-Kriptografi
2026/2027
←Kembali ke Daftar Isi Halaman 24 dari 47 Program Studi Teknik Informatika
Sekolah Teknik Elektro dan Informatika
Institut Teknologi Bandung
Chapter 3: Penandatanganan dan 
Verifikasi Software Release
2 November 2026
Panjang atau encoding tanda tangan yang
tidak sesuai juga menghasilkan status ini.
6 METADATA_MISMATCH Nama paket dan versi pada manifest sama
persis dengan masukan pengguna. Nama
artefak juga sama dengan basename
berkas masukan.
7 ARTIFACT_MISMATCH Ukuran berkas dan SHA-256 hasil
pembacaan artefak sama dengan nilai
pada manifest.
8 OK Seluruh pemeriksaan berhasil.
Ketidaksesuaian tipe, parameter, atau fingerprint kunci pada trust store menghasilkan
FORMAT_ERROR. Perbedaan profil kunci dengan manifest menghasilkan KEY_NOT_TRUSTED.
Program wajib berhenti pada kegagalan pertama tanpa mencoba kunci, profil, atau trust
store lain.
Kunci pada trust store yang memiliki encoding tidak valid, tipe kunci tidak sesuai, parameter
tidak sesuai profil, atau fingerprint yang tidak cocok dengan public_key_pem menghasilkan
FORMAT_ERROR. Kunci yang valid secara format tetapi profilnya berbeda dari nilai algorithm
pada manifest menghasilkan KEY_NOT_TRUSTED.
Pseudocode Verifikasi Rilis
Urutan pemeriksaan berikut mengikuti Tabel 2.8. Fungsi 𝑅(𝑡, 𝑐) membentuk hasil sesuai
Tabel 2.9 dan mengakhiri perintah dengan exit code 𝑐 dengan status 𝑡. Nilai valid hanya
bernilai true untuk status OK.
Tugas 3 IF4020-Kriptografi
2026/2027
←Kembali ke Daftar Isi Halaman 25 dari 47 Program Studi Teknik Informatika
Sekolah Teknik Elektro dan Informatika
Institut Teknologi Bandung
Chapter 3: Penandatanganan dan 
Verifikasi Software Release
2 November 2026
Fungsi ParseStrict membaca bundle dan trust store, men-decode Base64 menjadi 𝑀 dan 𝜎,
serta membaca manifest 𝑚. Struktur, tipe data, field duplikat, batas ukuran, encoding, dan
kunci diperiksa sesuai kontrak. Kesalahan format menghasilkan 𝑅(FORMAT_ERROR, 1) dan
kesalahan I/O pada langkah mana pun menghasilkan 𝑅(INPUT_ERROR, 2). Operasi
Verify𝑎 menggunakan parameter yang sama dengan Sign𝑎 . Panjang, encoding, atau nilai
tanda tangan yang tidak sah menghasilkan false.
Untuk ECDSA, pisahkan r | s menjadi dua nilai 32 byte big-endian dan ubah ke DER jika
API verifikasi pustaka memerlukannya. Nilai r atau s yang berada di luar domain valid
algoritma menghasilkan INVALID_SIGNATURE, selama tanda tangan tetap memenuhi
encoding r | s sepanjang 64 byte.
Tugas 3 IF4020-Kriptografi
2026/2027
←Kembali ke Daftar Isi Halaman 26 dari 47 Program Studi Teknik Informatika
Sekolah Teknik Elektro dan Informatika
Institut Teknologi Bandung
Chapter 3: Penandatanganan dan 
Verifikasi Software Release
2 November 2026
Format Keluaran JSON dan Exit Code
Program wajib menyediakan hasil verifikasi dalam format JSON apabila opsi --json
digunakan. Hasil tersebut ditulis ke stdout sebagai satu objek JSON, diikuti satu karakter
baris baru pada akhir keluaran. Pesan kesalahan atau informasi tambahan ditulis ke stderr.
Struktur hasil verifikasi dan exit code program dapat dilihat pada Tabel 2.9 dan Tabel 2.10.
Tabel 2.9 Struktur hasil verifikasi
Field Tipe Ketentuan
valid boolean Bernilai true jika status OK. Untuk seluruh status
lain, nilainya false.
status string Status akhir pemeriksaan sesuai Tabel 2.8.
message string Penjelasan singkat mengenai hasil pemeriksaan.
Redaksi pesan dibebaskan.
algorithm string/null Profil algoritma yang dibaca dari manifest. Bernilai
null jika belum dapat dibaca.
keyid string/null Fingerprint yang dibaca dari manifest. Bernilai null
jika belum dapat dibaca.
package string/null Nama paket yang dibaca dari manifest. Bernilai
null jika belum dapat dibaca.
version string/null Versi yang dibaca dari manifest. Bernilai null jika
belum dapat dibaca.
Tabel 2.10 Exit code program
Kode Keterangan
0 Perintah berhasil. Khusus verify, seluruh pemeriksaan lulus, valid bernilai true,
dan status bernilai OK.
Tugas 3 IF4020-Kriptografi
2026/2027
←Kembali ke Daftar Isi Halaman 27 dari 47 Program Studi Teknik Informatika
Sekolah Teknik Elektro dan Informatika
Institut Teknologi Bandung
Chapter 3: Penandatanganan dan 
Verifikasi Software Release
2 November 2026
1 Verifikasi ditolak: FORMAT_ERROR, UNSUPPORTED_ALGORITHM, KEY_NOT_TRUSTED,
INVALID_SIGNATURE, METADATA_MISMATCH, atau ARTIFACT_MISMATCH.
2 Terjadi kesalahan pemakaian, I/O, atau lingkungan. Perintah verify -json
menghasilkan status INPUT_ERROR. Kegagalan perintah selain verify juga
menggunakan kode ini.
{
"valid": true,
"status": "OK",
"message": "Tanda tangan dan artefak valid.",
"algorithm": "ed25519",
"keyid": "<fingerprint kunci publik>",
"package": "contoh-app",
"version": "1.0.0"
}
Penerimaan artefak ditentukan berdasarkan nilai valid, status, dan exit code program.
Apabila verifikasi gagal, metadata yang ditampilkan hanya digunakan untuk menjelaskan
hasil pemeriksaan dan tidak boleh dianggap sebagai data yang sah.
2.8 Pengujian dan Analisis Keamanan
Setelah program diimplementasikan, lakukan pengujian untuk menganalisis keandalan dan
tingkat keamanan sistem yang telah Anda rancang. Cakupan pengujian minimum dapat
dilihat pada Tabel 2.11. Skenario U01 dan U14 wajib dilakukan pada ketiga algoritma.
Skenario U02–U13 cukup dilakukan menggunakan sedikitnya satu profil algoritma, kecuali
skenario yang secara khusus berkaitan dengan karakteristik suatu algoritma. Pengujian
interoperabilitas tetap wajib dilakukan pada ketiga algoritma. Setiap pengujian harus
Tugas 3 IF4020-Kriptografi
2026/2027
←Kembali ke Daftar Isi Halaman 28 dari 47 Program Studi Teknik Informatika
Sekolah Teknik Elektro dan Informatika
Institut Teknologi Bandung
Chapter 3: Penandatanganan dan 
Verifikasi Software Release
2 November 2026
disertai berkas masukan, hasil yang diharapkan, hasil pengujian, dan tata cara menjalankan
pengujian tersebut.
Tabel 2.11 Skenario pengujian minimum
ID Skenario
U01 Tandatangani dan verifikasi berkas teks, berkas biner, serta berkas kosong
menggunakan kunci dan metadata yang sesuai.
U02 Ubah satu byte artefak tanpa mengubah ukuran atau nama berkas.
U03 Tambahkan atau hapus byte pada artefak.
U04 Ubah versi pada manifest dan pertahankan aturan serialisasinya. Gunakan tanda
tangan dari manifest sebelum diubah.
U05 Ubah satu bit tanda tangan. Pertahankan panjang tanda tangan dan gunakan
encoding Base64 yang valid.
U06 Gunakan trust store kosong atau hapus kunci penerbit dari trust store sebelum
verifikasi.
U07 Gunakan kunci yang hanya diizinkan untuk paket lain.
U08 Verifikasi bundle sah dengan nama paket yang sesuai dan versi yang berbeda dari
manifest.
U09 Ubah nama berkas artefak tanpa mengubah isinya.
U10 Uji field duplikat, tipe data yang salah, Base64 yang tidak valid, dan manifest yang
melebihi batas ukuran. Setiap kondisi diuji secara terpisah.
U11 Gunakan nilai string algorithm yang tidak didukung pada manifest.
U12 Tandatangani dengan kunci lain pada profil yang sama. Isi keyid sesuai kunci
tersebut, tetapi jangan tambahkan kuncinya ke trust store.
U13 Ubah white space dan urutan field pada JSON bundle. Pertahankan kedua string
Base64 tanpa perubahan.
U14 Tandatangani manifest yang identik sebanyak dua kali menggunakan kunci yang
Tugas 3 IF4020-Kriptografi
2026/2027
←Kembali ke Daftar Isi Halaman 29 dari 47 Program Studi Teknik Informatika
Sekolah Teknik Elektro dan Informatika
Institut Teknologi Bandung
Chapter 3: Penandatanganan dan 
Verifikasi Software Release
2 November 2026
sama. Bandingkan kedua tanda tangan yang dihasilkan dan jelaskan apakah
hasilnya identik atau berbeda berdasarkan karakteristik algoritma serta
mekanisme pembangkitan randomness atau nonce yang digunakan. Kedua bundle
wajib berhasil diverifikasi.
Pengujian dapat menggunakan fitur program, skrip terpisah, atau kakas/pustaka eksternal.
Setiap algoritma wajib menjalani sedikitnya satu pengujian interoperabilitas dengan
implementasi independen atau kakas eksternal. Pada ECDSA, perhatikan perbedaan format
tanda tangan ASN.1 DER dan r | s.
Pengujian Performa
Lakukan pengujian performa menggunakan artefak dengan ukuran beragam (minimal 3
buah artefak). Berkas uji dapat dibuat sendiri, tetapi berkas yang sama wajib digunakan
pada ketiga algoritma. Pengukuran waktu penandatanganan dan verifikasi dilakukan
sebanyak minimum 30 kali, setelah 5 kali pengulangan awal sebagai pemanasan.
Komponen yang diukur dapat dilihat pada Tabel 2.12.
Tabel 2.12 Metrik pengujian performa
Metrik Ketentuan Pengukuran
Pembangkitan Kunci Ukur pembangkitan sedikitnya 5 pasangan kunci per algoritma
dan catat mediannya. Pisahkan pengukuran ini dari operasi
sign dan verify.
Hash Artefak Ukur waktu perhitungan SHA-256 atas byte artefak. Pisahkan
dari waktu operasi kriptografi atas manifest.
Sign / Verify Ukur waktu operasi kriptografi atas byte manifest, termasuk
hash internal algoritma. Kecualikan I/O dan hashing artefak.
Tugas 3 IF4020-Kriptografi
2026/2027
←Kembali ke Daftar Isi Halaman 30 dari 47 Program Studi Teknik Informatika
Sekolah Teknik Elektro dan Informatika
Institut Teknologi Bandung
Chapter 3: Penandatanganan dan 
Verifikasi Software Release
2 November 2026
Catat median dan persentil ke-95 untuk masing-masing
operasi.
Waktu End-to-End Ukur waktu sign dan verify melalui aplikasi lengkap,
termasuk I/O, hashing artefak, parsing, serta penulisan
keluaran. Catat median dan persentil ke-95 untuk
masing-masing command.
Ukuran Catat ukuran kunci publik dan privat dalam DER tanpa enkripsi,
tanda tangan sebelum Base64, serta bundle. Seluruh ukuran
dinyatakan dalam byte.
Cantumkan spesifikasi hardware, sistem operasi, bahasa pemrograman, versi runtime, dan
pustaka pada laporan. Jika lingkungan yang digunakan heterogen, cantumkan semua
spesifikasinya. Gunakan pencatat waktu monotonik agar pengukuran tidak dipengaruhi
perubahan jam sistem, dan selain itu juga, jelaskan metode perhitungan persentil. Sebagai
contoh, metode nearest-rank mengambil P95 pada posisi ceil(0.95 * n) dalam data
terurut, dengan posisi dimulai dari 1.
Terakhir, lakukan analisis keamanan dari program yang sudah Anda buat. Jelaskan pada
laporan langkah apa saja yang Anda lakukan untuk mengurangi security risk dari program
yang telah Anda buat. Sebagai contoh, analisis risiko kebocoran kunci privat, penggunaan
ulang nonce ECDSA, kesalahan parameter, dan penggunaan kunci publik dari sumber yang
tidak dipercaya. Sebagai contoh yang lain, jelaskan apakah rancangan saat ini dapat
mencegah rollback attack. Jika tidak, jelaskan trusted state/informasi tambahan yang
diperlukan untuk mendeteksinya.
2.9 Distribusi dan Integrasi CI/CD
Program wajib didistribusikan sebagai image container siap pakai yang dapat diambil
melalui docker pull. Pengguna pipeline harus dapat menjalankan program tanpa
Tugas 3 IF4020-Kriptografi
2026/2027
←Kembali ke Daftar Isi Halaman 31 dari 47 Program Studi Teknik Informatika
Sekolah Teknik Elektro dan Informatika
Institut Teknologi Bandung
Chapter 3: Penandatanganan dan 
Verifikasi Software Release
2 November 2026
membangun kode sumber, memasang runtime, atau mengunduh dependensi program pada
runner. Registry yang digunakan dibebaskan, misalnya GitHub Container Registry atau
Docker Hub.
Tabel 2.13 Kontrak distribusi dan eksekusi container
Metrik Ketentuan Pengukuran
Release Image Image tersedia pada registry publik dan dapat diambil tanpa
kredensial penilai. Platform minimum: linux/amd64.
Versi dan Digest Identitas rilis: tag versi, misalnya 1.0.0, dan digest sha256.
Keduanya dicantumkan pada README.
Pemakaian: workflow mengunci referensi image berdasarkan
digest. Tag latest saja tidak memenuhi ketentuan.
Entrypoint Bentuk pemanggilan:
docker run -rm <image> <subcommand> .
Container langsung menjalankan CLI pada Tabel 2.7, termasuk
opsi global -help dan -version.
Runtime Dependency Seluruh dependensi program tersedia di dalam image. Setelah
image diambil, perintah kunci, trust store, sign, dan verify dapat
dijalankan dengan -network none.
Akses Berkas Masukan: dibaca melalui bind mount.
Keluaran: ditulis ke direktori runner yang di-mount dan tetap
tersedia setelah container selesai.
Policy: mendukung UID/GID runner melalui -user.
Keluaran dan Exit Code Stdout, stderr, dan exit code program diteruskan ke runner.
Container tidak boleh mengubah kode kegagalan menjadi 0.
Perintah verify -json mengikuti Tabel 2.9 dan Tabel 2.10.
Kunci Privat Kunci diberikan saat eksekusi melalui berkas sementara yang
Tugas 3 IF4020-Kriptografi
2026/2027
←Kembali ke Daftar Isi Halaman 32 dari 47 Program Studi Teknik Informatika
Sekolah Teknik Elektro dan Informatika
Institut Teknologi Bandung
Chapter 3: Penandatanganan dan 
Verifikasi Software Release
2 November 2026
di-mount readonly. Isi kunci tidak boleh tersimpan pada
image, layer build, log, atau artefak keluaran pipeline.
Seluruh perintah wajib dapat dijalankan tanpa interaksi pengguna, prompt konfirmasi, atau
TTY. Kekurangan parameter dan konflik berkas keluaran harus menghasilkan kesalahan yang
jelas, bukan menunggu masukan pengguna. Penimpaan kunci privat hanya boleh dilakukan
melalui opsi eksplisit yang didokumentasikan.
Sertakan Dockerfile atau berkas build container yang setara pada repositori. Image wajib
dibangun dari kode sumber yang sesuai dengan tag rilis tugas. Cantumkan pemetaan versi
program, tag repositori, dan digest image pada README. Penguncian digest menentukan
image yang dijalankan, sehingga kepercayaan terhadap kunci penerbit artefak tetap
ditentukan oleh trust store.
Alur Pipeline dan Pengelolaan Kunci
Sediakan sekurang-kurangnya satu workflow pada layanan CI/CD, misalnya GitHub Actions
atau GitLab CI. Workflow tersebut wajib mengambil image rilis dari registry dan
menggunakannya sebagai kakas penandatanganan serta verifikasi. Alur minimum dapat
dilihat pada Gambar 2.3 dan Tabel 2.14.
Tugas 3 IF4020-Kriptografi
2026/2027
←Kembali ke Daftar Isi Halaman 33 dari 47 Program Studi Teknik Informatika
Sekolah Teknik Elektro dan Informatika
Institut Teknologi Bandung
Chapter 3: Penandatanganan dan 
Verifikasi Software Release
2 November 2026
Gambar 2.3 Penggunaan program pada pipeline CI/CD
Tabel 2.14 Tahapan minimum pipeline pemakai
Tahap Ketentuan
Persiapan Ambil image sesuai digest yang ditetapkan. Siapkan
artefak hasil build serta metadata rilis dari konfigurasi
pipeline.
Penandatanganan Jalankan sign menggunakan kunci privat penerbit dari
secret CI/CD. Simpan artefak dan bundle sebagai
pasangan keluaran rilis.
Verifikasi Jalankan verify -json menggunakan artefak, bundle,
trust store, serta nama paket dan versi yang diharapkan.
Tahap ini tidak menerima kunci privat.
Deployment Tahap ini cukup disimulasikan dengan pembuatan
berkas penanda, tanpa deployment ke service (tetapi
dianjurkan untuk melakukan real deployment ke service).
Tahap publikasi atau deployment harus menggunakan artefak yang sama dengan hasil
verifikasi. Apabila artefak dibangun ulang atau diubah setelah pemeriksaan, proses
penandatanganan dan verifikasi harus diulang.
Kunci untuk demo pipeline harus khusus dibuat bagi pengujian. Kunci privat disimpan
melalui mekanisme secret CI/CD dan ditulis ke berkas sementara dengan akses terbatas,
kemudian dihapus setelah digunakan. Workflow yang memiliki akses ke secret hanya boleh
menjalankan kode dan konfigurasi dari sumber yang dipercaya.
Trust store disiapkan sebelum workflow pemakai dijalankan dan berasal dari konfigurasi
yang dipercaya, bukan dari bundle atau unduhan yang sedang diverifikasi. Pembangkitan
kunci dan penambahan kepercayaan tidak boleh dilakukan secara otomatis untuk membuat
Tugas 3 IF4020-Kriptografi
2026/2027
←Kembali ke Daftar Isi Halaman 34 dari 47 Program Studi Teknik Informatika
Sekolah Teknik Elektro dan Informatika
Institut Teknologi Bandung
Chapter 3: Penandatanganan dan 
Verifikasi Software Release
2 November 2026
suatu rilis lolos verifikasi. Pada runner yang berbeda, nama berkas dan byte artefak harus
tetap sama.
Contoh Pemanggilan pada Runner Linux
Contoh berikut memperlihatkan pemanggilan image dari shell POSIX. Variabel IMAGE berisi
referensi image beserta digest yang telah dipublikasikan. Variabel SIGNING_KEY_FILE berisi
absolute path berkas kunci privat sementara dari secret CI/CD. Artefak tersedia di
dist/contoh-app.zip, sedangkan trust store telah disiapkan di ci/trust.json. Direktori
out menyimpan keluaran yang tetap tersedia setelah container selesai.
set -eu
: "${IMAGE:?mandatory}"
: "${SIGNING_KEY_FILE:?mandatory}"
trap 'rm -f "$SIGNING_KEY_FILE"' 0
mkdir -p out
docker pull "$IMAGE"
docker run --rm --network none \
--user "$(id -u):$(id -g)" \
-v "$PWD/dist:/input:ro" \
-v "$PWD/out:/output" \
-v "$SIGNING_KEY_FILE:/run/signing.key.pem:ro" \
"$IMAGE" sign --file /input/contoh-app.zip \
--package contoh-app --version 1.0.0 \
--key /run/signing.key.pem --out /output/rilis.json
docker run --rm --network none \
--user "$(id -u):$(id -g)" \
-v "$PWD/dist:/input:ro" \
-v "$PWD/out:/output:ro" \
Tugas 3 IF4020-Kriptografi
2026/2027
←Kembali ke Daftar Isi Halaman 35 dari 47 Program Studi Teknik Informatika
Sekolah Teknik Elektro dan Informatika
Institut Teknologi Bandung
Chapter 3: Penandatanganan dan 
Verifikasi Software Release
2 November 2026
-v "$PWD/ci/trust.json:/trust.json:ro" \
"$IMAGE" verify --file /input/contoh-app.zip \
--bundle /output/rilis.json --trust-store /trust.json \
--package contoh-app --version 1.0.0 --json \
> out/verification.json
Pada konfigurasi CI/CD, tahap publikasi atau deployment wajib bergantung pada
keberhasilan tahap verifikasi. Jangan mengabaikan kegagalan verify melalui
continue-on-error, allow_failure, atau | true pada alur rilis. Kegagalan penarikan
image atau eksekusi container juga harus menghentikan alur tersebut. Kode pada Tabel 2.10
berlaku untuk proses program, sehingga kegagalan infrastruktur container dapat
menghasilkan kode non-zero lain.
Pengujian Integrasi CI/CD
Demonstrasikan bahwa image dapat digunakan pada runner yang bersih dan bahwa
keputusan verifikasi benar-benar menentukan kelanjutan pipeline. Cakupan minimum dapat
dilihat pada Tabel 2.15. Skenario C01 wajib dilakukan untuk ketiga algoritma, sedangkan
skenario C02–C04 cukup dilakukan menggunakan sedikitnya satu profil algoritma dan
skenario C05 cukup dilakukan satu kali.
Tabel 2.15 Skenario pengujian Integrasi CI/CD
ID Skenario
C01 Ambil image rilis dari registry, lalu jalankan sign dan verify terhadap artefak sah.
Simulasikan publikasi atau deployment dengan berkas penanda. Jangan
memasang program dari kode sumber.
Tugas 3 IF4020-Kriptografi
2026/2027
←Kembali ke Daftar Isi Halaman 36 dari 47 Program Studi Teknik Informatika
Sekolah Teknik Elektro dan Informatika
Institut Teknologi Bandung
Chapter 3: Penandatanganan dan 
Verifikasi Software Release
2 November 2026
C02 Ubah satu byte artefak setelah sign. Pertahankan ukuran dan nama berkas, lalu
ulangi alur verifikasi.
C03 Verifikasi artefak menggunakan trust store kosong atau kunci yang tidak diizinkan
untuk paket tersebut.
C04 Jalankan verifikasi dengan path artefak yang berkasnya tidak tersedia.
C05 Setelah image diambil, jalankan CLI dengan UID/GID runner, tanpa TTY, dan
menggunakan -network none.
Setiap skenario dijalankan pada direktori keluaran yang bersih agar penanda dari pengujian
sebelumnya tidak memengaruhi hasil. Pengujian negatif harus memeriksa exit code asli dari
proses verifikasi sebelum melaporkan bahwa penolakan berjalan sesuai harapan. Workflow
pengujian boleh berakhir berhasil setelah membuktikan penolakan tersebut, sehingga tahap
publikasi atau deployment yang dilindungi tetap tidak boleh dijalankan.
Sertakan konfigurasi workflow, referensi image beserta digest, log yang telah dibersihkan dari
informasi rahasia, keluaran JSON, dan bukti keberadaan atau ketiadaan penanda untuk
setiap skenario. Tautan workflow run dan salinan hasilnya wajib tersedia pada repositori atau
laporan. Workflow build image dapat dipisahkan dari workflow pemakai, sehingga
menjalankan docker build saja tidak memenuhi pengujian integrasi ini.
2.10 Bonus
1. Video (+5)
2. API documentation (+3)
3. Signed SBOM (+7)
Tugas 3 IF4020-Kriptografi
2026/2027
←Kembali ke Daftar Isi Halaman 37 dari 47 Program Studi Teknik Informatika
Sekolah Teknik Elektro dan Informatika
Institut Teknologi Bandung
Chapter 3: Penandatanganan dan 
Verifikasi Software Release
2 November 2026
Implementasikan fitur penandatanganan dan verifikasi Software Bill of Materials
(SBOM) dalam format JSON. SBOM dapat dibuat sendiri atau dihasilkan
menggunakan kakas eksternal. SBOM ditandatangani sebagai artefak terpisah
menggunakan format bundle yang sama dan wajib memuat nilai SHA-256 artefak
rilis yang dirujuk. Program harus menyediakan perintah tambahan untuk
memverifikasi kedua bundle dan mencocokkan nilai hash tersebut. Pengujian wajib
mencakup perubahan isi SBOM dan penggantian artefak rilis. Format data,
parameter, dan keluaran perintah tambahan dijelaskan dalam tabel pada
dokumentasi. Dan jangan lupa untuk menjelaskan implementasinya pada laporan
dan mencatat hasil pengujiannya pada laporan.
p.s.: Nama dan bentuk subcommand tambahan dibebaskan, tetapi program minimal
harus menyediakan operasi untuk menandatangani SBOM, memverifikasi signature
SBOM, dan memeriksa keterikatan antara SBOM dengan SHA-256 artefak rilis yang
dirujuk.
Nilai bonus maksimum adalah 15 poin. Pengerjaan bonus tidak menggantikan ketentuan
fitur wajib. Fitur tambahan harus tetap menggunakan format manifest, bundle, dan trust store
yang ditentukan serta mempertahankan behaviour dari spesifikasi wajib. Implementasi
package manager, dependency resolution, vulnerability database, dan pembaruan dependensi
otomatis tidak diwajibkan untuk bonus SBOM.
