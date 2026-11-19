# `Nadina.Verify`
[🔗](https://github.com/reletz/IF4020-19-Tubes3/blob/main/lib/nadina/verify.ex#L1)

Tujuh langkah pemeriksaan verifikasi dan hasil JSON (spek Tabel 2.8 sampai 2.10).

Urutan dan status, berhenti pada kegagalan pertama

1. INPUT_ERROR: opsi wajib ada dan semua berkas masukan dapat dibaca
2. FORMAT_ERROR: struktur, tipe, ukuran, dan serialisasi bundle, manifest, trust store
3. UNSUPPORTED_ALGORITHM: nilai algorithm bukan salah satu profil
4. KEY_NOT_TRUSTED: keyid ada di trust store, profil cocok, paket diizinkan
5. INVALID_SIGNATURE: tanda tangan atas byte manifest sah
6. METADATA_MISMATCH: paket, versi, dan nama artefak sesuai masukan
7. ARTIFACT_MISMATCH: ukuran dan SHA-256 artefak sesuai manifest

Hanya kunci dari trust store yang dipakai. Kunci pada bundle tidak ada, dan trust store
tidak pernah diubah oleh verifikasi. Metadata pada hasil (algorithm, keyid, package,
version) hanya untuk menjelaskan hasil dan tidak boleh dianggap sah bila verifikasi gagal.

# `result`

```elixir
@type result() :: %{
  valid: boolean(),
  status: status(),
  message: String.t(),
  algorithm: String.t() | nil,
  keyid: String.t() | nil,
  package: String.t() | nil,
  version: String.t() | nil
}
```

# `status`

```elixir
@type status() ::
  :ok
  | :input_error
  | :format_error
  | :unsupported_algorithm
  | :key_not_trusted
  | :invalid_signature
  | :metadata_mismatch
  | :artifact_mismatch
```

# `exit_code`

```elixir
@spec exit_code(result()) :: 0 | 1 | 2
```

Exit code untuk hasil verifikasi: 0 bila OK, 2 untuk INPUT_ERROR, selain itu 1.

# `run`

```elixir
@spec run(keyword()) :: result()
```

Menjalankan verifikasi. Opsi: file, bundle, trust_store, package, version.

# `status_name`

```elixir
@spec status_name(status()) :: String.t()
```

Nama status sebagaimana tertulis pada keluaran JSON.

# `to_json`

```elixir
@spec to_json(result()) :: binary()
```

Hasil verifikasi sebagai objek JSON (satu baris, diakhiri baris baru).

---

*Consult [api-reference.md](api-reference.md) for complete listing*
