# `Nadina.Manifest`
[🔗](https://github.com/reletz/IF4020-19-Tubes3/blob/main/lib/nadina/manifest.ex#L1)

Release manifest (spek Tabel 2.3): pembentukan, serialisasi canonical, dan parse strict.

Byte hasil `serialize/1` adalah pesan M yang ditandatangani. Saat verifikasi, `parse/1`
menerima byte M apa adanya dari bundle, memeriksa ukuran, struktur, nilai field, lalu
membandingkan M byte-for-byte dengan hasil serialisasi ulang. Semua kesalahan `parse/1`
berarti `FORMAT_ERROR`.

Nilai `algorithm` yang bukan salah satu profil tetap lolos `parse/1` asalkan berupa string
ASCII yang bisa ditulis tanpa escape, karena spek memisahkannya sebagai
`UNSUPPORTED_ALGORITHM`. Gunakan `supported_algorithm?/1` untuk langkah itu.

# `field_path`

```elixir
@type field_path() :: [String.t()]
```

# `parse_error`

```elixir
@type parse_error() ::
  {:too_large, pos_integer()}
  | Nadina.StrictJSON.decode_error()
  | Nadina.StrictJSON.validate_error()
  | {:invalid_field, field_path()}
  | :not_canonical
```

# `t`

```elixir
@type t() :: %Nadina.Manifest{
  algorithm: String.t(),
  artifact_name: String.t(),
  artifact_sha256: String.t(),
  artifact_size: non_neg_integer(),
  keyid: String.t(),
  package: String.t(),
  version: String.t()
}
```

# `algorithms`

```elixir
@spec algorithms() :: [String.t()]
```

Daftar profil algoritma yang didukung (spek Tabel 2.1).

# `max_size`

```elixir
@spec max_size() :: pos_integer()
```

Ukuran maksimum manifest dalam byte (16 KiB).

# `new`

```elixir
@spec new(
  String.t(),
  String.t(),
  String.t(),
  String.t(),
  String.t(),
  non_neg_integer(),
  String.t()
) ::
  {:ok, t()}
  | {:error, {:invalid_field, field_path()} | {:unsupported_algorithm, term()}}
```

Membentuk manifest dengan urutan argumen sesuai spek: paket, versi, profil, fingerprint,
nama artefak, ukuran, dan hash. Dipakai saat sign, sehingga profil wajib didukung.

# `parse`

```elixir
@spec parse(binary()) :: {:ok, t()} | {:error, parse_error()}
```

Parse strict byte manifest dari bundle. Urutan pemeriksaan: ukuran (sebelum parsing),
JSON strict dan struktur, nilai field, lalu kesesuaian serialisasi canonical.

# `serialize`

```elixir
@spec serialize(t()) :: binary()
```

Serialisasi canonical: urutan field tetap, tanpa white space, tanpa escape, tanpa baris
baru di akhir. Hanya untuk manifest yang sudah lolos `new/7` atau `parse/1`.

# `supported_algorithm?`

```elixir
@spec supported_algorithm?(String.t()) :: boolean()
```

Apakah `algorithm` termasuk profil yang didukung.

    iex> Nadina.Manifest.supported_algorithm?("ed25519")
    true
    iex> Nadina.Manifest.supported_algorithm?("rsa-pkcs1-sha256")
    false

---

*Consult [api-reference.md](api-reference.md) for complete listing*
