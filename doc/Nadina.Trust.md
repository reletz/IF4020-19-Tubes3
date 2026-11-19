# `Nadina.Trust`
[🔗](https://github.com/reletz/IF4020-19-Tubes3/blob/main/lib/nadina/trust.ex#L1)

Pengelolaan trust store (spek Tabel 2.6) dengan penulisan atomik.

Format berkas

    {"schema":"minisign-trust/v1","keys":[
      {"keyid":"...","algorithm":"...","public_key_pem":"...","packages":["..."]}]}

parse/1 memeriksa struktur, tipe, keunikan keyid, daftar paket (tidak kosong, tanpa
duplikat, tanpa wildcard), serta kesesuaian profil dan fingerprint dengan kunci publik.
Semua kegagalan format menghasilkan error, yang bagi verifier berarti FORMAT_ERROR.

Trust store hanya berubah lewat add/3 dan remove/2. Tidak ada pembaruan otomatis
dari bundle. Perubahan ditulis ke berkas sementara di direktori yang sama lalu rename,
sehingga berkas lama tidak rusak bila penulisan gagal.

# `error`

```elixir
@type error() ::
  :too_large
  | :invalid_json
  | :invalid_schema
  | :invalid_entry
  | :duplicate_keyid
  | :keyid_not_found
  | {:io, File.posix()}
```

# `t`

```elixir
@type t() :: [Nadina.Trust.Entry.t()]
```

# `add`

```elixir
@spec add(t(), Nadina.Profile.public_key(), module(), String.t()) ::
  {:ok, t(), Nadina.Trust.Entry.t()} | {:error, :invalid_package}
```

Menambahkan izin paket untuk kunci publik. Kunci baru dibuat sebagai entri baru, kunci
yang sudah ada diperbarui daftar paketnya. Pasangan keyid dan paket yang sama tidak
menambah apa pun (idempoten).

# `empty`

```elixir
@spec empty() :: t()
```

Trust store kosong. Tidak memberi kepercayaan kepada kunci mana pun.

# `encode`

```elixir
@spec encode(t()) :: binary()
```

Serialisasi trust store ke JSON.

# `find`

```elixir
@spec find(t(), String.t()) :: Nadina.Trust.Entry.t() | nil
```

Mencari entri berdasarkan keyid.

# `load`

```elixir
@spec load(Path.t()) :: {:ok, t()} | {:error, error()}
```

Membaca dan memparse trust store dari berkas. Berkas yang tidak ada atau tidak dapat
dibaca menghasilkan error io.

# `load_or_empty`

```elixir
@spec load_or_empty(Path.t()) :: {:ok, t()} | {:error, error()}
```

Seperti load/1, tetapi berkas yang belum ada dianggap trust store kosong. Dipakai
oleh trust add, yang membuat trust store bila belum tersedia.

# `parse`

```elixir
@spec parse(binary()) :: {:ok, t()} | {:error, error()}
```

Parse strict isi berkas trust store.

## Contoh

    iex> Nadina.Trust.parse(~s({"schema":"minisign-trust/v1","keys":[]}))
    {:ok, []}

    iex> Nadina.Trust.parse(~s({"schema":"minisign-trust/v1","keys":[],"x":1}))
    {:error, :invalid_json}

# `remove`

```elixir
@spec remove(t(), String.t() | [String.t()]) ::
  {:ok, t()} | {:error, :keyid_not_found}
```

Menghapus entri berdasarkan satu atau beberapa keyid.

# `save`

```elixir
@spec save(Path.t(), t()) :: :ok | {:error, error()}
```

Menulis trust store secara atomik: berkas sementara pada direktori yang sama, lalu rename.
Berkas lama tetap utuh bila penulisan gagal.

---

*Consult [api-reference.md](api-reference.md) for complete listing*
