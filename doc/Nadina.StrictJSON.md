# `Nadina.StrictJSON`
[🔗](https://github.com/reletz/IF4020-19-Tubes3/blob/main/lib/nadina/strict_json.ex#L1)

Parser JSON strict (RFC 8259) untuk manifest, bundle, dan trust store.

Dibandingkan parser JSON umum, `decode/1` menolak:

  * duplicate key pada objek mana pun (dideteksi saat parsing, sebelum nilainya dibaca),
  * nilai `null` di posisi mana pun,
  * bilangan pecahan atau eksponen (hanya integer yang diterima), leading zero, dan `-0`,
  * BOM UTF-8 di awal masukan,
  * UTF-8 tidak valid, karakter kontrol di dalam string, escape tidak sah, dan surrogate
    tunggal,
  * data apa pun setelah nilai pertama (selain white space),
  * kedalaman bersarang lebih dari 32 level.

Pemeriksaan bentuk dokumen (field wajib, field tambahan, dan tipe) dilakukan oleh
`validate/2` atau `decode_as/2` dengan skema sederhana. Batas ukuran (16 KiB manifest,
64 KiB bundle) dicek oleh pemanggil sebelum `decode/1`, dan serialisasi canonical
dicek oleh `Nadina.Manifest`.

Objek didekode menjadi map dengan key string, array menjadi list.

# `decode_error`

```elixir
@type decode_error() ::
  {:not_binary, 0}
  | {:bom_not_allowed, offset()}
  | {:unexpected_end, offset()}
  | {:unexpected_byte, offset()}
  | {:trailing_data, offset()}
  | {:null_not_allowed, offset()}
  | {:duplicate_key, String.t(), offset()}
  | {:invalid_number, offset()}
  | {:non_integer_number, offset()}
  | {:control_character, offset()}
  | {:invalid_escape, offset()}
  | {:invalid_surrogate, offset()}
  | {:invalid_utf8, offset()}
  | {:too_deep, offset()}
```

# `offset`

```elixir
@type offset() :: non_neg_integer()
```

Offset byte (mulai dari 0) pada masukan tempat kesalahan ditemukan.

# `path`

```elixir
@type path() :: [String.t() | non_neg_integer()]
```

Lokasi nilai di dokumen, berupa daftar key objek dan indeks array.

# `schema`

```elixir
@type schema() ::
  :string
  | :integer
  | :boolean
  | {:array, schema()}
  | {:object, [{String.t(), schema()}]}
```

Skema untuk `validate/2`.

`{:object, fields}` mewajibkan tepat field yang disebut (tidak kurang, tidak lebih).
Urutan di `fields` menentukan urutan pemeriksaan, bukan urutan yang wajib di dokumen.

# `validate_error`

```elixir
@type validate_error() ::
  {:missing_field, path()}
  | {:unknown_field, path()}
  | {:wrong_type, path(), :string | :integer | :boolean | :array | :object}
```

# `value`

```elixir
@type value() ::
  String.t()
  | integer()
  | boolean()
  | [value()]
  | %{optional(String.t()) =&gt; value()}
```

Nilai JSON hasil decode. Tidak ada `nil` karena `null` ditolak.

# `decode`

```elixir
@spec decode(binary()) :: {:ok, value()} | {:error, decode_error()}
```

Mendekode `input` secara strict.

## Contoh

    iex> Nadina.StrictJSON.decode(~s({"a":[1,true]}))
    {:ok, %{"a" => [1, true]}}

    iex> Nadina.StrictJSON.decode(~s({"a":1,"a":2}))
    {:error, {:duplicate_key, "a", 7}}

    iex> Nadina.StrictJSON.decode(~s({"a":null}))
    {:error, {:null_not_allowed, 5}}

    iex> Nadina.StrictJSON.decode("{} {}")
    {:error, {:trailing_data, 3}}

# `decode_as`

```elixir
@spec decode_as(binary(), schema()) ::
  {:ok, value()} | {:error, decode_error() | validate_error()}
```

Mendekode lalu memvalidasi terhadap `schema`. Kesalahan decode dilaporkan lebih dulu.

## Contoh

    iex> Nadina.StrictJSON.decode_as(~s({"n":1}), {:object, [{"n", :integer}]})
    {:ok, %{"n" => 1}}

    iex> Nadina.StrictJSON.decode_as(~s({"n":true}), {:object, [{"n", :integer}]})
    {:error, {:wrong_type, ["n"], :integer}}

# `validate`

```elixir
@spec validate(value(), schema()) :: :ok | {:error, validate_error()}
```

Memeriksa bahwa `value` sesuai `schema`: semua field wajib ada, tidak ada field tambahan,
dan tipe setiap nilai tepat. Boolean tidak diterima sebagai integer (dan sebaliknya).

Kesalahan pertama yang ditemukan dikembalikan beserta path-nya. Field diperiksa dalam
urutan skema, lalu field tambahan (urut abjad).

## Contoh

    iex> schema = {:object, [{"name", :string}, {"tags", {:array, :string}}]}
    iex> Nadina.StrictJSON.validate(%{"name" => "a", "tags" => ["x"]}, schema)
    :ok
    iex> Nadina.StrictJSON.validate(%{"name" => "a"}, schema)
    {:error, {:missing_field, ["tags"]}}
    iex> Nadina.StrictJSON.validate(%{"name" => "a", "tags" => [1]}, schema)
    {:error, {:wrong_type, ["tags", 0], :string}}

---

*Consult [api-reference.md](api-reference.md) for complete listing*
