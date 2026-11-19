# `Nadina.Bundle`
[🔗](https://github.com/reletz/IF4020-19-Tubes3/blob/main/lib/nadina/bundle.ex#L1)

Bundle tanda tangan (spek Tabel 2.4): byte manifest M dan tanda tangan, keduanya Base64.

`parse/1` hanya memeriksa format bundle. Isi manifest diperiksa `Nadina.Manifest.parse/1`,
panjang tanda tangan diperiksa saat verifikasi tanda tangan.

# `parse_error`

```elixir
@type parse_error() ::
  {:too_large, pos_integer()}
  | Nadina.StrictJSON.decode_error()
  | Nadina.StrictJSON.validate_error()
  | {:invalid_field, [String.t()]}
  | {:invalid_base64, [String.t()]}
```

# `t`

```elixir
@type t() :: %Nadina.Bundle{manifest: binary(), signature: binary()}
```

# `encode`

```elixir
@spec encode(t()) :: binary()
```

Encode bundle ke JSON.

    iex> Nadina.Bundle.encode(%Nadina.Bundle{manifest: "a", signature: "bc"})
    ~s({"schema":"minisign-bundle/v1","manifest_b64":"YQ==","signature_b64":"YmM="}\n)

# `max_size`

```elixir
@spec max_size() :: pos_integer()
```

Ukuran maksimum bundle dalam byte (64 KiB).

# `parse`

```elixir
@spec parse(binary()) :: {:ok, t()} | {:error, parse_error()}
```

Parse strict bundle. Ukuran dicek sebelum parsing.

---

*Consult [api-reference.md](api-reference.md) for complete listing*
