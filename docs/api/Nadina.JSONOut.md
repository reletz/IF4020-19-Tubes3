# `Nadina.JSONOut`
[🔗](https://github.com/reletz/IF4020-19-Tubes3/blob/main/lib/nadina/json_out.ex#L1)

Penulis JSON kecil untuk keluaran program (hasil verifikasi dan trust store).

Objek ditulis sebagai daftar pasangan agar urutan field tetap. String di-escape sesuai
RFC 8259, dan karakter non-ASCII ditulis langsung sebagai UTF-8.

# `t`

```elixir
@type t() ::
  nil
  | boolean()
  | integer()
  | String.t()
  | [t()]
  | {:object, [{String.t(), t()}]}
```

# `encode`

```elixir
@spec encode(t()) :: binary()
```

Mengubah nilai menjadi JSON tanpa white space.

## Contoh

    iex> Nadina.JSONOut.encode({:object, [{"a", 1}, {"b", [true, nil]}, {"c", "x\ny"}]})
    ~s({"a":1,"b":[true,null],"c":"x\\ny"})

---

*Consult [api-reference.md](api-reference.md) for complete listing*
