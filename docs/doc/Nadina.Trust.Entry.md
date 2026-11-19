# `Nadina.Trust.Entry`
[🔗](https://github.com/reletz/IF4020-19-Tubes3/blob/main/lib/nadina/trust.ex#L40)

Satu entri kunci pada trust store.

# `t`

```elixir
@type t() :: %Nadina.Trust.Entry{
  algorithm: String.t(),
  keyid: String.t(),
  packages: [String.t()],
  public_key: Nadina.Profile.public_key(),
  public_key_pem: String.t()
}
```

---

*Consult [api-reference.md](api-reference.md) for complete listing*
