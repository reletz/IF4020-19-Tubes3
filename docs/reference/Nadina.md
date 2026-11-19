# `Nadina`
[🔗](https://github.com/reletz/IF4020-19-Tubes3/blob/main/lib/nadina.ex#L1)

Nadina: penandatanganan dan verifikasi software release (RSA-PSS, ECDSA P-256, Ed25519).

Alur: artefak dihitung SHA-256-nya dan dicatat pada release manifest. Byte manifest
ditandatangani, lalu manifest dan tanda tangan disimpan pada satu bundle. Verifikasi
memakai trust store yang dikelola pengguna.

Modul utama

- Nadina.CLI antarmuka baris perintah
- Nadina.Keys kunci, PEM, fingerprint
- Nadina.Profile kontrak profil algoritma
- Nadina.Manifest dan Nadina.Bundle format data
- Nadina.Sign, Nadina.Verify, Nadina.Trust alur utama

# `version`

```elixir
@spec version() :: String.t()
```

Nomor versi program.

## Contoh

    iex> Nadina.version() =~ ~r/^\d+\.\d+\.\d+/
    true

---

*Consult [api-reference.md](api-reference.md) for complete listing*
