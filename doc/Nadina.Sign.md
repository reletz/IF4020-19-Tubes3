# `Nadina.Sign`
[🔗](https://github.com/reletz/IF4020-19-Tubes3/blob/main/lib/nadina/sign.ex#L1)

Alur penandatanganan: baca artefak, bentuk manifest, tandatangani byte manifest, tulis
bundle.

Profil ditentukan dari kunci privat. Nilai artifact.name diambil dari basename berkas
masukan. SHA-256 atas byte artefak dihitung terpisah dan dicatat pada manifest, sedangkan
yang ditandatangani adalah seluruh byte manifest M. Isi kunci privat tidak pernah
dicatat atau ditulis ke bundle.

# `reason`

```elixir
@type reason() ::
  Nadina.Keys.reason()
  | {:io, File.posix()}
  | {:invalid_field, Nadina.Manifest.field_path()}
  | {:unsupported_algorithm, term()}
```

# `run`

```elixir
@spec run(keyword()) ::
  {:ok, %{bundle: Path.t(), keyid: String.t(), algorithm: String.t()}}
  | {:error, reason()}
```

Menandatangani berkas. Opsi wajib: file, package, version, key, out. Hasil sukses
berisi path bundle, keyid, dan profil.

---

*Consult [api-reference.md](api-reference.md) for complete listing*
