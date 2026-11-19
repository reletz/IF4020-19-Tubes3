# `Nadina.Artifact`
[🔗](https://github.com/reletz/IF4020-19-Tubes3/blob/main/lib/nadina/artifact.ex#L1)

Pembacaan artefak: ukuran dan SHA-256 dari byte berkas.

Berkas dibaca sebagai byte apa adanya, per potongan, tanpa normalisasi dan tanpa
menjalankan atau mengekstrak isinya.

# `digest`

```elixir
@spec digest(Path.t()) ::
  {:ok, non_neg_integer(), String.t()} | {:error, {:io, File.posix()}}
```

Menghitung ukuran dan SHA-256 (hex huruf kecil) dari berkas.

## Contoh

    iex> path = Path.join(System.tmp_dir!(), "nadina-artifact-doctest")
    iex> File.write!(path, "")
    iex> Nadina.Artifact.digest(path)
    {:ok, 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}

---

*Consult [api-reference.md](api-reference.md) for complete listing*
