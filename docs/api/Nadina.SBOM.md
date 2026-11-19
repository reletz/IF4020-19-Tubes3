# `Nadina.SBOM`
[🔗](https://github.com/reletz/IF4020-19-Tubes3/blob/main/lib/nadina/sbom.ex#L1)

Pengikatan SBOM ke artefak rilis (bonus spek 2.10).

SBOM dibuat oleh kakas eksternal, misalnya Trivy, Syft, atau cdxgen, dalam format apa
pun yang berupa objek JSON. Nadina tidak menafsirkan isinya dan hanya memastikan bahwa
byte SBOM tersimpan utuh dan terikat ke artefak rilis.

Wrapper minisign-sbom/v1 memuat subject (name, size, sha256 artefak rilis) dan
sbom_b64 (Base64 standar dari byte SBOM asli, tanpa perubahan). Wrapper inilah yang
ditandatangani sebagai artefak dengan alur sign biasa, sehingga bundle SBOM memakai format
bundle yang sama.

Verifikasi memeriksa dua bundle, yaitu bundle wrapper dan bundle rilis, lalu mencocokkan
subject dengan artefak rilis dan memastikan sbom_b64 berisi objek JSON.

# `subject`

```elixir
@type subject() :: %{name: String.t(), size: non_neg_integer(), sha256: String.t()}
```

# `bind`

```elixir
@spec bind(Path.t(), Path.t()) ::
  {:ok, binary()}
  | {:error, :not_json_object | :too_large | {:io, File.posix()}}
```

Membaca berkas artefak dan berkas SBOM, lalu membentuk wrapper. Berkas yang tidak
dapat dibaca menghasilkan error io.

# `extract`

```elixir
@spec extract(binary()) ::
  {:ok, subject(), binary()} | {:error, :too_large | :invalid_sbom}
```

Mengambil subject dan byte SBOM asli dari wrapper. Tidak melakukan perubahan apa pun
pada byte SBOM.

# `max_sbom_size`

```elixir
@spec max_sbom_size() :: pos_integer()
```

Ukuran maksimum SBOM eksternal dalam byte (16 MiB).

# `verify`

```elixir
@spec verify(keyword()) :: Nadina.Verify.result()
```

Memverifikasi wrapper dan rilis. Langkah dijalankan berurutan dan berhenti pada
kegagalan pertama.

1. Bundle wrapper diverifikasi terhadap berkas wrapper, dengan trust store dan paket
   yang sama.
2. Bundle rilis diverifikasi terhadap artefak rilis.
3. Subject harus merujuk artefak rilis, dan sbom_b64 harus berupa objek JSON.

Opsi: sbom (berkas wrapper), sbom_bundle, file, bundle, trust_store, package, version.
Hasil memakai bentuk yang sama dengan Verify.run/1.

# `wrap`

```elixir
@spec wrap(String.t(), binary(), non_neg_integer(), String.t()) ::
  {:ok, binary()} | {:error, :not_json_object | :too_large}
```

Membungkus SBOM eksternal dengan subject artefak. Byte SBOM harus berupa objek JSON
dan tidak lebih dari 16 MiB. Mengembalikan JSON wrapper tanpa baris baru di akhir.

## Contoh

    iex> {:error, reason} = Nadina.SBOM.wrap("contoh.zip", "bukan json", 10, "0")
    iex> reason
    :not_json_object

---

*Consult [api-reference.md](api-reference.md) for complete listing*
