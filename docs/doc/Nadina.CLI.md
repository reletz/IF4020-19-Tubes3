# `Nadina.CLI`
[🔗](https://github.com/reletz/IF4020-19-Tubes3/blob/main/lib/nadina/cli.ex#L1)

Antarmuka baris perintah (spek Tabel 2.7): keygen, sign, verify, dan trust.

Opsi boleh ditulis dengan satu atau dua tanda hubung (-key atau --key). Semua perintah
non-interaktif dan tidak membaca stdin.

Exit code: 0 berhasil, 1 verifikasi ditolak, 2 kesalahan pemakaian, I/O, atau
lingkungan. Hasil ditulis ke stdout dan pesan kesalahan ke stderr. stdout di-flush
sebelum program berhenti.

# `main`

```elixir
@spec main([String.t()]) :: no_return()
```

Titik masuk dari bin/nadina eval. Tidak kembali, memanggil halt.

# `run`

```elixir
@spec run([String.t()]) :: {0 | 1 | 2, String.t(), String.t()}
```

Menjalankan perintah tanpa efek halt. Mengembalikan exit code, isi stdout, dan isi stderr.

## Contoh

    iex> {code, out, _err} = Nadina.CLI.run(["-version"])
    iex> {code, out == Nadina.version() <> "\n"}
    {0, true}

    iex> {code, _out, err} = Nadina.CLI.run(["bukan-perintah"])
    iex> {code, err =~ "tidak dikenal"}
    {2, true}

---

*Consult [api-reference.md](api-reference.md) for complete listing*
