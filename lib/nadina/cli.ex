defmodule Nadina.CLI do
  @moduledoc """
  Antarmuka baris perintah (spek Tabel 2.7): keygen, sign, verify, dan trust.

  Opsi boleh ditulis dengan satu atau dua tanda hubung (-key atau --key). Semua perintah
  non-interaktif dan tidak membaca stdin.

  Exit code: 0 berhasil, 1 verifikasi ditolak, 2 kesalahan pemakaian, I/O, atau
  lingkungan. Hasil ditulis ke stdout dan pesan kesalahan ke stderr. stdout di-flush
  sebelum program berhenti.
  """

  alias Nadina.{Keys, Sign, Trust, Verify}

  @usage """
  Pemakaian: nadina <perintah> [opsi]

  Perintah
    keygen        -algorithm <profil> -out <prefix> [-force]
    sign          -file <path> -package <nama> -version <versi> -key <private.pem> -out <bundle.json>
    verify        -file <path> -bundle <bundle.json> -trust-store <trust.json>
                  -package <nama> -version <versi> [-json]
    trust add     -key <public.pem> -package <nama> -store <trust.json>
    trust list    -store <trust.json>
    trust remove  -keyid <fingerprint> -store <trust.json>

  Profil: rsa-pss-sha256, ecdsa-p256-sha256, ed25519

  Opsi global
    -help         tampilkan petunjuk ini
    -version      tampilkan nomor versi program
  """

  @doc "Titik masuk dari bin/nadina eval. Tidak kembali, memanggil halt."
  @spec main([String.t()]) :: no_return()
  def main(argv) do
    {code, stdout, stderr} = run(argv)
    :ok = IO.write(:stdio, stdout)
    :ok = IO.write(:stderr, stderr)
    :erlang.halt(code, flush: true)
  end

  @doc """
  Menjalankan perintah tanpa efek halt. Mengembalikan exit code, isi stdout, dan isi stderr.

  ## Contoh

      iex> {code, out, _err} = Nadina.CLI.run(["-version"])
      iex> {code, out == Nadina.version() <> "\\n"}
      {0, true}

      iex> {code, _out, err} = Nadina.CLI.run(["bukan-perintah"])
      iex> {code, err =~ "tidak dikenal"}
      {2, true}
  """
  @spec run([String.t()]) :: {0 | 1 | 2, String.t(), String.t()}
  def run(argv) do
    case normalize(argv) do
      [flag] when flag in ["--version"] -> {0, Nadina.version() <> "\n", ""}
      [flag] when flag in ["--help", "-h"] -> {0, @usage, ""}
      [] -> {2, "", "Perintah tidak diberikan.\n\n" <> @usage}
      ["--help" | _] -> {0, @usage, ""}
      [cmd | rest] -> dispatch(cmd, rest)
    end
  end

  # -key menjadi --key, -key=nilai menjadi --key=nilai. Nilai opsi tidak diubah.
  defp normalize(argv), do: normalize(argv, false, [])

  defp normalize([], _, acc), do: Enum.reverse(acc)

  defp normalize([arg | rest], _expect_value, acc) do
    cond do
      match?("--" <> _, arg) -> normalize(rest, false, [arg | acc])
      Regex.match?(~r/\A-[A-Za-z][A-Za-z-]+/, arg) -> normalize(rest, false, ["-" <> arg | acc])
      true -> normalize(rest, false, [arg | acc])
    end
  end

  defp dispatch("keygen", args), do: keygen(args)
  defp dispatch("sign", args), do: sign(args)
  defp dispatch("verify", args), do: verify(args)
  defp dispatch("trust", [sub | args]) when sub in ["add", "list", "remove"], do: trust(sub, args)
  defp dispatch("trust", _), do: usage_error("Subperintah trust tidak dikenal atau kosong.")
  defp dispatch(cmd, _), do: usage_error("Perintah tidak dikenal: #{cmd}.")

  # ---- parsing opsi

  defp parse(args, strict) do
    case OptionParser.parse(args, strict: strict) do
      {opts, [], []} ->
        {:ok, opts}

      {_, extra, []} when extra != [] ->
        {:error, "Argumen tidak dikenal: #{Enum.join(extra, " ")}."}

      {_, _, [{name, _} | _]} ->
        {:error, "Opsi tidak dikenal atau nilainya hilang: #{name}."}
    end
  end

  defp require_opts(opts, names) do
    case Enum.find(names, &(not is_binary(opts[&1]) or opts[&1] == "")) do
      nil -> :ok
      missing -> {:error, "Opsi wajib tidak diberikan: --#{opt_name(missing)}."}
    end
  end

  defp opt_name(atom), do: atom |> Atom.to_string() |> String.replace("_", "-")

  defp usage_error(message), do: {2, "", message <> "\nGunakan -help untuk petunjuk.\n"}

  defp with_opts(args, strict, required, fun) do
    with {:ok, opts} <- parse(args, strict),
         :ok <- require_opts(opts, required) do
      fun.(opts)
    else
      {:error, message} -> usage_error(message)
    end
  end

  # ---- keygen

  defp keygen(args) do
    strict = [algorithm: :string, out: :string, force: :boolean]
    with_opts(args, strict, [:algorithm, :out], &do_keygen/1)
  end

  defp do_keygen(opts) do
    with {:ok, _mod, priv, pub} <- Keys.generate(opts[:algorithm]) |> map_error(),
         {:ok, fingerprint} <-
           Keys.write_keypair(opts[:out], priv, pub, force: opts[:force] == true) |> map_error() do
      {0, fingerprint <> "\n", ""}
    else
      {:error, message} -> fail(message)
    end
  end

  # ---- sign

  defp sign(args) do
    strict = [file: :string, package: :string, version: :string, key: :string, out: :string]
    with_opts(args, strict, [:file, :package, :version, :key, :out], &do_sign/1)
  end

  defp do_sign(opts) do
    case Sign.run(opts) do
      {:ok, %{keyid: keyid, algorithm: algorithm}} ->
        {0, "Bundle ditulis ke #{opts[:out]}\nkeyid: #{keyid}\nalgorithm: #{algorithm}\n", ""}

      {:error, reason} ->
        fail(describe(reason))
    end
  end

  # ---- verify

  defp verify(args) do
    strict = [
      file: :string,
      bundle: :string,
      trust_store: :string,
      package: :string,
      version: :string,
      json: :boolean
    ]

    case parse(args, strict) do
      {:ok, opts} -> verify_output(opts, Verify.run(opts))
      {:error, message} -> verify_usage_error(args, message)
    end
  end

  defp verify_output(opts, result) do
    code = Verify.exit_code(result)

    cond do
      opts[:json] == true -> {code, Verify.to_json(result), ""}
      code == 2 -> {code, "", result.message <> "\n"}
      true -> {code, human(result), ""}
    end
  end

  defp verify_usage_error(args, message) do
    if json_requested?(args) do
      result = %{Verify.run([]) | message: message}
      {2, Verify.to_json(result), message <> "\n"}
    else
      usage_error(message)
    end
  end

  defp json_requested?(args), do: Enum.any?(args, &(&1 in ["--json", "--json=true"]))

  defp human(%{valid: true} = r),
    do: "OK #{r.package} #{r.version} (#{r.algorithm}, #{r.keyid})\n"

  defp human(%{status: :input_error}), do: ""
  defp human(r), do: "#{Verify.status_name(r.status)}: #{r.message}\n"

  # ---- trust

  defp trust("add", args) do
    with_opts(
      args,
      [key: :string, package: :string, store: :string],
      [:key, :package, :store],
      &trust_add/1
    )
  end

  defp trust("list", args), do: with_opts(args, [store: :string], [:store], &trust_list/1)

  defp trust("remove", args) do
    with_opts(args, [keyid: :string, store: :string], [:keyid, :store], &trust_remove/1)
  end

  defp trust_add(opts) do
    with {:ok, mod, pub} <- Keys.load_public_file(opts[:key]) |> map_error(),
         {:ok, entries} <- Trust.load_or_empty(opts[:store]) |> map_error(),
         {:ok, entries, entry} <- Trust.add(entries, pub, mod, opts[:package]) |> map_error(),
         :ok <- Trust.save(opts[:store], entries) |> map_error() do
      {0, "keyid: #{entry.keyid}\nalgorithm: #{entry.algorithm}\npackage: #{opts[:package]}\n",
       ""}
    else
      {:error, message} -> fail(message)
    end
  end

  defp trust_list(opts) do
    case Trust.load(opts[:store]) do
      {:ok, entries} ->
        lines =
          for e <- entries, do: "#{e.keyid}  #{e.algorithm}  #{Enum.join(e.packages, ",")}\n"

        {0, Enum.join(lines), ""}

      {:error, reason} ->
        fail(describe(reason))
    end
  end

  defp trust_remove(opts) do
    with {:ok, entries} <- Trust.load(opts[:store]) |> map_error(),
         {:ok, entries} <- Trust.remove(entries, opts[:keyid]) |> map_error(),
         :ok <- Trust.save(opts[:store], entries) |> map_error() do
      {0, "Dihapus: #{opts[:keyid]}\n", ""}
    else
      {:error, message} -> fail(message)
    end
  end

  defp map_error({:error, reason}), do: {:error, describe(reason)}
  defp map_error(other), do: other

  defp fail(message), do: {2, "", message <> "\n"}

  # ---- pesan kesalahan. Tidak pernah memuat isi kunci.

  defp describe(:exists), do: "Berkas keluaran sudah ada. Gunakan -force untuk menimpa."
  defp describe(:invalid_pem), do: "Berkas kunci bukan PEM yang sah."
  defp describe(:unsupported_key), do: "Jenis kunci tidak didukung."
  defp describe(:wrong_key_type), do: "Tipe kunci tidak sesuai profil."
  defp describe(:wrong_parameters), do: "Parameter kunci tidak sesuai profil."
  defp describe({:io, posix}), do: "Kesalahan berkas: #{:file.format_error(posix)}."
  defp describe({:invalid_field, path}), do: "Nilai tidak sah pada: #{Enum.join(path, ".")}."
  defp describe(:unsupported_algorithm), do: "Algoritma tidak didukung."
  defp describe({:unsupported_algorithm, _}), do: "Algoritma tidak didukung."
  defp describe(:invalid_package), do: "Nama paket tidak sesuai pola."
  defp describe(:keyid_not_found), do: "keyid tidak ditemukan pada trust store."
  defp describe(:too_large), do: "Trust store terlalu besar."
  defp describe(:invalid_json), do: "Trust store bukan JSON yang sesuai format."
  defp describe(:invalid_schema), do: "Trust store memiliki schema yang salah."
  defp describe(:invalid_entry), do: "Trust store memuat entri kunci yang tidak sah."
  defp describe(:duplicate_keyid), do: "Trust store memuat keyid ganda."
end
