defmodule Nadina.Verify do
  @moduledoc """
  Tujuh langkah pemeriksaan verifikasi dan hasil JSON (spek Tabel 2.8 sampai 2.10).

  Urutan dan status, berhenti pada kegagalan pertama

  1. INPUT_ERROR: opsi wajib ada dan semua berkas masukan dapat dibaca
  2. FORMAT_ERROR: struktur, tipe, ukuran, dan serialisasi bundle, manifest, trust store
  3. UNSUPPORTED_ALGORITHM: nilai algorithm bukan salah satu profil
  4. KEY_NOT_TRUSTED: keyid ada di trust store, profil cocok, paket diizinkan
  5. INVALID_SIGNATURE: tanda tangan atas byte manifest sah
  6. METADATA_MISMATCH: paket, versi, dan nama artefak sesuai masukan
  7. ARTIFACT_MISMATCH: ukuran dan SHA-256 artefak sesuai manifest

  Hanya kunci dari trust store yang dipakai. Kunci pada bundle tidak ada, dan trust store
  tidak pernah diubah oleh verifikasi. Metadata pada hasil (algorithm, keyid, package,
  version) hanya untuk menjelaskan hasil dan tidak boleh dianggap sah bila verifikasi gagal.
  """

  alias Nadina.{Artifact, Bundle, Manifest, Profile, Trust}

  @type status ::
          :ok
          | :input_error
          | :format_error
          | :unsupported_algorithm
          | :key_not_trusted
          | :invalid_signature
          | :metadata_mismatch
          | :artifact_mismatch

  @type result :: %{
          valid: boolean(),
          status: status(),
          message: String.t(),
          algorithm: String.t() | nil,
          keyid: String.t() | nil,
          package: String.t() | nil,
          version: String.t() | nil
        }

  @required [:file, :bundle, :trust_store, :package, :version]

  @doc """
  Menjalankan verifikasi. Opsi: file, bundle, trust_store, package, version.
  """
  @spec run(keyword()) :: result()
  def run(opts) do
    with :ok <- check_options(opts),
         {:ok, inputs} <- read_inputs(opts),
         {:ok, bundle, manifest, store} <- parse_inputs(inputs) do
      info = info(manifest)

      with :ok <- check_algorithm(manifest, info),
           {:ok, mod, pub} <- check_trust(store, manifest, opts[:package], info),
           :ok <- check_signature(mod, pub, bundle, info),
           :ok <- check_metadata(manifest, opts, info) do
        check_artifact(manifest, opts[:file], info)
      end
    end
    |> finish()
  end

  @doc "Exit code untuk hasil verifikasi: 0 bila OK, 2 untuk INPUT_ERROR, selain itu 1."
  @spec exit_code(result()) :: 0 | 1 | 2
  def exit_code(%{status: :ok}), do: 0
  def exit_code(%{status: :input_error}), do: 2
  def exit_code(_), do: 1

  @doc "Nama status sebagaimana tertulis pada keluaran JSON."
  @spec status_name(status()) :: String.t()
  def status_name(status), do: status |> Atom.to_string() |> String.upcase()

  @doc "Hasil verifikasi sebagai objek JSON (satu baris, diakhiri baris baru)."
  @spec to_json(result()) :: binary()
  def to_json(r) do
    Nadina.JSONOut.encode(
      {:object,
       [
         {"valid", r.valid},
         {"status", status_name(r.status)},
         {"message", r.message},
         {"algorithm", r.algorithm},
         {"keyid", r.keyid},
         {"package", r.package},
         {"version", r.version}
       ]}
    ) <> "\n"
  end

  defp finish({:ok, info}), do: result(:ok, "Tanda tangan dan artefak valid.", info)
  defp finish({:error, status, message, info}), do: result(status, message, info)

  defp result(status, message, info) do
    Map.merge(
      %{valid: status == :ok, status: status, message: message},
      Map.take(info, [:algorithm, :keyid, :package, :version])
    )
  end

  @blank %{algorithm: nil, keyid: nil, package: nil, version: nil}

  defp fail(status, message, info \\ @blank), do: {:error, status, message, info}

  defp info(%Manifest{} = m),
    do: %{algorithm: m.algorithm, keyid: m.keyid, package: m.package, version: m.version}

  # Langkah 1
  defp check_options(opts) do
    case Enum.find(@required, &(not is_binary(opts[&1]) or opts[&1] == "")) do
      nil -> :ok
      missing -> fail(:input_error, "Opsi wajib tidak diberikan: #{missing}.")
    end
  end

  defp read_inputs(opts) do
    with {:ok, bundle} <- read(opts[:bundle], "bundle"),
         {:ok, store} <- read(opts[:trust_store], "trust store"),
         {:ok, _size, _sha} <- digest(opts[:file]) do
      {:ok, {bundle, store}}
    end
  end

  defp read(path, label) do
    case File.read(path) do
      {:ok, bytes} -> {:ok, bytes}
      {:error, posix} -> fail(:input_error, "Berkas #{label} tidak dapat dibaca: #{posix}.")
    end
  end

  defp digest(path) do
    case Artifact.digest(path) do
      {:ok, _, _} = ok -> ok
      {:error, {:io, posix}} -> fail(:input_error, "Artefak tidak dapat dibaca: #{posix}.")
    end
  end

  # Langkah 2
  defp parse_inputs({bundle_bytes, store_bytes}) do
    with {:bundle, {:ok, bundle}} <- {:bundle, Bundle.parse(bundle_bytes)},
         {:manifest, {:ok, manifest}} <- {:manifest, Manifest.parse(bundle.manifest)},
         {:store, {:ok, store}} <- {:store, Trust.parse(store_bytes)} do
      {:ok, bundle, manifest, store}
    else
      {:bundle, {:error, _}} -> fail(:format_error, "Format bundle tidak sesuai ketentuan.")
      {:manifest, {:error, _}} -> fail(:format_error, "Format manifest tidak sesuai ketentuan.")
      {:store, {:error, _}} -> fail(:format_error, "Format trust store tidak sesuai ketentuan.")
    end
  end

  # Langkah 3
  defp check_algorithm(manifest, info) do
    if Manifest.supported_algorithm?(manifest.algorithm),
      do: :ok,
      else: fail(:unsupported_algorithm, "Algoritma pada manifest tidak didukung.", info)
  end

  # Langkah 4
  defp check_trust(store, manifest, expected_package, info) do
    with %Trust.Entry{} = entry <- Trust.find(store, manifest.keyid),
         true <- entry.algorithm == manifest.algorithm,
         true <- expected_package in entry.packages,
         {:ok, mod} <- Profile.fetch(manifest.algorithm) do
      {:ok, mod, entry.public_key}
    else
      _ -> fail(:key_not_trusted, "Kunci tidak tepercaya untuk paket dan profil ini.", info)
    end
  end

  # Langkah 5
  defp check_signature(mod, pub, bundle, info) do
    if mod.verify(pub, bundle.manifest, bundle.signature),
      do: :ok,
      else: fail(:invalid_signature, "Tanda tangan tidak sah.", info)
  end

  # Langkah 6
  defp check_metadata(manifest, opts, info) do
    cond do
      manifest.package != opts[:package] ->
        fail(:metadata_mismatch, "Nama paket tidak sesuai.", info)

      manifest.version != opts[:version] ->
        fail(:metadata_mismatch, "Versi tidak sesuai.", info)

      manifest.artifact_name != Path.basename(opts[:file]) ->
        fail(:metadata_mismatch, "Nama artefak tidak sesuai dengan nama berkas.", info)

      true ->
        :ok
    end
  end

  # Langkah 7
  defp check_artifact(manifest, file, info) do
    case Artifact.digest(file) do
      {:ok, size, sha} when size == manifest.artifact_size and sha == manifest.artifact_sha256 ->
        {:ok, info}

      {:ok, _size, _sha} ->
        fail(:artifact_mismatch, "Ukuran atau SHA-256 artefak tidak sesuai.", info)

      {:error, {:io, posix}} ->
        fail(:input_error, "Artefak tidak dapat dibaca: #{posix}.", info)
    end
  end
end
