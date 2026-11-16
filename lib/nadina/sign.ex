defmodule Nadina.Sign do
  @moduledoc """
  Alur penandatanganan: baca artefak, bentuk manifest, tandatangani byte manifest, tulis
  bundle.

  Profil ditentukan dari kunci privat. Nilai artifact.name diambil dari basename berkas
  masukan. SHA-256 atas byte artefak dihitung terpisah dan dicatat pada manifest, sedangkan
  yang ditandatangani adalah seluruh byte manifest M. Isi kunci privat tidak pernah
  dicatat atau ditulis ke bundle.
  """

  alias Nadina.{Artifact, Bundle, Keys, Manifest}

  @type reason ::
          Keys.reason()
          | {:io, File.posix()}
          | {:invalid_field, Manifest.field_path()}
          | {:unsupported_algorithm, term()}

  @doc """
  Menandatangani berkas. Opsi wajib: file, package, version, key, out. Hasil sukses
  berisi path bundle, keyid, dan profil.
  """
  @spec run(keyword()) ::
          {:ok, %{bundle: Path.t(), keyid: String.t(), algorithm: String.t()}}
          | {:error, reason()}
  def run(opts) do
    file = Keyword.fetch!(opts, :file)
    out = Keyword.fetch!(opts, :out)

    with {:ok, size, sha256} <- Artifact.digest(file),
         {:ok, mod, priv, pub} <- Keys.load_private_file(Keyword.fetch!(opts, :key)),
         keyid = Keys.fingerprint(pub),
         {:ok, manifest} <-
           Manifest.new(
             Keyword.fetch!(opts, :package),
             Keyword.fetch!(opts, :version),
             mod.name(),
             keyid,
             Path.basename(file),
             size,
             sha256
           ),
         message = Manifest.serialize(manifest),
         signature = mod.sign(priv, message),
         bundle = Bundle.encode(%Bundle{manifest: message, signature: signature}),
         :ok <- write_atomic(out, bundle) do
      {:ok, %{bundle: out, keyid: keyid, algorithm: mod.name()}}
    end
  end

  # Bundle ditulis ke berkas sementara pada direktori yang sama lalu di-rename.
  defp write_atomic(path, content) do
    tmp = path <> ".tmp-" <> Base.encode16(:crypto.strong_rand_bytes(6), case: :lower)

    result =
      with :ok <- File.mkdir_p(Path.dirname(path)),
           :ok <- File.write(tmp, content, [:exclusive]),
           :ok <- File.chmod(tmp, 0o644) do
        File.rename(tmp, path)
      end

    case result do
      :ok ->
        :ok

      {:error, posix} ->
        File.rm(tmp)
        {:error, {:io, posix}}
    end
  end
end
