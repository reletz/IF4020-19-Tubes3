defmodule Nadina.Manifest do
  @moduledoc """
  Release manifest (spek Tabel 2.3): pembentukan, serialisasi canonical, dan parse strict.

  Byte hasil `serialize/1` adalah pesan M yang ditandatangani. Saat verifikasi, `parse/1`
  menerima byte M apa adanya dari bundle, memeriksa ukuran, struktur, nilai field, lalu
  membandingkan M byte-for-byte dengan hasil serialisasi ulang. Semua kesalahan `parse/1`
  berarti `FORMAT_ERROR`.

  Nilai `algorithm` yang bukan salah satu profil tetap lolos `parse/1` asalkan berupa string
  ASCII yang bisa ditulis tanpa escape, karena spek memisahkannya sebagai
  `UNSUPPORTED_ALGORITHM`. Gunakan `supported_algorithm?/1` untuk langkah itu.
  """

  @schema_id "minisign-manifest/v1"
  @max_size 16 * 1024
  @max_artifact_size 9_007_199_254_740_991
  @algorithms ["rsa-pss-sha256", "ecdsa-p256-sha256", "ed25519"]

  @package_re ~r/\A[a-z0-9][a-z0-9._-]{0,63}\z/
  @version_re ~r/\A[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\z/
  @name_re ~r/\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\z/
  @hex64_re ~r/\A[0-9a-f]{64}\z/

  @json_schema {:object,
                [
                  {"schema", :string},
                  {"package", :string},
                  {"version", :string},
                  {"algorithm", :string},
                  {"keyid", :string},
                  {"artifact",
                   {:object, [{"name", :string}, {"size", :integer}, {"sha256", :string}]}}
                ]}

  @enforce_keys [
    :package,
    :version,
    :algorithm,
    :keyid,
    :artifact_name,
    :artifact_size,
    :artifact_sha256
  ]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          package: String.t(),
          version: String.t(),
          algorithm: String.t(),
          keyid: String.t(),
          artifact_name: String.t(),
          artifact_size: non_neg_integer(),
          artifact_sha256: String.t()
        }

  @type field_path :: [String.t()]

  @type parse_error ::
          {:too_large, pos_integer()}
          | Nadina.StrictJSON.decode_error()
          | Nadina.StrictJSON.validate_error()
          | {:invalid_field, field_path()}
          | :not_canonical

  @doc "Ukuran maksimum manifest dalam byte (16 KiB)."
  @spec max_size() :: pos_integer()
  def max_size, do: @max_size

  @doc "Daftar profil algoritma yang didukung (spek Tabel 2.1)."
  @spec algorithms() :: [String.t()]
  def algorithms, do: @algorithms

  @doc """
  Apakah `algorithm` termasuk profil yang didukung.

      iex> Nadina.Manifest.supported_algorithm?("ed25519")
      true
      iex> Nadina.Manifest.supported_algorithm?("rsa-pkcs1-sha256")
      false
  """
  @spec supported_algorithm?(String.t()) :: boolean()
  def supported_algorithm?(algorithm), do: algorithm in @algorithms

  @doc """
  Membentuk manifest dengan urutan argumen sesuai spek: paket, versi, profil, fingerprint,
  nama artefak, ukuran, dan hash. Dipakai saat sign, sehingga profil wajib didukung.
  """
  @spec new(
          String.t(),
          String.t(),
          String.t(),
          String.t(),
          String.t(),
          non_neg_integer(),
          String.t()
        ) ::
          {:ok, t()} | {:error, {:invalid_field, field_path()} | {:unsupported_algorithm, term()}}
  def new(package, version, algorithm, keyid, name, size, sha256) do
    manifest = %__MODULE__{
      package: package,
      version: version,
      algorithm: algorithm,
      keyid: keyid,
      artifact_name: name,
      artifact_size: size,
      artifact_sha256: sha256
    }

    with :ok <- validate_fields(manifest) do
      if supported_algorithm?(algorithm),
        do: {:ok, manifest},
        else: {:error, {:unsupported_algorithm, algorithm}}
    end
  end

  @doc """
  Serialisasi canonical: urutan field tetap, tanpa white space, tanpa escape, tanpa baris
  baru di akhir. Hanya untuk manifest yang sudah lolos `new/7` atau `parse/1`.
  """
  @spec serialize(t()) :: binary()
  def serialize(%__MODULE__{} = m) do
    IO.iodata_to_binary([
      ~s({"schema":"),
      @schema_id,
      ~s(","package":"),
      m.package,
      ~s(","version":"),
      m.version,
      ~s(","algorithm":"),
      m.algorithm,
      ~s(","keyid":"),
      m.keyid,
      ~s(","artifact":{"name":"),
      m.artifact_name,
      ~s(","size":),
      Integer.to_string(m.artifact_size),
      ~s(,"sha256":"),
      m.artifact_sha256,
      ~s("}})
    ])
  end

  @doc """
  Parse strict byte manifest dari bundle. Urutan pemeriksaan: ukuran (sebelum parsing),
  JSON strict dan struktur, nilai field, lalu kesesuaian serialisasi canonical.
  """
  @spec parse(binary()) :: {:ok, t()} | {:error, parse_error()}
  def parse(bytes) when byte_size(bytes) > @max_size, do: {:error, {:too_large, byte_size(bytes)}}

  def parse(bytes) when is_binary(bytes) do
    with {:ok, doc} <- Nadina.StrictJSON.decode_as(bytes, @json_schema),
         :ok <- check_schema_id(doc["schema"]),
         manifest = from_doc(doc),
         :ok <- validate_fields(manifest),
         :ok <- check_canonical(manifest, bytes) do
      {:ok, manifest}
    end
  end

  defp from_doc(%{"artifact" => artifact} = doc) do
    %__MODULE__{
      package: doc["package"],
      version: doc["version"],
      algorithm: doc["algorithm"],
      keyid: doc["keyid"],
      artifact_name: artifact["name"],
      artifact_size: artifact["size"],
      artifact_sha256: artifact["sha256"]
    }
  end

  defp check_schema_id(@schema_id), do: :ok
  defp check_schema_id(_), do: {:error, {:invalid_field, ["schema"]}}

  defp check_canonical(manifest, bytes) do
    if serialize(manifest) == bytes, do: :ok, else: {:error, :not_canonical}
  end

  defp validate_fields(m) do
    checks = [
      {["package"], matches?(m.package, @package_re)},
      {["version"], matches?(m.version, @version_re)},
      {["algorithm"], plain_ascii?(m.algorithm)},
      {["keyid"], matches?(m.keyid, @hex64_re)},
      {["artifact", "name"], matches?(m.artifact_name, @name_re)},
      {["artifact", "size"],
       is_integer(m.artifact_size) and m.artifact_size in 0..@max_artifact_size},
      {["artifact", "sha256"], matches?(m.artifact_sha256, @hex64_re)}
    ]

    case Enum.find(checks, fn {_path, ok?} -> not ok? end) do
      nil -> :ok
      {path, false} -> {:error, {:invalid_field, path}}
    end
  end

  defp matches?(value, re), do: is_binary(value) and Regex.match?(re, value)

  # Algorithm tidak punya pola di spek, tapi harus bisa ditulis canonical tanpa escape.
  defp plain_ascii?(value) when is_binary(value) do
    for(<<c <- value>>, do: c) |> Enum.all?(&(&1 in 0x20..0x7E and &1 not in [?", ?\\]))
  end

  defp plain_ascii?(_), do: false
end
