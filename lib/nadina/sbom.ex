defmodule Nadina.SBOM do
  @moduledoc """
  Pengikatan SBOM ke artefak rilis (bonus spek 2.10).

  SBOM dibuat oleh kakas eksternal, misalnya Trivy, Syft, atau cdxgen, dalam format apa
  pun yang berupa objek JSON. Nadina tidak menafsirkan isinya dan hanya memastikan bahwa
  byte SBOM tersimpan utuh dan terikat ke artefak rilis.

  Pembungkus minisign-sbom/v1 memuat subject (name, size, sha256 artefak rilis) dan
  sbom_b64 (Base64 standar dari byte SBOM asli, tanpa perubahan). Pembungkus inilah yang
  ditandatangani sebagai artefak dengan alur sign biasa, sehingga bundle SBOM memakai format
  bundle yang sama.

  Verifikasi memeriksa dua bundle, yaitu bundle pembungkus dan bundle rilis, lalu mencocokkan
  subject dengan artefak rilis dan memastikan sbom_b64 berisi objek JSON.
  """

  alias Nadina.{Artifact, JSONOut, StrictJSON, Verify}

  @schema_id "minisign-sbom/v1"
  @max_sbom 16 * 1024 * 1024
  @max_wrapper div(@max_sbom * 4, 3) + 4096

  @json_schema {:object,
                [
                  {"schema", :string},
                  {"subject",
                   {:object, [{"name", :string}, {"size", :integer}, {"sha256", :string}]}},
                  {"sbom_b64", :string}
                ]}

  @type subject :: %{name: String.t(), size: non_neg_integer(), sha256: String.t()}

  @doc "Ukuran maksimum SBOM eksternal dalam byte (16 MiB)."
  @spec max_sbom_size() :: pos_integer()
  def max_sbom_size, do: @max_sbom

  @doc """
  Membungkus SBOM eksternal dengan subject artefak. Byte SBOM harus berupa objek JSON
  dan tidak lebih dari 16 MiB. Mengembalikan JSON pembungkus tanpa baris baru di akhir.

  ## Contoh

      iex> {:error, reason} = Nadina.SBOM.wrap("contoh.zip", "bukan json", 10, "0")
      iex> reason
      :not_json_object
  """
  @spec wrap(String.t(), binary(), non_neg_integer(), String.t()) ::
          {:ok, binary()} | {:error, :not_json_object | :too_large}
  def wrap(name, sbom_bytes, size, sha256) do
    cond do
      byte_size(sbom_bytes) > @max_sbom -> {:error, :too_large}
      not json_object?(sbom_bytes) -> {:error, :not_json_object}
      true -> {:ok, encode(%{name: name, size: size, sha256: sha256}, sbom_bytes)}
    end
  end

  @doc """
  Membaca berkas artefak dan berkas SBOM, lalu membentuk pembungkus. Berkas yang tidak
  dapat dibaca menghasilkan error io.
  """
  @spec bind(Path.t(), Path.t()) ::
          {:ok, binary()} | {:error, :not_json_object | :too_large | {:io, File.posix()}}
  def bind(artifact_path, sbom_path) do
    with {:ok, sbom_bytes} <- read(sbom_path),
         {:ok, size, sha256} <- Artifact.digest(artifact_path) |> io_only() do
      wrap(Path.basename(artifact_path), sbom_bytes, size, sha256)
    end
  end

  defp io_only({:ok, _, _} = ok), do: ok
  defp io_only({:error, {:io, _}} = err), do: err

  @doc """
  Mengambil subject dan byte SBOM asli dari pembungkus. Tidak melakukan perubahan apa pun
  pada byte SBOM.
  """
  @spec extract(binary()) :: {:ok, subject(), binary()} | {:error, :too_large | :invalid_sbom}
  def extract(bytes) when byte_size(bytes) > @max_wrapper, do: {:error, :too_large}

  def extract(bytes) do
    with {:ok, %{"schema" => @schema_id} = doc} <- StrictJSON.decode_as(bytes, @json_schema),
         {:ok, sbom_bytes} <- decode64(doc["sbom_b64"]) do
      subject = %{
        name: doc["subject"]["name"],
        size: doc["subject"]["size"],
        sha256: doc["subject"]["sha256"]
      }

      {:ok, subject, sbom_bytes}
    else
      _ -> {:error, :invalid_sbom}
    end
  end

  @doc """
  Memverifikasi pembungkus dan rilis. Langkah dijalankan berurutan dan berhenti pada
  kegagalan pertama.

  1. Bundle pembungkus diverifikasi terhadap berkas pembungkus, dengan trust store dan paket
     yang sama.
  2. Bundle rilis diverifikasi terhadap artefak rilis.
  3. Subject harus merujuk artefak rilis, dan sbom_b64 harus berupa objek JSON.

  Opsi: sbom (berkas pembungkus), sbom_bundle, file, bundle, trust_store, package, version.
  Hasil memakai bentuk yang sama dengan Verify.run/1.
  """
  @spec verify(keyword()) :: Verify.result()
  def verify(opts) do
    sbom_result =
      Verify.run(
        file: opts[:sbom],
        bundle: opts[:sbom_bundle],
        trust_store: opts[:trust_store],
        package: opts[:package],
        version: opts[:version]
      )

    if sbom_result.valid do
      release_result =
        Verify.run(Keyword.take(opts, [:file, :bundle, :trust_store, :package, :version]))

      if release_result.valid, do: link(opts, release_result), else: release_result
    else
      sbom_result
    end
  end

  defp link(opts, release_result) do
    with {:ok, wrapper} <- read_wrapper(opts[:sbom]),
         {:ok, subject, sbom_bytes} <- parse_wrapper(wrapper),
         :ok <- check_json_object(sbom_bytes),
         {:ok, size, sha} <- digest(opts[:file]) do
      if subject.name == Path.basename(opts[:file]) and subject.size == size and
           subject.sha256 == sha do
        %{release_result | message: "SBOM dan artefak rilis valid dan saling merujuk."}
      else
        mismatch(release_result, "SBOM tidak merujuk artefak rilis ini.")
      end
    else
      {:error, :input_error, message} -> input_error(release_result, message)
      {:error, :format_error, message} -> format_error(release_result, message)
    end
  end

  defp parse_wrapper(bytes) do
    case extract(bytes) do
      {:ok, subject, sbom_bytes} -> {:ok, subject, sbom_bytes}
      {:error, _} -> {:error, :format_error, "Format pembungkus SBOM tidak sesuai ketentuan."}
    end
  end

  defp check_json_object(sbom_bytes) do
    if json_object?(sbom_bytes),
      do: :ok,
      else: {:error, :format_error, "Isi SBOM bukan objek JSON."}
  end

  defp read_wrapper(path) do
    case File.read(path) do
      {:ok, bytes} -> {:ok, bytes}
      {:error, posix} -> {:error, :input_error, "Berkas SBOM tidak dapat dibaca: #{posix}."}
    end
  end

  defp read(path) do
    case File.read(path) do
      {:ok, bytes} when byte_size(bytes) > @max_sbom -> {:error, :too_large}
      {:ok, bytes} -> {:ok, bytes}
      {:error, posix} -> {:error, {:io, posix}}
    end
  end

  defp digest(path) do
    case Artifact.digest(path) do
      {:ok, _, _} = ok -> ok
      {:error, {:io, posix}} -> {:error, :input_error, "Artefak tidak dapat dibaca: #{posix}."}
    end
  end

  defp json_object?(bytes) do
    case JSON.decode(bytes) do
      {:ok, %{}} -> true
      _ -> false
    end
  end

  defp encode(subject, sbom_bytes) do
    JSONOut.encode(
      {:object,
       [
         {"schema", @schema_id},
         {"subject",
          {:object, [{"name", subject.name}, {"size", subject.size}, {"sha256", subject.sha256}]}},
         {"sbom_b64", Base.encode64(sbom_bytes)}
       ]}
    ) <> "\n"
  end

  # decode lalu encode ulang supaya padding dan bentuk non-canonical ikut tertolak
  defp decode64(string) do
    with {:ok, bytes} <- Base.decode64(string),
         ^string <- Base.encode64(bytes) do
      {:ok, bytes}
    else
      _ -> {:error, :invalid_sbom}
    end
  end

  defp input_error(result, message),
    do: %{result | valid: false, status: :input_error, message: message}

  defp format_error(result, message),
    do: %{result | valid: false, status: :format_error, message: message}

  defp mismatch(result, message),
    do: %{result | valid: false, status: :artifact_mismatch, message: message}
end
