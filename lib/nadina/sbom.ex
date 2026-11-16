defmodule Nadina.SBOM do
  @moduledoc """
  Software Bill of Materials (bonus spek 2.10).

  SBOM berformat JSON dengan schema minisign-sbom/v1. Isinya subject, yaitu artefak rilis
  yang dirujuk (name, size, sha256), dan daftar components dari mix.lock. Urutan field dan
  components tetap, sehingga pembentukan SBOM dari masukan yang sama selalu menghasilkan
  byte yang sama.

  SBOM ditandatangani sebagai artefak terpisah memakai alur sign biasa dan bundle yang sama.
  Verifikasi SBOM memeriksa dua bundle, yaitu bundle SBOM dan bundle rilis, lalu
  mencocokkan subject pada SBOM dengan artefak rilis.

  Catatan keamanan: mix.lock dievaluasi sebagai term Elixir, sama seperti Mix membacanya.
  Berkas ini harus berasal dari sumber tepercaya, misalnya repositori yang sama dengan
  artefak.
  """

  alias Nadina.{Artifact, JSONOut, StrictJSON, Verify}

  @schema_id "minisign-sbom/v1"
  @max_size 1024 * 1024

  @json_schema {:object,
                [
                  {"schema", :string},
                  {"subject",
                   {:object, [{"name", :string}, {"size", :integer}, {"sha256", :string}]}},
                  {"components",
                   {:array,
                    {:object,
                     [
                       {"name", :string},
                       {"version", :string},
                       {"purl", :string},
                       {"sha256", :string}
                     ]}}}
                ]}

  @type component :: %{name: String.t(), version: String.t(), sha256: String.t()}
  @type subject :: %{name: String.t(), size: non_neg_integer(), sha256: String.t()}

  @doc """
  Membaca mix.lock dan mengembalikan daftar komponen hex, diurutkan menurut nama.
  Entri selain hex (misalnya git atau path) ditolak agar SBOM tidak diam-diam tidak lengkap.
  """
  @spec components_from_lock(Path.t()) ::
          {:ok, [component()]}
          | {:error, {:io, File.posix()} | :invalid_lock | :unsupported_source}
  def components_from_lock(path) do
    with {:ok, text} <- read(path),
         {:ok, lock} <- eval_lock(text) do
      lock
      |> Enum.map(&to_component/1)
      |> collect()
      |> case do
        {:ok, comps} -> {:ok, Enum.sort_by(comps, & &1.name)}
        error -> error
      end
    end
  end

  defp read(path) do
    case File.read(path) do
      {:ok, text} -> {:ok, text}
      {:error, posix} -> {:error, {:io, posix}}
    end
  end

  # Diagnostik parser (misalnya gaya kunci lama pada mix.lock) ditangkap agar tidak
  # mengotori stderr. Hanya hasil evaluasi yang dipakai.
  defp eval_lock(text) do
    {result, _diagnostics} = Code.with_diagnostics(fn -> evaluate_lock(text) end)
    result
  rescue
    _ -> {:error, :invalid_lock}
  end

  defp evaluate_lock(text) do
    case Code.string_to_quoted(text) do
      {:ok, quoted} -> quoted |> Code.eval_quoted() |> elem(0) |> lock_result()
      {:error, _} -> {:error, :invalid_lock}
    end
  end

  defp lock_result(lock) when is_map(lock), do: {:ok, Map.to_list(lock)}
  defp lock_result(_), do: {:error, :invalid_lock}

  defp to_component({_name, {:hex, app, version, _inner, _managers, _deps, _repo, outer_sha256}})
       when is_binary(version) and is_binary(outer_sha256) do
    {:ok, %{name: Atom.to_string(app), version: version, sha256: outer_sha256}}
  end

  defp to_component(_), do: {:error, :unsupported_source}

  defp collect(results) do
    Enum.reduce_while(results, {:ok, []}, fn
      {:ok, c}, {:ok, acc} -> {:cont, {:ok, [c | acc]}}
      {:error, _} = err, _ -> {:halt, err}
    end)
  end

  @doc """
  Membentuk SBOM dari subject dan daftar komponen. Menghasilkan byte JSON tanpa white space
  dan tanpa baris baru di akhir.
  """
  @spec encode(subject(), [component()]) :: binary()
  def encode(subject, components) do
    comps =
      for c <- components do
        {:object,
         [
           {"name", c.name},
           {"version", c.version},
           {"purl", "pkg:hex/#{c.name}@#{c.version}"},
           {"sha256", c.sha256}
         ]}
      end

    JSONOut.encode(
      {:object,
       [
         {"schema", @schema_id},
         {"subject",
          {:object, [{"name", subject.name}, {"size", subject.size}, {"sha256", subject.sha256}]}},
         {"components", comps}
       ]}
    )
  end

  @doc """
  Membuat SBOM untuk berkas artefak. Subject diambil dari basename, ukuran, dan SHA-256
  byte berkas.
  """
  @spec generate(Path.t(), Path.t()) ::
          {:ok, binary()} | {:error, term()}
  def generate(artifact_path, lock_path) do
    with {:ok, size, sha256} <- Artifact.digest(artifact_path),
         {:ok, comps} <- components_from_lock(lock_path) do
      subject = %{name: Path.basename(artifact_path), size: size, sha256: sha256}
      {:ok, encode(subject, comps)}
    end
  end

  @doc """
  Mem-parse SBOM secara strict dan mengembalikan subject serta daftar komponen.
  """
  @spec parse(binary()) :: {:ok, subject(), [component()]} | {:error, :too_large | :invalid_sbom}
  def parse(bytes) when byte_size(bytes) > @max_size, do: {:error, :too_large}

  def parse(bytes) do
    case StrictJSON.decode_as(bytes, @json_schema) do
      {:ok, %{"schema" => @schema_id, "subject" => subject, "components" => comps}} ->
        {:ok, %{name: subject["name"], size: subject["size"], sha256: subject["sha256"]},
         Enum.map(comps, &%{name: &1["name"], version: &1["version"], sha256: &1["sha256"]})}

      _ ->
        {:error, :invalid_sbom}
    end
  end

  @doc """
  Memverifikasi SBOM dan rilis. Langkah dijalankan berurutan dan berhenti pada kegagalan
  pertama.

  1. Bundle SBOM diverifikasi terhadap SBOM, dengan trust store dan paket yang sama.
  2. Bundle rilis diverifikasi terhadap artefak rilis.
  3. Subject pada SBOM harus merujuk artefak rilis: nama, ukuran, dan SHA-256 sama.

  Opsi: sbom, sbom_bundle, file, bundle, trust_store, package, version. Hasil memakai
  bentuk yang sama dengan Verify.run/1.
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

      if release_result.valid do
        link(opts, release_result)
      else
        release_result
      end
    else
      sbom_result
    end
  end

  defp link(opts, release_result) do
    with {:ok, bytes} <- read_sbom(opts[:sbom]),
         {:ok, subject, _comps} <- parse_sbom(bytes),
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

  defp read_sbom(path) do
    case File.read(path) do
      {:ok, bytes} -> {:ok, bytes}
      {:error, posix} -> {:error, :input_error, "SBOM tidak dapat dibaca: #{posix}."}
    end
  end

  defp parse_sbom(bytes) do
    case parse(bytes) do
      {:ok, subject, comps} -> {:ok, subject, comps}
      {:error, _} -> {:error, :format_error, "Format SBOM tidak sesuai ketentuan."}
    end
  end

  defp digest(path) do
    case Artifact.digest(path) do
      {:ok, _, _} = ok -> ok
      {:error, {:io, posix}} -> {:error, :input_error, "Artefak tidak dapat dibaca: #{posix}."}
    end
  end

  defp input_error(result, message),
    do: %{result | valid: false, status: :input_error, message: message}

  defp format_error(result, message),
    do: %{result | valid: false, status: :format_error, message: message}

  defp mismatch(result, message) do
    %{result | valid: false, status: :artifact_mismatch, message: message}
  end
end
