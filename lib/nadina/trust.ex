defmodule Nadina.Trust do
  @moduledoc """
  Pengelolaan trust store (spek Tabel 2.6) dengan penulisan atomik.

  Format berkas

      {"schema":"minisign-trust/v1","keys":[
        {"keyid":"...","algorithm":"...","public_key_pem":"...","packages":["..."]}]}

  parse/1 memeriksa struktur, tipe, keunikan keyid, daftar paket (tidak kosong, tanpa
  duplikat, tanpa wildcard), serta kesesuaian profil dan fingerprint dengan kunci publik.
  Semua kegagalan format menghasilkan error, yang bagi verifier berarti FORMAT_ERROR.

  Trust store hanya berubah lewat add/3 dan remove/2. Tidak ada pembaruan otomatis
  dari bundle. Perubahan ditulis ke berkas sementara di direktori yang sama lalu rename,
  sehingga berkas lama tidak rusak bila penulisan gagal.
  """

  alias Nadina.{JSONOut, Keys, Profile, StrictJSON}

  @schema_id "minisign-trust/v1"
  @max_size 1024 * 1024
  @package_re ~r/\A[a-z0-9][a-z0-9._-]{0,63}\z/
  @hex64_re ~r/\A[0-9a-f]{64}\z/

  @json_schema {:object,
                [
                  {"schema", :string},
                  {"keys",
                   {:array,
                    {:object,
                     [
                       {"keyid", :string},
                       {"algorithm", :string},
                       {"public_key_pem", :string},
                       {"packages", {:array, :string}}
                     ]}}}
                ]}

  defmodule Entry do
    @moduledoc "Satu entri kunci pada trust store."
    @enforce_keys [:keyid, :algorithm, :public_key_pem, :public_key, :packages]
    defstruct @enforce_keys

    @type t :: %__MODULE__{
            keyid: String.t(),
            algorithm: String.t(),
            public_key_pem: String.t(),
            public_key: Nadina.Profile.public_key(),
            packages: [String.t()]
          }
  end

  @type t :: [Entry.t()]

  @type error ::
          :too_large
          | :invalid_json
          | :invalid_schema
          | :invalid_entry
          | :duplicate_keyid
          | :keyid_not_found
          | {:io, File.posix()}

  @doc "Trust store kosong. Tidak memberi kepercayaan kepada kunci mana pun."
  @spec empty() :: t()
  def empty, do: []

  @doc """
  Parse strict isi berkas trust store.

  ## Contoh

      iex> Nadina.Trust.parse(~s({"schema":"minisign-trust/v1","keys":[]}))
      {:ok, []}

      iex> Nadina.Trust.parse(~s({"schema":"minisign-trust/v1","keys":[],"x":1}))
      {:error, :invalid_json}
  """
  @spec parse(binary()) :: {:ok, t()} | {:error, error()}
  def parse(bytes) when byte_size(bytes) > @max_size, do: {:error, :too_large}

  def parse(bytes) when is_binary(bytes) do
    with {:ok, doc} <- decode(bytes),
         :ok <- check_schema_id(doc["schema"]),
         {:ok, entries} <- build_entries(doc["keys"]),
         :ok <- check_unique(entries) do
      {:ok, entries}
    end
  end

  defp decode(bytes) do
    case StrictJSON.decode_as(bytes, @json_schema) do
      {:ok, doc} -> {:ok, doc}
      {:error, _} -> {:error, :invalid_json}
    end
  end

  defp check_schema_id(@schema_id), do: :ok
  defp check_schema_id(_), do: {:error, :invalid_schema}

  defp build_entries(raw) do
    Enum.reduce_while(raw, {:ok, []}, fn item, {:ok, acc} ->
      case build_entry(item) do
        {:ok, entry} -> {:cont, {:ok, [entry | acc]}}
        {:error, _} = err -> {:halt, err}
      end
    end)
    |> case do
      {:ok, entries} -> {:ok, Enum.reverse(entries)}
      err -> err
    end
  end

  defp build_entry(%{
         "keyid" => keyid,
         "algorithm" => algorithm,
         "public_key_pem" => pem,
         "packages" => packages
       }) do
    with :ok <- check_keyid_format(keyid),
         :ok <- check_packages(packages),
         {:ok, mod, pub} <- decode_key(pem),
         :ok <- check_profile(mod, algorithm),
         :ok <- check_fingerprint(pub, keyid) do
      {:ok,
       %Entry{
         keyid: keyid,
         algorithm: algorithm,
         public_key_pem: pem,
         public_key: pub,
         packages: packages
       }}
    end
  end

  defp check_keyid_format(keyid),
    do: if(Regex.match?(@hex64_re, keyid), do: :ok, else: {:error, :invalid_entry})

  defp check_packages([]), do: {:error, :invalid_entry}

  defp check_packages(packages) do
    valid? =
      Enum.all?(packages, &Regex.match?(@package_re, &1)) and
        length(Enum.uniq(packages)) == length(packages)

    if valid?, do: :ok, else: {:error, :invalid_entry}
  end

  defp decode_key(pem) do
    case Keys.decode_public_pem(pem) do
      {:ok, mod, pub} -> {:ok, mod, pub}
      {:error, _} -> {:error, :invalid_entry}
    end
  end

  defp check_profile(mod, algorithm),
    do: if(mod.name() == algorithm, do: :ok, else: {:error, :invalid_entry})

  defp check_fingerprint(pub, keyid),
    do: if(Keys.fingerprint(pub) == keyid, do: :ok, else: {:error, :invalid_entry})

  defp check_unique(entries) do
    ids = Enum.map(entries, & &1.keyid)
    if length(Enum.uniq(ids)) == length(ids), do: :ok, else: {:error, :duplicate_keyid}
  end

  @doc """
  Membaca dan memparse trust store dari berkas. Berkas yang tidak ada atau tidak dapat
  dibaca menghasilkan error io.
  """
  @spec load(Path.t()) :: {:ok, t()} | {:error, error()}
  def load(path) do
    case File.read(path) do
      {:ok, bytes} -> parse(bytes)
      {:error, posix} -> {:error, {:io, posix}}
    end
  end

  @doc """
  Seperti load/1, tetapi berkas yang belum ada dianggap trust store kosong. Dipakai
  oleh trust add, yang membuat trust store bila belum tersedia.
  """
  @spec load_or_empty(Path.t()) :: {:ok, t()} | {:error, error()}
  def load_or_empty(path) do
    case load(path) do
      {:error, {:io, :enoent}} -> {:ok, empty()}
      other -> other
    end
  end

  @doc "Mencari entri berdasarkan keyid."
  @spec find(t(), String.t()) :: Entry.t() | nil
  def find(entries, keyid), do: Enum.find(entries, &(&1.keyid == keyid))

  @doc """
  Menambahkan izin paket untuk kunci publik. Kunci baru dibuat sebagai entri baru, kunci
  yang sudah ada diperbarui daftar paketnya. Pasangan keyid dan paket yang sama tidak
  menambah apa pun (idempoten).
  """
  @spec add(t(), Profile.public_key(), module(), String.t()) ::
          {:ok, t(), Entry.t()} | {:error, :invalid_package}
  def add(entries, pub, mod, package) do
    if Regex.match?(@package_re, package) do
      keyid = Keys.fingerprint(pub)

      entry =
        case find(entries, keyid) do
          nil ->
            %Entry{
              keyid: keyid,
              algorithm: mod.name(),
              public_key_pem: Keys.encode_public_pem(pub),
              public_key: pub,
              packages: [package]
            }

          %Entry{packages: pkgs} = existing ->
            %{existing | packages: Enum.uniq(pkgs ++ [package])}
        end

      others = Enum.reject(entries, &(&1.keyid == keyid))
      position = Enum.find_index(entries, &(&1.keyid == keyid)) || length(others)
      {:ok, List.insert_at(others, position, entry), entry}
    else
      {:error, :invalid_package}
    end
  end

  @doc "Menghapus entri berdasarkan keyid."
  @spec remove(t(), String.t()) :: {:ok, t()} | {:error, :keyid_not_found}
  def remove(entries, keyid) do
    case find(entries, keyid) do
      nil -> {:error, :keyid_not_found}
      _ -> {:ok, Enum.reject(entries, &(&1.keyid == keyid))}
    end
  end

  @doc "Serialisasi trust store ke JSON."
  @spec encode(t()) :: binary()
  def encode(entries) do
    keys =
      for e <- entries do
        {:object,
         [
           {"keyid", e.keyid},
           {"algorithm", e.algorithm},
           {"public_key_pem", e.public_key_pem},
           {"packages", e.packages}
         ]}
      end

    JSONOut.encode({:object, [{"schema", @schema_id}, {"keys", keys}]}) <> "\n"
  end

  @doc """
  Menulis trust store secara atomik: berkas sementara pada direktori yang sama, lalu rename.
  Berkas lama tetap utuh bila penulisan gagal.
  """
  @spec save(Path.t(), t()) :: :ok | {:error, error()}
  def save(path, entries) do
    tmp = path <> ".tmp-" <> Base.encode16(:crypto.strong_rand_bytes(6), case: :lower)

    result =
      with :ok <- File.mkdir_p(Path.dirname(path)),
           {:ok, io} <- File.open(tmp, [:write, :exclusive, :binary]),
           :ok <- File.chmod(tmp, 0o644),
           :ok <- IO.binwrite(io, encode(entries)),
           :ok <- File.close(io) do
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
