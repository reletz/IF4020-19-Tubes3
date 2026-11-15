defmodule Nadina.Keys do
  @moduledoc """
  Pembangkitan kunci, pemuatan PEM (PKCS8 dan SPKI), dan fingerprint (Tabel 2.5).

  Format berkas kunci

  - kunci privat berupa PKCS8 dalam PEM dengan label PRIVATE KEY
  - kunci publik berupa SubjectPublicKeyInfo dalam PEM dengan label PUBLIC KEY
  - fingerprint (keyid) adalah hex huruf kecil dari SHA-256 atas DER SPKI

  DER SPKI untuk fingerprint diperoleh dari ekspor ulang kunci publik, bukan dari teks
  PEM. Karena itu perbedaan line ending atau pemenggalan baris PEM tidak mengubah keyid.

  Profil kunci ditentukan dari tipe dan parameter kunci (RSA, kurva P-256, atau
  Ed25519), lalu divalidasi oleh modul profil terkait.

  Isi kunci privat tidak pernah dicatat pada log. Berkas kunci privat dibuat dengan
  izin 0600 dan tidak ditimpa kecuali pemanggil meminta secara eksplisit.
  """

  alias Nadina.Profile

  @p256_oid {1, 2, 840, 10045, 3, 1, 7}
  @ed25519_oid {1, 3, 101, 112}

  @type reason ::
          :invalid_pem
          | :unsupported_key
          | :wrong_key_type
          | :wrong_parameters
          | :exists
          | {:io, File.posix()}

  @doc """
  Membangkitkan pasangan kunci untuk profil bernama. Nama profil tidak dikenal
  menghasilkan error unsupported_algorithm.

  ## Contoh

      iex> {:ok, mod, _priv, _pub} = Nadina.Keys.generate("ecdsa-p256-sha256")
      iex> mod
      Nadina.Profile.EcdsaP256

      iex> Nadina.Keys.generate("rsa-sha1")
      {:error, :unsupported_algorithm}
  """
  @spec generate(String.t()) ::
          {:ok, module(), Profile.private_key(), Profile.public_key()}
          | {:error, :unsupported_algorithm}
  def generate(profile_name) do
    case Profile.fetch(profile_name) do
      {:ok, mod} ->
        {priv, pub} = mod.generate_key()
        {:ok, mod, priv, pub}

      :error ->
        {:error, :unsupported_algorithm}
    end
  end

  @doc """
  Mengubah kunci privat menjadi teks PEM PKCS8 dengan label PRIVATE KEY.
  """
  @spec encode_private_pem(Profile.private_key()) :: String.t()
  def encode_private_pem(priv) do
    :public_key.pem_encode([:public_key.pem_entry_encode(:PrivateKeyInfo, priv)])
  end

  @doc """
  Mengubah kunci publik menjadi teks PEM SPKI dengan label PUBLIC KEY.
  """
  @spec encode_public_pem(Profile.public_key()) :: String.t()
  def encode_public_pem(pub) do
    :public_key.pem_encode([:public_key.pem_entry_encode(:SubjectPublicKeyInfo, pub)])
  end

  @doc """
  Memuat kunci privat dari teks PEM PKCS8. Mengembalikan modul profil, kunci, dan
  kunci publik turunannya. Kunci dengan tipe atau parameter yang tidak sesuai ditolak.
  """
  @spec decode_private_pem(binary()) ::
          {:ok, module(), Profile.private_key(), Profile.public_key()} | {:error, reason()}
  def decode_private_pem(pem) when is_binary(pem) do
    with {:ok, :PrivateKeyInfo, entry} <- single_entry(pem),
         {:ok, priv} <- safe_decode(entry),
         {:ok, mod} <- profile_for(priv),
         :ok <- mod.check_key(priv) do
      {:ok, mod, priv, mod.public_from_private(priv)}
    else
      {:ok, _other_label, _} -> {:error, :invalid_pem}
      {:error, _} = err -> err
    end
  end

  def decode_private_pem(_), do: {:error, :invalid_pem}

  @doc """
  Memuat kunci publik dari teks PEM SPKI. Mengembalikan modul profil dan kunci.

  ## Contoh

      iex> {:ok, _mod, _priv, pub} = Nadina.Keys.generate("ecdsa-p256-sha256")
      iex> pem = Nadina.Keys.encode_public_pem(pub)
      iex> {:ok, Nadina.Profile.EcdsaP256, ^pub} = Nadina.Keys.decode_public_pem(pem)
      iex> :ok
      :ok
  """
  @spec decode_public_pem(binary()) ::
          {:ok, module(), Profile.public_key()} | {:error, reason()}
  def decode_public_pem(pem) when is_binary(pem) do
    with {:ok, :SubjectPublicKeyInfo, entry} <- single_entry(pem),
         {:ok, pub} <- safe_decode(entry),
         {:ok, mod} <- profile_for(pub),
         :ok <- mod.check_key(pub) do
      {:ok, mod, pub}
    else
      {:ok, _other_label, _} -> {:error, :invalid_pem}
      {:error, _} = err -> err
    end
  end

  def decode_public_pem(_), do: {:error, :invalid_pem}

  @doc """
  Menghitung fingerprint kunci publik, yaitu hex huruf kecil dari SHA-256 atas DER SPKI.

  ## Contoh

      iex> {:ok, _mod, _priv, pub} = Nadina.Keys.generate("ecdsa-p256-sha256")
      iex> fp = Nadina.Keys.fingerprint(pub)
      iex> {byte_size(fp), fp == String.downcase(fp)}
      {64, true}
  """
  @spec fingerprint(Profile.public_key()) :: String.t()
  def fingerprint(pub) do
    {:SubjectPublicKeyInfo, der, _} = :public_key.pem_entry_encode(:SubjectPublicKeyInfo, pub)
    :crypto.hash(:sha256, der) |> Base.encode16(case: :lower)
  end

  @doc """
  Menulis pasangan kunci ke prefix.key.pem (izin 0600) dan prefix.pub.pem (izin 0644).

  Berkas yang sudah ada tidak ditimpa, kecuali opsi force bernilai true. Penulisan
  memakai berkas sementara pada direktori yang sama lalu rename, sehingga berkas lama
  tidak rusak bila penulisan gagal. Isi kunci tidak pernah dicatat pada log.

  Mengembalikan fingerprint kunci publik.
  """
  @spec write_keypair(String.t(), Profile.private_key(), Profile.public_key(), keyword()) ::
          {:ok, String.t()} | {:error, reason()}
  def write_keypair(prefix, priv, pub, opts \\ []) do
    force? = Keyword.get(opts, :force, false)
    key_path = prefix <> ".key.pem"
    pub_path = prefix <> ".pub.pem"

    with :ok <- ensure_free(key_path, force?),
         :ok <- ensure_free(pub_path, force?),
         :ok <- File.mkdir_p(Path.dirname(key_path)) |> io_result(),
         :ok <- write_private(key_path, encode_private_pem(priv)),
         :ok <- write_atomic(pub_path, encode_public_pem(pub), 0o644) do
      {:ok, fingerprint(pub)}
    end
  end

  @doc """
  Membaca berkas kunci privat lalu memuatnya. Kegagalan baca menghasilkan error io.
  """
  @spec load_private_file(Path.t()) ::
          {:ok, module(), Profile.private_key(), Profile.public_key()} | {:error, reason()}
  def load_private_file(path) do
    case File.read(path) do
      {:ok, pem} -> decode_private_pem(pem)
      {:error, posix} -> {:error, {:io, posix}}
    end
  end

  @doc """
  Membaca berkas kunci publik lalu memuatnya. Kegagalan baca menghasilkan error io.
  """
  @spec load_public_file(Path.t()) ::
          {:ok, module(), Profile.public_key()} | {:error, reason()}
  def load_public_file(path) do
    case File.read(path) do
      {:ok, pem} -> decode_public_pem(pem)
      {:error, posix} -> {:error, {:io, posix}}
    end
  end

  # PEM harus memuat tepat satu entri tanpa enkripsi.
  defp single_entry(pem) do
    case :public_key.pem_decode(pem) do
      [{type, _der, :not_encrypted} = entry] -> {:ok, type, entry}
      _ -> {:error, :invalid_pem}
    end
  rescue
    _ -> {:error, :invalid_pem}
  end

  defp safe_decode(entry) do
    {:ok, :public_key.pem_entry_decode(entry)}
  rescue
    _ -> {:error, :invalid_pem}
  catch
    _, _ -> {:error, :invalid_pem}
  end

  defp profile_for({:RSAPrivateKey, _, _, _, _, _, _, _, _, _, _}), do: {:ok, Profile.RsaPss}
  defp profile_for({:RSAPublicKey, _, _}), do: {:ok, Profile.RsaPss}
  defp profile_for({:ECPrivateKey, _, _, params, _, _}), do: profile_for_params(params)
  defp profile_for({{:ECPoint, _}, params}), do: profile_for_params(params)
  defp profile_for(_), do: {:error, :unsupported_key}

  defp profile_for_params({:namedCurve, @p256_oid}), do: {:ok, Profile.EcdsaP256}
  defp profile_for_params({:namedCurve, @ed25519_oid}), do: {:ok, Profile.Ed25519}
  defp profile_for_params(_), do: {:error, :unsupported_key}

  defp ensure_free(path, true), do: ensure_not_dir(path)

  defp ensure_free(path, false) do
    if File.exists?(path), do: {:error, :exists}, else: :ok
  end

  defp ensure_not_dir(path) do
    if File.dir?(path), do: {:error, {:io, :eisdir}}, else: :ok
  end

  defp write_private(path, pem), do: write_atomic(path, pem, 0o600)

  # Tulis ke berkas sementara (izin dibatasi sebelum isi ditulis), lalu rename.
  defp write_atomic(path, content, mode) do
    tmp = path <> ".tmp-" <> Base.encode16(:crypto.strong_rand_bytes(6), case: :lower)

    result =
      with {:ok, io} <- File.open(tmp, [:write, :exclusive, :binary]),
           :ok <- File.chmod(tmp, mode),
           :ok <- IO.binwrite(io, content),
           :ok <- File.close(io),
           :ok <- File.rename(tmp, path) do
        :ok
      end

    case result do
      :ok ->
        :ok

      {:error, posix} ->
        File.rm(tmp)
        {:error, {:io, posix}}
    end
  end

  defp io_result(:ok), do: :ok
  defp io_result({:error, posix}), do: {:error, {:io, posix}}
end
