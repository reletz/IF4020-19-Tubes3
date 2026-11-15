defmodule Nadina.Profile.EcdsaP256 do
  @moduledoc """
  Profil ecdsa-p256-sha256, yaitu ECDSA pada kurva NIST P-256 (secp256r1) dengan SHA-256.

  Tanda tangan disimpan sebagai r | s sepanjang 64 byte, masing-masing 32 byte
  big-endian. Pustaka OTP bekerja dengan ASN.1 DER, sehingga modul ini mengonversi
  DER ke r | s saat menandatangani dan sebaliknya saat memverifikasi.

  Pustaka yang dipakai adalah public_key dan crypto bawaan OTP (OpenSSL di bawahnya).
  SHA-256 diterapkan tepat satu kali atas byte manifest. Nonce dibangkitkan pustaka
  dari CSPRNG sehingga dua tanda tangan atas pesan yang sama berbeda (skenario U14).
  """

  @behaviour Nadina.Profile

  # OID 1.2.840.10045.3.1.7 (prime256v1 / secp256r1)
  @p256_oid {1, 2, 840, 10045, 3, 1, 7}

  @sig_size 64

  @impl true
  def name, do: "ecdsa-p256-sha256"

  @impl true
  def signature_size, do: @sig_size

  @doc """
  Membangkitkan pasangan kunci P-256 dari CSPRNG.

  ## Contoh

      iex> {priv, pub} = Nadina.Profile.EcdsaP256.generate_key()
      iex> {Nadina.Profile.EcdsaP256.check_key(priv), Nadina.Profile.EcdsaP256.check_key(pub)}
      {:ok, :ok}
  """
  @impl true
  @spec generate_key() :: {Nadina.Profile.private_key(), Nadina.Profile.public_key()}
  def generate_key do
    priv = :public_key.generate_key({:namedCurve, :secp256r1})
    {priv, public_from_private(priv)}
  end

  @impl true
  def public_from_private({:ECPrivateKey, _, _, params, point, _}) do
    {{:ECPoint, point}, params}
  end

  @doc """
  Memeriksa tipe dan parameter kunci. Kunci harus EC pada kurva P-256 dengan titik
  publik SEC1 uncompressed (65 byte, diawali 0x04).

  ## Contoh

      iex> Nadina.Profile.EcdsaP256.check_key({:RSAPublicKey, 1, 3})
      {:error, :wrong_key_type}
  """
  @impl true
  def check_key({:ECPrivateKey, _, priv, params, point, _}) when is_binary(priv) do
    with :ok <- check_params(params), do: check_point(point)
  end

  def check_key({{:ECPoint, point}, params}) do
    with :ok <- check_params(params), do: check_point(point)
  end

  def check_key(_), do: {:error, :wrong_key_type}

  defp check_params({:namedCurve, @p256_oid}), do: :ok
  defp check_params({:namedCurve, :secp256r1}), do: :ok
  defp check_params({:namedCurve, :prime256v1}), do: :ok
  defp check_params(_), do: {:error, :wrong_parameters}

  defp check_point(<<4, _::binary-size(64)>>), do: :ok
  defp check_point(_), do: {:error, :wrong_parameters}

  @doc """
  Menandatangani message dan mengembalikan r | s sepanjang 64 byte.

  ## Contoh

      iex> {priv, pub} = Nadina.Profile.EcdsaP256.generate_key()
      iex> sig = Nadina.Profile.EcdsaP256.sign(priv, "pesan")
      iex> {byte_size(sig), Nadina.Profile.EcdsaP256.verify(pub, "pesan", sig)}
      {64, true}
  """
  @impl true
  @spec sign(Nadina.Profile.private_key(), binary()) :: binary()
  def sign(priv, message) when is_binary(message) do
    der = :public_key.sign(message, :sha256, priv)
    der_to_rs(der)
  end

  @doc """
  Memverifikasi tanda tangan r | s. Panjang selain 64 byte, r atau s di luar
  rentang 1 sampai n-1, dan nilai tidak sah lainnya menghasilkan false tanpa raise.

  ## Contoh

      iex> {_priv, pub} = Nadina.Profile.EcdsaP256.generate_key()
      iex> Nadina.Profile.EcdsaP256.verify(pub, "pesan", <<0::512>>)
      false

      iex> {_priv, pub} = Nadina.Profile.EcdsaP256.generate_key()
      iex> Nadina.Profile.EcdsaP256.verify(pub, "pesan", <<1, 2, 3>>)
      false
  """
  @impl true
  @spec verify(Nadina.Profile.public_key(), binary(), binary()) :: boolean()
  def verify(pub, message, <<r::unsigned-big-256, s::unsigned-big-256>>)
      when is_binary(message) do
    der = :public_key.der_encode(:"ECDSA-Sig-Value", {:"ECDSA-Sig-Value", r, s})
    :public_key.verify(message, :sha256, der, pub) == true
  rescue
    _ -> false
  catch
    _, _ -> false
  end

  def verify(_pub, _message, _signature), do: false

  @doc """
  Mengubah tanda tangan ASN.1 DER menjadi r | s (32 byte tiap nilai, big-endian,
  dengan padding nol di kiri).

  ## Contoh

      iex> der = :public_key.der_encode(:"ECDSA-Sig-Value", {:"ECDSA-Sig-Value", 1, 2})
      iex> Nadina.Profile.EcdsaP256.der_to_rs(der) == <<1::256, 2::256>>
      true
  """
  @spec der_to_rs(binary()) :: binary()
  def der_to_rs(der) do
    {:"ECDSA-Sig-Value", r, s} = :public_key.der_decode(:"ECDSA-Sig-Value", der)
    <<r::unsigned-big-256, s::unsigned-big-256>>
  end
end
