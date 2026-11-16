defmodule Nadina.Profile.Ed25519 do
  @moduledoc """
  Profil ed25519, yaitu PureEdDSA sesuai RFC 8032 pada kurva Ed25519.

  Pesan diberikan apa adanya kepada pustaka tanpa pre-hash eksternal dan tanpa context
  (bukan Ed25519ph). Tanda tangan sepanjang 64 byte memakai encoding standar RFC 8032.
  Nonce diturunkan secara deterministik dari kunci dan pesan, sehingga dua tanda tangan
  atas pesan yang sama identik.

  Kunci disimpan sebagai PKCS8 dan SPKI mengikuti RFC 8410 (tanpa field parameter pada
  AlgorithmIdentifier). Pustaka yang dipakai adalah public_key dan crypto bawaan OTP.
  """

  @behaviour Nadina.Profile

  # OID 1.3.101.112 (id-Ed25519)
  @ed25519_oid {1, 3, 101, 112}

  @sig_size 64

  @impl true
  def name, do: "ed25519"

  @impl true
  def signature_size, do: @sig_size

  @doc """
  Membangkitkan pasangan kunci Ed25519 dari CSPRNG.

  ## Contoh

      iex> {priv, pub} = Nadina.Profile.Ed25519.generate_key()
      iex> {Nadina.Profile.Ed25519.check_key(priv), Nadina.Profile.Ed25519.check_key(pub)}
      {:ok, :ok}
  """
  @impl true
  @spec generate_key() :: {Nadina.Profile.private_key(), Nadina.Profile.public_key()}
  def generate_key do
    priv = :public_key.generate_key({:namedCurve, :ed25519})
    {priv, public_from_private(priv)}
  end

  @impl true
  def public_from_private({:ECPrivateKey, _, _, params, point, _}) do
    {{:ECPoint, point}, params}
  end

  @doc """
  Memeriksa tipe dan parameter kunci. Kunci harus EC pada kurva Ed25519 dengan titik
  publik 32 byte.

  ## Contoh

      iex> Nadina.Profile.Ed25519.check_key({:RSAPublicKey, 1, 3})
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

  defp check_params({:namedCurve, @ed25519_oid}), do: :ok
  defp check_params({:namedCurve, :ed25519}), do: :ok
  defp check_params(_), do: {:error, :wrong_parameters}

  defp check_point(<<_::binary-size(32)>>), do: :ok
  defp check_point(_), do: {:error, :wrong_parameters}

  @doc """
  Menandatangani message dan mengembalikan tanda tangan 64 byte.

  ## Contoh

      iex> {priv, pub} = Nadina.Profile.Ed25519.generate_key()
      iex> sig = Nadina.Profile.Ed25519.sign(priv, "pesan")
      iex> {byte_size(sig), Nadina.Profile.Ed25519.verify(pub, "pesan", sig)}
      {64, true}
  """
  @impl true
  @spec sign(Nadina.Profile.private_key(), binary()) :: binary()
  def sign(priv, message) when is_binary(message) do
    :public_key.sign(message, :none, priv)
  end

  @doc """
  Memverifikasi tanda tangan Ed25519. Panjang selain 64 byte dan nilai tidak sah
  menghasilkan false tanpa raise.

  ## Contoh

      iex> {_priv, pub} = Nadina.Profile.Ed25519.generate_key()
      iex> Nadina.Profile.Ed25519.verify(pub, "pesan", <<0::512>>)
      false

      iex> {_priv, pub} = Nadina.Profile.Ed25519.generate_key()
      iex> Nadina.Profile.Ed25519.verify(pub, "pesan", <<1, 2, 3>>)
      false
  """
  @impl true
  @spec verify(Nadina.Profile.public_key(), binary(), binary()) :: boolean()
  def verify({{:ECPoint, _}, _} = pub, message, signature)
      when is_binary(message) and byte_size(signature) == @sig_size do
    :public_key.verify(message, :none, signature, pub) == true
  rescue
    _ -> false
  catch
    _, _ -> false
  end

  def verify(_pub, _message, _signature), do: false
end
