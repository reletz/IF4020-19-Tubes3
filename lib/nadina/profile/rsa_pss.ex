defmodule Nadina.Profile.RsaPss do
  @moduledoc """
  Profil rsa-pss-sha256, yaitu RSASSA-PSS (RFC 8017 bagian 8.1) dengan kunci RSA
  3072 bit dan e = 65537.

  Parameter yang dikunci

  - fungsi hash SHA-256, diterapkan tepat satu kali atas byte manifest oleh pustaka
    (pemanggil tidak boleh meng-hash lebih dulu)
  - MGF1 dengan SHA-256
  - salt 32 byte dari CSPRNG, sehingga dua tanda tangan atas pesan yang sama berbeda
  - tanda tangan mentah 384 byte (panjang modulus), big-endian

  Saat verifikasi, parameter yang sama dipaksakan. Tanda tangan PKCS#1 v1.5, PSS
  dengan salt lain, MGF1 atau hash lain ditolak.

  Pustaka yang dipakai adalah public_key dan crypto bawaan OTP (OpenSSL di bawahnya),
  lewat :public_key.sign/4 dan :public_key.verify/5 dengan opsi rsa_padding,
  rsa_pss_saltlen, dan rsa_mgf1_md.
  """

  @behaviour Nadina.Profile

  @modulus_bits 3072
  @public_exponent 65_537
  @sig_size div(@modulus_bits, 8)
  @salt_len 32

  @pss_opts [
    rsa_padding: :rsa_pkcs1_pss_padding,
    rsa_pss_saltlen: @salt_len,
    rsa_mgf1_md: :sha256
  ]

  @impl true
  def name, do: "rsa-pss-sha256"

  @impl true
  def signature_size, do: @sig_size

  @doc """
  Membangkitkan pasangan kunci RSA 3072 bit dengan e = 65537 dari CSPRNG.

  ## Contoh

      iex> {priv, pub} = Nadina.Profile.RsaPss.generate_key()
      iex> {Nadina.Profile.RsaPss.check_key(priv), Nadina.Profile.RsaPss.check_key(pub)}
      {:ok, :ok}
  """
  @impl true
  @spec generate_key() :: {Nadina.Profile.private_key(), Nadina.Profile.public_key()}
  def generate_key do
    priv = :public_key.generate_key({:rsa, @modulus_bits, @public_exponent})
    {priv, public_from_private(priv)}
  end

  @impl true
  def public_from_private({:RSAPrivateKey, _, n, e, _, _, _, _, _, _, _}) do
    {:RSAPublicKey, n, e}
  end

  @doc """
  Memeriksa tipe dan parameter kunci. Kunci harus RSA dengan modulus tepat 3072 bit
  (bit tertinggi menyala) dan eksponen publik 65537.

  ## Contoh

      iex> Nadina.Profile.RsaPss.check_key({:RSAPublicKey, 3233, 17})
      {:error, :wrong_parameters}

      iex> Nadina.Profile.RsaPss.check_key({{:ECPoint, <<4>>}, {:namedCurve, :secp256r1}})
      {:error, :wrong_key_type}
  """
  @impl true
  def check_key({:RSAPrivateKey, _, n, e, _, _, _, _, _, _, _})
      when is_integer(n) and is_integer(e),
      do: check_params(n, e)

  def check_key({:RSAPublicKey, n, e}) when is_integer(n) and is_integer(e),
    do: check_params(n, e)

  def check_key(_), do: {:error, :wrong_key_type}

  # Modulus tepat 3072 bit berarti 2^3071 <= n < 2^3072 (bit tertinggi menyala).
  @n_min Bitwise.bsl(1, @modulus_bits - 1)
  @n_max Bitwise.bsl(1, @modulus_bits)

  defp check_params(n, @public_exponent) when n >= @n_min and n < @n_max, do: :ok
  defp check_params(_n, _e), do: {:error, :wrong_parameters}

  @doc """
  Menandatangani message dan mengembalikan tanda tangan mentah 384 byte.

  ## Contoh

      iex> {priv, pub} = Nadina.Profile.RsaPss.generate_key()
      iex> sig = Nadina.Profile.RsaPss.sign(priv, "pesan")
      iex> {byte_size(sig), Nadina.Profile.RsaPss.verify(pub, "pesan", sig)}
      {384, true}
  """
  @impl true
  @spec sign(Nadina.Profile.private_key(), binary()) :: binary()
  def sign(priv, message) when is_binary(message) do
    :public_key.sign(message, :sha256, priv, @pss_opts)
  end

  @doc """
  Memverifikasi tanda tangan RSASSA-PSS. Panjang selain 384 byte, nilai di luar
  rentang modulus, parameter PSS yang berbeda, dan kunci tidak sah menghasilkan
  false tanpa raise.

  ## Contoh

      iex> {_priv, pub} = Nadina.Profile.RsaPss.generate_key()
      iex> Nadina.Profile.RsaPss.verify(pub, "pesan", <<0::3072>>)
      false

      iex> {_priv, pub} = Nadina.Profile.RsaPss.generate_key()
      iex> Nadina.Profile.RsaPss.verify(pub, "pesan", <<1, 2, 3>>)
      false
  """
  @impl true
  @spec verify(Nadina.Profile.public_key(), binary(), binary()) :: boolean()
  def verify({:RSAPublicKey, _, _} = pub, message, signature)
      when is_binary(message) and byte_size(signature) == @sig_size do
    :public_key.verify(message, :sha256, signature, pub, @pss_opts) == true
  rescue
    _ -> false
  catch
    _, _ -> false
  end

  def verify(_pub, _message, _signature), do: false
end
