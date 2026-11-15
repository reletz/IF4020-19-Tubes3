defmodule Nadina.Profile do
  @moduledoc """
  Behaviour untuk profil algoritma tanda tangan (Tabel 2.1 spesifikasi).

  Setiap profil (`rsa-pss-sha256`, `ecdsa-p256-sha256`, `ed25519`) mengimplementasikan
  behaviour ini. Hanya modul `Nadina.Profile.*` dan `Nadina.Keys` yang menyentuh API
  kripto OTP; modul lain memakai profil lewat behaviour ini.

  Kunci direpresentasikan sebagai record `:public_key` (hasil `:public_key.pem_entry_decode/1`
  atau `:public_key.generate_key/1`):

    * kunci privat: `:RSAPrivateKey` atau `:ECPrivateKey`
    * kunci publik: `:RSAPublicKey` atau `{{:ECPoint, point}, params}`

  Aturan umum untuk semua implementasi:

    * `c:sign/2` menerima byte manifest `M` apa adanya. SHA-256 diterapkan tepat satu kali
      (RSA-PSS dan ECDSA), sedangkan Ed25519 menerima `M` tanpa hashing eksternal.
    * `c:verify/3` tidak boleh raise. Tanda tangan dengan panjang atau nilai yang tidak
      sah menghasilkan `false`.
  """

  @typedoc "Nama profil, dipakai sebagai nilai `algorithm` pada manifest."
  @type name :: String.t()

  @typedoc "Record kunci privat dari `:public_key`."
  @type private_key :: tuple()

  @typedoc "Record kunci publik dari `:public_key`."
  @type public_key :: tuple()

  @typedoc "Alasan kunci ditolak oleh `c:check_key/1`."
  @type key_error :: :wrong_key_type | :wrong_parameters

  @profiles %{
    "rsa-pss-sha256" => Nadina.Profile.RsaPss,
    "ecdsa-p256-sha256" => Nadina.Profile.EcdsaP256,
    "ed25519" => Nadina.Profile.Ed25519
  }

  @doc "Nama profil sesuai Tabel 2.1, misal `\"ed25519\"`."
  @callback name() :: name()

  @doc "Panjang tanda tangan dalam byte sebelum Base64 (384, 64, atau 64)."
  @callback signature_size() :: pos_integer()

  @doc """
  Membangkitkan pasangan kunci baru dari CSPRNG.
  """
  @callback generate_key() :: {private_key(), public_key()}

  @doc """
  Menurunkan kunci publik dari kunci privat.
  """
  @callback public_from_private(private_key()) :: public_key()

  @doc """
  Memeriksa bahwa kunci (privat atau publik) sesuai tipe dan parameter profil.

  Mengembalikan `:ok`, `{:error, :wrong_key_type}` bila tipe kunci salah, atau
  `{:error, :wrong_parameters}` bila parameter (ukuran modulus, eksponen, kurva) salah.
  """
  @callback check_key(private_key() | public_key()) :: :ok | {:error, key_error()}

  @doc """
  Menandatangani byte `message` dengan kunci privat. Mengembalikan tanda tangan mentah
  sepanjang `c:signature_size/0` byte.
  """
  @callback sign(private_key(), message :: binary()) :: binary()

  @doc """
  Memverifikasi `signature` atas `message`. Tidak pernah raise; nilai yang tidak sah
  menghasilkan `false`.
  """
  @callback verify(public_key(), message :: binary(), signature :: binary()) :: boolean()

  @doc """
  Daftar nama profil yang didukung.

  ## Contoh

      iex> Nadina.Profile.names() |> Enum.sort()
      ["ecdsa-p256-sha256", "ed25519", "rsa-pss-sha256"]
  """
  @spec names() :: [name()]
  def names, do: Map.keys(@profiles)

  @doc """
  Mencari modul profil dari nama. Nama tidak dikenal menghasilkan `:error`.

  ## Contoh

      iex> Nadina.Profile.fetch("ed25519")
      {:ok, Nadina.Profile.Ed25519}

      iex> Nadina.Profile.fetch("rsa-sha1")
      :error
  """
  @spec fetch(String.t()) :: {:ok, module()} | :error
  def fetch(name) when is_binary(name), do: Map.fetch(@profiles, name)
  def fetch(_), do: :error
end
