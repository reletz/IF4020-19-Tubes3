defmodule Nadina.Profile do
  @moduledoc """
  Behaviour untuk profil algoritma tanda tangan (Tabel 2.1 spesifikasi).

  Setiap profil (rsa-pss-sha256, ecdsa-p256-sha256, ed25519) mengimplementasikan
  behaviour ini. Hanya modul Nadina.Profile dan Nadina.Keys yang menyentuh API
  kripto OTP. Modul lain memakai profil lewat behaviour ini.

  Kunci direpresentasikan sebagai record dari pustaka public_key OTP, hasil
  pem_entry_decode atau generate_key.

  - kunci privat berupa record RSAPrivateKey atau ECPrivateKey
  - kunci publik berupa record RSAPublicKey atau tuple {{ECPoint, titik}, parameter}

  Aturan umum untuk semua implementasi

  - sign menerima byte manifest M apa adanya. SHA-256 diterapkan tepat satu kali
    (RSA-PSS dan ECDSA), sedangkan Ed25519 menerima M tanpa hashing eksternal.
  - verify tidak boleh raise. Tanda tangan dengan panjang atau nilai yang tidak sah
    menghasilkan false.
  """

  @typedoc "Nama profil, dipakai sebagai nilai algorithm pada manifest."
  @type name :: String.t()

  @typedoc "Record kunci privat dari pustaka public_key."
  @type private_key :: tuple()

  @typedoc "Record kunci publik dari pustaka public_key."
  @type public_key :: tuple()

  @typedoc "Alasan kunci ditolak oleh check_key."
  @type key_error :: :wrong_key_type | :wrong_parameters

  @profiles %{
    "rsa-pss-sha256" => Nadina.Profile.RsaPss,
    "ecdsa-p256-sha256" => Nadina.Profile.EcdsaP256,
    "ed25519" => Nadina.Profile.Ed25519
  }

  @doc "Nama profil sesuai Tabel 2.1, misalnya ed25519."
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

  Hasilnya ok bila sesuai, error wrong_key_type bila tipe kunci salah, atau
  error wrong_parameters bila parameter (ukuran modulus, eksponen, kurva) salah.
  """
  @callback check_key(private_key() | public_key()) :: :ok | {:error, key_error()}

  @doc """
  Menandatangani byte message dengan kunci privat. Mengembalikan tanda tangan mentah
  sepanjang signature_size byte.
  """
  @callback sign(private_key(), message :: binary()) :: binary()

  @doc """
  Memverifikasi signature atas message. Tidak pernah raise. Nilai yang tidak sah
  menghasilkan false.
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
  Mencari modul profil dari nama. Nama tidak dikenal menghasilkan error.

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
