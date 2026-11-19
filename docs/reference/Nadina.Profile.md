# `Nadina.Profile`
[🔗](https://github.com/reletz/IF4020-19-Tubes3/blob/main/lib/nadina/profile.ex#L1)

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

# `key_error`

```elixir
@type key_error() :: :wrong_key_type | :wrong_parameters
```

Alasan kunci ditolak oleh check_key.

# `name`

```elixir
@type name() :: String.t()
```

Nama profil, dipakai sebagai nilai algorithm pada manifest.

# `private_key`

```elixir
@type private_key() :: tuple()
```

Record kunci privat dari pustaka public_key.

# `public_key`

```elixir
@type public_key() :: tuple()
```

Record kunci publik dari pustaka public_key.

# `check_key`

```elixir
@callback check_key(private_key() | public_key()) :: :ok | {:error, key_error()}
```

Memeriksa bahwa kunci (privat atau publik) sesuai tipe dan parameter profil.

Hasilnya ok bila sesuai, error wrong_key_type bila tipe kunci salah, atau
error wrong_parameters bila parameter (ukuran modulus, eksponen, kurva) salah.

# `generate_key`

```elixir
@callback generate_key() :: {private_key(), public_key()}
```

Membangkitkan pasangan kunci baru dari CSPRNG.

# `name`

```elixir
@callback name() :: name()
```

Nama profil sesuai Tabel 2.1, misalnya ed25519.

# `public_from_private`

```elixir
@callback public_from_private(private_key()) :: public_key()
```

Menurunkan kunci publik dari kunci privat.

# `sign`

```elixir
@callback sign(private_key(), message :: binary()) :: binary()
```

Menandatangani byte message dengan kunci privat. Mengembalikan tanda tangan mentah
sepanjang signature_size byte.

# `signature_size`

```elixir
@callback signature_size() :: pos_integer()
```

Panjang tanda tangan dalam byte sebelum Base64 (384, 64, atau 64).

# `verify`

```elixir
@callback verify(public_key(), message :: binary(), signature :: binary()) :: boolean()
```

Memverifikasi signature atas message. Tidak pernah raise. Nilai yang tidak sah
menghasilkan false.

# `fetch`

```elixir
@spec fetch(String.t()) :: {:ok, module()} | :error
```

Mencari modul profil dari nama. Nama tidak dikenal menghasilkan error.

## Contoh

    iex> Nadina.Profile.fetch("ed25519")
    {:ok, Nadina.Profile.Ed25519}

    iex> Nadina.Profile.fetch("rsa-sha1")
    :error

# `names`

```elixir
@spec names() :: [name()]
```

Daftar nama profil yang didukung.

## Contoh

    iex> Nadina.Profile.names() |> Enum.sort()
    ["ecdsa-p256-sha256", "ed25519", "rsa-pss-sha256"]

---

*Consult [api-reference.md](api-reference.md) for complete listing*
