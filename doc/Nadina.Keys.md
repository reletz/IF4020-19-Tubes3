# `Nadina.Keys`
[🔗](https://github.com/reletz/IF4020-19-Tubes3/blob/main/lib/nadina/keys.ex#L1)

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

# `reason`

```elixir
@type reason() ::
  :invalid_pem
  | :unsupported_key
  | :wrong_key_type
  | :wrong_parameters
  | :exists
  | {:io, File.posix()}
```

# `decode_private_pem`

```elixir
@spec decode_private_pem(binary()) ::
  {:ok, module(), Nadina.Profile.private_key(), Nadina.Profile.public_key()}
  | {:error, reason()}
```

Memuat kunci privat dari teks PEM PKCS8. Mengembalikan modul profil, kunci, dan
kunci publik turunannya. Kunci dengan tipe atau parameter yang tidak sesuai ditolak.

# `decode_public_pem`

```elixir
@spec decode_public_pem(binary()) ::
  {:ok, module(), Nadina.Profile.public_key()} | {:error, reason()}
```

Memuat kunci publik dari teks PEM SPKI. Mengembalikan modul profil dan kunci.

## Contoh

    iex> {:ok, _mod, _priv, pub} = Nadina.Keys.generate("ecdsa-p256-sha256")
    iex> pem = Nadina.Keys.encode_public_pem(pub)
    iex> {:ok, Nadina.Profile.EcdsaP256, ^pub} = Nadina.Keys.decode_public_pem(pem)
    iex> :ok
    :ok

# `encode_private_pem`

```elixir
@spec encode_private_pem(Nadina.Profile.private_key()) :: String.t()
```

Mengubah kunci privat menjadi teks PEM PKCS8 dengan label PRIVATE KEY.

# `encode_public_pem`

```elixir
@spec encode_public_pem(Nadina.Profile.public_key()) :: String.t()
```

Mengubah kunci publik menjadi teks PEM SPKI dengan label PUBLIC KEY.

# `fingerprint`

```elixir
@spec fingerprint(Nadina.Profile.public_key()) :: String.t()
```

Menghitung fingerprint kunci publik, yaitu hex huruf kecil dari SHA-256 atas DER SPKI.

## Contoh

    iex> {:ok, _mod, _priv, pub} = Nadina.Keys.generate("ecdsa-p256-sha256")
    iex> fp = Nadina.Keys.fingerprint(pub)
    iex> {byte_size(fp), fp == String.downcase(fp)}
    {64, true}

# `generate`

```elixir
@spec generate(String.t()) ::
  {:ok, module(), Nadina.Profile.private_key(), Nadina.Profile.public_key()}
  | {:error, :unsupported_algorithm}
```

Membangkitkan pasangan kunci untuk profil bernama. Nama profil tidak dikenal
menghasilkan error unsupported_algorithm.

## Contoh

    iex> {:ok, mod, _priv, _pub} = Nadina.Keys.generate("ecdsa-p256-sha256")
    iex> mod
    Nadina.Profile.EcdsaP256

    iex> Nadina.Keys.generate("rsa-sha1")
    {:error, :unsupported_algorithm}

# `load_private_file`

```elixir
@spec load_private_file(Path.t()) ::
  {:ok, module(), Nadina.Profile.private_key(), Nadina.Profile.public_key()}
  | {:error, reason()}
```

Membaca berkas kunci privat lalu memuatnya. Kegagalan baca menghasilkan error io.

# `load_public_file`

```elixir
@spec load_public_file(Path.t()) ::
  {:ok, module(), Nadina.Profile.public_key()} | {:error, reason()}
```

Membaca berkas kunci publik lalu memuatnya. Kegagalan baca menghasilkan error io.

# `write_keypair`

```elixir
@spec write_keypair(
  String.t(),
  Nadina.Profile.private_key(),
  Nadina.Profile.public_key(),
  keyword()
) ::
  {:ok, String.t()} | {:error, reason()}
```

Menulis pasangan kunci ke prefix.key.pem (izin 0600) dan prefix.pub.pem (izin 0644).

Berkas yang sudah ada tidak ditimpa, kecuali opsi force bernilai true. Penulisan
memakai berkas sementara pada direktori yang sama lalu rename, sehingga berkas lama
tidak rusak bila penulisan gagal. Isi kunci tidak pernah dicatat pada log.

Mengembalikan fingerprint kunci publik.

---

*Consult [api-reference.md](api-reference.md) for complete listing*
