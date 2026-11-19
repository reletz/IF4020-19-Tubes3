# `Nadina.Profile.EcdsaP256`
[🔗](https://github.com/reletz/IF4020-19-Tubes3/blob/main/lib/nadina/profile/ecdsa_p256.ex#L1)

Profil ecdsa-p256-sha256, yaitu ECDSA pada kurva NIST P-256 (secp256r1) dengan SHA-256.

Tanda tangan disimpan sebagai r | s sepanjang 64 byte, masing-masing 32 byte
big-endian. Pustaka OTP bekerja dengan ASN.1 DER, sehingga modul ini mengonversi
DER ke r | s saat menandatangani dan sebaliknya saat memverifikasi.

Pustaka yang dipakai adalah public_key dan crypto bawaan OTP (OpenSSL di bawahnya).
SHA-256 diterapkan tepat satu kali atas byte manifest. Nonce dibangkitkan pustaka
dari CSPRNG sehingga dua tanda tangan atas pesan yang sama berbeda (skenario U14).

# `check_key`

Memeriksa tipe dan parameter kunci. Kunci harus EC pada kurva P-256 dengan titik
publik SEC1 uncompressed (65 byte, diawali 0x04).

## Contoh

    iex> Nadina.Profile.EcdsaP256.check_key({:RSAPublicKey, 1, 3})
    {:error, :wrong_key_type}

# `der_to_rs`

```elixir
@spec der_to_rs(binary()) :: binary()
```

Mengubah tanda tangan ASN.1 DER menjadi r | s (32 byte tiap nilai, big-endian,
dengan padding nol di kiri).

## Contoh

    iex> der = :public_key.der_encode(:"ECDSA-Sig-Value", {:"ECDSA-Sig-Value", 1, 2})
    iex> Nadina.Profile.EcdsaP256.der_to_rs(der) == <<1::256, 2::256>>
    true

# `generate_key`

```elixir
@spec generate_key() :: {Nadina.Profile.private_key(), Nadina.Profile.public_key()}
```

Membangkitkan pasangan kunci P-256 dari CSPRNG.

## Contoh

    iex> {priv, pub} = Nadina.Profile.EcdsaP256.generate_key()
    iex> {Nadina.Profile.EcdsaP256.check_key(priv), Nadina.Profile.EcdsaP256.check_key(pub)}
    {:ok, :ok}

# `sign`

```elixir
@spec sign(Nadina.Profile.private_key(), binary()) :: binary()
```

Menandatangani message dan mengembalikan r | s sepanjang 64 byte.

## Contoh

    iex> {priv, pub} = Nadina.Profile.EcdsaP256.generate_key()
    iex> sig = Nadina.Profile.EcdsaP256.sign(priv, "pesan")
    iex> {byte_size(sig), Nadina.Profile.EcdsaP256.verify(pub, "pesan", sig)}
    {64, true}

# `verify`

```elixir
@spec verify(Nadina.Profile.public_key(), binary(), binary()) :: boolean()
```

Memverifikasi tanda tangan r | s. Panjang selain 64 byte, r atau s di luar
rentang 1 sampai n-1, dan nilai tidak sah lainnya menghasilkan false tanpa raise.

## Contoh

    iex> {_priv, pub} = Nadina.Profile.EcdsaP256.generate_key()
    iex> Nadina.Profile.EcdsaP256.verify(pub, "pesan", <<0::512>>)
    false

    iex> {_priv, pub} = Nadina.Profile.EcdsaP256.generate_key()
    iex> Nadina.Profile.EcdsaP256.verify(pub, "pesan", <<1, 2, 3>>)
    false

---

*Consult [api-reference.md](api-reference.md) for complete listing*
