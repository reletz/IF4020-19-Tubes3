# `Nadina.Profile.Ed25519`
[🔗](https://github.com/reletz/IF4020-19-Tubes3/blob/main/lib/nadina/profile/ed25519.ex#L1)

Profil ed25519, yaitu PureEdDSA sesuai RFC 8032 pada kurva Ed25519.

Pesan diberikan apa adanya kepada pustaka tanpa pre-hash eksternal dan tanpa context
(bukan Ed25519ph). Tanda tangan sepanjang 64 byte memakai encoding standar RFC 8032.
Nonce diturunkan secara deterministik dari kunci dan pesan, sehingga dua tanda tangan
atas pesan yang sama identik.

Kunci disimpan sebagai PKCS8 dan SPKI mengikuti RFC 8410 (tanpa field parameter pada
AlgorithmIdentifier). Pustaka yang dipakai adalah public_key dan crypto bawaan OTP.

# `check_key`

Memeriksa tipe dan parameter kunci. Kunci harus EC pada kurva Ed25519 dengan titik
publik 32 byte.

## Contoh

    iex> Nadina.Profile.Ed25519.check_key({:RSAPublicKey, 1, 3})
    {:error, :wrong_key_type}

# `generate_key`

```elixir
@spec generate_key() :: {Nadina.Profile.private_key(), Nadina.Profile.public_key()}
```

Membangkitkan pasangan kunci Ed25519 dari CSPRNG.

## Contoh

    iex> {priv, pub} = Nadina.Profile.Ed25519.generate_key()
    iex> {Nadina.Profile.Ed25519.check_key(priv), Nadina.Profile.Ed25519.check_key(pub)}
    {:ok, :ok}

# `sign`

```elixir
@spec sign(Nadina.Profile.private_key(), binary()) :: binary()
```

Menandatangani message dan mengembalikan tanda tangan 64 byte.

## Contoh

    iex> {priv, pub} = Nadina.Profile.Ed25519.generate_key()
    iex> sig = Nadina.Profile.Ed25519.sign(priv, "pesan")
    iex> {byte_size(sig), Nadina.Profile.Ed25519.verify(pub, "pesan", sig)}
    {64, true}

# `verify`

```elixir
@spec verify(Nadina.Profile.public_key(), binary(), binary()) :: boolean()
```

Memverifikasi tanda tangan Ed25519. Panjang selain 64 byte dan nilai tidak sah
menghasilkan false tanpa raise.

## Contoh

    iex> {_priv, pub} = Nadina.Profile.Ed25519.generate_key()
    iex> Nadina.Profile.Ed25519.verify(pub, "pesan", <<0::512>>)
    false

    iex> {_priv, pub} = Nadina.Profile.Ed25519.generate_key()
    iex> Nadina.Profile.Ed25519.verify(pub, "pesan", <<1, 2, 3>>)
    false

---

*Consult [api-reference.md](api-reference.md) for complete listing*
