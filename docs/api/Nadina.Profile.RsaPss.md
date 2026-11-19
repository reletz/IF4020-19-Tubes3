# `Nadina.Profile.RsaPss`
[🔗](https://github.com/reletz/IF4020-19-Tubes3/blob/main/lib/nadina/profile/rsa_pss.ex#L1)

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

# `check_key`

Memeriksa tipe dan parameter kunci. Kunci harus RSA dengan modulus tepat 3072 bit
(bit tertinggi menyala) dan eksponen publik 65537.

## Contoh

    iex> Nadina.Profile.RsaPss.check_key({:RSAPublicKey, 3233, 17})
    {:error, :wrong_parameters}

    iex> Nadina.Profile.RsaPss.check_key({{:ECPoint, <<4>>}, {:namedCurve, :secp256r1}})
    {:error, :wrong_key_type}

# `generate_key`

```elixir
@spec generate_key() :: {Nadina.Profile.private_key(), Nadina.Profile.public_key()}
```

Membangkitkan pasangan kunci RSA 3072 bit dengan e = 65537 dari CSPRNG.

## Contoh

    iex> {priv, pub} = Nadina.Profile.RsaPss.generate_key()
    iex> {Nadina.Profile.RsaPss.check_key(priv), Nadina.Profile.RsaPss.check_key(pub)}
    {:ok, :ok}

# `sign`

```elixir
@spec sign(Nadina.Profile.private_key(), binary()) :: binary()
```

Menandatangani message dan mengembalikan tanda tangan mentah 384 byte.

## Contoh

    iex> {priv, pub} = Nadina.Profile.RsaPss.generate_key()
    iex> sig = Nadina.Profile.RsaPss.sign(priv, "pesan")
    iex> {byte_size(sig), Nadina.Profile.RsaPss.verify(pub, "pesan", sig)}
    {384, true}

# `verify`

```elixir
@spec verify(Nadina.Profile.public_key(), binary(), binary()) :: boolean()
```

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

---

*Consult [api-reference.md](api-reference.md) for complete listing*
