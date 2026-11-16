defmodule Nadina.Profile.Ed25519Test do
  use ExUnit.Case, async: true

  alias Nadina.Profile.Ed25519

  doctest Nadina.Profile.Ed25519

  # RFC 8032 section 7.1, TEST 1 (pesan kosong) dan TEST 2 (pesan 1 byte).
  @vectors [
    {"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"},
    {"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"}
  ]

  setup_all do
    {priv, pub} = Ed25519.generate_key()
    %{priv: priv, pub: pub}
  end

  test "vektor RFC 8032: kunci publik, verifikasi, dan tanda tangan deterministik" do
    for {seed, pub_hex, msg_hex, sig_hex} <- @vectors do
      seed = Base.decode16!(seed, case: :lower)
      pub_bytes = Base.decode16!(pub_hex, case: :lower)
      msg = Base.decode16!(msg_hex, case: :lower)
      sig = Base.decode16!(sig_hex, case: :lower)

      {^pub_bytes, _} = :crypto.generate_key(:eddsa, :ed25519, seed)

      priv =
        {:ECPrivateKey, :ecPrivkeyVer1, seed, {:namedCurve, {1, 3, 101, 112}}, pub_bytes,
         :asn1_NOVALUE}

      pub = Ed25519.public_from_private(priv)

      assert Ed25519.check_key(priv) == :ok
      assert Ed25519.verify(pub, msg, sig)
      assert Ed25519.sign(priv, msg) == sig
    end
  end

  test "sign lalu verify, panjang 64 byte", %{priv: priv, pub: pub} do
    sig = Ed25519.sign(priv, "manifest")
    assert byte_size(sig) == 64
    assert Ed25519.verify(pub, "manifest", sig)
    assert Ed25519.verify(pub, "", Ed25519.sign(priv, ""))
  end

  test "deterministik: dua tanda tangan identik", %{priv: priv} do
    assert Ed25519.sign(priv, "m") == Ed25519.sign(priv, "m")
  end

  test "pesan, tanda tangan, atau kunci lain ditolak tanpa raise", %{priv: priv, pub: pub} do
    sig = Ed25519.sign(priv, "m")
    refute Ed25519.verify(pub, "n", sig)
    {_, other} = Ed25519.generate_key()
    refute Ed25519.verify(other, "m", sig)

    for i <- [0, 31, 32, 63] do
      <<head::binary-size(^i), b, tail::binary>> = sig
      refute Ed25519.verify(pub, "m", <<head::binary, Bitwise.bxor(b, 1), tail::binary>>)
    end

    refute Ed25519.verify(pub, "m", binary_part(sig, 0, 63))
    refute Ed25519.verify(pub, "m", sig <> <<0>>)
    refute Ed25519.verify(pub, "m", :bukan_binary)
    refute Ed25519.verify(:bukan_kunci, "m", sig)
  end

  test "check_key menolak kurva dan tipe lain" do
    p256 = :public_key.generate_key({:namedCurve, :secp256r1})
    assert Ed25519.check_key(p256) == {:error, :wrong_parameters}
    assert Ed25519.check_key(:sampah) == {:error, :wrong_key_type}
  end

  test "kunci privat hasil decode PKCS8 (tanpa titik publik) tetap dapat dipakai" do
    {priv, pub} = Ed25519.generate_key()
    pem = Nadina.Keys.encode_private_pem(priv)
    assert {:ok, Ed25519, decoded, ^pub} = Nadina.Keys.decode_private_pem(pem)
    assert Ed25519.sign(decoded, "m") == Ed25519.sign(priv, "m")
    assert Ed25519.verify(pub, "m", Ed25519.sign(decoded, "m"))
  end
end
