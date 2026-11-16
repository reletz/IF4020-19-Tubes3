defmodule Nadina.NonceAnalysisTest do
  @moduledoc """
  Bahan analisis U14 (penandatanganan manifest identik dua kali).

  - ECDSA dan RSA-PSS memakai randomness dari CSPRNG, sehingga tanda tangan berbeda.
  - Ed25519 deterministik (RFC 8032), sehingga tanda tangan identik.
  - Satu tes memperagakan mengapa nonce ECDSA tidak boleh dipakai ulang: kunci privat
    pulih dari dua tanda tangan dengan nonce sama (kunci uji, bukan kunci nyata).
  """
  use ExUnit.Case, async: true

  alias Nadina.Profile.{EcdsaP256, RsaPss}

  @message ~s({"schema":"minisign-manifest/v1","package":"contoh-app"})
  @n 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

  test "ECDSA: 200 tanda tangan atas manifest sama, semua r berbeda dan semua sah" do
    {priv, pub} = EcdsaP256.generate_key()
    sigs = for _ <- 1..200, do: EcdsaP256.sign(priv, @message)

    assert length(Enum.uniq(sigs)) == 200
    rs = for <<r::binary-size(32), _::binary-size(32)>> <- sigs, do: r
    assert length(Enum.uniq(rs)) == 200, "r berulang menandakan nonce dipakai ulang"
    assert Enum.all?(sigs, &EcdsaP256.verify(pub, @message, &1))
  end

  test "RSA-PSS: tanda tangan atas manifest sama berbeda (salt acak) dan semuanya sah" do
    {priv, pub} = RsaPss.generate_key()
    sigs = for _ <- 1..10, do: RsaPss.sign(priv, @message)

    assert length(Enum.uniq(sigs)) == 10
    assert Enum.all?(sigs, &RsaPss.verify(pub, @message, &1))
  end

  test "Ed25519 (pustaka OTP): deterministik, dua tanda tangan identik" do
    {pub, priv} = :crypto.generate_key(:eddsa, :ed25519)
    a = :crypto.sign(:eddsa, :none, @message, [priv, :ed25519])
    b = :crypto.sign(:eddsa, :none, @message, [priv, :ed25519])

    assert a == b
    assert byte_size(a) == 64
    assert :crypto.verify(:eddsa, :none, @message, a, [pub, :ed25519])
  end

  test "nonce ECDSA yang dipakai ulang membocorkan kunci privat (peragaan, kunci uji)" do
    d = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
    k = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
    {<<4, x::256, _::256>>, _} = :crypto.generate_key(:ecdh, :secp256r1, <<k::256>>)
    r = rem(x, @n)

    z1 = hash_int("pesan satu")
    z2 = hash_int("pesan dua")
    s1 = rem(inv(k) * (z1 + r * d), @n)
    s2 = rem(inv(k) * (z2 + r * d), @n)

    # penyerang hanya mengetahui (z1, r, s1) dan (z2, r, s2)
    k_rec = Integer.mod((z1 - z2) * inv(Integer.mod(s1 - s2, @n)), @n)
    d_rec = Integer.mod((s1 * k_rec - z1) * inv(r), @n)

    assert k_rec == k
    assert d_rec == d
  end

  defp hash_int(msg), do: :binary.decode_unsigned(:crypto.hash(:sha256, msg))
  defp inv(a), do: :crypto.mod_pow(a, @n - 2, @n) |> :binary.decode_unsigned()
end
