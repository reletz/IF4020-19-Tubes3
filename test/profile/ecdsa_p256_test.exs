defmodule Nadina.Profile.EcdsaP256Test do
  use ExUnit.Case, async: true

  alias Nadina.Profile.EcdsaP256

  doctest Nadina.Profile.EcdsaP256

  # Orde grup P-256
  @n 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

  # Vektor dari RFC 6979 Appendix A.2.5 (P-256, SHA-256, pesan "sample").
  # Nonce k ditentukan RFC 6979; kita hanya memverifikasi (bukan menandatangani),
  # karena implementasi OTP memakai nonce acak.
  @rfc6979_priv 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
  @rfc6979_ux 0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6
  @rfc6979_uy 0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299
  @rfc6979_r 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
  @rfc6979_s 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8

  setup_all do
    {priv, pub} = EcdsaP256.generate_key()
    %{priv: priv, pub: pub}
  end

  test "sign lalu verify berhasil, panjang 64 byte", %{priv: priv, pub: pub} do
    sig = EcdsaP256.sign(priv, "manifest")
    assert byte_size(sig) == 64
    assert EcdsaP256.verify(pub, "manifest", sig)
  end

  test "pesan kosong dapat ditandatangani", %{priv: priv, pub: pub} do
    assert EcdsaP256.verify(pub, "", EcdsaP256.sign(priv, ""))
  end

  test "pesan berbeda ditolak", %{priv: priv, pub: pub} do
    sig = EcdsaP256.sign(priv, "manifest")
    refute EcdsaP256.verify(pub, "manifesT", sig)
  end

  test "satu bit tanda tangan diubah ditolak", %{priv: priv, pub: pub} do
    sig = EcdsaP256.sign(priv, "manifest")

    for i <- [0, 31, 32, 63] do
      <<head::binary-size(^i), b, tail::binary>> = sig
      refute EcdsaP256.verify(pub, "manifest", <<head::binary, Bitwise.bxor(b, 1), tail::binary>>)
    end
  end

  test "kunci publik lain ditolak", %{priv: priv} do
    {_, other_pub} = EcdsaP256.generate_key()
    refute EcdsaP256.verify(other_pub, "manifest", EcdsaP256.sign(priv, "manifest"))
  end

  test "panjang tanda tangan salah ditolak tanpa raise", %{priv: priv, pub: pub} do
    sig = EcdsaP256.sign(priv, "m")
    refute EcdsaP256.verify(pub, "m", binary_part(sig, 0, 63))
    refute EcdsaP256.verify(pub, "m", sig <> <<0>>)
    refute EcdsaP256.verify(pub, "m", <<>>)
    refute EcdsaP256.verify(pub, "m", :bukan_binary)
  end

  test "r atau s di luar domain (0, n, 2^256-1) ditolak tanpa raise", %{pub: pub} do
    max = Bitwise.bsl(1, 256) - 1

    for {r, s} <- [{0, 0}, {0, 1}, {1, 0}, {@n, 1}, {1, @n}, {@n, @n}, {max, max}] do
      refute EcdsaP256.verify(pub, "m", <<r::256, s::256>>)
    end
  end

  test "tanda tangan non-low-S yang sah diterima", %{priv: priv, pub: pub} do
    <<r::256, s::256>> = EcdsaP256.sign(priv, "m")
    flipped = <<r::256, @n - s::256>>
    assert EcdsaP256.verify(pub, "m", flipped)
  end

  test "dua tanda tangan atas pesan sama berbeda (nonce acak) dan keduanya sah",
       %{priv: priv, pub: pub} do
    a = EcdsaP256.sign(priv, "m")
    b = EcdsaP256.sign(priv, "m")
    refute a == b
    assert EcdsaP256.verify(pub, "m", a)
    assert EcdsaP256.verify(pub, "m", b)
  end

  describe "der_to_rs/1" do
    test "padding nol untuk r dan s yang pendek" do
      der = :public_key.der_encode(:"ECDSA-Sig-Value", {:"ECDSA-Sig-Value", 0xAB, 0xCDEF})
      assert EcdsaP256.der_to_rs(der) == <<0xAB::256, 0xCDEF::256>>
    end

    test "nilai 32 byte penuh dengan bit tertinggi menyala tetap 32 byte" do
      big = Bitwise.bsl(1, 255) + 5
      der = :public_key.der_encode(:"ECDSA-Sig-Value", {:"ECDSA-Sig-Value", big, big})
      assert byte_size(EcdsaP256.der_to_rs(der)) == 64
    end
  end

  test "vektor RFC 6979 A.2.5 (verifikasi)" do
    point = <<4, @rfc6979_ux::256, @rfc6979_uy::256>>
    pub = {{:ECPoint, point}, {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}}}
    assert EcdsaP256.check_key(pub) == :ok
    assert EcdsaP256.verify(pub, "sample", <<@rfc6979_r::256, @rfc6979_s::256>>)
    refute EcdsaP256.verify(pub, "Sample", <<@rfc6979_r::256, @rfc6979_s::256>>)
    # kunci privat yang sama menurunkan titik publik yang sama
    {pt, _} = :crypto.generate_key(:ecdh, :secp256r1, <<@rfc6979_priv::256>>)
    assert pt == point
  end

  describe "check_key/1" do
    test "menerima kunci privat dan publik P-256", %{priv: priv, pub: pub} do
      assert EcdsaP256.check_key(priv) == :ok
      assert EcdsaP256.check_key(pub) == :ok
    end

    test "menolak kurva selain P-256" do
      other = :public_key.generate_key({:namedCurve, :secp384r1})
      assert EcdsaP256.check_key(other) == {:error, :wrong_parameters}
    end

    test "menolak tipe kunci selain EC" do
      rsa_pub = {:RSAPublicKey, 12345, 65537}
      assert EcdsaP256.check_key(rsa_pub) == {:error, :wrong_key_type}
      assert EcdsaP256.check_key(:sampah) == {:error, :wrong_key_type}
    end

    test "menolak titik publik bukan uncompressed" do
      pub = {{:ECPoint, <<2, 0::256>>}, {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}}}
      assert EcdsaP256.check_key(pub) == {:error, :wrong_parameters}
    end
  end
end
