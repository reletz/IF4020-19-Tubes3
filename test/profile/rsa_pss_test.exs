defmodule Nadina.Profile.RsaPssTest do
  use ExUnit.Case, async: true

  alias Nadina.Profile.RsaPss

  doctest Nadina.Profile.RsaPss

  @wycheproof Path.expand("../testdata/wycheproof/rsa_pss_3072_sha256_mgf1_32.json", __DIR__)

  setup_all do
    {priv, pub} = RsaPss.generate_key()
    %{priv: priv, pub: pub}
  end

  # ---- pembantu: EMSA-PSS-VERIFY (RFC 8017 9.1.2) yang ditulis ulang di tes ----
  # Dipakai untuk membuktikan parameter tanpa bergantung pada OTP: tanda tangan
  # dibuka dengan operasi RSA mentah, lalu struktur PSS-nya diurai manual.

  defp rsa_open(sig, {:RSAPublicKey, n, e}) do
    m = :crypto.mod_pow(sig, e, n) |> :binary.decode_unsigned()
    em_len = div(bit_size(:binary.encode_unsigned(n)) - 1 + 7, 8)
    <<m::unsigned-big-size(em_len)-unit(8)>>
  end

  defp mgf1(seed, len) do
    0..div(len - 1, 32)
    |> Enum.map_join(fn c -> :crypto.hash(:sha256, seed <> <<c::32>>) end)
    |> binary_part(0, len)
  end

  # Mengembalikan {salt, h} dari EM, atau :error bila struktur tidak sah.
  defp pss_decode(em) do
    db_len = byte_size(em) - 32 - 1
    <<masked_db::binary-size(^db_len), h::binary-size(32), 0xBC>> = em
    <<top, rest::binary>> = :crypto.exor(masked_db, mgf1(h, db_len))
    # emBits = 3071, jadi 1 bit teratas DB harus dinolkan
    db = <<Bitwise.band(top, 0x7F), rest::binary>>

    case :binary.split(String.trim_leading(db, <<0>>), <<1>>) do
      ["", salt] -> {salt, h}
      _ -> :error
    end
  end

  defp pss_h(m_hash, salt), do: :crypto.hash(:sha256, <<0::64, m_hash::binary, salt::binary>>)

  # ---- identitas profil ----

  test "nama dan panjang tanda tangan sesuai Tabel 2.1" do
    assert RsaPss.name() == "rsa-pss-sha256"
    assert RsaPss.signature_size() == 384
  end

  test "terdaftar di Nadina.Profile" do
    assert Nadina.Profile.fetch("rsa-pss-sha256") == {:ok, RsaPss}
  end

  # ---- pembangkitan kunci ----

  test "kunci baru RSA 3072 bit dengan e = 65537", %{priv: priv, pub: pub} do
    assert {:RSAPublicKey, n, 65_537} = pub
    assert bit_size(:binary.encode_unsigned(n)) == 3072
    assert RsaPss.public_from_private(priv) == pub
  end

  test "dua kali generate menghasilkan modulus berbeda", %{pub: {:RSAPublicKey, n1, _}} do
    {_, {:RSAPublicKey, n2, _}} = RsaPss.generate_key()
    refute n1 == n2
  end

  # ---- sign dan verify ----

  test "sign lalu verify berhasil, panjang 384 byte", %{priv: priv, pub: pub} do
    sig = RsaPss.sign(priv, "manifest")
    assert byte_size(sig) == 384
    assert RsaPss.verify(pub, "manifest", sig)
  end

  test "pesan kosong dapat ditandatangani", %{priv: priv, pub: pub} do
    assert RsaPss.verify(pub, "", RsaPss.sign(priv, ""))
  end

  test "pesan berbeda ditolak", %{priv: priv, pub: pub} do
    sig = RsaPss.sign(priv, "manifest")
    refute RsaPss.verify(pub, "manifesT", sig)
    refute RsaPss.verify(pub, "manifest ", sig)
  end

  test "satu bit tanda tangan diubah ditolak", %{priv: priv, pub: pub} do
    sig = RsaPss.sign(priv, "manifest")

    for i <- [0, 1, 191, 382, 383] do
      <<head::binary-size(^i), b, tail::binary>> = sig
      refute RsaPss.verify(pub, "manifest", <<head::binary, Bitwise.bxor(b, 1), tail::binary>>)
    end
  end

  test "kunci publik lain ditolak", %{priv: priv} do
    {_, other_pub} = RsaPss.generate_key()
    refute RsaPss.verify(other_pub, "manifest", RsaPss.sign(priv, "manifest"))
  end

  test "panjang tanda tangan salah ditolak tanpa raise", %{priv: priv, pub: pub} do
    sig = RsaPss.sign(priv, "m")
    refute RsaPss.verify(pub, "m", binary_part(sig, 1, 383))
    refute RsaPss.verify(pub, "m", <<0>> <> sig)
    refute RsaPss.verify(pub, "m", sig <> <<0>>)
    refute RsaPss.verify(pub, "m", <<>>)
    refute RsaPss.verify(pub, "m", :bukan_binary)
  end

  test "nilai tanda tangan 0, 1, n-1, n, dan 2^3072-1 ditolak tanpa raise", %{pub: pub} do
    {:RSAPublicKey, n, _} = pub
    max = Bitwise.bsl(1, 3072) - 1

    for v <- [0, 1, n - 1, n, n + 1, max] do
      refute RsaPss.verify(pub, "m", <<v::unsigned-big-3072>>)
    end
  end

  test "kunci yang tidak sah saat verify menghasilkan false tanpa raise", %{priv: priv} do
    sig = RsaPss.sign(priv, "m")
    refute RsaPss.verify({:RSAPublicKey, 0, 65_537}, "m", sig)
    refute RsaPss.verify(:sampah, "m", sig)
  end

  test "dua tanda tangan atas pesan sama berbeda (salt acak) dan keduanya sah",
       %{priv: priv, pub: pub} do
    a = RsaPss.sign(priv, "m")
    b = RsaPss.sign(priv, "m")
    refute a == b
    assert RsaPss.verify(pub, "m", a)
    assert RsaPss.verify(pub, "m", b)
  end

  # ---- parameter PSS dibuktikan dari struktur tanda tangan ----

  describe "struktur EMSA-PSS" do
    test "salt 32 byte, MGF1-SHA-256, dan SHA-256 diterapkan tepat sekali",
         %{priv: priv, pub: pub} do
      msg = ~s({"schema":"nadina-manifest/v1"})
      em = rsa_open(RsaPss.sign(priv, msg), pub)

      assert {salt, h} = pss_decode(em)
      assert byte_size(salt) == 32
      assert h == pss_h(:crypto.hash(:sha256, msg), salt)
      # double hashing akan menghasilkan H yang berbeda
      refute h == pss_h(:crypto.hash(:sha256, :crypto.hash(:sha256, msg)), salt)
    end

    test "salt berbeda di setiap tanda tangan", %{priv: priv, pub: pub} do
      {s1, _} = rsa_open(RsaPss.sign(priv, "m"), pub) |> pss_decode()
      {s2, _} = rsa_open(RsaPss.sign(priv, "m"), pub) |> pss_decode()
      refute s1 == s2
    end
  end

  defp other_sign(msg, digest, priv, opts), do: :public_key.sign(msg, digest, priv, opts)

  describe "parameter lain ditolak" do
    test "PKCS#1 v1.5 atas pesan yang sama ditolak", %{priv: priv, pub: pub} do
      sig = other_sign("m", :sha256, priv, rsa_padding: :rsa_pkcs1_padding)
      refute RsaPss.verify(pub, "m", sig)
    end

    test "PSS dengan salt selain 32 byte ditolak", %{priv: priv, pub: pub} do
      for len <- [0, 20, 31, 33, 64] do
        sig =
          other_sign("m", :sha256, priv,
            rsa_padding: :rsa_pkcs1_pss_padding,
            rsa_pss_saltlen: len,
            rsa_mgf1_md: :sha256
          )

        refute RsaPss.verify(pub, "m", sig), "salt #{len} seharusnya ditolak"
      end
    end

    test "PSS dengan MGF1-SHA-1 ditolak", %{priv: priv, pub: pub} do
      sig =
        other_sign("m", :sha256, priv,
          rsa_padding: :rsa_pkcs1_pss_padding,
          rsa_pss_saltlen: 32,
          rsa_mgf1_md: :sha
        )

      refute RsaPss.verify(pub, "m", sig)
    end

    test "PSS dengan hash SHA-384 ditolak", %{priv: priv, pub: pub} do
      sig =
        other_sign("m", :sha384, priv,
          rsa_padding: :rsa_pkcs1_pss_padding,
          rsa_pss_saltlen: 32,
          rsa_mgf1_md: :sha256
        )

      refute RsaPss.verify(pub, "m", sig)
    end

    test "tanda tangan atas SHA-256(m) (double hashing) ditolak", %{priv: priv, pub: pub} do
      sig = RsaPss.sign(priv, :crypto.hash(:sha256, "m"))
      refute RsaPss.verify(pub, "m", sig)
    end
  end

  # ---- check_key ----

  describe "check_key/1" do
    test "menerima kunci privat dan publik RSA 3072, e = 65537", %{priv: priv, pub: pub} do
      assert RsaPss.check_key(priv) == :ok
      assert RsaPss.check_key(pub) == :ok
    end

    test "menolak modulus selain 3072 bit" do
      priv = :public_key.generate_key({:rsa, 2048, 65_537})
      assert RsaPss.check_key(priv) == {:error, :wrong_parameters}
      assert RsaPss.check_key(RsaPss.public_from_private(priv)) == {:error, :wrong_parameters}
    end

    test "menolak modulus 3072 byte-panjang tapi bit teratas nol", %{pub: {:RSAPublicKey, n, e}} do
      # 3071 bit: bit tertinggi dimatikan
      short = Bitwise.bxor(n, Bitwise.bsl(1, 3071))
      assert RsaPss.check_key({:RSAPublicKey, short, e}) == {:error, :wrong_parameters}
    end

    test "menolak eksponen selain 65537", %{pub: {:RSAPublicKey, n, _}} do
      for e <- [3, 17, 65_539] do
        assert RsaPss.check_key({:RSAPublicKey, n, e}) == {:error, :wrong_parameters}
      end
    end

    test "menolak tipe kunci selain RSA" do
      ec = :public_key.generate_key({:namedCurve, :secp256r1})
      assert RsaPss.check_key(ec) == {:error, :wrong_key_type}

      assert RsaPss.check_key({{:ECPoint, <<4, 0::512>>}, {:namedCurve, :secp256r1}}) ==
               {:error, :wrong_key_type}

      assert RsaPss.check_key(:sampah) == {:error, :wrong_key_type}
      assert RsaPss.check_key({:RSAPublicKey, "n", 65_537}) == {:error, :wrong_key_type}
    end
  end

  # ---- vektor Wycheproof ----

  describe "vektor Wycheproof rsa_pss_3072_sha256_mgf1_32" do
    setup do
      data = @wycheproof |> File.read!() |> JSON.decode!()
      [{:SubjectPublicKeyInfo, _, _} = entry] = :public_key.pem_decode(data["publicKeyPem"])
      %{data: data, wpub: :public_key.pem_entry_decode(entry)}
    end

    test "parameter berkas cocok dengan profil", %{data: data, wpub: wpub} do
      assert {data["keySize"], data["sha"], data["mgf"], data["mgfSha"], data["sLen"]} ==
               {3072, "SHA-256", "MGF1", "SHA-256", 32}

      assert RsaPss.check_key(wpub) == :ok
      assert length(data["tests"]) == 108
    end

    test "semua kasus valid diterima dan invalid ditolak", %{data: data, wpub: wpub} do
      failures =
        Enum.flat_map(data["tests"], fn t ->
          msg = Base.decode16!(t["msg"], case: :lower)
          sig = Base.decode16!(t["sig"], case: :lower)
          got = RsaPss.verify(wpub, msg, sig)

          if got == (t["result"] == "valid"),
            do: [],
            else: ["tcId #{t["tcId"]} (#{t["comment"]}): hasil #{got}, harapan #{t["result"]}"]
        end)

      assert failures == []
    end
  end
end
