defmodule Nadina.Interop.EcdsaP256Test do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Nadina.Keys
  alias Nadina.Profile.EcdsaP256

  @moduletag :interop
  @moduletag :tmp_dir

  @message ~s({"schema":"minisign-manifest/v1","package":"contoh-app"})

  defp openssl!(args, opts \\ []) do
    {out, status} = System.cmd("openssl", args, [stderr_to_stdout: true] ++ opts)
    assert status == 0, "openssl #{Enum.join(args, " ")} gagal: #{out}"
    out
  end

  defp write_nadina_keys(dir) do
    {:ok, EcdsaP256, priv, pub} = Keys.generate("ecdsa-p256-sha256")
    prefix = Path.join(dir, "nadina")
    {:ok, _fp} = Keys.write_keypair(prefix, priv, pub)
    {priv, pub, prefix <> ".key.pem", prefix <> ".pub.pem"}
  end

  defp rs_to_der(<<r::unsigned-big-256, s::unsigned-big-256>>) do
    :public_key.der_encode(:"ECDSA-Sig-Value", {:"ECDSA-Sig-Value", r, s})
  end

  describe "kunci Nadina dibaca OpenSSL" do
    test "kunci publik turunan OpenSSL sama dengan berkas Nadina", %{tmp_dir: dir} do
      {_priv, _pub, key_path, pub_path} = write_nadina_keys(dir)

      derived = openssl!(["pkey", "-in", key_path, "-pubout"])
      assert String.trim(derived) == String.trim(File.read!(pub_path))
    end

    test "kurva dikenali sebagai prime256v1", %{tmp_dir: dir} do
      {_priv, _pub, _key_path, pub_path} = write_nadina_keys(dir)

      text = openssl!(["pkey", "-pubin", "-in", pub_path, "-noout", "-text"])
      assert text =~ "prime256v1" or text =~ "P-256"
    end

    test "fingerprint sama dengan SHA-256 atas DER SPKI versi OpenSSL", %{tmp_dir: dir} do
      {_priv, pub, _key_path, pub_path} = write_nadina_keys(dir)
      der_path = Path.join(dir, "spki.der")

      openssl!([
        "pkey",
        "-pubin",
        "-in",
        pub_path,
        "-pubout",
        "-outform",
        "DER",
        "-out",
        der_path
      ])

      expected = :crypto.hash(:sha256, File.read!(der_path)) |> Base.encode16(case: :lower)
      assert Keys.fingerprint(pub) == expected
    end
  end

  describe "tanda tangan Nadina diverifikasi OpenSSL" do
    test "r|s diubah ke DER diterima openssl dgst -verify", %{tmp_dir: dir} do
      {priv, _pub, _key_path, pub_path} = write_nadina_keys(dir)
      msg_path = Path.join(dir, "msg.bin")
      sig_path = Path.join(dir, "sig.der")
      File.write!(msg_path, @message)

      rs = EcdsaP256.sign(priv, @message)
      assert byte_size(rs) == 64
      File.write!(sig_path, rs_to_der(rs))

      out = openssl!(["dgst", "-sha256", "-verify", pub_path, "-signature", sig_path, msg_path])
      assert out =~ "Verified OK"
    end

    test "pesan diubah ditolak openssl", %{tmp_dir: dir} do
      {priv, _pub, _key_path, pub_path} = write_nadina_keys(dir)
      msg_path = Path.join(dir, "msg.bin")
      sig_path = Path.join(dir, "sig.der")
      File.write!(msg_path, @message <> "x")
      File.write!(sig_path, rs_to_der(EcdsaP256.sign(priv, @message)))

      {out, status} =
        System.cmd(
          "openssl",
          ["dgst", "-sha256", "-verify", pub_path, "-signature", sig_path, msg_path],
          stderr_to_stdout: true
        )

      refute status == 0
      refute out =~ "Verified OK"
    end
  end

  describe "tanda tangan OpenSSL diverifikasi Nadina" do
    setup %{tmp_dir: dir} do
      key_path = Path.join(dir, "ossl.key.pem")
      pub_path = Path.join(dir, "ossl.pub.pem")

      openssl!([
        "genpkey",
        "-algorithm",
        "EC",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-out",
        key_path
      ])

      openssl!(["pkey", "-in", key_path, "-pubout", "-out", pub_path])
      %{key_path: key_path, pub_path: pub_path}
    end

    test "kunci OpenSSL dimuat Keys sebagai profil ECDSA P-256", ctx do
      assert {:ok, EcdsaP256, _priv, pub} = Keys.load_private_file(ctx.key_path)
      assert {:ok, EcdsaP256, ^pub} = Keys.load_public_file(ctx.pub_path)
    end

    test "DER OpenSSL diubah ke r|s lalu diverifikasi", %{tmp_dir: dir} = ctx do
      msg_path = Path.join(dir, "msg.bin")
      sig_path = Path.join(dir, "sig.der")
      File.write!(msg_path, @message)
      openssl!(["dgst", "-sha256", "-sign", ctx.key_path, "-out", sig_path, msg_path])

      {:ok, EcdsaP256, pub} = Keys.load_public_file(ctx.pub_path)
      rs = EcdsaP256.der_to_rs(File.read!(sig_path))

      assert byte_size(rs) == 64
      assert EcdsaP256.verify(pub, @message, rs)
      refute EcdsaP256.verify(pub, @message <> "x", rs)
    end

    test "banyak tanda tangan OpenSSL (panjang DER bervariasi) semuanya diterima",
         %{tmp_dir: dir} = ctx do
      {:ok, EcdsaP256, pub} = Keys.load_public_file(ctx.pub_path)

      lengths =
        for i <- 1..40 do
          msg = "pesan-#{i}"
          msg_path = Path.join(dir, "m#{i}.bin")
          sig_path = Path.join(dir, "s#{i}.der")
          File.write!(msg_path, msg)
          openssl!(["dgst", "-sha256", "-sign", ctx.key_path, "-out", sig_path, msg_path])

          der = File.read!(sig_path)
          rs = EcdsaP256.der_to_rs(der)
          assert byte_size(rs) == 64
          assert EcdsaP256.verify(pub, msg, rs)
          byte_size(der)
        end

      # DER tidak berukuran tetap, sedangkan r|s selalu 64 byte.
      assert length(Enum.uniq(lengths)) > 1
    end
  end
end
