defmodule Nadina.Interop.RsaPssTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Nadina.Keys
  alias Nadina.Profile.RsaPss

  @moduletag :interop
  @moduletag :tmp_dir

  @message ~s({"schema":"minisign-manifest/v1","package":"contoh-app"})
  @pss [
    "-pkeyopt",
    "rsa_padding_mode:pss",
    "-pkeyopt",
    "rsa_pss_saltlen:32",
    "-pkeyopt",
    "rsa_mgf1_md:sha256"
  ]

  setup_all do
    {:ok, RsaPss, priv, pub} = Keys.generate("rsa-pss-sha256")
    %{priv: priv, pub: pub}
  end

  defp openssl!(args) do
    {out, status} = System.cmd("openssl", args, stderr_to_stdout: true)
    assert status == 0, "openssl #{Enum.join(args, " ")} gagal: #{out}"
    out
  end

  defp openssl_status(args) do
    {_out, status} = System.cmd("openssl", args, stderr_to_stdout: true)
    status
  end

  defp write_keys(dir, priv, pub) do
    prefix = Path.join(dir, "nadina")
    {:ok, _fp} = Keys.write_keypair(prefix, priv, pub)
    {prefix <> ".key.pem", prefix <> ".pub.pem"}
  end

  defp verify_args(pub_path, msg_path, sig_path) do
    [
      "pkeyutl",
      "-verify",
      "-pubin",
      "-inkey",
      pub_path,
      "-rawin",
      "-in",
      msg_path,
      "-sigfile",
      sig_path,
      "-digest",
      "sha256"
    ] ++ @pss
  end

  describe "kunci Nadina dibaca OpenSSL" do
    test "kunci publik turunan OpenSSL sama dengan berkas Nadina",
         %{tmp_dir: dir, priv: priv, pub: pub} do
      {key_path, pub_path} = write_keys(dir, priv, pub)
      derived = openssl!(["pkey", "-in", key_path, "-pubout"])
      assert String.trim(derived) == String.trim(File.read!(pub_path))
    end

    test "modulus 3072 bit dan eksponen 65537", %{tmp_dir: dir, priv: priv, pub: pub} do
      {_key_path, pub_path} = write_keys(dir, priv, pub)
      text = openssl!(["pkey", "-pubin", "-in", pub_path, "-noout", "-text"])
      assert text =~ "3072 bit"
      assert text =~ "65537"
    end

    test "fingerprint sama dengan SHA-256 atas DER SPKI versi OpenSSL",
         %{tmp_dir: dir, priv: priv, pub: pub} do
      {_key_path, pub_path} = write_keys(dir, priv, pub)
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
    test "diterima, dan pesan berubah ditolak", %{tmp_dir: dir, priv: priv, pub: pub} do
      {_key_path, pub_path} = write_keys(dir, priv, pub)
      sig = RsaPss.sign(priv, @message)
      assert byte_size(sig) == 384

      msg_path = Path.join(dir, "m.json")
      bad_path = Path.join(dir, "bad.json")
      sig_path = Path.join(dir, "m.sig")
      File.write!(msg_path, @message)
      File.write!(bad_path, @message <> " ")
      File.write!(sig_path, sig)

      assert openssl!(verify_args(pub_path, msg_path, sig_path)) =~ "Successfully"
      refute openssl_status(verify_args(pub_path, bad_path, sig_path)) == 0
    end
  end

  describe "tanda tangan OpenSSL diverifikasi Nadina" do
    test "kunci buatan OpenSSL dimuat sebagai RSA-PSS dan tanda tangannya sah", %{tmp_dir: dir} do
      key_path = Path.join(dir, "ossl.key.pem")
      pub_path = Path.join(dir, "ossl.pub.pem")

      openssl!([
        "genpkey",
        "-algorithm",
        "RSA",
        "-pkeyopt",
        "rsa_keygen_bits:3072",
        "-pkeyopt",
        "rsa_keygen_pubexp:65537",
        "-out",
        key_path
      ])

      openssl!(["pkey", "-in", key_path, "-pubout", "-out", pub_path])

      assert {:ok, RsaPss, _priv, pub} = Keys.load_private_file(key_path)
      assert {:ok, RsaPss, ^pub} = Keys.load_public_file(pub_path)

      msg_path = Path.join(dir, "m.json")
      sig_path = Path.join(dir, "m.sig")
      File.write!(msg_path, @message)

      openssl!(
        [
          "pkeyutl",
          "-sign",
          "-inkey",
          key_path,
          "-rawin",
          "-in",
          msg_path,
          "-out",
          sig_path,
          "-digest",
          "sha256"
        ] ++ @pss
      )

      sig = File.read!(sig_path)
      assert byte_size(sig) == 384
      assert RsaPss.verify(pub, @message, sig)
      refute RsaPss.verify(pub, @message <> " ", sig)
    end

    test "PSS dengan salt lain atau PKCS1 v1.5 dari OpenSSL ditolak", %{tmp_dir: dir} do
      key_path = Path.join(dir, "ossl.key.pem")

      openssl!([
        "genpkey",
        "-algorithm",
        "RSA",
        "-pkeyopt",
        "rsa_keygen_bits:3072",
        "-out",
        key_path
      ])

      {:ok, RsaPss, _priv, pub} = Keys.load_private_file(key_path)

      msg_path = Path.join(dir, "m.json")
      File.write!(msg_path, @message)

      salt20 = [
        "-pkeyopt",
        "rsa_padding_mode:pss",
        "-pkeyopt",
        "rsa_pss_saltlen:20",
        "-pkeyopt",
        "rsa_mgf1_md:sha256"
      ]

      for {name, extra} <- [salt20: salt20, pkcs1: ["-pkeyopt", "rsa_padding_mode:pkcs1"]] do
        sig_path = Path.join(dir, "#{name}.sig")

        openssl!(
          [
            "pkeyutl",
            "-sign",
            "-inkey",
            key_path,
            "-rawin",
            "-in",
            msg_path,
            "-out",
            sig_path,
            "-digest",
            "sha256"
          ] ++ extra
        )

        refute RsaPss.verify(pub, @message, File.read!(sig_path)), "#{name} harus ditolak"
      end
    end
  end
end
