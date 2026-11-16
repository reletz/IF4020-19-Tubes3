defmodule Nadina.Interop.Ed25519Test do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Nadina.Keys
  alias Nadina.Profile.Ed25519

  @moduletag :interop
  @moduletag :tmp_dir

  @message ~s({"schema":"minisign-manifest/v1","package":"contoh-app"})

  defp openssl!(args) do
    {out, status} = System.cmd("openssl", args, stderr_to_stdout: true)
    assert status == 0, "openssl #{Enum.join(args, " ")} gagal: #{out}"
    out
  end

  defp openssl_status(args) do
    {_out, status} = System.cmd("openssl", args, stderr_to_stdout: true)
    status
  end

  defp write_nadina_keys(dir) do
    {:ok, Ed25519, priv, pub} = Keys.generate("ed25519")
    prefix = Path.join(dir, "nadina")
    {:ok, _fp} = Keys.write_keypair(prefix, priv, pub)
    {prefix <> ".key.pem", prefix <> ".pub.pem", priv, pub}
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
      sig_path
    ]
  end

  describe "kunci Nadina dibaca OpenSSL" do
    test "kunci publik turunan OpenSSL sama dengan berkas Nadina", %{tmp_dir: dir} do
      {key_path, pub_path, _priv, _pub} = write_nadina_keys(dir)
      derived = openssl!(["pkey", "-in", key_path, "-pubout"])
      assert String.trim(derived) == String.trim(File.read!(pub_path))
    end

    test "kurva dikenali sebagai Ed25519", %{tmp_dir: dir} do
      {_key_path, pub_path, _priv, _pub} = write_nadina_keys(dir)
      text = openssl!(["pkey", "-pubin", "-in", pub_path, "-noout", "-text"])
      assert text =~ "ED25519"
    end

    test "SPKI dari OpenSSL tanpa field parameter, dan fingerprint cocok", %{tmp_dir: dir} do
      {_key_path, pub_path, _priv, pub} = write_nadina_keys(dir)
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

      der = File.read!(der_path)

      # SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING } tanpa parameter (RFC 8410)
      assert <<0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00, _::binary>> =
               der

      assert Keys.fingerprint(pub) == :crypto.hash(:sha256, der) |> Base.encode16(case: :lower)
    end
  end

  describe "tanda tangan Nadina diverifikasi OpenSSL" do
    test "diterima, dan pesan berubah ditolak", %{tmp_dir: dir} do
      {_key_path, pub_path, priv, _pub} = write_nadina_keys(dir)
      sig = Ed25519.sign(priv, @message)
      assert byte_size(sig) == 64

      msg_path = Path.join(dir, "m.json")
      bad_path = Path.join(dir, "bad.json")
      sig_path = Path.join(dir, "m.sig")
      File.write!(msg_path, @message)
      File.write!(bad_path, @message <> " ")
      File.write!(sig_path, sig)

      assert openssl!(verify_args(pub_path, msg_path, sig_path)) =~
               "Signature Verified Successfully"

      refute openssl_status(verify_args(pub_path, bad_path, sig_path)) == 0
    end
  end

  describe "tanda tangan OpenSSL diverifikasi Nadina" do
    test "kunci buatan OpenSSL dimuat sebagai Ed25519 dan tanda tangannya sah", %{tmp_dir: dir} do
      key_path = Path.join(dir, "ossl.key.pem")
      pub_path = Path.join(dir, "ossl.pub.pem")
      openssl!(["genpkey", "-algorithm", "ED25519", "-out", key_path])
      openssl!(["pkey", "-in", key_path, "-pubout", "-out", pub_path])

      assert {:ok, Ed25519, priv, pub} = Keys.load_private_file(key_path)
      assert {:ok, Ed25519, ^pub} = Keys.load_public_file(pub_path)

      msg_path = Path.join(dir, "m.json")
      sig_path = Path.join(dir, "m.sig")
      File.write!(msg_path, @message)

      openssl!([
        "pkeyutl",
        "-sign",
        "-inkey",
        key_path,
        "-rawin",
        "-in",
        msg_path,
        "-out",
        sig_path
      ])

      sig = File.read!(sig_path)
      assert byte_size(sig) == 64
      assert Ed25519.verify(pub, @message, sig)
      refute Ed25519.verify(pub, @message <> " ", sig)
      assert Ed25519.sign(priv, @message) == sig
    end

    test "tanda tangan atas hash pesan (pola Ed25519ph) ditolak", %{tmp_dir: dir} do
      key_path = Path.join(dir, "ossl.key.pem")
      openssl!(["genpkey", "-algorithm", "ED25519", "-out", key_path])
      {:ok, Ed25519, _priv, pub} = Keys.load_private_file(key_path)

      # Ed25519ph menandatangani SHA-512 pesan, bukan pesan itu sendiri. Nadina memakai
      # Ed25519 murni, sehingga tanda tangan semacam ini harus ditolak.
      digest = :crypto.hash(:sha512, @message)
      digest_path = Path.join(dir, "digest.bin")
      sig_path = Path.join(dir, "ph.sig")
      File.write!(digest_path, digest)

      openssl!([
        "pkeyutl",
        "-sign",
        "-inkey",
        key_path,
        "-rawin",
        "-in",
        digest_path,
        "-out",
        sig_path
      ])

      refute Ed25519.verify(pub, @message, File.read!(sig_path))
    end
  end
end
