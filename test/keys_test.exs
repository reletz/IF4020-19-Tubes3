defmodule Nadina.KeysTest do
  use ExUnit.Case, async: true

  alias Nadina.Keys
  alias Nadina.Profile.EcdsaP256

  doctest Nadina.Keys

  @moduletag :tmp_dir

  setup_all do
    {:ok, EcdsaP256, priv, pub} = Keys.generate("ecdsa-p256-sha256")
    %{priv: priv, pub: pub}
  end

  test "PEM privat dan publik round trip", %{priv: priv, pub: pub} do
    priv_pem = Keys.encode_private_pem(priv)
    pub_pem = Keys.encode_public_pem(pub)
    assert priv_pem =~ "-----BEGIN PRIVATE KEY-----"
    assert pub_pem =~ "-----BEGIN PUBLIC KEY-----"
    assert {:ok, EcdsaP256, ^priv, ^pub} = Keys.decode_private_pem(priv_pem)
    assert {:ok, EcdsaP256, ^pub} = Keys.decode_public_pem(pub_pem)
  end

  test "fingerprint tidak berubah oleh CRLF atau pemenggalan baris PEM", %{pub: pub} do
    pem = Keys.encode_public_pem(pub)
    crlf = String.replace(pem, "\n", "\r\n")
    [header | rest] = String.split(pem, "\n", trim: true)
    {body_lines, [footer]} = Enum.split(rest, -1)
    body = Enum.join(body_lines)
    wrapped = for <<chunk::binary-size(20) <- body>>, do: chunk
    tail = binary_part(body, length(wrapped) * 20, byte_size(body) - length(wrapped) * 20)
    rewrapped = Enum.join([header | wrapped] ++ [tail, footer], "\n") <> "\n"

    for variant <- [pem, crlf, rewrapped] do
      assert {:ok, EcdsaP256, decoded} = Keys.decode_public_pem(variant)
      assert Keys.fingerprint(decoded) == Keys.fingerprint(pub)
    end
  end

  test "fingerprint sama dengan sha256 atas DER SPKI", %{pub: pub} do
    {:SubjectPublicKeyInfo, der, _} = :public_key.pem_entry_encode(:SubjectPublicKeyInfo, pub)
    expected = :crypto.hash(:sha256, der) |> Base.encode16(case: :lower)
    assert Keys.fingerprint(pub) == expected
  end

  test "SPKI Ed25519 tidak memuat field parameter (RFC 8410)" do
    ed = :public_key.generate_key({:namedCurve, :ed25519})
    {:ECPrivateKey, _, _, params, point, _} = ed

    {:SubjectPublicKeyInfo, der, _} =
      :public_key.pem_entry_encode(:SubjectPublicKeyInfo, {{:ECPoint, point}, params})

    # SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING }
    assert <<0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
             _::binary-size(32)>> = der
  end

  test "generate menolak profil tidak dikenal" do
    assert Keys.generate("rsa-sha1") == {:error, :unsupported_algorithm}
  end

  test "PEM sampah atau label salah ditolak", %{pub: pub, priv: priv} do
    assert Keys.decode_private_pem("bukan pem") == {:error, :invalid_pem}
    assert Keys.decode_private_pem("") == {:error, :invalid_pem}
    assert Keys.decode_private_pem(Keys.encode_public_pem(pub)) == {:error, :invalid_pem}
    assert Keys.decode_public_pem(Keys.encode_private_pem(priv)) == {:error, :invalid_pem}
    assert Keys.decode_public_pem(nil) == {:error, :invalid_pem}
  end

  test "dua entri PEM ditolak", %{pub: pub} do
    pem = Keys.encode_public_pem(pub)
    assert Keys.decode_public_pem(pem <> pem) == {:error, :invalid_pem}
  end

  test "kunci P-384 ditolak sebagai kunci tidak didukung" do
    other = :public_key.generate_key({:namedCurve, :secp384r1})
    pem = Keys.encode_private_pem(other)
    assert Keys.decode_private_pem(pem) == {:error, :unsupported_key}
  end

  describe "write_keypair/4" do
    test "menulis berkas dengan izin yang benar", %{tmp_dir: dir, priv: priv, pub: pub} do
      prefix = Path.join(dir, "pub")
      assert {:ok, fp} = Keys.write_keypair(prefix, priv, pub)
      assert fp == Keys.fingerprint(pub)

      %File.Stat{mode: key_mode} = File.stat!(prefix <> ".key.pem")
      %File.Stat{mode: pub_mode} = File.stat!(prefix <> ".pub.pem")
      assert Bitwise.band(key_mode, 0o777) == 0o600
      assert Bitwise.band(pub_mode, 0o777) == 0o644

      assert {:ok, EcdsaP256, ^priv, ^pub} = Keys.load_private_file(prefix <> ".key.pem")
      assert {:ok, EcdsaP256, ^pub} = Keys.load_public_file(prefix <> ".pub.pem")
      assert Path.wildcard(prefix <> "*.tmp-*") == []
    end

    test "tidak menimpa tanpa force dan berkas lama utuh", %{tmp_dir: dir, priv: priv, pub: pub} do
      prefix = Path.join(dir, "k")
      {:ok, _} = Keys.write_keypair(prefix, priv, pub)
      before = File.read!(prefix <> ".key.pem")

      {:ok, EcdsaP256, priv2, pub2} = Keys.generate("ecdsa-p256-sha256")
      assert Keys.write_keypair(prefix, priv2, pub2) == {:error, :exists}
      assert File.read!(prefix <> ".key.pem") == before
    end

    test "menimpa dengan force", %{tmp_dir: dir, priv: priv, pub: pub} do
      prefix = Path.join(dir, "f")
      {:ok, _} = Keys.write_keypair(prefix, priv, pub)

      {:ok, EcdsaP256, priv2, pub2} = Keys.generate("ecdsa-p256-sha256")
      assert {:ok, fp} = Keys.write_keypair(prefix, priv2, pub2, force: true)
      assert fp == Keys.fingerprint(pub2)
      assert {:ok, EcdsaP256, ^priv2, ^pub2} = Keys.load_private_file(prefix <> ".key.pem")
    end

    test "direktori keluaran dibuat bila belum ada", %{tmp_dir: dir, priv: priv, pub: pub} do
      prefix = Path.join([dir, "baru", "sub", "k"])
      assert {:ok, _} = Keys.write_keypair(prefix, priv, pub)
      assert File.exists?(prefix <> ".key.pem")
    end
  end

  test "load file yang tidak ada menghasilkan error io", %{tmp_dir: dir} do
    assert Keys.load_private_file(Path.join(dir, "tidak-ada.pem")) == {:error, {:io, :enoent}}
    assert Keys.load_public_file(Path.join(dir, "tidak-ada.pem")) == {:error, {:io, :enoent}}
  end
end
