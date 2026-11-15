defmodule Nadina.ManifestTest do
  use ExUnit.Case, async: true

  alias Nadina.Manifest

  doctest Nadina.Manifest

  @keyid String.duplicate("a", 64)
  @sha String.duplicate("b", 64)

  @canonical ~s({"schema":"minisign-manifest/v1","package":"contoh-app","version":"1.0.0",) <>
               ~s("algorithm":"ed25519","keyid":"#{@keyid}",) <>
               ~s("artifact":{"name":"contoh-app.zip","size":1048576,"sha256":"#{@sha}"}})

  defp u(hex), do: <<92, ?u>> <> hex

  defp manifest(overrides \\ []) do
    args =
      Keyword.merge(
        [
          package: "contoh-app",
          version: "1.0.0",
          algorithm: "ed25519",
          keyid: @keyid,
          name: "contoh-app.zip",
          size: 1_048_576,
          sha256: @sha
        ],
        overrides
      )

    Manifest.new(
      args[:package],
      args[:version],
      args[:algorithm],
      args[:keyid],
      args[:name],
      args[:size],
      args[:sha256]
    )
  end

  describe "new/7 dan serialize/1" do
    test "serialisasi canonical sesuai contoh spek" do
      assert {:ok, m} = manifest()
      assert Manifest.serialize(m) == @canonical
    end

    test "ketiga profil diterima" do
      for alg <- ["rsa-pss-sha256", "ecdsa-p256-sha256", "ed25519"] do
        assert {:ok, %Manifest{algorithm: ^alg}} = manifest(algorithm: alg)
      end
    end

    test "size 0 dan batas atas 2^53 - 1 diterima" do
      assert {:ok, _} = manifest(size: 0)
      assert {:ok, m} = manifest(size: 9_007_199_254_740_991)
      assert Manifest.serialize(m) =~ ~s("size":9007199254740991,)
    end

    test "profil tidak didukung ditolak saat membentuk manifest" do
      assert {:error, {:unsupported_algorithm, "rsa-pkcs1-sha256"}} =
               manifest(algorithm: "rsa-pkcs1-sha256")
    end

    test "field tidak valid ditolak" do
      cases = [
        {[package: "Contoh"], ["package"]},
        {[package: ".app"], ["package"]},
        {[package: String.duplicate("a", 65)], ["package"]},
        {[version: "-1"], ["version"]},
        {[version: String.duplicate("1", 65)], ["version"]},
        {[keyid: String.upcase(@keyid)], ["keyid"]},
        {[keyid: String.duplicate("a", 63)], ["keyid"]},
        {[name: "dist/app.zip"], ["artifact", "name"]},
        {[name: String.duplicate("a", 129)], ["artifact", "name"]},
        {[size: -1], ["artifact", "size"]},
        {[size: 9_007_199_254_740_992], ["artifact", "size"]},
        {[size: true], ["artifact", "size"]},
        {[sha256: String.duplicate("g", 64)], ["artifact", "sha256"]},
        {[sha256: 1], ["artifact", "sha256"]}
      ]

      for {override, path} <- cases do
        assert {:error, {:invalid_field, ^path}} = manifest(override), inspect(override)
      end
    end

    test "batas panjang tepat diterima, termasuk karakter + pada versi" do
      assert {:ok, _} = manifest(package: String.duplicate("a", 64))
      assert {:ok, _} = manifest(version: "1.0.0+build." <> String.duplicate("1", 52))
      assert {:ok, _} = manifest(name: String.duplicate("a", 128))
    end
  end

  describe "parse/1 menerima" do
    test "round trip untuk ketiga profil" do
      for alg <- ["rsa-pss-sha256", "ecdsa-p256-sha256", "ed25519"] do
        {:ok, m} = manifest(algorithm: alg)
        assert {:ok, ^m} = Manifest.parse(Manifest.serialize(m))
      end
    end

    test "algorithm tidak dikenal tetap lolos format (diperiksa di langkah verify berikutnya)" do
      bytes = String.replace(@canonical, ~s("ed25519"), ~s("rsa-pkcs1-sha256"))
      assert {:ok, %Manifest{algorithm: "rsa-pkcs1-sha256"} = m} = Manifest.parse(bytes)
      refute Manifest.supported_algorithm?(m.algorithm)
    end
  end

  describe "parse/1 menolak" do
    test "ukuran lebih dari 16 KiB ditolak sebelum parsing" do
      assert {:error, {:too_large, 16_385}} = Manifest.parse(String.duplicate(" ", 16_385))
      assert {:error, {:unexpected_end, _}} = Manifest.parse(String.duplicate(" ", 16_384))
    end

    test "white space, baris baru, dan urutan field yang tidak canonical" do
      pretty = String.replace(@canonical, ~s(","), ~s(", "))

      reordered =
        String.replace(
          @canonical,
          ~s("package":"contoh-app","version":"1.0.0"),
          ~s("version":"1.0.0","package":"contoh-app")
        )

      for bytes <- [pretty, @canonical <> "\n", " " <> @canonical, reordered] do
        assert {:error, :not_canonical} = Manifest.parse(bytes)
      end
    end

    test "escape pada string tidak canonical" do
      bytes =
        String.replace(
          @canonical,
          "contoh-app\",\"version",
          "contoh" <> u("002d") <> "app\",\"version"
        )

      assert {:error, :not_canonical} = Manifest.parse(bytes)
    end

    test "BOM ditolak" do
      assert {:error, {:bom_not_allowed, 0}} = Manifest.parse(<<0xEF, 0xBB, 0xBF>> <> @canonical)
    end

    test "duplicate key, field tambahan, field hilang, null" do
      dup =
        String.replace(@canonical, ~s("version":"1.0.0"), ~s("version":"1.0.0","version":"1.0.0"))

      assert {:error, {:duplicate_key, "version", _}} = Manifest.parse(dup)

      extra = String.replace(@canonical, ~s("size":1048576), ~s("size":1048576,"mode":"x"))
      assert {:error, {:unknown_field, ["artifact", "mode"]}} = Manifest.parse(extra)

      missing = String.replace(@canonical, ~s("version":"1.0.0",), "")
      assert {:error, {:missing_field, ["version"]}} = Manifest.parse(missing)

      null = String.replace(@canonical, ~s("1.0.0"), "null")
      assert {:error, {:null_not_allowed, _}} = Manifest.parse(null)
    end

    test "tipe size salah" do
      for {raw, reason} <- [{"true", :wrong_type}, {~s("1048576"), :wrong_type}] do
        bytes = String.replace(@canonical, "1048576", raw)
        assert {:error, {^reason, ["artifact", "size"], :integer}} = Manifest.parse(bytes)
      end

      bytes = String.replace(@canonical, "1048576", "1048576.0")
      assert {:error, {:non_integer_number, _}} = Manifest.parse(bytes)
    end

    test "nilai field di luar aturan" do
      cases = [
        {~s("minisign-manifest/v1"), ~s("minisign-manifest/v2"), ["schema"]},
        {"1048576", "9007199254740992", ["artifact", "size"]},
        {"1048576", "-1", ["artifact", "size"]},
        {~s("contoh-app.zip"), ~s("../contoh-app.zip"), ["artifact", "name"]},
        {@keyid, String.upcase(@keyid), ["keyid"]},
        {~s("ed25519"), ~s("ed 25519\\""), ["algorithm"]},
        {~s("ed25519"), ~s("ed25519) <> <<0xE9::utf8>> <> ~s("), ["algorithm"]}
      ]

      for {from, to, path} <- cases do
        bytes = String.replace(@canonical, from, to, global: false)
        assert {:error, {:invalid_field, ^path}} = Manifest.parse(bytes), to
      end
    end
  end
end
