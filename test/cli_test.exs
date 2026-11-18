defmodule Nadina.CLITest do
  use ExUnit.Case, async: true

  alias Nadina.{Bundle, Manifest}

  @moduletag :tmp_dir
  @profiles ["rsa-pss-sha256", "ecdsa-p256-sha256", "ed25519"]

  # Pasangan kunci per profil dibangkitkan sekali (RSA 3072 cukup lambat).
  setup_all do
    keys =
      for profile <- @profiles, into: %{} do
        dir =
          Path.join(
            System.tmp_dir!(),
            "nadina-cli-#{profile}-#{System.unique_integer([:positive])}"
          )

        prefix = Path.join(dir, "k")
        {0, fp, ""} = Nadina.CLI.run(["keygen", "-algorithm", profile, "-out", prefix])
        {profile, %{prefix: prefix, fingerprint: String.trim(fp)}}
      end

    on_exit(fn -> for {_, %{prefix: p}} <- keys, do: File.rm_rf!(Path.dirname(p)) end)
    %{keys: keys}
  end

  defp cli(args), do: Nadina.CLI.run(args)

  defp json!(out) do
    assert String.ends_with?(out, "\n")
    JSON.decode!(String.trim_trailing(out, "\n"))
  end

  # Menyiapkan artefak, trust store, dan bundle untuk satu profil.
  defp release(dir, key, content \\ "isi artefak", opts \\ []) do
    file = Path.join(dir, "contoh-app.zip")
    File.write!(file, content)
    store = Path.join(dir, "trust.json")
    bundle = Path.join(dir, "rilis.json")

    {0, _, ""} =
      cli([
        "trust",
        "add",
        "-key",
        key.prefix <> ".pub.pem",
        "-package",
        "contoh-app",
        "-store",
        store
      ])

    {0, _, ""} =
      cli([
        "sign",
        "-file",
        file,
        "-package",
        "contoh-app",
        "-version",
        Keyword.get(opts, :version, "1.0.0"),
        "-key",
        key.prefix <> ".key.pem",
        "-out",
        bundle
      ])

    %{file: file, store: store, bundle: bundle}
  end

  defp verify(r, overrides \\ []) do
    args = [
      "verify",
      "-file",
      Keyword.get(overrides, :file, r.file),
      "-bundle",
      Keyword.get(overrides, :bundle, r.bundle),
      "-trust-store",
      Keyword.get(overrides, :store, r.store),
      "-package",
      Keyword.get(overrides, :package, "contoh-app"),
      "-version",
      Keyword.get(overrides, :version, "1.0.0"),
      "-json"
    ]

    {code, out, _err} = cli(args)
    {code, json!(out)}
  end

  describe "U01: sign dan verify untuk tiga profil" do
    for profile <- @profiles do
      test "#{profile}: teks, biner, dan berkas kosong", %{tmp_dir: dir, keys: keys} do
        key = keys[unquote(profile)]

        for {label, content} <- [
              teks: "halo dunia\n",
              biner: :crypto.strong_rand_bytes(5000),
              kosong: ""
            ] do
          sub = Path.join(dir, Atom.to_string(label))
          File.mkdir_p!(sub)
          r = release(sub, key, content)
          assert {0, doc} = verify(r)
          assert doc["valid"] == true
          assert doc["status"] == "OK"
          assert doc["algorithm"] == unquote(profile)
          assert doc["keyid"] == key.fingerprint
          assert doc["package"] == "contoh-app"
          assert doc["version"] == "1.0.0"
        end
      end
    end
  end

  describe "skenario negatif (profil ecdsa-p256-sha256)" do
    setup %{tmp_dir: dir, keys: keys} do
      key = keys["ecdsa-p256-sha256"]
      %{r: release(dir, key), key: key, dir: dir}
    end

    test "U02: satu byte artefak diubah", %{r: r} do
      File.write!(r.file, "isi artefaK")
      assert {1, %{"status" => "ARTIFACT_MISMATCH", "valid" => false}} = verify(r)
    end

    test "U03: byte ditambah atau dihapus", %{r: r} do
      File.write!(r.file, "isi artefak!")
      assert {1, %{"status" => "ARTIFACT_MISMATCH"}} = verify(r)
      File.write!(r.file, "isi artefa")
      assert {1, %{"status" => "ARTIFACT_MISMATCH"}} = verify(r)
    end

    test "U04: versi manifest diubah dengan tanda tangan lama", %{r: r} do
      {:ok, b} = Bundle.parse(File.read!(r.bundle))
      {:ok, m} = Manifest.parse(b.manifest)
      forged = Manifest.serialize(%{m | version: "9.9.9"})
      File.write!(r.bundle, Bundle.encode(%Bundle{b | manifest: forged}))
      assert {1, %{"status" => "INVALID_SIGNATURE"}} = verify(r, version: "9.9.9")
    end

    test "U05: satu bit tanda tangan diubah", %{r: r} do
      {:ok, b} = Bundle.parse(File.read!(r.bundle))
      <<first, rest::binary>> = b.signature

      File.write!(
        r.bundle,
        Bundle.encode(%Bundle{b | signature: <<Bitwise.bxor(first, 1), rest::binary>>})
      )

      assert {1, %{"status" => "INVALID_SIGNATURE"}} = verify(r)
    end

    test "U08: versi yang diharapkan berbeda dari manifest", %{r: r} do
      assert {1, %{"status" => "METADATA_MISMATCH"}} = verify(r, version: "2.0.0")
    end

    test "U09: nama berkas artefak diubah", %{r: r, dir: dir} do
      renamed = Path.join(dir, "nama-lain.zip")
      File.cp!(r.file, renamed)
      assert {1, %{"status" => "METADATA_MISMATCH"}} = verify(r, file: renamed)
    end

    test "U10: field duplikat, tipe salah, base64 salah, manifest terlalu besar", %{r: r} do
      {:ok, b} = Bundle.parse(File.read!(r.bundle))
      good = Bundle.encode(b)
      sig64 = Base.encode64(b.signature)
      man64 = Base.encode64(b.manifest)

      duplicate =
        ~s({"schema":"minisign-bundle/v1","manifest_b64":"#{man64}","manifest_b64":"#{man64}","signature_b64":"#{sig64}"})

      wrong_type = ~s({"schema":"minisign-bundle/v1","manifest_b64":1,"signature_b64":"#{sig64}"})
      bad_b64 = String.replace(good, sig64, "!!" <> String.slice(sig64, 2..-1//1))

      huge = Bundle.encode(%Bundle{b | manifest: String.duplicate("a", Manifest.max_size() + 1)})

      for bytes <- [duplicate, wrong_type, bad_b64, huge] do
        File.write!(r.bundle, bytes)
        assert {1, %{"status" => "FORMAT_ERROR", "algorithm" => nil}} = verify(r)
      end
    end

    test "U11: algoritma tidak didukung pada manifest", %{r: r} do
      {:ok, b} = Bundle.parse(File.read!(r.bundle))
      {:ok, m} = Manifest.parse(b.manifest)
      forged = Manifest.serialize(%{m | algorithm: "rsa-sha1"})
      File.write!(r.bundle, Bundle.encode(%Bundle{b | manifest: forged}))
      assert {1, %{"status" => "UNSUPPORTED_ALGORITHM", "algorithm" => "rsa-sha1"}} = verify(r)
    end

    test "U13: white space dan urutan field bundle diubah", %{r: r} do
      {:ok, b} = Bundle.parse(File.read!(r.bundle))

      reordered =
        ~s(  {\n "signature_b64" : "#{Base.encode64(b.signature)}",\n\t"schema":"minisign-bundle/v1",\n"manifest_b64":"#{Base.encode64(b.manifest)}"\n}\n\n)

      File.write!(r.bundle, reordered)
      assert {0, %{"status" => "OK"}} = verify(r)
    end

    test "C04: artefak tidak tersedia menghasilkan INPUT_ERROR dan exit 2", %{r: r, dir: dir} do
      assert {2, %{"status" => "INPUT_ERROR", "valid" => false}} =
               verify(r, file: Path.join(dir, "tidak-ada.zip"))

      assert {2, %{"status" => "INPUT_ERROR"}} =
               verify(r, bundle: Path.join(dir, "tidak-ada.json"))
    end

    test "opsi wajib hilang pada verify -json menghasilkan INPUT_ERROR", %{} do
      {code, out, _} = cli(["verify", "-json"])
      assert code == 2
      assert %{"status" => "INPUT_ERROR", "valid" => false} = json!(out)
    end

    test "trust store rusak menghasilkan FORMAT_ERROR", %{r: r, dir: dir} do
      bad = Path.join(dir, "rusak.json")
      File.write!(bad, "bukan json")
      assert {1, %{"status" => "FORMAT_ERROR"}} = verify(r, store: bad)
    end

    test "fingerprint pada trust store tidak cocok dengan kunci: FORMAT_ERROR", %{
      r: r,
      key: key,
      dir: dir
    } do
      doc = r.store |> File.read!() |> String.replace(key.fingerprint, String.duplicate("0", 64))
      bad = Path.join(dir, "keyid-salah.json")
      File.write!(bad, doc)
      assert {1, %{"status" => "FORMAT_ERROR"}} = verify(r, store: bad)
    end

    test "profil kunci trust store berbeda dari manifest: KEY_NOT_TRUSTED", %{
      r: r,
      keys: keys,
      dir: dir
    } do
      # kunci ed25519 yang valid secara format, tetapi manifest meminta keyid ECDSA
      ed = keys["ed25519"]
      store = Path.join(dir, "ed.json")

      {0, _, ""} =
        cli([
          "trust",
          "add",
          "-key",
          ed.prefix <> ".pub.pem",
          "-package",
          "contoh-app",
          "-store",
          store
        ])

      assert {1, %{"status" => "KEY_NOT_TRUSTED"}} = verify(r, store: store)
    end
  end

  describe "U14: dua tanda tangan atas manifest identik" do
    for {profile, same?} <- [
          {"rsa-pss-sha256", false},
          {"ecdsa-p256-sha256", false},
          {"ed25519", true}
        ] do
      test "#{profile}: #{if same?, do: "identik", else: "berbeda"}, keduanya sah", %{
        tmp_dir: dir,
        keys: keys
      } do
        key = keys[unquote(profile)]
        r = release(dir, key)
        second = Path.join(dir, "rilis2.json")

        {0, _, ""} =
          cli([
            "sign",
            "-file",
            r.file,
            "-package",
            "contoh-app",
            "-version",
            "1.0.0",
            "-key",
            key.prefix <> ".key.pem",
            "-out",
            second
          ])

        {:ok, b1} = Bundle.parse(File.read!(r.bundle))
        {:ok, b2} = Bundle.parse(File.read!(second))
        assert b1.manifest == b2.manifest
        assert b1.signature == b2.signature == unquote(same?)
        assert {0, %{"status" => "OK"}} = verify(r)
        assert {0, %{"status" => "OK"}} = verify(r, bundle: second)
      end
    end
  end

  describe "trust" do
    test "add idempoten, memperbarui paket, list, remove", %{tmp_dir: dir, keys: keys} do
      key = keys["ed25519"]
      store = Path.join(dir, "t.json")

      add = fn pkg ->
        cli(["trust", "add", "-key", key.prefix <> ".pub.pem", "-package", pkg, "-store", store])
      end

      assert {0, out, ""} = add.("app-a")
      assert out =~ key.fingerprint and out =~ "ed25519" and out =~ "app-a"
      first = File.read!(store)
      assert {0, _, ""} = add.("app-a")
      assert File.read!(store) == first
      assert {0, _, ""} = add.("app-b")

      assert {0, list, ""} = cli(["trust", "list", "-store", store])
      assert list == "#{key.fingerprint}  ed25519  app-a,app-b\n"

      assert {0, _, ""} = cli(["trust", "remove", "-keyid", key.fingerprint, "-store", store])
      assert {2, "", err} = cli(["trust", "remove", "-keyid", key.fingerprint, "-store", store])
      assert err =~ "tidak ditemukan"
      assert {0, "", ""} = cli(["trust", "list", "-store", store])
      assert Path.wildcard(store <> ".tmp-*") == []
    end

    test "remove banyak keyid sekaligus dan batal tanpa perubahan bila ada yang hilang", %{
      tmp_dir: dir,
      keys: keys
    } do
      store = Path.join(dir, "multi.json")
      ecdsa = keys["ecdsa-p256-sha256"]
      ed = keys["ed25519"]

      for key <- [ecdsa, ed] do
        {0, _, ""} =
          cli([
            "trust",
            "add",
            "-key",
            key.prefix <> ".pub.pem",
            "-package",
            "app",
            "-store",
            store
          ])
      end

      original = File.read!(store)
      missing = String.duplicate("0", 64)

      assert {2, "", err} =
               cli([
                 "trust",
                 "remove",
                 "-keyid",
                 ecdsa.fingerprint,
                 "-keyid",
                 missing,
                 "-store",
                 store
               ])

      assert err =~ "tidak ditemukan"
      assert File.read!(store) == original

      assert {0, out, ""} =
               cli([
                 "trust",
                 "remove",
                 "-keyid",
                 ecdsa.fingerprint <> "," <> ed.fingerprint,
                 "-store",
                 store
               ])

      assert out =~ ecdsa.fingerprint and out =~ ed.fingerprint
      assert {0, "", ""} = cli(["trust", "list", "-store", store])
    end

    test "trust store rusak tidak ditimpa", %{tmp_dir: dir, keys: keys} do
      store = Path.join(dir, "rusak.json")
      File.write!(store, "bukan json")
      key = keys["ed25519"]

      assert {2, "", _} =
               cli([
                 "trust",
                 "add",
                 "-key",
                 key.prefix <> ".pub.pem",
                 "-package",
                 "app",
                 "-store",
                 store
               ])

      assert File.read!(store) == "bukan json"
    end

    test "wildcard dan paket tidak sah ditolak", %{tmp_dir: dir, keys: keys} do
      key = keys["ed25519"]
      store = Path.join(dir, "t.json")

      for pkg <- ["*", "App", "a b", ""] do
        assert {2, "", _} =
                 cli([
                   "trust",
                   "add",
                   "-key",
                   key.prefix <> ".pub.pem",
                   "-package",
                   pkg,
                   "-store",
                   store
                 ])
      end

      refute File.exists?(store)
    end
  end

  describe "keygen, sign, dan opsi global" do
    test "keygen tidak menimpa tanpa -force", %{tmp_dir: dir} do
      prefix = Path.join(dir, "k")
      assert {0, fp1, ""} = cli(["keygen", "-algorithm", "ed25519", "-out", prefix])
      assert {2, "", err} = cli(["keygen", "-algorithm", "ed25519", "-out", prefix])
      assert err =~ "-force"
      assert {0, fp2, ""} = cli(["keygen", "-algorithm", "ed25519", "-out", prefix, "-force"])
      refute fp1 == fp2
      assert String.length(String.trim(fp2)) == 64
    end

    test "keygen menolak algoritma tidak dikenal dan opsi hilang", %{tmp_dir: dir} do
      assert {2, "", _} = cli(["keygen", "-algorithm", "rsa-sha1", "-out", Path.join(dir, "x")])
      assert {2, "", _} = cli(["keygen", "-algorithm", "ed25519"])
    end

    test "sign gagal dengan exit 2 untuk berkas atau kunci tidak ada", %{tmp_dir: dir, keys: keys} do
      key = keys["ed25519"]
      file = Path.join(dir, "a.bin")
      File.write!(file, "x")
      base = ["sign", "-package", "app", "-version", "1", "-out", Path.join(dir, "b.json")]

      assert {2, "", _} =
               cli(
                 base ++ ["-file", Path.join(dir, "ada-tidak"), "-key", key.prefix <> ".key.pem"]
               )

      assert {2, "", _} = cli(base ++ ["-file", file, "-key", Path.join(dir, "tidak-ada.pem")])
      assert {2, "", _} = cli(base ++ ["-file", file, "-key", key.prefix <> ".pub.pem"])

      assert {2, "", _} =
               cli([
                 "sign",
                 "-file",
                 file,
                 "-package",
                 "Salah!",
                 "-version",
                 "1",
                 "-key",
                 key.prefix <> ".key.pem",
                 "-out",
                 Path.join(dir, "c.json")
               ])
    end

    test "sign hanya memuat nama berkas tanpa direktori", %{tmp_dir: dir, keys: keys} do
      r = release(dir, keys["ed25519"])
      {:ok, b} = Bundle.parse(File.read!(r.bundle))
      {:ok, m} = Manifest.parse(b.manifest)
      assert m.artifact_name == "contoh-app.zip"
      refute File.read!(r.bundle) =~ "PRIVATE"
    end

    test "sign tidak menimpa bundle tanpa -force", %{tmp_dir: dir, keys: keys} do
      key = keys["ecdsa-p256-sha256"]
      r = release(dir, key)
      original = File.read!(r.bundle)

      args = [
        "sign",
        "-file",
        r.file,
        "-package",
        "contoh-app",
        "-version",
        "1.0.0",
        "-key",
        key.prefix <> ".key.pem",
        "-out",
        r.bundle
      ]

      assert {2, "", err} = cli(args)
      assert err =~ "-force"
      assert File.read!(r.bundle) == original
      assert {0, _, ""} = cli(args ++ ["-force"])
      assert File.read!(r.bundle) != original
    end

    test "-help, -version, dan perintah tidak dikenal" do
      assert {0, out, ""} = cli(["-help"])
      assert out =~ "keygen" and out =~ "trust remove"
      assert {0, ver, ""} = cli(["-version"])
      assert ver == Nadina.version() <> "\n"
      assert {0, ^ver, ""} = cli(["--version"])
      assert {0, out, ""} = cli(["keygen", "-help"])
      assert out =~ "keygen"
      assert {0, ^out, ""} = cli(["verify", "-h"])
      assert {2, "", err} = cli(["foo"])
      assert err =~ "tidak dikenal"
      assert {2, "", _} = cli([])
      assert {2, "", _} = cli(["trust"])
    end

    test "opsi dengan satu atau dua tanda hubung setara", %{tmp_dir: dir} do
      assert {0, _, ""} = cli(["keygen", "--algorithm", "ed25519", "--out", Path.join(dir, "a")])
      assert {0, _, ""} = cli(["keygen", "-algorithm", "ed25519", "-out", Path.join(dir, "b")])
    end
  end
end
