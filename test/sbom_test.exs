defmodule Nadina.SBOMTest do
  use ExUnit.Case, async: true

  alias Nadina.{Artifact, Bundle, SBOM}

  @moduletag :tmp_dir

  @fixtures Path.expand("testdata/sbom", __DIR__)
  @cyclonedx Path.join(@fixtures, "cyclonedx-trivy.json")
  @spdx Path.join(@fixtures, "spdx-trivy.json")

  defp cli(args), do: Nadina.CLI.run(args)

  defp json!(out) do
    assert String.ends_with?(out, "\n")
    JSON.decode!(String.trim_trailing(out, "\n"))
  end

  # Rilis lengkap: kunci, trust store, bundle rilis, wrapper SBOM, dan bundle wrapper.
  setup %{tmp_dir: dir} do
    prefix = Path.join(dir, "k")
    {0, _fp, ""} = cli(["keygen", "-algorithm", "ed25519", "-out", prefix])
    store = Path.join(dir, "trust.json")

    {0, _, ""} =
      cli([
        "trust",
        "add",
        "-key",
        prefix <> ".pub.pem",
        "-package",
        "contoh-app",
        "-store",
        store
      ])

    artifact = Path.join(dir, "contoh-app.zip")
    File.write!(artifact, "isi artefak rilis")
    bundle = Path.join(dir, "rilis.json")

    {0, _, ""} =
      cli([
        "sign",
        "-file",
        artifact,
        "-package",
        "contoh-app",
        "-version",
        "1.0.0",
        "-key",
        prefix <> ".key.pem",
        "-out",
        bundle
      ])

    sbom = Path.join(dir, "sbom.json")
    {0, _, ""} = cli(["sbom", "bind", "-file", artifact, "-sbom", @cyclonedx, "-out", sbom])
    sbom_bundle = Path.join(dir, "sbom-bundle.json")

    {0, _, ""} =
      cli([
        "sbom",
        "sign",
        "-sbom",
        sbom,
        "-package",
        "contoh-app",
        "-version",
        "1.0.0",
        "-key",
        prefix <> ".key.pem",
        "-out",
        sbom_bundle
      ])

    %{
      dir: dir,
      prefix: prefix,
      store: store,
      artifact: artifact,
      bundle: bundle,
      sbom: sbom,
      sbom_bundle: sbom_bundle
    }
  end

  defp verify(r, overrides \\ []) do
    args = [
      "sbom",
      "verify",
      "-file",
      Keyword.get(overrides, :artifact, r.artifact),
      "-bundle",
      Keyword.get(overrides, :bundle, r.bundle),
      "-sbom",
      Keyword.get(overrides, :sbom, r.sbom),
      "-sbom-bundle",
      Keyword.get(overrides, :sbom_bundle, r.sbom_bundle),
      "-trust-store",
      Keyword.get(overrides, :store, r.store),
      "-package",
      "contoh-app",
      "-version",
      "1.0.0",
      "-json"
    ]

    {code, out, _} = cli(args)
    {code, json!(out)}
  end

  describe "bind dan extract" do
    test "CycloneDX dan SPDX dari Trivy: byte SBOM kembali identik", %{
      dir: dir,
      artifact: artifact
    } do
      for fixture <- [@cyclonedx, @spdx] do
        wrapper = Path.join(dir, "w-#{Path.basename(fixture)}")
        out = Path.join(dir, "x-#{Path.basename(fixture)}")

        assert {0, _, ""} =
                 cli(["sbom", "bind", "-file", artifact, "-sbom", fixture, "-out", wrapper])

        assert {0, _, ""} = cli(["sbom", "extract", "-sbom", wrapper, "-out", out])
        assert File.read!(out) == File.read!(fixture)
      end
    end

    test "subject wrapper merujuk artefak", %{dir: dir, artifact: artifact} do
      wrapper = Path.join(dir, "w.json")
      {0, _, ""} = cli(["sbom", "bind", "-file", artifact, "-sbom", @spdx, "-out", wrapper])
      {:ok, size, sha} = Artifact.digest(artifact)
      assert {:ok, subject, _} = SBOM.extract(File.read!(wrapper))
      assert subject == %{name: "contoh-app.zip", size: size, sha256: sha}
    end

    test "SBOM dengan null tetap diterima, karena isinya buram", %{dir: dir, artifact: artifact} do
      sbom = Path.join(dir, "null.json")
      File.write!(sbom, ~s({"bomFormat":"X","meta":null}\n))
      wrapper = Path.join(dir, "w.json")
      assert {0, _, ""} = cli(["sbom", "bind", "-file", artifact, "-sbom", sbom, "-out", wrapper])
    end

    test "masukan yang bukan objek JSON ditolak", %{dir: dir, artifact: artifact} do
      for {name, content} <- [teks: "bukan json", larik: "[1,2]", skalar: "42"] do
        sbom = Path.join(dir, "#{name}.json")
        File.write!(sbom, content)
        out = Path.join(dir, "w-#{name}.json")
        assert {2, "", err} = cli(["sbom", "bind", "-file", artifact, "-sbom", sbom, "-out", out])
        assert err =~ "objek JSON"
        refute File.exists?(out)
      end
    end

    test "wrapper yang diubah atau tidak sah ditolak extract", %{dir: dir} do
      assert {:error, :invalid_sbom} = SBOM.extract("{}")
      assert {:error, :invalid_sbom} = SBOM.extract(~s({"schema":"minisign-sbom/v2"}))

      bad_b64 =
        ~s({"schema":"minisign-sbom/v1","subject":{"name":"a","size":0,"sha256":"#{String.duplicate("0", 64)}"},"sbom_b64":"!!"})

      assert {:error, :invalid_sbom} = SBOM.extract(bad_b64)

      extra =
        ~s({"schema":"minisign-sbom/v1","subject":{"name":"a","size":0,"sha256":"#{String.duplicate("0", 64)}"},"sbom_b64":"e30=","x":1})

      assert {:error, :invalid_sbom} = SBOM.extract(extra)

      assert {2, "", _} =
               cli([
                 "sbom",
                 "extract",
                 "-sbom",
                 Path.join(dir, "tidak-ada.json"),
                 "-out",
                 Path.join(dir, "o.json")
               ])
    end

    test "bind dan extract tidak menimpa berkas yang sudah ada", %{
      artifact: artifact,
      sbom: sbom
    } do
      assert {2, "", err} =
               cli(["sbom", "bind", "-file", artifact, "-sbom", @cyclonedx, "-out", sbom])

      assert err =~ "sudah ada"
      assert {2, "", err2} = cli(["sbom", "extract", "-sbom", sbom, "-out", artifact])
      assert err2 =~ "sudah ada"
    end
  end

  describe "verifikasi wrapper dan rilis" do
    test "valid: kedua bundle sah dan subject merujuk artefak", r do
      assert {0, %{"valid" => true, "status" => "OK"}} = verify(r)
    end

    test "wrapper diubah: ditolak pada bundle wrapper", r do
      File.write!(r.sbom, String.replace(File.read!(r.sbom), "\"size\":", "\"size\":0,\"size\":"))
      assert {1, %{"status" => "ARTIFACT_MISMATCH", "valid" => false}} = verify(r)
    end

    test "artefak rilis diganti isinya: ditolak pada bundle rilis", r do
      File.write!(r.artifact, "artefak lain")
      assert {1, %{"status" => "ARTIFACT_MISMATCH"}} = verify(r)
    end

    test "wrapper milik artefak lain dengan bundle sah: ditolak pada keterikatan", r do
      other = Path.join(r.dir, "lain.zip")
      File.write!(other, "artefak lain sama sekali")
      other_sbom = Path.join(r.dir, "sbom-lain.json")
      {0, _, ""} = cli(["sbom", "bind", "-file", other, "-sbom", @spdx, "-out", other_sbom])
      other_bundle = Path.join(r.dir, "sbom-lain-bundle.json")

      {0, _, ""} =
        cli([
          "sbom",
          "sign",
          "-sbom",
          other_sbom,
          "-package",
          "contoh-app",
          "-version",
          "1.0.0",
          "-key",
          r.prefix <> ".key.pem",
          "-out",
          other_bundle
        ])

      assert {1, %{"status" => "ARTIFACT_MISMATCH", "message" => message}} =
               verify(r, sbom: other_sbom, sbom_bundle: other_bundle)

      assert message =~ "tidak merujuk"
    end

    test "bundle wrapper dari kunci tak tepercaya: KEY_NOT_TRUSTED", r do
      lain = Path.join(r.dir, "lain")
      {0, _, _} = cli(["keygen", "-algorithm", "ed25519", "-out", lain])
      lain_bundle = Path.join(r.dir, "lain-bundle.json")

      {0, _, ""} =
        cli([
          "sbom",
          "sign",
          "-sbom",
          r.sbom,
          "-package",
          "contoh-app",
          "-version",
          "1.0.0",
          "-key",
          lain <> ".key.pem",
          "-out",
          lain_bundle
        ])

      assert {1, %{"status" => "KEY_NOT_TRUSTED"}} = verify(r, sbom_bundle: lain_bundle)
    end

    test "wrapper rusak namun ditandatangani: FORMAT_ERROR", r do
      bad = Path.join(r.dir, "bad-sbom.json")
      File.write!(bad, "{}\n")
      bad_bundle = Path.join(r.dir, "bad-bundle.json")

      {0, _, ""} =
        cli([
          "sbom",
          "sign",
          "-sbom",
          bad,
          "-package",
          "contoh-app",
          "-version",
          "1.0.0",
          "-key",
          r.prefix <> ".key.pem",
          "-out",
          bad_bundle
        ])

      assert {1, %{"status" => "FORMAT_ERROR"}} = verify(r, sbom: bad, sbom_bundle: bad_bundle)
    end

    test "isi SBOM bukan objek JSON tetapi wrapper sah: FORMAT_ERROR", r do
      # Wrapper dibuat langsung, melewati bind, sehingga isi yang bukan JSON lolos ke verifikasi.
      {:ok, size, sha} = Artifact.digest(r.artifact)
      inner = "bukan json"

      wrapper =
        ~s({"schema":"minisign-sbom/v1","subject":{"name":"contoh-app.zip","size":#{size},"sha256":"#{sha}"},"sbom_b64":"#{Base.encode64(inner)}"}\n)

      path = Path.join(r.dir, "inner-bad.json")
      File.write!(path, wrapper)
      bundle = Path.join(r.dir, "inner-bad-bundle.json")

      {0, _, ""} =
        cli([
          "sbom",
          "sign",
          "-sbom",
          path,
          "-package",
          "contoh-app",
          "-version",
          "1.0.0",
          "-key",
          r.prefix <> ".key.pem",
          "-out",
          bundle
        ])

      assert {1, %{"status" => "FORMAT_ERROR"}} = verify(r, sbom: path, sbom_bundle: bundle)
    end

    test "berkas wrapper tidak ada: INPUT_ERROR dengan exit 2", r do
      assert {2, %{"status" => "INPUT_ERROR"}} =
               verify(r, sbom: Path.join(r.dir, "tidak-ada.json"))
    end

    test "opsi wajib hilang atau subperintah salah: exit 2" do
      assert {2, "", _} = cli(["sbom", "verify", "-file", "x"])
      assert {2, "", _} = cli(["sbom", "bukan-subperintah"])
      assert {2, "", _} = cli(["sbom"])

      assert {2, "", _} =
               cli(["sbom", "generate", "-file", "x", "-lock", "mix.lock", "-out", "y"])
    end
  end

  test "bundle wrapper memakai format bundle yang sama dengan rilis", r do
    {:ok, b} = Bundle.parse(File.read!(r.sbom_bundle))
    assert byte_size(b.manifest) > 0
  end
end
