defmodule Nadina.SBOMTest do
  use ExUnit.Case, async: true

  alias Nadina.SBOM

  @moduletag :tmp_dir

  defp cli(args), do: Nadina.CLI.run(args)

  defp json!(out) do
    assert String.ends_with?(out, "\n")
    JSON.decode!(String.trim_trailing(out, "\n"))
  end

  # Rilis lengkap: kunci, trust store, bundle rilis, SBOM, dan bundle SBOM.
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
    {0, _, ""} = cli(["sbom", "generate", "-file", artifact, "-lock", "mix.lock", "-out", sbom])
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

  describe "pembentukan dari mix.lock" do
    test "komponen hex, diurutkan, dengan checksum SHA-256" do
      assert {:ok, comps} = SBOM.components_from_lock("mix.lock")
      assert comps == Enum.sort_by(comps, & &1.name)
      assert Enum.any?(comps, &(&1.name == "credo"))
      assert Enum.all?(comps, &Regex.match?(~r/\A[0-9a-f]{64}\z/, &1.sha256))
    end

    test "SBOM deterministik dan memuat subject yang benar", %{artifact: artifact} do
      assert {:ok, a} = SBOM.generate(artifact, "mix.lock")
      assert {:ok, b} = SBOM.generate(artifact, "mix.lock")
      assert a == b
      assert {:ok, subject, comps} = SBOM.parse(a)
      assert subject.name == "contoh-app.zip"
      assert subject.size == byte_size("isi artefak rilis")
      assert comps != []
    end

    test "entri selain hex ditolak", %{dir: dir} do
      lock = Path.join(dir, "git.lock")
      File.write!(lock, ~s(%{"x" => {:git, "https://example.invalid/x.git", "abc", []}}))
      assert SBOM.components_from_lock(lock) == {:error, :unsupported_source}
    end

    test "lock rusak dan lock yang tidak ada", %{dir: dir} do
      bad = Path.join(dir, "bad.lock")
      File.write!(bad, "bukan term elixir (")
      assert SBOM.components_from_lock(bad) == {:error, :invalid_lock}
      assert {:error, {:io, :enoent}} = SBOM.components_from_lock(Path.join(dir, "tidak-ada"))
    end

    test "generate menolak artefak yang tidak ada", %{dir: dir} do
      assert {:error, {:io, :enoent}} = SBOM.generate(Path.join(dir, "tidak-ada.zip"), "mix.lock")
    end

    test "sbom generate tidak menimpa berkas yang sudah ada", %{artifact: artifact, sbom: sbom} do
      assert {2, "", err} =
               cli(["sbom", "generate", "-file", artifact, "-lock", "mix.lock", "-out", sbom])

      assert err =~ "sudah ada"
    end
  end

  describe "verifikasi SBOM dan rilis" do
    test "valid: kedua bundle sah dan subject merujuk artefak", r do
      assert {0, %{"valid" => true, "status" => "OK"}} = verify(r)
    end

    test "isi SBOM diubah: ditolak pada bundle SBOM", r do
      File.write!(r.sbom, String.replace(File.read!(r.sbom), "\"version\":\"", "\"version\":\"9"))
      assert {1, %{"status" => "ARTIFACT_MISMATCH", "valid" => false}} = verify(r)
    end

    test "artefak rilis diganti dengan isi lain: ditolak pada bundle rilis", r do
      File.write!(r.artifact, "artefak lain")
      assert {1, %{"status" => "ARTIFACT_MISMATCH"}} = verify(r)
    end

    test "SBOM milik artefak lain dengan bundle sah: ditolak pada langkah keterikatan", r do
      other = Path.join(r.dir, "lain.zip")
      File.write!(other, "artefak lain sama sekali")
      other_sbom = Path.join(r.dir, "sbom-lain.json")

      {0, _, ""} =
        cli(["sbom", "generate", "-file", other, "-lock", "mix.lock", "-out", other_sbom])

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

    test "bundle SBOM ditandatangani kunci yang tidak tepercaya: KEY_NOT_TRUSTED", r do
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

    test "SBOM yang formatnya rusak namun ditandatangani: FORMAT_ERROR", r do
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

    test "berkas SBOM tidak ada: INPUT_ERROR dengan exit 2", r do
      assert {2, %{"status" => "INPUT_ERROR"}} =
               verify(r, sbom: Path.join(r.dir, "tidak-ada.json"))
    end

    test "opsi wajib hilang atau subperintah salah: exit 2" do
      assert {2, "", _} = cli(["sbom", "verify", "-file", "x"])
      assert {2, "", _} = cli(["sbom", "bukan-subperintah"])
      assert {2, "", _} = cli(["sbom"])
    end
  end
end
