defmodule Nadina.CLIHarness do
  @moduledoc false

  import ExUnit.Assertions

  @profiles ["rsa-pss-sha256", "ecdsa-p256-sha256", "ed25519"]

  def cli(args), do: Nadina.CLI.run(args)

  def json!(output) do
    assert String.ends_with?(output, "\n")
    JSON.decode!(String.trim_trailing(output, "\n"))
  end

  def keypair(profile, dir, name \\ "key") do
    prefix = Path.join(dir, name)
    {0, fingerprint, ""} = cli(["keygen", "-algorithm", profile, "-out", prefix])
    %{prefix: prefix, fingerprint: String.trim(fingerprint)}
  end

  def keys(dir) do
    for profile <- @profiles, into: %{} do
      profile_dir = Path.join(dir, profile)
      File.mkdir_p!(profile_dir)
      {profile, keypair(profile, profile_dir)}
    end
  end

  def release(dir, key, content \\ "isi artefak", opts \\ []) do
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

  def verify(r, overrides \\ []) do
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
end
