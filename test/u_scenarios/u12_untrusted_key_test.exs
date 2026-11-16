defmodule Nadina.UScenarios.U12UntrustedKeyTest do
  use ExUnit.Case, async: true

  alias Nadina.CLIHarness

  @moduletag :tmp_dir

  setup %{tmp_dir: dir} do
    %{dir: dir, key: CLIHarness.keypair("ecdsa-p256-sha256", dir)}
  end

  test "kunci lain pada profil sama yang tidak ada di trust store ditolak", %{
    dir: dir,
    key: key
  } do
    r = CLIHarness.release(dir, key)
    other_prefix = Path.join(dir, "lain")

    {0, other_fingerprint, ""} =
      CLIHarness.cli(["keygen", "-algorithm", "ecdsa-p256-sha256", "-out", other_prefix])

    other_bundle = Path.join(dir, "lain.json")

    assert {0, _, _} =
             CLIHarness.cli([
               "sign",
               "-file",
               r.file,
               "-package",
               "contoh-app",
               "-version",
               "1.0.0",
               "-key",
               other_prefix <> ".key.pem",
               "-out",
               other_bundle
             ])

    assert {1, %{"status" => "KEY_NOT_TRUSTED", "keyid" => keyid}} =
             CLIHarness.verify(r, bundle: other_bundle)

    assert keyid == String.trim(other_fingerprint)
    refute keyid == key.fingerprint
  end
end
