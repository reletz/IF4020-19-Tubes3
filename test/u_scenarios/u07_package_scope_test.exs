defmodule Nadina.UScenarios.U07PackageScopeTest do
  use ExUnit.Case, async: true

  alias Nadina.CLIHarness

  @moduletag :tmp_dir

  setup %{tmp_dir: dir} do
    %{dir: dir, key: CLIHarness.keypair("ecdsa-p256-sha256", dir)}
  end

  test "kunci yang hanya diizinkan untuk paket lain ditolak", %{dir: dir, key: key} do
    r = CLIHarness.release(dir, key)
    other_store = Path.join(dir, "lain.json")

    assert {0, _, ""} =
             CLIHarness.cli([
               "trust",
               "add",
               "-key",
               key.prefix <> ".pub.pem",
               "-package",
               "paket-lain",
               "-store",
               other_store
             ])

    assert {1, %{"status" => "KEY_NOT_TRUSTED", "valid" => false}} =
             CLIHarness.verify(r, store: other_store)
  end
end
