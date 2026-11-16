defmodule Nadina.UScenarios.U06TrustStoreTest do
  use ExUnit.Case, async: true

  alias Nadina.CLIHarness

  @moduletag :tmp_dir

  setup %{tmp_dir: dir} do
    %{dir: dir, key: CLIHarness.keypair("ecdsa-p256-sha256", dir)}
  end

  test "trust store kosong menolak dengan KEY_NOT_TRUSTED", %{dir: dir, key: key} do
    r = CLIHarness.release(dir, key)
    empty = Path.join(dir, "kosong.json")
    File.write!(empty, ~s({"schema":"minisign-trust/v1","keys":[]}\n))

    assert {1, %{"status" => "KEY_NOT_TRUSTED", "valid" => false}} =
             CLIHarness.verify(r, store: empty)
  end

  test "kunci yang dihapus dari trust store ditolak", %{dir: dir, key: key} do
    r = CLIHarness.release(dir, key)

    assert {0, _, ""} =
             CLIHarness.cli([
               "trust",
               "remove",
               "-keyid",
               key.fingerprint,
               "-store",
               r.store
             ])

    assert {1, %{"status" => "KEY_NOT_TRUSTED"}} = CLIHarness.verify(r)
  end
end
