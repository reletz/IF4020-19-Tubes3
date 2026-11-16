defmodule Nadina.TrustTest do
  use ExUnit.Case, async: true

  alias Nadina.{Keys, Trust}

  defp entry(profile \\ "ed25519", package \\ "app") do
    {:ok, mod, _priv, pub} = Keys.generate(profile)
    {:ok, entries, entry} = Trust.add([], pub, mod, package)
    {entries, entry, mod, pub}
  end

  defp entry_doc(entry, overrides \\ %{}) do
    Map.merge(
      %{
        "keyid" => entry.keyid,
        "algorithm" => entry.algorithm,
        "public_key_pem" => entry.public_key_pem,
        "packages" => entry.packages
      },
      overrides
    )
  end

  defp store_doc(keys, overrides \\ %{}) do
    Map.merge(%{"schema" => "minisign-trust/v1", "keys" => keys}, overrides)
  end

  defp parse_doc(doc), do: Trust.parse(JSON.encode!(doc))

  test "add idempoten untuk pasangan kunci dan paket yang sama" do
    {entries, entry, mod, pub} = entry()

    assert {:ok, ^entries, updated} = Trust.add(entries, pub, mod, "app")
    assert updated.keyid == entry.keyid
    assert updated.packages == ["app"]
  end

  test "add paket baru memperbarui entri yang sama" do
    {entries, entry, mod, pub} = entry()

    assert {:ok, updated_entries, updated} = Trust.add(entries, pub, mod, "other")
    assert length(updated_entries) == 1
    assert updated.keyid == entry.keyid
    assert Enum.sort(updated.packages) == ["app", "other"]
  end

  test "remove menerima beberapa keyid sekaligus" do
    {entries, entry, _mod, _pub} = entry()
    {other_entries, other_entry, _other_mod, _other_pub} = entry("ecdsa-p256-sha256")
    all = entries ++ other_entries

    assert {:ok, []} = Trust.remove(all, [entry.keyid, other_entry.keyid])
  end

  test "remove gagal tanpa mengubah daftar bila salah satu keyid tidak ada" do
    {entries, entry, _mod, _pub} = entry()
    {other_entries, _other_entry, _other_mod, _other_pub} = entry("ecdsa-p256-sha256")
    all = entries ++ other_entries
    missing = String.duplicate("0", 64)

    assert {:error, :keyid_not_found} = Trust.remove(all, [entry.keyid, missing])
  end

  test "remove mengabaikan keyid duplikat pada masukan" do
    {entries, entry, _mod, _pub} = entry()
    {other_entries, _other_entry, _other_mod, _other_pub} = entry("ecdsa-p256-sha256")

    assert {:ok, remaining} = Trust.remove(entries ++ other_entries, [entry.keyid, entry.keyid])
    assert remaining == other_entries
  end

  test "encode dan parse round trip" do
    {entries, _entry, _mod, _pub} = entry()

    assert {:ok, ^entries} = Trust.parse(Trust.encode(entries))
  end

  test "parse menolak fingerprint yang tidak cocok" do
    {_entries, entry, _mod, _pub} = entry()

    assert {:error, :invalid_entry} =
             parse_doc(store_doc([entry_doc(entry, %{"keyid" => String.duplicate("0", 64)})]))
  end

  test "parse menolak keyid huruf besar" do
    {_entries, entry, _mod, _pub} = entry()

    assert {:error, :invalid_entry} =
             parse_doc(store_doc([entry_doc(entry, %{"keyid" => String.upcase(entry.keyid)})]))
  end

  test "parse menolak profil yang tidak sesuai kunci" do
    {_entries, entry, _mod, _pub} = entry()

    assert {:error, :invalid_entry} =
             parse_doc(store_doc([entry_doc(entry, %{"algorithm" => "rsa-pss-sha256"})]))
  end

  test "parse menolak daftar paket kosong, duplikat, atau wildcard" do
    {_entries, entry, _mod, _pub} = entry()

    for packages <- [[], ["app", "app"], ["*"]] do
      assert {:error, :invalid_entry} =
               parse_doc(store_doc([entry_doc(entry, %{"packages" => packages})]))
    end
  end

  test "parse menolak field tambahan dan keyid duplikat" do
    {_entries, entry, _mod, _pub} = entry()
    doc = entry_doc(entry)

    assert {:error, :invalid_json} =
             parse_doc(store_doc([Map.put(doc, "extra", 1)]))

    assert {:error, :duplicate_keyid} = parse_doc(store_doc([doc, doc]))
  end

  test "parse menolak schema salah, ukuran berlebih, dan json rusak" do
    assert {:error, :invalid_schema} = parse_doc(store_doc([], %{"schema" => "lain/v1"}))
    assert {:error, :too_large} = Trust.parse(String.duplicate("a", 1_048_577))
    assert {:error, :invalid_json} = Trust.parse("{")
  end
end
