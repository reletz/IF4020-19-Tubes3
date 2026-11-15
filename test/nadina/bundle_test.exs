defmodule Nadina.BundleTest do
  use ExUnit.Case, async: true

  alias Nadina.Bundle

  doctest Nadina.Bundle

  @m ~s({"schema":"minisign-manifest/v1"})
  @sig :binary.copy(<<0xAB>>, 64)

  defp json(fields) do
    body = Enum.map_join(fields, ",", fn {k, v} -> ~s("#{k}":"#{v}") end)
    "{" <> body <> "}"
  end

  defp valid_fields do
    [
      {"schema", "minisign-bundle/v1"},
      {"manifest_b64", Base.encode64(@m)},
      {"signature_b64", Base.encode64(@sig)}
    ]
  end

  describe "encode/1 dan parse/1" do
    test "round trip" do
      bundle = %Bundle{manifest: @m, signature: @sig}
      assert {:ok, ^bundle} = bundle |> Bundle.encode() |> Bundle.parse()
    end

    test "encode menghasilkan tiga field dengan urutan tetap" do
      assert Bundle.encode(%Bundle{manifest: "a", signature: "bc"}) ==
               ~s({"schema":"minisign-bundle/v1","manifest_b64":"YQ==","signature_b64":"YmM="}\n)
    end

    test "white space dan urutan field bebas (U13)" do
      [s, m, sig] = valid_fields()
      bytes = "\n{ " <> String.trim_leading(json([sig, s, m]), "{") <> " \n"
      bytes = String.replace(bytes, ",", " ,\n  ")
      assert {:ok, %Bundle{manifest: @m, signature: @sig}} = Bundle.parse(bytes)
    end

    test "signature kosong tetap lolos format (panjang dicek di langkah tanda tangan)" do
      fields = List.keyreplace(valid_fields(), "signature_b64", 0, {"signature_b64", ""})
      assert {:ok, %Bundle{signature: ""}} = Bundle.parse(json(fields))
    end
  end

  describe "parse/1 menolak" do
    test "ukuran lebih dari 64 KiB ditolak sebelum parsing" do
      assert {:error, {:too_large, 65_537}} = Bundle.parse(String.duplicate(" ", 65_537))
      assert {:error, {:unexpected_end, _}} = Bundle.parse(String.duplicate(" ", 65_536))
    end

    test "BOM ditolak" do
      assert {:error, {:bom_not_allowed, 0}} =
               Bundle.parse(<<0xEF, 0xBB, 0xBF>> <> json(valid_fields()))
    end

    test "duplicate key, field tambahan, field hilang, tipe salah" do
      dup = json(valid_fields() ++ [{"schema", "minisign-bundle/v1"}])
      assert {:error, {:duplicate_key, "schema", _}} = Bundle.parse(dup)

      extra = json(valid_fields() ++ [{"private_key", "x"}])
      assert {:error, {:unknown_field, ["private_key"]}} = Bundle.parse(extra)

      missing = json(List.keydelete(valid_fields(), "signature_b64", 0))
      assert {:error, {:missing_field, ["signature_b64"]}} = Bundle.parse(missing)

      wrong = ~s({"schema":"minisign-bundle/v1","manifest_b64":1,"signature_b64":""})
      assert {:error, {:wrong_type, ["manifest_b64"], :string}} = Bundle.parse(wrong)
    end

    test "schema salah" do
      fields = List.keyreplace(valid_fields(), "schema", 0, {"schema", "minisign-bundle/v2"})
      assert {:error, {:invalid_field, ["schema"]}} = Bundle.parse(json(fields))
    end

    test "Base64 tidak strict" do
      good = Base.encode64(@m)

      bad = [
        "YQ",
        good <> "=",
        " " <> good,
        String.slice(good, 0, 4) <> "\\n" <> String.slice(good, 4..-1//1),
        "-" <> String.slice(good, 1..-1//1),
        "_" <> String.slice(good, 1..-1//1),
        "QR==",
        "QUI=QUI=",
        "Q"
      ]

      for b64 <- bad do
        fields = List.keyreplace(valid_fields(), "manifest_b64", 0, {"manifest_b64", b64})

        assert {:error, {:invalid_base64, ["manifest_b64"]}} = Bundle.parse(json(fields)),
               inspect(b64)
      end

      fields = List.keyreplace(valid_fields(), "signature_b64", 0, {"signature_b64", "YmN="})
      assert {:error, {:invalid_base64, ["signature_b64"]}} = Bundle.parse(json(fields))
    end
  end
end
