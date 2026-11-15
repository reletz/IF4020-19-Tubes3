defmodule Nadina.StrictJSONTest do
  use ExUnit.Case, async: true

  alias Nadina.StrictJSON

  doctest Nadina.StrictJSON

  defp u(hex), do: <<92, ?u>> <> hex

  describe "decode/1 nilai valid" do
    test "objek, array, string, integer, boolean" do
      assert {:ok, %{"a" => [1, -2, 0], "b" => true, "c" => false, "d" => "x"}} =
               StrictJSON.decode(~s({"a":[1,-2,0],"b":true,"c":false,"d":"x"}))
    end

    test "white space di luar token diterima" do
      assert {:ok, %{"a" => %{}, "b" => []}} =
               StrictJSON.decode(" \t\r\n{ \"a\" : { } ,\n \"b\" : [ ] } \n")
    end

    test "escape string termasuk surrogate pair" do
      assert {:ok, "\"\\/\b\f\n\r\t" <> <<0xE9::utf8, 0x1F600::utf8>>} =
               StrictJSON.decode(
                 ~S("\"\\\/\b\f\n\r\t) <> u("00e9") <> u("d83d") <> u("de00") <> ~s(")
               )
    end

    test "utf-8 langsung diterima" do
      assert {:ok, "h" <> <<0xE9::utf8>> <> "llo"} =
               StrictJSON.decode(~s("h) <> <<0xE9::utf8>> <> ~s(llo"))
    end

    test "integer besar tetap presisi" do
      assert {:ok, 9_007_199_254_740_991} = StrictJSON.decode("9007199254740991")
      assert {:ok, 123_456_789_012_345_678_901} = StrictJSON.decode("123456789012345678901")
    end
  end

  describe "decode/1 penolakan" do
    test "duplicate key, termasuk di objek bersarang dan lewat escape" do
      assert {:error, {:duplicate_key, "a", _}} = StrictJSON.decode(~s({"a":1,"a":2}))
      assert {:error, {:duplicate_key, "b", _}} = StrictJSON.decode(~s({"x":{"b":1,"b":1}}))

      assert {:error, {:duplicate_key, "a", _}} =
               StrictJSON.decode(~s({"a":1,") <> u("0061") <> ~s(":2}))
    end

    test "null ditolak di mana pun" do
      assert {:error, {:null_not_allowed, 0}} = StrictJSON.decode("null")
      assert {:error, {:null_not_allowed, 5}} = StrictJSON.decode(~s({"a":null}))
      assert {:error, {:null_not_allowed, 1}} = StrictJSON.decode("[null]")
    end

    test "trailing data ditolak" do
      assert {:error, {:trailing_data, 2}} = StrictJSON.decode("{}{}")
      assert {:error, {:trailing_data, 3}} = StrictJSON.decode("{} x")
      assert {:error, {:trailing_data, 1}} = StrictJSON.decode("1\0")
    end

    test "BOM ditolak" do
      assert {:error, {:bom_not_allowed, 0}} = StrictJSON.decode(<<0xEF, 0xBB, 0xBF, "{}">>)
    end

    test "masukan kosong atau hanya white space" do
      assert {:error, {:unexpected_end, 0}} = StrictJSON.decode("")
      assert {:error, {:unexpected_end, 2}} = StrictJSON.decode("  ")
    end

    test "angka non-integer dan bentuk angka tidak sah" do
      for bad <- ["1.0", "1e3", "1E3", "-0.5", "01", "-01", "+1", "-", ".5", "1.", "0x10", "-0"] do
        assert {:error, {reason, _}} = StrictJSON.decode(bad), "harus ditolak: #{bad}"
        assert reason in [:invalid_number, :non_integer_number, :unexpected_byte, :trailing_data]
      end
    end

    test "fraction dan eksponen dilaporkan sebagai non_integer_number" do
      assert {:error, {:non_integer_number, 0}} = StrictJSON.decode("1.0")
      assert {:error, {:non_integer_number, 0}} = StrictJSON.decode("1e3")
    end

    test "string cacat" do
      assert {:error, {:unexpected_end, _}} = StrictJSON.decode(~s("abc))
      assert {:error, {:control_character, 1}} = StrictJSON.decode("\"\n\"")
      assert {:error, {:invalid_escape, 1}} = StrictJSON.decode(~S("\x"))
      assert {:error, {:invalid_escape, 1}} = StrictJSON.decode(~s(") <> u("12G4") <> ~s("))
      assert {:error, {:invalid_utf8, 1}} = StrictJSON.decode(<<?", 0xFF, ?">>)
      assert {:error, {:invalid_utf8, 1}} = StrictJSON.decode(<<?", 0xC0, 0xAF, ?">>)
    end

    test "surrogate tunggal ditolak" do
      assert {:error, {:invalid_surrogate, 1}} = StrictJSON.decode(~s(") <> u("d83d") <> ~s("))
      assert {:error, {:invalid_surrogate, 1}} = StrictJSON.decode(~s(") <> u("de00") <> ~s("))

      assert {:error, {:invalid_surrogate, 1}} =
               StrictJSON.decode(~s(") <> u("d83d") <> u("0041") <> ~s("))
    end

    test "struktur cacat" do
      for bad <- [
            "{",
            "[",
            "[1,]",
            "{\"a\":1,}",
            "{\"a\"}",
            "{a:1}",
            "{1:1}",
            "[1 2]",
            "tru",
            "True",
            "'a'",
            "}"
          ] do
        assert {:error, {_, _}} = StrictJSON.decode(bad), "harus ditolak: #{inspect(bad)}"
      end
    end

    test "kedalaman bersarang dibatasi" do
      ok = String.duplicate("[", 32) <> String.duplicate("]", 32)
      deep = String.duplicate("[", 33) <> String.duplicate("]", 33)
      assert {:ok, _} = StrictJSON.decode(ok)
      assert {:error, {:too_deep, 32}} = StrictJSON.decode(deep)
    end

    test "bukan binary" do
      assert {:error, {:not_binary, 0}} = StrictJSON.decode(~c"{}")
    end
  end

  describe "validate/2" do
    @artifact {:object, [{"name", :string}, {"size", :integer}, {"sha256", :string}]}
    @schema {:object, [{"schema", :string}, {"ok", :boolean}, {"artifact", @artifact}]}

    defp doc(overrides \\ %{}) do
      Map.merge(
        %{
          "schema" => "s",
          "ok" => true,
          "artifact" => %{"name" => "a", "size" => 1, "sha256" => "h"}
        },
        overrides
      )
    end

    test "dokumen sesuai skema" do
      assert :ok = StrictJSON.validate(doc(), @schema)
    end

    test "field hilang" do
      assert {:error, {:missing_field, ["ok"]}} =
               StrictJSON.validate(Map.delete(doc(), "ok"), @schema)
    end

    test "field tambahan, termasuk di objek bersarang" do
      assert {:error, {:unknown_field, ["extra"]}} =
               StrictJSON.validate(doc(%{"extra" => 1}), @schema)

      art = %{"name" => "a", "size" => 1, "sha256" => "h", "x" => "y"}

      assert {:error, {:unknown_field, ["artifact", "x"]}} =
               StrictJSON.validate(doc(%{"artifact" => art}), @schema)
    end

    test "boolean tidak diterima sebagai integer, integer tidak sebagai boolean" do
      art = %{"name" => "a", "size" => true, "sha256" => "h"}

      assert {:error, {:wrong_type, ["artifact", "size"], :integer}} =
               StrictJSON.validate(doc(%{"artifact" => art}), @schema)

      assert {:error, {:wrong_type, ["ok"], :boolean}} =
               StrictJSON.validate(doc(%{"ok" => 1}), @schema)
    end

    test "tipe salah lainnya" do
      assert {:error, {:wrong_type, ["schema"], :string}} =
               StrictJSON.validate(doc(%{"schema" => 1}), @schema)

      assert {:error, {:wrong_type, ["artifact"], :object}} =
               StrictJSON.validate(doc(%{"artifact" => []}), @schema)

      assert {:error, {:wrong_type, [], :object}} = StrictJSON.validate([], @schema)
    end

    test "array dengan tipe elemen" do
      schema = {:object, [{"keys", {:array, {:object, [{"id", :string}]}}}]}
      assert :ok = StrictJSON.validate(%{"keys" => []}, schema)
      assert :ok = StrictJSON.validate(%{"keys" => [%{"id" => "a"}]}, schema)

      assert {:error, {:wrong_type, ["keys", 1, "id"], :string}} =
               StrictJSON.validate(%{"keys" => [%{"id" => "a"}, %{"id" => 2}]}, schema)

      assert {:error, {:wrong_type, ["keys"], :array}} =
               StrictJSON.validate(%{"keys" => %{}}, schema)
    end

    test "decode_as/2 menggabungkan decode dan validate" do
      schema = {:object, [{"n", :integer}]}
      assert {:ok, %{"n" => 1}} = StrictJSON.decode_as(~s({"n":1}), schema)
      assert {:error, {:unknown_field, ["m"]}} = StrictJSON.decode_as(~s({"n":1,"m":2}), schema)
      assert {:error, {:duplicate_key, "n", _}} = StrictJSON.decode_as(~s({"n":1,"n":1}), schema)
    end
  end
end
