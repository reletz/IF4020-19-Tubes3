defmodule Nadina.Property.StrictJSONTest do
  @moduledoc """
  Property test parser JSON strict: dokumen sah selalu diterima apa adanya, sedangkan
  varian cacat (duplicate key, null, trailing data, boolean di posisi integer) selalu
  ditolak dengan alasan yang tepat, di level mana pun varian itu berada.
  """
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Nadina.StrictJSON

  @ws [" ", "\t", "\n", "\r"]

  defp key, do: string(:utf8, max_length: 8)

  defp leaf, do: one_of([integer(), boolean(), string(:utf8, max_length: 12)])

  # Nilai JSON tanpa null dengan kedalaman terbatas (jauh di bawah batas 32 level).
  defp json_value(0), do: leaf()

  defp json_value(depth) do
    child = json_value(depth - 1)

    one_of([
      leaf(),
      list_of(child, max_length: 3),
      map_of(key(), child, max_length: 3)
    ])
  end

  defp container,
    do:
      one_of([list_of(json_value(3), max_length: 4), map_of(key(), json_value(3), max_length: 4)])

  defp enc(value), do: JSON.encode!(value)

  defp object(pairs),
    do: "{" <> Enum.map_join(pairs, ",", fn {k, v} -> enc(k) <> ":" <> v end) <> "}"

  # Membungkus teks JSON di dalam array atau objek supaya cacat juga diuji di level dalam.
  defp wrapper do
    member_of([
      & &1,
      &("[1," <> &1 <> "]"),
      &(~s|{"luar":| <> &1 <> "}"),
      &(~s|{"a":[{"b":| <> &1 <> "}]}")
    ])
  end

  property "dokumen sah diterima dan hasilnya sama dengan nilai asal" do
    check all value <- json_value(4) do
      assert StrictJSON.decode(enc(value)) == {:ok, value}
    end
  end

  property "duplicate key ditolak" do
    check all map <- map_of(key(), json_value(2), min_length: 1, max_length: 5),
              dup <- member_of(Map.keys(map)),
              dup_value <- json_value(2),
              pos <- integer(0..map_size(map)),
              wrap <- wrapper() do
      pairs =
        map
        |> Enum.map(fn {k, v} -> {k, enc(v)} end)
        |> List.insert_at(pos, {dup, enc(dup_value)})

      assert {:error, {:duplicate_key, ^dup, _}} = StrictJSON.decode(wrap.(object(pairs)))
    end
  end

  property "null di posisi mana pun ditolak" do
    check all items <- list_of(json_value(2), max_length: 5),
              pos <- integer(0..length(items)),
              as_object? <- boolean(),
              wrap <- wrapper() do
      texts = items |> Enum.map(&enc/1) |> List.insert_at(pos, "null")

      doc =
        if as_object?,
          do: texts |> Enum.with_index(fn v, i -> {"k#{i}", v} end) |> object(),
          else: "[" <> Enum.join(texts, ",") <> "]"

      assert {:error, {:null_not_allowed, _}} = StrictJSON.decode(wrap.(doc))
    end
  end

  property "data setelah nilai pertama ditolak dengan offset tepat" do
    check all value <- container(),
              ws <- map(list_of(member_of(@ws), max_length: 3), &Enum.join/1),
              extra <- one_of([map(container(), &enc/1), string(:printable, min_length: 1)]),
              # cek byte pertama, bukan grafem ("\r\n" adalah satu grafem)
              binary_part(extra, 0, 1) not in @ws do
      text = enc(value)

      assert StrictJSON.decode(text <> ws <> extra) ==
               {:error, {:trailing_data, byte_size(text) + byte_size(ws)}}
    end
  end

  property "boolean di posisi integer ditolak oleh skema" do
    check all map <- map_of(key(), integer(), min_length: 1, max_length: 6),
              target <- member_of(Map.keys(map)),
              bool <- boolean() do
      schema = {:object, map |> Map.keys() |> Enum.map(&{&1, :integer})}
      doc = enc(Map.put(map, target, bool))

      assert StrictJSON.decode_as(enc(map), schema) == {:ok, map}
      assert StrictJSON.decode_as(doc, schema) == {:error, {:wrong_type, [target], :integer}}
    end
  end
end
