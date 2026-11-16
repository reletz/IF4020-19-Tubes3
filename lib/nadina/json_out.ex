defmodule Nadina.JSONOut do
  @moduledoc """
  Penulis JSON kecil untuk keluaran program (hasil verifikasi dan trust store).

  Objek ditulis sebagai daftar pasangan agar urutan field tetap. String di-escape sesuai
  RFC 8259, dan karakter non-ASCII ditulis langsung sebagai UTF-8.
  """

  @type t ::
          nil
          | boolean()
          | integer()
          | String.t()
          | [t()]
          | {:object, [{String.t(), t()}]}

  @doc """
  Mengubah nilai menjadi JSON tanpa white space.

  ## Contoh

      iex> Nadina.JSONOut.encode({:object, [{"a", 1}, {"b", [true, nil]}, {"c", "x\\ny"}]})
      ~s({"a":1,"b":[true,null],"c":"x\\\\ny"})
  """
  @spec encode(t()) :: binary()
  def encode(value), do: value |> to_iodata() |> IO.iodata_to_binary()

  defp to_iodata(nil), do: "null"
  defp to_iodata(true), do: "true"
  defp to_iodata(false), do: "false"
  defp to_iodata(n) when is_integer(n), do: Integer.to_string(n)
  defp to_iodata(s) when is_binary(s), do: [?", escape(s, []), ?"]

  defp to_iodata(list) when is_list(list),
    do: [?[, Enum.intersperse(Enum.map(list, &to_iodata/1), ?,), ?]]

  defp to_iodata({:object, pairs}) do
    members = Enum.map(pairs, fn {k, v} -> [to_iodata(k), ?:, to_iodata(v)] end)
    [?{, Enum.intersperse(members, ?,), ?}]
  end

  defp escape(<<>>, acc), do: Enum.reverse(acc)
  defp escape(<<?", rest::binary>>, acc), do: escape(rest, ["\\\"" | acc])
  defp escape(<<?\\, rest::binary>>, acc), do: escape(rest, ["\\\\" | acc])
  defp escape(<<?\n, rest::binary>>, acc), do: escape(rest, ["\\n" | acc])
  defp escape(<<?\r, rest::binary>>, acc), do: escape(rest, ["\\r" | acc])
  defp escape(<<?\t, rest::binary>>, acc), do: escape(rest, ["\\t" | acc])

  defp escape(<<c, rest::binary>>, acc) when c < 0x20 do
    hex = c |> Integer.to_string(16) |> String.pad_leading(4, "0")
    escape(rest, ["\\u" <> hex | acc])
  end

  defp escape(<<c, rest::binary>>, acc), do: escape(rest, [c | acc])
end
