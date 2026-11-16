defmodule Nadina.StrictJSON do
  @moduledoc """
  Parser JSON strict (RFC 8259) untuk manifest, bundle, dan trust store.

  Dibandingkan parser JSON umum, `decode/1` menolak:

    * duplicate key pada objek mana pun (dideteksi saat parsing, sebelum nilainya dibaca),
    * nilai `null` di posisi mana pun,
    * bilangan pecahan atau eksponen (hanya integer yang diterima), leading zero, dan `-0`,
    * BOM UTF-8 di awal masukan,
    * UTF-8 tidak valid, karakter kontrol di dalam string, escape tidak sah, dan surrogate
      tunggal,
    * data apa pun setelah nilai pertama (selain white space),
    * kedalaman bersarang lebih dari 32 level.

  Pemeriksaan bentuk dokumen (field wajib, field tambahan, dan tipe) dilakukan oleh
  `validate/2` atau `decode_as/2` dengan skema sederhana. Batas ukuran (16 KiB manifest,
  64 KiB bundle) dicek oleh pemanggil sebelum `decode/1`, dan serialisasi canonical
  dicek oleh `Nadina.Manifest`.

  Objek didekode menjadi map dengan key string, array menjadi list.
  """

  @max_depth 32

  @typedoc "Nilai JSON hasil decode. Tidak ada `nil` karena `null` ditolak."
  @type value ::
          String.t() | integer() | boolean() | [value()] | %{optional(String.t()) => value()}

  @typedoc "Offset byte (mulai dari 0) pada masukan tempat kesalahan ditemukan."
  @type offset :: non_neg_integer()

  @type decode_error ::
          {:not_binary, 0}
          | {:bom_not_allowed, offset()}
          | {:unexpected_end, offset()}
          | {:unexpected_byte, offset()}
          | {:trailing_data, offset()}
          | {:null_not_allowed, offset()}
          | {:duplicate_key, String.t(), offset()}
          | {:invalid_number, offset()}
          | {:non_integer_number, offset()}
          | {:control_character, offset()}
          | {:invalid_escape, offset()}
          | {:invalid_surrogate, offset()}
          | {:invalid_utf8, offset()}
          | {:too_deep, offset()}

  @typedoc """
  Skema untuk `validate/2`.

  `{:object, fields}` mewajibkan tepat field yang disebut (tidak kurang, tidak lebih).
  Urutan di `fields` menentukan urutan pemeriksaan, bukan urutan yang wajib di dokumen.
  """
  @type schema ::
          :string
          | :integer
          | :boolean
          | {:array, schema()}
          | {:object, [{String.t(), schema()}]}

  @typedoc "Lokasi nilai di dokumen, berupa daftar key objek dan indeks array."
  @type path :: [String.t() | non_neg_integer()]

  @type validate_error ::
          {:missing_field, path()}
          | {:unknown_field, path()}
          | {:wrong_type, path(), :string | :integer | :boolean | :array | :object}

  @doc """
  Mendekode `input` secara strict.

  ## Contoh

      iex> Nadina.StrictJSON.decode(~s({"a":[1,true]}))
      {:ok, %{"a" => [1, true]}}

      iex> Nadina.StrictJSON.decode(~s({"a":1,"a":2}))
      {:error, {:duplicate_key, "a", 7}}

      iex> Nadina.StrictJSON.decode(~s({"a":null}))
      {:error, {:null_not_allowed, 5}}

      iex> Nadina.StrictJSON.decode("{} {}")
      {:error, {:trailing_data, 3}}
  """
  @spec decode(binary()) :: {:ok, value()} | {:error, decode_error()}
  def decode(<<0xEF, 0xBB, 0xBF, _::binary>>), do: {:error, {:bom_not_allowed, 0}}

  def decode(input) when is_binary(input) do
    {value, rest, pos} = parse_value(input, 0, 0)

    case skip_ws(rest, pos) do
      {<<>>, _} -> {:ok, value}
      {_, pos} -> {:error, {:trailing_data, pos}}
    end
  catch
    {__MODULE__, reason} -> {:error, reason}
  end

  def decode(_), do: {:error, {:not_binary, 0}}

  @doc """
  Mendekode lalu memvalidasi terhadap `schema`. Kesalahan decode dilaporkan lebih dulu.

  ## Contoh

      iex> Nadina.StrictJSON.decode_as(~s({"n":1}), {:object, [{"n", :integer}]})
      {:ok, %{"n" => 1}}

      iex> Nadina.StrictJSON.decode_as(~s({"n":true}), {:object, [{"n", :integer}]})
      {:error, {:wrong_type, ["n"], :integer}}
  """
  @spec decode_as(binary(), schema()) ::
          {:ok, value()} | {:error, decode_error() | validate_error()}
  def decode_as(input, schema) do
    with {:ok, value} <- decode(input),
         :ok <- validate(value, schema) do
      {:ok, value}
    end
  end

  defp fail(reason), do: throw({__MODULE__, reason})

  defp skip_ws(<<c, rest::binary>>, pos) when c in [?\s, ?\t, ?\n, ?\r],
    do: skip_ws(rest, pos + 1)

  defp skip_ws(rest, pos), do: {rest, pos}

  defp parse_value(input, pos, depth) do
    {rest, pos} = skip_ws(input, pos)
    parse_value_at(rest, pos, depth)
  end

  defp parse_value_at(<<>>, pos, _depth), do: fail({:unexpected_end, pos})

  defp parse_value_at(<<?{, rest::binary>>, pos, depth),
    do: parse_object(rest, pos, enter(depth, pos))

  defp parse_value_at(<<?[, rest::binary>>, pos, depth),
    do: parse_array(rest, pos, enter(depth, pos))

  defp parse_value_at(<<?", rest::binary>>, pos, _depth), do: parse_string(rest, pos + 1, [])
  defp parse_value_at(<<"true", rest::binary>>, pos, _depth), do: {true, rest, pos + 4}
  defp parse_value_at(<<"false", rest::binary>>, pos, _depth), do: {false, rest, pos + 5}
  defp parse_value_at(<<"null", _::binary>>, pos, _depth), do: fail({:null_not_allowed, pos})

  defp parse_value_at(<<c, _::binary>> = rest, pos, _depth) when c == ?- or c in ?0..?9,
    do: parse_number(rest, pos)

  defp parse_value_at(_, pos, _depth), do: fail({:unexpected_byte, pos})

  defp enter(depth, pos) when depth >= @max_depth, do: fail({:too_deep, pos})
  defp enter(depth, _pos), do: depth + 1

  defp expect(input, pos, char) do
    case skip_ws(input, pos) do
      {<<^char, rest::binary>>, pos} -> {rest, pos + 1}
      {<<>>, pos} -> fail({:unexpected_end, pos})
      {_, pos} -> fail({:unexpected_byte, pos})
    end
  end

  defp parse_object(rest, open_pos, depth) do
    case skip_ws(rest, open_pos + 1) do
      {<<?}, rest::binary>>, pos} -> {%{}, rest, pos + 1}
      {rest, pos} -> parse_members(rest, pos, depth, %{})
    end
  end

  defp parse_members(input, pos, depth, acc) do
    {rest, key_pos} = skip_ws(input, pos)

    {key, rest, pos} =
      case rest do
        <<?", rest::binary>> -> parse_string(rest, key_pos + 1, [])
        <<>> -> fail({:unexpected_end, key_pos})
        _ -> fail({:unexpected_byte, key_pos})
      end

    if Map.has_key?(acc, key), do: fail({:duplicate_key, key, key_pos})

    {rest, pos} = expect(rest, pos, ?:)
    {value, rest, pos} = parse_value(rest, pos, depth)
    acc = Map.put(acc, key, value)

    case skip_ws(rest, pos) do
      {<<?,, rest::binary>>, pos} -> parse_members(rest, pos + 1, depth, acc)
      {<<?}, rest::binary>>, pos} -> {acc, rest, pos + 1}
      {<<>>, pos} -> fail({:unexpected_end, pos})
      {_, pos} -> fail({:unexpected_byte, pos})
    end
  end

  defp parse_array(rest, open_pos, depth) do
    case skip_ws(rest, open_pos + 1) do
      {<<?], rest::binary>>, pos} -> {[], rest, pos + 1}
      {rest, pos} -> parse_elements(rest, pos, depth, [])
    end
  end

  defp parse_elements(input, pos, depth, acc) do
    {value, rest, pos} = parse_value(input, pos, depth)
    acc = [value | acc]

    case skip_ws(rest, pos) do
      {<<?,, rest::binary>>, pos} -> parse_elements(rest, pos + 1, depth, acc)
      {<<?], rest::binary>>, pos} -> {Enum.reverse(acc), rest, pos + 1}
      {<<>>, pos} -> fail({:unexpected_end, pos})
      {_, pos} -> fail({:unexpected_byte, pos})
    end
  end

  # Hanya integer: -?(0|[1-9][0-9]*). Pecahan/eksponen -> :non_integer_number.
  # Leading zero dan -0 -> :invalid_number (bukan bentuk canonical).

  defp parse_number(input, start) do
    {sign, digits_input} =
      case input do
        <<?-, rest::binary>> -> {-1, rest}
        rest -> {1, rest}
      end

    {digits, rest} = take_digits(digits_input, [])
    check_digits(digits, sign, start)
    check_no_fraction(rest, start)

    consumed = byte_size(digits) + if(sign == -1, do: 1, else: 0)
    {sign * String.to_integer(digits), rest, start + consumed}
  end

  defp check_digits("", _sign, start), do: fail({:invalid_number, start})
  defp check_digits("0", -1, start), do: fail({:invalid_number, start})
  defp check_digits(<<?0, _, _::binary>>, _sign, start), do: fail({:invalid_number, start})
  defp check_digits(_digits, _sign, _start), do: :ok

  defp check_no_fraction(<<c, _::binary>>, start) when c in [?., ?e, ?E],
    do: fail({:non_integer_number, start})

  defp check_no_fraction(_rest, _start), do: :ok

  defp take_digits(<<c, rest::binary>>, acc) when c in ?0..?9, do: take_digits(rest, [c | acc])
  defp take_digits(rest, acc), do: {acc |> Enum.reverse() |> IO.iodata_to_binary(), rest}

  defp parse_string(<<?", rest::binary>>, pos, acc),
    do: {IO.iodata_to_binary(acc), rest, pos + 1}

  defp parse_string(<<?\\, rest::binary>>, pos, acc) do
    {char, rest, len} = parse_escape(rest, pos)
    parse_string(rest, pos + len, [acc, char])
  end

  defp parse_string(<<c, _::binary>>, pos, _acc) when c < 0x20,
    do: fail({:control_character, pos})

  defp parse_string(<<cp::utf8, rest::binary>>, pos, acc) do
    char = <<cp::utf8>>
    parse_string(rest, pos + byte_size(char), [acc, char])
  end

  defp parse_string(<<>>, pos, _acc), do: fail({:unexpected_end, pos})
  defp parse_string(_, pos, _acc), do: fail({:invalid_utf8, pos})

  # Mengembalikan {byte hasil, sisa masukan, panjang escape termasuk backslash}.
  defp parse_escape(<<c, rest::binary>>, _pos) when c in [?", ?\\, ?/], do: {<<c>>, rest, 2}
  defp parse_escape(<<?b, rest::binary>>, _pos), do: {"\b", rest, 2}
  defp parse_escape(<<?f, rest::binary>>, _pos), do: {"\f", rest, 2}
  defp parse_escape(<<?n, rest::binary>>, _pos), do: {"\n", rest, 2}
  defp parse_escape(<<?r, rest::binary>>, _pos), do: {"\r", rest, 2}
  defp parse_escape(<<?t, rest::binary>>, _pos), do: {"\t", rest, 2}

  defp parse_escape(<<?u, rest::binary>>, pos) do
    {cp, rest} = hex4(rest, pos)
    unicode_escape(cp, rest, pos)
  end

  defp parse_escape(<<>>, pos), do: fail({:unexpected_end, pos + 1})
  defp parse_escape(_, pos), do: fail({:invalid_escape, pos})

  defp unicode_escape(cp, <<?\\, ?u, low_rest::binary>>, pos) when cp in 0xD800..0xDBFF do
    {low, rest} = hex4(low_rest, pos)
    if low not in 0xDC00..0xDFFF, do: fail({:invalid_surrogate, pos})
    combined = 0x10000 + Bitwise.bsl(cp - 0xD800, 10) + (low - 0xDC00)
    {<<combined::utf8>>, rest, 12}
  end

  defp unicode_escape(cp, _rest, pos) when cp in 0xD800..0xDFFF,
    do: fail({:invalid_surrogate, pos})

  defp unicode_escape(cp, rest, _pos), do: {<<cp::utf8>>, rest, 6}

  defp hex4(<<a, b, c, d, rest::binary>>, pos) do
    {Enum.reduce([a, b, c, d], 0, &(&2 * 16 + hex_digit(&1, pos))), rest}
  end

  defp hex4(_, pos), do: fail({:invalid_escape, pos})

  defp hex_digit(c, _pos) when c in ?0..?9, do: c - ?0
  defp hex_digit(c, _pos) when c in ?a..?f, do: c - ?a + 10
  defp hex_digit(c, _pos) when c in ?A..?F, do: c - ?A + 10
  defp hex_digit(_, pos), do: fail({:invalid_escape, pos})

  @doc """
  Memeriksa bahwa `value` sesuai `schema`: semua field wajib ada, tidak ada field tambahan,
  dan tipe setiap nilai tepat. Boolean tidak diterima sebagai integer (dan sebaliknya).

  Kesalahan pertama yang ditemukan dikembalikan beserta path-nya. Field diperiksa dalam
  urutan skema, lalu field tambahan (urut abjad).

  ## Contoh

      iex> schema = {:object, [{"name", :string}, {"tags", {:array, :string}}]}
      iex> Nadina.StrictJSON.validate(%{"name" => "a", "tags" => ["x"]}, schema)
      :ok
      iex> Nadina.StrictJSON.validate(%{"name" => "a"}, schema)
      {:error, {:missing_field, ["tags"]}}
      iex> Nadina.StrictJSON.validate(%{"name" => "a", "tags" => [1]}, schema)
      {:error, {:wrong_type, ["tags", 0], :string}}
  """
  @spec validate(value(), schema()) :: :ok | {:error, validate_error()}
  def validate(value, schema) do
    check(value, schema, [])
  catch
    {__MODULE__, reason} -> {:error, reason}
  end

  defp check(v, :string, _path) when is_binary(v), do: :ok
  defp check(v, :integer, _path) when is_integer(v), do: :ok
  defp check(v, :boolean, _path) when is_boolean(v), do: :ok

  defp check(list, {:array, item}, path) when is_list(list) do
    list |> Enum.with_index() |> Enum.each(fn {v, i} -> check(v, item, path ++ [i]) end)
  end

  defp check(map, {:object, fields}, path) when is_map(map) do
    Enum.each(fields, fn {name, field_schema} ->
      case Map.fetch(map, name) do
        {:ok, v} -> check(v, field_schema, path ++ [name])
        :error -> fail({:missing_field, path ++ [name]})
      end
    end)

    names = Enum.map(fields, &elem(&1, 0))

    case map |> Map.keys() |> Enum.reject(&(&1 in names)) |> Enum.sort() do
      [] -> :ok
      [extra | _] -> fail({:unknown_field, path ++ [extra]})
    end
  end

  defp check(_v, schema, path), do: fail({:wrong_type, path, type_name(schema)})

  defp type_name({:array, _}), do: :array
  defp type_name({:object, _}), do: :object
  defp type_name(atom) when is_atom(atom), do: atom
end
