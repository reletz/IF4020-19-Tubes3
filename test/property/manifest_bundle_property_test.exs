defmodule Nadina.Property.ManifestBundleTest do
  @moduledoc """
  Property test serialisasi canonical manifest dan bundle.

  Manifest: setiap manifest sah lolos round trip new, serialize, parse tanpa perubahan,
  dan setiap bentuk lain dari byte yang sama (white space, urutan field, tipe salah,
  field tambahan) ditolak. Bundle: round trip encode lalu parse untuk byte sembarang,
  white space dan urutan field tidak mengubah hasil, dan Base64 yang tidak canonical
  ditolak.
  """
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Nadina.{Bundle, Manifest}

  @lower_digit Enum.concat(?a..?z, ?0..?9)
  @alnum Enum.concat([?a..?z, ?A..?Z, ?0..?9])
  @max_artifact_size 9_007_199_254_740_991
  @ws [" ", "\t", "\n", "\r"]

  # String dengan karakter pertama dari first dan sisanya dari rest (pola regex Tabel 2.3).
  defp pattern(first, rest, max_rest) do
    gen all f <- member_of(first), r <- list_of(member_of(rest), max_length: max_rest) do
      List.to_string([f | r])
    end
  end

  # Permutasi 0..n-1, dibangkitkan StreamData supaya bisa diulang dengan seed yang sama.
  # Caranya: indeks diurutkan menurut kunci acak (stabil bila kunci sama).
  defp permutation(n) do
    map(list_of(integer(), length: n), fn keys ->
      keys |> Enum.with_index() |> Enum.sort_by(&elem(&1, 0)) |> Enum.map(&elem(&1, 1))
    end)
  end

  defp hex64, do: map(binary(length: 32), &Base.encode16(&1, case: :lower))

  defp manifest do
    gen all package <- pattern(@lower_digit, @lower_digit ++ ~c"._-", 63),
            version <- pattern(@alnum, @alnum ++ ~c"._+-", 63),
            algorithm <- member_of(Manifest.algorithms()),
            keyid <- hex64(),
            name <- pattern(@alnum, @alnum ++ ~c"._-", 127),
            size <-
              one_of([
                member_of([0, @max_artifact_size]),
                integer(0..1_000_000),
                integer(0..@max_artifact_size)
              ]),
            sha256 <- hex64() do
      {:ok, m} = Manifest.new(package, version, algorithm, keyid, name, size, sha256)
      m
    end
  end

  # Pasangan field manifest dalam urutan canonical, nilai sudah dalam teks JSON.
  defp manifest_pairs(m) do
    artifact =
      ~s({"name":"#{m.artifact_name}","size":#{m.artifact_size},"sha256":"#{m.artifact_sha256}"})

    [
      {"schema", ~s("minisign-manifest/v1")},
      {"package", ~s("#{m.package}")},
      {"version", ~s("#{m.version}")},
      {"algorithm", ~s("#{m.algorithm}")},
      {"keyid", ~s("#{m.keyid}")},
      {"artifact", artifact}
    ]
  end

  defp object(pairs),
    do: "{" <> Enum.map_join(pairs, ",", fn {k, v} -> ~s("#{k}":#{v}) end) <> "}"

  defp insert_at(bin, pos, s),
    do: binary_part(bin, 0, pos) <> s <> binary_part(bin, pos, byte_size(bin) - pos)

  describe "manifest" do
    property "round trip: parse(serialize(m)) mengembalikan m dan byte yang sama" do
      check all m <- manifest() do
        bytes = Manifest.serialize(m)
        assert byte_size(bytes) <= Manifest.max_size()
        assert Manifest.parse(bytes) == {:ok, m}
        assert bytes == object(manifest_pairs(m))
      end
    end

    property "white space di antara token ditolak sebagai not_canonical" do
      check all m <- manifest(),
                bytes = Manifest.serialize(m),
                # nilai field tidak memuat { : , sehingga posisi ini selalu antar-token
                positions =
                  for({i, 1} <- :binary.matches(bytes, ["{", ":", ","]), do: i + 1),
                pos <- member_of([0, byte_size(bytes) | positions]),
                ws <- map(list_of(member_of(@ws), min_length: 1, max_length: 3), &Enum.join/1) do
        assert Manifest.parse(insert_at(bytes, pos, ws)) == {:error, :not_canonical}
      end
    end

    property "urutan field selain urutan canonical ditolak" do
      check all m <- manifest(),
                pairs = manifest_pairs(m),
                order <- permutation(6),
                shuffled = Enum.map(order, &Enum.at(pairs, &1)),
                shuffled != pairs do
        assert Manifest.parse(object(shuffled)) == {:error, :not_canonical}
      end
    end

    property "boolean atau pecahan di posisi size ditolak" do
      check all m <- manifest(),
                bad <- member_of(["true", "false", "#{m.artifact_size}.0", "1e3"]) do
        bytes =
          String.replace(
            Manifest.serialize(m),
            ~s("size":#{m.artifact_size}),
            ~s("size":#{bad})
          )

        if bad in ["true", "false"] do
          assert Manifest.parse(bytes) == {:error, {:wrong_type, ["artifact", "size"], :integer}}
        else
          assert {:error, {:non_integer_number, _}} = Manifest.parse(bytes)
        end
      end
    end

    property "field tambahan ditolak sebagai unknown_field" do
      known = ~w(schema package version algorithm keyid artifact)

      check all m <- manifest(),
                key <- pattern(Enum.to_list(?a..?z), Enum.to_list(?a..?z), 10),
                key not in known,
                value <- member_of([~s("x"), "1", "true", "[]", "{}"]),
                pos <- integer(0..6) do
        pairs = List.insert_at(manifest_pairs(m), pos, {key, value})
        assert Manifest.parse(object(pairs)) == {:error, {:unknown_field, [key]}}
      end
    end
  end

  describe "bundle" do
    property "round trip: parse(encode(b)) mengembalikan byte manifest dan tanda tangan" do
      check all manifest <- binary(max_length: 4096), signature <- binary(max_length: 512) do
        b = %Bundle{manifest: manifest, signature: signature}
        encoded = Bundle.encode(b)
        assert byte_size(encoded) <= Bundle.max_size()
        assert Bundle.parse(encoded) == {:ok, b}
      end
    end

    property "white space dan urutan field tidak mengubah isi bundle" do
      check all manifest <- binary(max_length: 1024),
                signature <- binary(max_length: 512),
                order <- permutation(3),
                gaps <-
                  list_of(map(list_of(member_of(@ws), max_length: 2), &Enum.join/1), length: 8) do
        fields = [
          {"schema", ~s("minisign-bundle/v1")},
          {"manifest_b64", ~s("#{Base.encode64(manifest)}")},
          {"signature_b64", ~s("#{Base.encode64(signature)}")}
        ]

        [g0, g1, g2, g3, g4, g5, g6, g7] = gaps

        body =
          order
          |> Enum.map(&Enum.at(fields, &1))
          |> Enum.map_join(g1 <> "," <> g2, fn {k, v} -> ~s("#{k}") <> g3 <> ":" <> g4 <> v end)

        json = g0 <> "{" <> g5 <> body <> g6 <> "}" <> g7
        assert Bundle.parse(json) == {:ok, %Bundle{manifest: manifest, signature: signature}}
      end
    end

    property "Base64 dengan bit padding tidak nol ditolak" do
      alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

      check all signature <- binary(min_length: 1, max_length: 200),
                rem(byte_size(signature), 3) != 0,
                # sisa 1 byte: 4 bit terakhir karakter kedua dari akhir, sisa 2 byte: 2 bit
                mask = if(rem(byte_size(signature), 3) == 1, do: 15, else: 3),
                delta <- integer(1..mask) do
        b64 = Base.encode64(signature)
        [_, last_data] = Regex.run(~r/([^=])=+\z/, b64)
        {idx, 1} = :binary.match(alphabet, last_data)
        pos = byte_size(String.trim_trailing(b64, "=")) - 1

        tampered =
          binary_part(b64, 0, pos) <>
            binary_part(alphabet, idx + delta, 1) <>
            binary_part(b64, pos + 1, byte_size(b64) - pos - 1)

        json =
          ~s({"schema":"minisign-bundle/v1","manifest_b64":"","signature_b64":"#{tampered}"})

        assert Bundle.parse(json) == {:error, {:invalid_base64, ["signature_b64"]}}
      end
    end

    property "Base64 tanpa padding ditolak" do
      check all manifest <- binary(min_length: 1, max_length: 200),
                rem(byte_size(manifest), 3) != 0 do
        unpadded = Base.encode64(manifest, padding: false)

        json =
          ~s({"schema":"minisign-bundle/v1","manifest_b64":"#{unpadded}","signature_b64":""})

        assert Bundle.parse(json) == {:error, {:invalid_base64, ["manifest_b64"]}}
      end
    end
  end
end
