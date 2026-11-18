defmodule Nadina.Property.SignVerifyTest do
  @moduledoc """
  Property test: untuk tiga profil, artefak, paket, versi, dan nama berkas sembarang yang
  sah, sign lalu verify selalu menghasilkan OK. Di level profil, tanda tangan atas pesan
  sembarang selalu sah dan panjangnya tetap, sedangkan pesan lain selalu ditolak.
  """
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Nadina.{Keys, Profile, Sign, Trust, Verify}

  @moduletag :tmp_dir
  @lower_digit Enum.concat(?a..?z, ?0..?9)
  @alnum Enum.concat([?a..?z, ?A..?Z, ?0..?9])

  # Satu pasangan kunci per profil (RSA 3072 lambat dibangkitkan).
  setup_all do
    keys =
      for name <- Profile.names(), into: %{} do
        {:ok, mod} = Profile.fetch(name)
        {priv, pub} = mod.generate_key()
        {name, %{mod: mod, priv: priv, pub: pub}}
      end

    %{keys: keys}
  end

  defp pattern(first, rest, max_rest) do
    gen all f <- member_of(first), r <- list_of(member_of(rest), max_length: max_rest) do
      List.to_string([f | r])
    end
  end

  defp release do
    gen all package <- pattern(@lower_digit, @lower_digit ++ ~c"._-", 63),
            version <- pattern(@alnum, @alnum ++ ~c"._+-", 63),
            name <- pattern(@alnum, @alnum ++ ~c"._-", 127),
            content <-
              one_of([binary(max_length: 64), binary(min_length: 4096, max_length: 70_000)]) do
      %{package: package, version: version, name: name, content: content}
    end
  end

  for profile <- ["rsa-pss-sha256", "ecdsa-p256-sha256", "ed25519"] do
    @profile profile

    property "#{profile}: sign lalu verify selalu OK", %{keys: keys, tmp_dir: tmp} do
      %{mod: mod, priv: priv, pub: pub} = keys[@profile]
      key_prefix = Path.join(tmp, "kunci")
      {:ok, _} = Keys.write_keypair(key_prefix, priv, pub)

      check all r <- release(), max_runs: 40 do
        dir = Path.join(tmp, "run-#{System.unique_integer([:positive])}")
        File.mkdir_p!(dir)
        file = Path.join(dir, r.name)
        File.write!(file, r.content)

        store = Path.join(dir, "trust.json")
        {:ok, entries, _} = Trust.add(Trust.empty(), pub, mod, r.package)
        :ok = Trust.save(store, entries)

        bundle = Path.join(dir, "rilis.bundle.json")

        assert {:ok, %{algorithm: @profile}} =
                 Sign.run(
                   file: file,
                   package: r.package,
                   version: r.version,
                   key: key_prefix <> ".key.pem",
                   out: bundle
                 )

        result =
          Verify.run(
            file: file,
            bundle: bundle,
            trust_store: store,
            package: r.package,
            version: r.version
          )

        assert %{status: :ok, valid: true, algorithm: @profile} = result
        assert Verify.exit_code(result) == 0
        File.rm_rf!(dir)
      end
    end

    property "#{profile}: tanda tangan atas pesan sembarang sah, pesan lain ditolak", %{
      keys: keys
    } do
      %{mod: mod, priv: priv, pub: pub} = keys[@profile]

      check all message <- binary(max_length: 2048),
                other <- binary(max_length: 2048),
                other != message,
                max_runs: 50 do
        signature = mod.sign(priv, message)
        assert byte_size(signature) == mod.signature_size()
        assert mod.verify(pub, message, signature)
        refute mod.verify(pub, other, signature)
      end
    end
  end
end
