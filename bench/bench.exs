# Benchmark nadina (docs/plan.md bagian 6), dijalankan di dalam image lewat bench/run.sh.
# Env: BENCH_RUNS (30), BENCH_WARMUP (5), BENCH_KEYGEN (5), BENCH_OUT, NADINA_BIN.

defmodule Bench do
  alias Nadina.{Artifact, Bundle, Keys, Manifest, Profile, Trust}

  @algorithms ["rsa-pss-sha256", "ecdsa-p256-sha256", "ed25519"]
  @sizes [{"64KiB", 64 * 1024}, {"4MiB", 4 * 1024 * 1024}, {"64MiB", 64 * 1024 * 1024}]
  @package "anmategra"
  @version "1.0.0"

  def main do
    cfg = %{
      runs: env_int("BENCH_RUNS", 30),
      warmup: env_int("BENCH_WARMUP", 5),
      keygen: env_int("BENCH_KEYGEN", 5),
      out: System.get_env("BENCH_OUT", "docs/report/data/benchmark"),
      bin: System.get_env("NADINA_BIN", "/usr/local/bin/nadina"),
      work: Path.join(System.tmp_dir!(), "nadina-bench-#{System.unique_integer([:positive])}")
    }

    File.mkdir_p!(cfg.out)
    File.mkdir_p!(cfg.work)
    log("runs=#{cfg.runs} warmup=#{cfg.warmup} keygen=#{cfg.keygen} out=#{cfg.out}")

    try do
      artifacts = make_artifacts(cfg.work)
      keys = make_keys(cfg.work)
      trust = make_trust(cfg.work, keys)

      {keygen_rows, keygen_samples} = bench_keygen(cfg)
      {hash_rows, hash_samples} = bench_hash(cfg, artifacts)
      {sv_rows, sv_samples, size_rows} = bench_sign_verify(cfg, keys, artifacts)
      {e2e_rows, e2e_samples} = bench_e2e(cfg, keys, artifacts, trust)

      write_csv(cfg.out, "env.csv", ["key", "value"], env_rows(cfg))
      write_csv(cfg.out, "keygen.csv", ~w(algorithm n median_us min_us max_us), keygen_rows)

      write_csv(
        cfg.out,
        "hash.csv",
        ~w(size_label size_bytes n median_us p95_us throughput_mib_s),
        hash_rows
      )

      write_csv(cfg.out, "sign_verify.csv", ~w(algorithm op n median_us p95_us), sv_rows)

      write_csv(
        cfg.out,
        "e2e.csv",
        ~w(algorithm op size_label size_bytes n median_us p95_us),
        e2e_rows
      )

      write_csv(
        cfg.out,
        "sizes.csv",
        ~w(algorithm private_der public_der signature manifest bundle),
        size_rows
      )

      write_csv(
        cfg.out,
        "samples.csv",
        ~w(bench algorithm op size_label iter us),
        keygen_samples ++ hash_samples ++ sv_samples ++ e2e_samples
      )

      log("selesai, hasil di #{cfg.out}")
    after
      File.rm_rf!(cfg.work)
    end
  end

  # Isi acak supaya tidak ada efek kompresi.
  defp make_artifacts(dir) do
    for {label, size} <- @sizes do
      path = Path.join(dir, "artifact-#{label}.bin")

      File.open!(path, [:write, :binary, :raw], fn io ->
        write_random(io, size)
      end)

      {label, size, path}
    end
  end

  defp write_random(_io, 0), do: :ok

  defp write_random(io, left) do
    n = min(left, 1024 * 1024)
    :ok = :file.write(io, :crypto.strong_rand_bytes(n))
    write_random(io, left - n)
  end

  defp make_keys(dir) do
    for alg <- @algorithms, into: %{} do
      {:ok, mod, priv, pub} = Keys.generate(alg)
      prefix = Path.join(dir, alg)
      {:ok, keyid} = Keys.write_keypair(prefix, priv, pub)
      {alg, %{mod: mod, priv: priv, pub: pub, keyid: keyid, key_path: prefix <> ".key.pem"}}
    end
  end

  defp make_trust(dir, keys) do
    store =
      Enum.reduce(@algorithms, Trust.empty(), fn alg, acc ->
        %{mod: mod, pub: pub} = keys[alg]
        {:ok, acc, _} = Trust.add(acc, pub, mod, @package)
        acc
      end)

    path = Path.join(dir, "trust.json")
    :ok = Trust.save(path, store)
    path
  end

  defp bench_keygen(cfg) do
    results =
      for alg <- @algorithms do
        log("keygen #{alg}")
        {:ok, mod} = Profile.fetch(alg)
        xs = sample(cfg.warmup, cfg.keygen, fn -> mod.generate_key() end)
        row = [alg, length(xs), r(median(xs)), r(Enum.min(xs)), r(Enum.max(xs))]
        {row, samples("keygen", alg, "keygen", "-", xs)}
      end

    unzip(results)
  end

  defp bench_hash(cfg, artifacts) do
    results =
      for {label, size, path} <- artifacts do
        log("hash #{label}")
        xs = sample(cfg.warmup, cfg.runs, fn -> {:ok, ^size, _} = Artifact.digest(path) end)
        med = median(xs)
        mib_s = size / (1024 * 1024) / (med / 1_000_000)
        row = [label, size, length(xs), r(med), r(p95(xs)), r(mib_s)]
        {row, samples("hash", "-", "sha256", label, xs)}
      end

    unzip(results)
  end

  # Ukuran M hampir tidak bergantung pada artefak, jadi satu manifest cukup.
  defp bench_sign_verify(cfg, keys, artifacts) do
    {_label, _size, path} = List.last(artifacts)
    {:ok, size, sha256} = Artifact.digest(path)

    results =
      for alg <- @algorithms do
        %{mod: mod, priv: priv, pub: pub, keyid: keyid} = keys[alg]

        {:ok, manifest} =
          Manifest.new(@package, @version, alg, keyid, Path.basename(path), size, sha256)

        m = Manifest.serialize(manifest)
        sig = mod.sign(priv, m)
        true = mod.verify(pub, m, sig)

        log("sign/verify #{alg}")
        sign_xs = sample(cfg.warmup, cfg.runs, fn -> mod.sign(priv, m) end)
        verify_xs = sample(cfg.warmup, cfg.runs, fn -> true = mod.verify(pub, m, sig) end)

        bundle = Bundle.encode(%Bundle{manifest: m, signature: sig})

        sizes = [
          alg,
          der_size(Keys.encode_private_pem(priv)),
          der_size(Keys.encode_public_pem(pub)),
          byte_size(sig),
          byte_size(m),
          byte_size(bundle)
        ]

        rows = [
          [alg, "sign", length(sign_xs), r(median(sign_xs)), r(p95(sign_xs))],
          [alg, "verify", length(verify_xs), r(median(verify_xs)), r(p95(verify_xs))]
        ]

        smp =
          samples("sign_verify", alg, "sign", "-", sign_xs) ++
            samples("sign_verify", alg, "verify", "-", verify_xs)

        {rows, smp, sizes}
      end

    {Enum.flat_map(results, &elem(&1, 0)), Enum.flat_map(results, &elem(&1, 1)),
     Enum.map(results, &elem(&1, 2))}
  end

  defp bench_e2e(cfg, keys, artifacts, trust) do
    log("boot")
    boot_xs = sample(cfg.warmup, cfg.runs, fn -> run!(cfg.bin, ["--version"]) end)
    boot_row = ["-", "boot", "-", 0, length(boot_xs), r(median(boot_xs)), r(p95(boot_xs))]

    results =
      for alg <- @algorithms, {label, size, path} <- artifacts do
        log("e2e #{alg} #{label}")
        bundle = Path.join(cfg.work, "#{alg}-#{label}.bundle.json")

        sign_args =
          ["sign", "--file", path, "--package", @package, "--version", @version] ++
            ["--key", keys[alg].key_path, "--out", bundle]

        verify_args =
          ["verify", "--file", path, "--bundle", bundle, "--trust-store", trust] ++
            ["--package", @package, "--version", @version, "--json"]

        sign_xs = sample(cfg.warmup, cfg.runs, fn -> run!(cfg.bin, sign_args) end)
        verify_xs = sample(cfg.warmup, cfg.runs, fn -> run!(cfg.bin, verify_args) end)

        rows = [
          [alg, "sign", label, size, length(sign_xs), r(median(sign_xs)), r(p95(sign_xs))],
          [alg, "verify", label, size, length(verify_xs), r(median(verify_xs)), r(p95(verify_xs))]
        ]

        smp =
          samples("e2e", alg, "sign", label, sign_xs) ++
            samples("e2e", alg, "verify", label, verify_xs)

        {rows, smp}
      end

    {rows, smp} = unzip(results)
    {[boot_row | Enum.concat(rows)], samples("e2e", "-", "boot", "-", boot_xs) ++ smp}
  end

  defp run!(bin, args) do
    case System.cmd(bin, args, stderr_to_stdout: true) do
      {_, 0} -> :ok
      {out, code} -> raise "nadina #{hd(args)} exit #{code}: #{out}"
    end
  end

  defp sample(warmup, runs, fun) do
    for _ <- 1..warmup//1, do: fun.()
    for _ <- 1..runs//1, do: time_us(fun)
  end

  defp time_us(fun) do
    t0 = :erlang.monotonic_time()
    fun.()
    t1 = :erlang.monotonic_time()
    :erlang.convert_time_unit(t1 - t0, :native, :nanosecond) / 1000
  end

  defp median(xs) do
    s = Enum.sort(xs)
    n = length(s)
    mid = div(n, 2)
    if rem(n, 2) == 1, do: Enum.at(s, mid), else: (Enum.at(s, mid - 1) + Enum.at(s, mid)) / 2
  end

  # Nearest-rank: k = ceil(95 * n / 100) tanpa float.
  defp p95(xs) do
    s = Enum.sort(xs)
    k = div(95 * length(s) + 99, 100)
    Enum.at(s, k - 1)
  end

  defp samples(bench, alg, op, label, xs) do
    xs |> Enum.with_index(1) |> Enum.map(fn {x, i} -> [bench, alg, op, label, i, r(x)] end)
  end

  defp unzip(results) do
    {rows, smp} = Enum.unzip(results)
    {rows, Enum.concat(smp)}
  end

  defp r(x), do: Float.round(x / 1, 1)

  defp der_size(pem) do
    [{_type, der, :not_encrypted}] = :public_key.pem_decode(pem)
    byte_size(der)
  end

  defp env_rows(cfg) do
    {_, _, openssl} = :crypto.info_lib() |> hd()

    [
      ["date_utc", DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601()],
      ["git_commit", System.get_env("BENCH_GIT_COMMIT", "unknown")],
      ["host_os", System.get_env("BENCH_HOST_OS", "unknown")],
      ["container_os", os_release()],
      ["kernel", read_trim("/proc/sys/kernel/osrelease")],
      ["arch", :erlang.system_info(:system_architecture) |> to_string()],
      ["cpu_model", cpuinfo("model name")],
      ["logical_cpus", :erlang.system_info(:logical_processors_available) |> to_string()],
      ["mem_total", meminfo("MemTotal")],
      ["elixir", System.version()],
      ["otp", :erlang.system_info(:otp_release) |> to_string()],
      ["erts", :erlang.system_info(:version) |> to_string()],
      ["openssl", to_string(openssl)],
      ["nadina", Nadina.version()],
      ["runs", cfg.runs],
      ["warmup", cfg.warmup],
      ["keygen_pairs", cfg.keygen],
      ["artifact_sizes", Enum.map_join(@sizes, " ", fn {l, s} -> "#{l}=#{s}" end)]
    ]
  end

  defp os_release do
    case File.read("/etc/os-release") do
      {:ok, text} ->
        case Regex.run(~r/^PRETTY_NAME="?([^"\n]*)"?$/m, text) do
          [_, name] -> name
          _ -> "unknown"
        end

      _ ->
        "unknown"
    end
  end

  defp cpuinfo(field), do: proc_field("/proc/cpuinfo", field)
  defp meminfo(field), do: proc_field("/proc/meminfo", field)

  defp proc_field(path, field) do
    with {:ok, text} <- File.read(path),
         [_, value] <- Regex.run(~r/^#{field}\s*:\s*(.+)$/m, text) do
      String.trim(value)
    else
      _ -> "unknown"
    end
  end

  defp read_trim(path) do
    case File.read(path) do
      {:ok, text} -> String.trim(text)
      _ -> "unknown"
    end
  end

  defp write_csv(dir, name, header, rows) do
    body =
      Enum.map_join([header | rows], "", fn row -> Enum.map_join(row, ",", &cell/1) <> "\n" end)

    File.write!(Path.join(dir, name), body)
  end

  defp cell(v) when is_binary(v) do
    if String.contains?(v, [",", "\"", "\n"]),
      do: "\"" <> String.replace(v, "\"", "\"\"") <> "\"",
      else: v
  end

  defp cell(v), do: to_string(v)

  defp env_int(name, default) do
    case System.get_env(name) do
      nil -> default
      v -> String.to_integer(v)
    end
  end

  defp log(msg), do: IO.puts(:stderr, "[bench] " <> msg)
end

Bench.main()
