# Konfigurasi minimal. Selain yang tertulis di sini, credo memakai bawaannya.
%{
  configs: [
    %{
      name: "default",
      files: %{
        included: ["lib/", "test/", "bench/", "mix.exs"],
        excluded: []
      },
      strict: false
    }
  ]
}
