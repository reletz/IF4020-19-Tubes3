# Konfigurasi minimal. Selain yang tertulis di sini, credo memakai bawaannya.
%{
  configs: [
    %{
      name: "default",
      files: %{
        included: ["lib/", "test/", "bench/", "mix.exs"],
        excluded: []
      },
      strict: false,
      checks: %{
        extra: [
          # TODO di modul yang belum dikerjakan tetap dilaporkan, tetapi tidak
          # menggagalkan CI. Hapus override ini setelah semua modul selesai.
          {Credo.Check.Design.TagTODO, [exit_status: 0]}
        ]
      }
    }
  ]
}
