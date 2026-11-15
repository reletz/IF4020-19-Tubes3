# Tes interop memakai openssl sebagai alat uji (bukan bagian program).
# Bila openssl tidak ada, tes bertag :interop dilewati.
exclude = if System.find_executable("openssl"), do: [], else: [:interop]

ExUnit.start(exclude: exclude)
