defmodule Nadina.MixProject do
  use Mix.Project

  def project do
    [
      app: :nadina,
      version: "0.1.0",
      elixir: "~> 1.20",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      escript: escript(),
      name: "Nadina",
      source_url: "https://github.com/reletz/IF4020-19-Tubes3",
      docs: docs()
    ]
  end

  def application do
    [extra_applications: [:logger, :crypto, :public_key]]
  end

  # Entry point CLI. Nadina.CLI.main/1 menerima daftar argumen dan mengakhiri
  # proses dengan exit code asli lewat System.halt/1.
  defp escript do
    [main_module: Nadina.CLI, name: "nadina"]
  end

  defp deps do
    [
      {:ex_doc, "~> 0.40", only: :dev, runtime: false}
    ]
  end

  defp docs do
    [
      main: "Nadina",
      groups_for_modules: [
        Profil: [~r/^Nadina\.Profile/]
      ]
    ]
  end
end
