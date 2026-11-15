defmodule Nadina.MixProject do
  use Mix.Project

  def project do
    [
      app: :nadina,
      version: "0.1.0",
      elixir: "~> 1.20",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      escript: escript()
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
    []
  end
end
