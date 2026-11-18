defmodule Nadina.MixProject do
  use Mix.Project

  def project do
    [
      app: :nadina,
      version: "0.1.0",
      elixir: "~> 1.20",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      releases: releases(),
      name: "Nadina",
      source_url: "https://github.com/reletz/IF4020-19-Tubes3",
      docs: docs(),
      dialyzer: dialyzer()
    ]
  end

  def application do
    [extra_applications: [:logger, :crypto, :public_key]]
  end

  # Release OTP untuk image container. Entry point CLI dipanggil lewat
  # bin/nadina eval, argumen diteruskan ke System.argv/0.
  defp releases do
    [nadina: [include_executables_for: [:unix], strip_beams: true]]
  end

  defp deps do
    [
      {:ex_doc, "~> 0.40", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:stream_data, "~> 1.1", only: [:dev, :test]}
    ]
  end

  defp dialyzer do
    [
      plt_add_apps: [:mix, :public_key, :crypto],
      plt_local_path: "priv/plts",
      plt_core_path: "priv/plts",
      flags: [:error_handling, :unknown]
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
