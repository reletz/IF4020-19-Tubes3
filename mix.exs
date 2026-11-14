defmodule Nadina.MixProject do
  use Mix.Project

  def project do
    [
      app: :nadina,
      version: "0.1.0",
      elixir: "~> 1.20",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [extra_applications: [:logger, :crypto, :public_key]]
  end

  defp deps do
    []
  end
end
