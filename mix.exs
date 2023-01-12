defmodule Eddy.MixProject do
  use Mix.Project

  def project do
    [
      app: :eddy,
      version: "1.0.0",
      elixir: "~> 1.12",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      name: "Eddy",
      description: "Eddy is a pure Elixir implementation of Ed25519 for use in signature schemes and ECDH shared secrets.",
      source_url: "https://github.com/libitx/eddy",
      docs: [
        main: "Eddy"
      ],
      package: pkg(),
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:crypto]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:ex_doc, "~> 0.29", only: :dev, runtime: false}
    ]
  end

  defp pkg do
    [
      name: "eddy",
      files: ~w(lib .formatter.exs mix.exs README.md LICENSE),
      licenses: ["Apache-2.0"],
      links: %{
        "GitHub" => "https://github.com/libitx/eddy"
      }
    ]
  end
end
