defmodule Univrse.MixProject do
  use Mix.Project

  def project do
    [
      app: :univrse,
      version: "0.2.0",
      elixir: "~> 1.11",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      name: "Univrse",
      description: "A universal schema for serializing data objects, secured with signatures and encryption.",
      source_url: "https://github.com/libitx/univrse",
      docs: [
        main: "Univrse",
        groups_for_modules: [
          "Algorithms": [
            Univrse.Alg.AES_CBC_HMAC,
            Univrse.Alg.AES_GCM,
            Univrse.Alg.ECDH_AES,
            Univrse.Alg.ECIES_BIE1,
            Univrse.Alg.ES256K,
            Univrse.Alg.ES256K_BSM,
            Univrse.Alg.HMAC
          ]
        ]
      ],
      package: [
        name: "univrse",
        files: ~w(lib .formatter.exs mix.exs README.md LICENSE),
        licenses: ["Apache-2.0"],
        links: %{
          "GitHub" => "https://github.com/libitx/univrse"
        }
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:crypto, :logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:bsv, "~> 2.0"},
      {:cbor, "~> 1.0"},
      {:curvy, "~> 0.3"},
      {:ex_doc, "~> 0.26", only: :dev, runtime: false}
    ]
  end
end
