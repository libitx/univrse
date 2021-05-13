defmodule Univrse do
  @moduledoc """
  ![Univrse](https://github.com/libitx/univrse/raw/master/media/poster.png)

  ![License](https://img.shields.io/github/license/libitx/univrse?color=informational)

  Univrse is a universal schema for serializing data objects, secured with
  signatures and encryption.

  * **Serialising data** - Simple, binary-friendly data exchange using the Concise Binary Object Representation (CBOR) data format.
  * **Authenticating data** - Protect integrity of data with digital signatures or message authentication code (MAC) algorithms.
  * **Securing data** - Ensure confidentiality and integrity of data for one or multiple recipients, using standardised authenticated encryption algorithms.

  ## Installation

  The package can be installed by adding `univrse` to your list of dependencies
  in `mix.exs`.

  ```elixir
  def deps do
    [
      {:manic, "~> #{ Mix.Project.config[:version] }"}
    ]
  end
  ```

  ## Usage

  For full documentation, please refer to:

  * [univrse.network docs](https://univrse.network/docs)
  * [univrse API docs](https://hexdocs.pm/univrse)

  ### 1. Serialising data

  Any arbitrary payload can be wrapped in a `t:Univrse.Envelope.t/0` structure,
  and then encoded in one of three serialisation formats, using
  `Univrse.Envelope.encode/2` and `Univrse.Envelope.to_script/2`

  * `:cbor` - Concise CBOR-encoded binary value
  * `:base64` - Compact Base64-url encoded string value
  * `:script` - Encoded in a Bitcoin `OP_RETURN` script

  ```elixir
  # Wrap any arbitrary data payload in an Envelope structure
  iex> payload = "Hello world!"
  iex> env = Univrse.wrap(payload, %{proto: "univrse.demo"})

  # Encode the data in one of three serialisation formats
  iex> env_cbor = Univrse.encode(env, :cbor)
  iex> env_base64 = Univrse.encode(env, :base64)
  iex> env_script = Univrse.Envelope.to_script(env)

  # Decode the serialised data back into an Envelope structure
  iex> {:ok, env2} = Univrse.decode(env_cbor)
  iex> {:ok, env3} = Univrse.decode(env_base64)
  iex> {:ok, env4} = Univrse.Envelope.parse_script(env_script)

  # Compare payload
  iex> env2.payload == payload and env3.payload == payload and env4.payload == payload
  true
  ```

  ### 2. Using signatures

  Digital signatures or message authentication code (MAC) algorithms can be used
  to protect the integrity of an Envelope's data payload.

  ```elixir
  # Generate keys
  iex> alice_key = Univrse.Key.generate_key({:ec, :secp256k1})
  iex> alice_pubkey = Univrse.Key.to_public(alice_key)
  iex> app_secret = Univrse.Key.generate_key({:oct, 256})

  # Sign and verify using a single key
  iex> {:ok, env1} = "Hello world!"
  ...> |> Univrse.wrap(%{proto: "univrse.demo"})
  ...> |> Univrse.sign(alice_key, %{"alg" => "ES256K", "kid" => "alice"})

  iex> Univrse.verify(env1, alice_pubkey)
  true

  # Sign and verify using multiple keys and algorithms
  iex> {:ok, env2} = "Hello world!"
  ...> |> Univrse.wrap(%{proto: "univrse.demo"})
  ...> |> Univrse.sign([
  ...>      {alice_key, %{"alg" => "ES256K", "kid" => "alice"}},
  ...>      {app_secret, %{"alg" => "HS256", "kid" => "app"}}
  ...> ])

  iex> Univrse.verify(env2, [alice_pubkey, app_secret])
  true
  ```

  ### 3. Using encryption

  Authenticated encryption algorithms may be used to ensure the confidentiality
  of an Envelope's data payload for one or multiple recipients.

  ```elixir
  # Generate keys
  iex> bob_key = Univrse.Key.generate_key({:ec, :secp256k1})
  iex> bob_pubkey = Univrse.Key.to_public(bob_key)
  iex> charlie_key = Univrse.Key.generate_key({:ec, :secp256k1})
  iex> charlie_pubkey = Univrse.Key.to_public(charlie_key)
  iex> app_secret = Univrse.Key.generate_key({:oct, 256})

  # Encrypt and decrypt data for a single recipient
  iex> {:ok, env1} = "Hello world!"
  ...> |> Univrse.wrap(%{proto: "univrse.demo"})
  ...> |> Univrse.encrypt(bob_pubkey, %{"alg" => "ECDH-ES+A128GCM", "kid" => "bob"})

  iex> {:ok, env1} = Univrse.decrypt(env1, bob_key)
  iex> env1.payload
  "Hello world!"

  # Encrypt and decrypt data for multiple recipients using multiple algorithms
  iex> {:ok, env2} = "Hello world!"
  ...> |> Univrse.wrap(%{proto: "univrse.demo"})
  ...> |> Univrse.encrypt([
  ...>      {app_secret, %{"alg" => "A256GCM"}},
  ...>      {bob_pubkey, %{"alg" => "ECDH-ES+A128GCM", "kid" => "bob"}},
  ...>      {charlie_pubkey, %{"alg" => "ECDH-ES+A128GCM", "kid" => "charlie"}}
  ...> ])

  iex> {:ok, bob_env} = Univrse.Envelope.decrypt_at(env2, 1, bob_key)
  iex> bob_env.payload
  "Hello world!"

  iex> {:ok, charlie_env} = Univrse.Envelope.decrypt_at(env2, 2, charlie_key)
  iex> charlie_env.payload
  "Hello world!"
  ```
  """
  alias Univrse.{Envelope, Recipient, Signature}

  defdelegate decode(env), to: Envelope
  defdelegate decode(env, encoding), to: Envelope
  defdelegate encode(env, encoding \\ :cbor), to: Envelope
  defdelegate wrap(payload, headers \\ %{}), to: Envelope

  defdelegate decrypt(env, key, opts \\ []), to: Recipient
  defdelegate encrypt(env, key, headers, opts \\ []), to: Recipient

  defdelegate sign(env, key, headers \\ %{}), to: Signature
  defdelegate verify(env, key), to: Signature

end
