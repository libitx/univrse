defmodule Univrse.Alg.ECDH_AES do
  @moduledoc """
  ECDH_AES algorithm module.

  Implements ECDH-ES+AES_GCM encryption and decryption.
  https://tools.ietf.org/html/rfc7518#section-4.6
  """
  alias Univrse.Key
  alias Univrse.Alg.AES_GCM


  @doc """
  Decrypts the cyphertext with the key using the specified algorithm.

  Accepted options:

  * `epk` - Ephemeral public key
  * `apu` - Agreement PartyUInfo
  * `apv` - Agreement PartyVInfo
  * Any accepted AES_GCM options
  """
  @spec decrypt(String.t, binary, Key.t, keyword) :: {:ok, binary} | {:error, any}
  def decrypt(alg, encrypted, key, opts \\ [])

  def decrypt("ECDH-ES+A128GCM", encrypted, %Key{type: "EC", params: %{crv: "secp256k1", d: privkey}}, opts) do
    epk = Keyword.get(opts, :epk, "")

    secret = privkey
    |> Curvy.get_shared_secret(epk)
    |> concat_kdf(128, Keyword.put(opts, :alg, "ECDH-ES+A128GCM"))

    AES_GCM.decrypt("A128GCM", encrypted, %Key{type: "oct", params: %{k: secret}}, opts)
  end

  def decrypt("ECDH-ES+A256GCM", encrypted, %Key{type: "EC", params: %{crv: "secp256k1", d: privkey}}, opts) do
    epk = Keyword.get(opts, :epk, "")

    secret = privkey
    |> Curvy.get_shared_secret(epk)
    |> concat_kdf(256, Keyword.put(opts, :alg, "ECDH-ES+A256GCM"))

    AES_GCM.decrypt("A256GCM", encrypted, %Key{type: "oct", params: %{k: secret}}, opts)
  end

  def decrypt(_alg, _encrypted, _key, _opts),
    do: {:error, :invalid_key}


  @doc """
  Encrypts the message with the key using the specified algorithm. Returns a
  three part tuple containing the encrypted cyphertext and any headers to add to
  the Recipient.

  Accepted options:

  * `apu` - Agreement PartyUInfo
  * `apv` - Agreement PartyVInfo
  * Any accepted AES_GCM options
  """
  @spec encrypt(String.t, binary, Key.t, keyword) :: {:ok, binary, map} | {:error, any}
  def encrypt(alg, message, key, opts \\ [])

  def encrypt("ECDH-ES+A128GCM", message, %Key{type: "EC", params: %{crv: "secp256k1", x: <<x::big-size(256)>>, y: <<y::big-size(256)>>}}, opts) do
    ephemeral_key = Curvy.generate_key()
    pubkey = Curvy.Key.from_point(%Curvy.Point{x: x, y: y})

    secret = ephemeral_key
    |> Curvy.get_shared_secret(pubkey)
    |> concat_kdf(128, Keyword.put(opts, :alg, "ECDH-ES+A128GCM"))

    with {:ok, encrypted, headers} <- AES_GCM.encrypt("A128GCM", message, %Key{type: "oct", params: %{k: secret}}, opts) do
      epk = Curvy.Key.to_pubkey(ephemeral_key)
      {:ok, encrypted, Map.put(headers, "epk", epk)}
    end
  end

  def encrypt("ECDH-ES+A256GCM", message, %Key{type: "EC", params: %{crv: "secp256k1", x: <<x::big-size(256)>>, y: <<y::big-size(256)>>}}, opts) do
    ephemeral_key = Curvy.generate_key()
    pubkey = Curvy.Key.from_point(%Curvy.Point{x: x, y: y})

    secret = ephemeral_key
    |> Curvy.get_shared_secret(pubkey)
    |> concat_kdf(256, Keyword.put(opts, :alg, "ECDH-ES+A256GCM"))

    with {:ok, encrypted, headers} <- AES_GCM.encrypt("A256GCM", message, %Key{type: "oct", params: %{k: secret}}, opts) do
      epk = Curvy.Key.to_pubkey(ephemeral_key)
      {:ok, encrypted, Map.put(headers, "epk", epk)}
    end
  end

  def encrypt(_alg, _message, _key, _opts),
    do: {:error, :invalid_key}


  # Implements Concat KDF as defined in NIST.800-56A.
  defp concat_kdf(secret, keylen, opts) do
    alg = Keyword.get(opts, :alg, "")
    apu = Keyword.get(opts, :apu, "")
    apv = Keyword.get(opts, :apv, "")

    <<kdf::bits-size(keylen), _::binary>> = :crypto.hash(:sha256, <<
      secret::binary,
      keylen::big-size(32),
      byte_size(alg)::big-size(32), alg::binary,
      byte_size(apu)::big-size(32), apu::binary,
      byte_size(apv)::big-size(32), apv::binary,
      ""
    >>)
    kdf
  end

end
