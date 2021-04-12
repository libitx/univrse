defmodule Univrse.Alg.AES_GCM do
  @moduledoc """
  AES_GCM algorithm module.

  Sign and encrypt messages using AES-GCM symetric encryption.
  """
  alias Univrse.Key


  @doc """
  Decrypts the cyphertext with the key using the specified algorithm.

  Accepted options:

  * `aad` - Ephemeral public key
  * `iv` - Agreement PartyUInfo
  * `tag` - Agreement PartyVInfo
  """
  @spec decrypt(String.t, binary, Key.t, keyword) :: {:ok, binary} | {:error, any}
  def decrypt(alg, encrypted, key, opts \\ [])

  def decrypt(alg, encrypted, %Key{type: "oct", params: %{k: k}}, opts)
    when (alg == "A128GCM" and byte_size(k) == 16)
    or (alg == "A256GCM" and byte_size(k) == 32)
  do
    aad = Keyword.get(opts, :aad, "")
    iv = Keyword.get(opts, :iv, "")
    tag = Keyword.get(opts, :tag, "")

    case :crypto.crypto_one_time_aead(cipher(alg), k, iv, encrypted, aad, tag, false) do
      result when is_binary(result) ->
        {:ok, result}
      {:error, _, error} ->
        {:error, error}
      :error ->
        {:error, "Decrypt error"}
    end
  end

  def decrypt(_alg, _encrypted, _key, _opts),
    do: {:error, :invalid_key}


  @doc """
  Encrypts the message with the key using the specified algorithm. Returns a
  three part tuple containing the encrypted cyphertext and any headers to add to
  the Recipient.

  Accepted options:

  * `aad` - Ephemeral public key
  * `iv` - Agreement PartyUInfo
  """
  @spec encrypt(String.t, binary, Key.t, keyword) :: {:ok, binary, map} | {:error, any}
  def encrypt(alg, message, key, opts \\ [])

  def encrypt(alg, message, %Key{type: "oct", params: %{k: k}}, opts)
    when (alg == "A128GCM" and byte_size(k) == 16)
    or (alg == "A256GCM" and byte_size(k) == 32)
  do
    aad = Keyword.get(opts, :aad, "")
    iv = Keyword.get(opts, :iv, :crypto.strong_rand_bytes(12))

    case :crypto.crypto_one_time_aead(cipher(alg), k, iv, message, aad, true) do
      {encrypted, tag} ->
        {:ok, encrypted, %{"iv" => iv, "tag" => tag}}
      {:error, _, error} ->
        {:error, error}
    end
  end

  def encrypt(_alg, _message, _key, _opts),
    do: {:error, :invalid_key}


  # Returns the cipher for the given algorithm
  defp cipher("A128GCM"), do: :aes_128_gcm
  defp cipher("A256GCM"), do: :aes_256_gcm

end
