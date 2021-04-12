defmodule Univrse.Alg.AES_CBC_HMAC do
  @moduledoc """
  AES_CBC_HMAC algorithm module.

  Sign and encrypt messages using AES-CBC symetric encryption, with HMAC message
  authentication.
  https://tools.ietf.org/html/rfc7518#section-5.2.2
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
    when (alg == "A128CBC-HS256" and byte_size(k) == 32)
    or (alg == "A256CBC-HS512" and byte_size(k) == 64)
  do
    aad = Keyword.get(opts, :aad, "")
    iv = Keyword.get(opts, :iv, "")
    tag = Keyword.get(opts, :tag, "")

    keylen = div(byte_size(k), 2)
    <<m::binary-size(keylen), k::binary-size(keylen)>> = k
    macmsg = aad <> iv <> encrypted <> <<bit_size(aad)::big-size(64)>>

    with <<^tag::binary-size(keylen), _::binary>> <- :crypto.mac(:hmac, hash(alg), m, macmsg),
         result when is_binary(result) <- :crypto.crypto_one_time(cipher(alg), k, iv, encrypted, false)
    do
      case :binary.last(result) do
        pad when 0 < pad and pad < 16 ->
          {:ok, :binary.part(result, 0, byte_size(result) - pad)}
        _ ->
          {:ok, result}
      end
    else
      {:error, _, error} ->
        {:error, error}
      :error ->
        {:error, "Decrypt error"}
      macresult when is_binary(macresult) ->
        {:error, "HMAC validation failed"}
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
    when (alg == "A128CBC-HS256" and byte_size(k) == 32)
    or (alg == "A256CBC-HS512" and byte_size(k) == 64)
  do
    aad = Keyword.get(opts, :aad, "")
    iv = Keyword.get(opts, :iv, :crypto.strong_rand_bytes(16))

    keylen = div(byte_size(k), 2)
    <<m::binary-size(keylen), k::binary-size(keylen)>> = k
    message = pkcs7_pad(message)

    case :crypto.crypto_one_time(cipher(alg), k, iv, message, true) do
      encrypted when is_binary(encrypted) ->
        macmsg = aad <> iv <> encrypted <> <<bit_size(aad)::big-size(64)>>
        <<tag::binary-size(keylen), _::binary>> = :crypto.mac(:hmac, hash(alg), m, macmsg)
        {:ok, encrypted, %{"iv" => iv, "tag" => tag}}
      {:error, _, error} ->
        {:error, error}
    end
  end

  def encrypt(_alg, _message, _key, _opts),
    do: {:error, :invalid_key}


  # Returns the hash alg for the given algorithm
  defp hash("A128CBC-HS256"), do: :sha256
  defp hash("A256CBC-HS512"), do: :sha512

  # Returns the cipher for the given algorithm
  defp cipher("A128CBC-HS256"), do: :aes_128_cbc
  defp cipher("A256CBC-HS512"), do: :aes_256_cbc

  # Pads the message using PKCS7
  defp pkcs7_pad(message) do
    case rem(byte_size(message), 16) do
      0 -> message
      pad ->
        pad = 16 - pad
        message <> :binary.copy(<<pad>>, pad)
    end
  end

end
