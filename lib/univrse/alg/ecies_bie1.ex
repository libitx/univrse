defmodule Univrse.Alg.ECIES_BIE1 do
  @moduledoc """
  ECIES_BIE1 algorithm module.

  Implements Electrum-flavoured ECIES encryption and decryption.
  """
  require Integer
  alias Univrse.Key


  @doc """
  Decrypts the cyphertext with the key using the specified algorithm.
  """
  @spec decrypt(String.t, binary, Key.t, keyword) :: {:ok, binary} | {:error, any}
  def decrypt(alg, encrypted, key, opts \\ [])

  def decrypt("ECIES-BIE1", encrypted, %Key{type: "EC", params: %{crv: "secp256k1"}} = key, _opts) do
    len = byte_size(encrypted) - 69
    <<
      "BIE1",                         # magic bytes
      ephemeral_pubkey::binary-33,    # ephermeral pubkey
      ciphertext::binary-size(len),   # ciphertext
      mac::binary-32                  # mac hash
    >> = encrypted

    # Derive ECDH key and sha512 hash to get iv, enc_key and mac_key
    ephemeral_key = Curvy.Key.from_pubkey(ephemeral_pubkey)
    <<
      iv::binary-16,
      enc_key::binary-16,
      mac_key::binary-32
    >> = :crypto.hash(:sha512, compute_shared_secret(key, ephemeral_key))

    # Mac validation and decryption
    with ^mac <- :crypto.mac(:hmac, :sha256, mac_key, "BIE1" <> ephemeral_pubkey <> ciphertext),
         result when is_binary(result) <- :crypto.crypto_one_time(:aes_128_cbc, enc_key, iv, ciphertext, false)
    do
      {:ok, pkcs7_unpad(result)}
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
  """
  @spec encrypt(String.t, binary, Key.t, keyword) :: {:ok, binary, map} | {:error, any}
  def encrypt(alg, message, key, opts \\ [])

  def encrypt("ECIES-BIE1", message, %Key{type: "EC", params: %{crv: "secp256k1"}} = key, _opts) do
    # Generate ephemeral keypair
    ephemeral_key = Key.generate_key({:ec, :secp256k1})

    # Derive ECDH key and sha512 hash to get iv, enc_key and mac_key
    <<
      iv::binary-16,
      enc_key::binary-16,
      mac_key::binary-32
    >> = :crypto.hash(:sha512, compute_shared_secret(ephemeral_key, key))

    # Create ciphertext
    case :crypto.crypto_one_time(:aes_128_cbc, enc_key, iv, pkcs7_pad(message), true) do
      ciphertext when is_binary(ciphertext) ->
        # Concat encrypted data with hmac
        ephemeral_pubkey = ephemeral_key.params.d
        |> Curvy.Key.from_privkey()
        |> Curvy.Key.to_pubkey()
        result = "BIE1" <> ephemeral_pubkey <> ciphertext
        mac = :crypto.mac(:hmac, :sha256, mac_key, result)
        {:ok, result <> mac, %{}}

      {:error, _, error} ->
        {:error, error}
    end
  end

  def encrypt(_alg, _message, _key, _opts),
    do: {:error, :invalid_key}


  # TODO
  defp compute_shared_secret(%Key{} = key, %Curvy.Key{point: %{x: x, y: y}}),
    do: compute_shared_secret(key, %Key{type: "EC", params: %{crv: "secp256k1", x: <<x::big-size(256)>>, y: <<y::big-size(256)>>}})

  defp compute_shared_secret(%Key{params: %{d: <<d::big-size(256)>>}}, %Key{params: %{x: <<x::big-size(256)>>, y: <<y::big-size(256)>>}}) do
    %Curvy.Point{x: x, y: y}
    |> Curvy.Point.mul(d)
    |> case do
      %{x: x, y: y} when Integer.is_odd(y) ->
        <<0x03, x::big-size(256)>>
      %{x: x} ->
        <<0x02, x::big-size(256)>>
    end
  end

  # Pads the message using PKCS7
  defp pkcs7_pad(message) do
    case rem(byte_size(message), 16) do
      0 -> message
      pad ->
        pad = 16 - pad
        message <> :binary.copy(<<pad>>, pad)
    end
  end

  # Unpads the message using PKCS7
  defp pkcs7_unpad(message) do
    case :binary.last(message) do
      pad when 0 < pad and pad < 16 ->
        :binary.part(message, 0, byte_size(message) - pad)
      _ ->
        message
    end
  end

end
