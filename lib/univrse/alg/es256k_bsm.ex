defmodule Univrse.Alg.ES256K_BSM do
  @moduledoc """
  ES256K algorithm module.

  Signs and verifies messages using ECDSA signatures on the secp256k1 curve.
  """
  alias Univrse.Key


  @doc """
  Signs the message with the key using the specified algorithm.
  """
  @spec sign(String.t, binary, Key.t) :: binary | {:error, any}
  def sign("ES256K-BSM", message, %Key{type: "EC", params: %{crv: "secp256k1", d: d}}) do
    message
    |> message_digest()
    |> Curvy.sign(d, hash: false, compact: true)
  end

  def sign(_alg, _message, _key),
    do: {:error, :invalid_key}


  @doc """
  Verifies the signature with the message and key, using the specified algorithm.
  """
  @spec verify(String.t, binary, binary, Key.t) :: boolean | {:error, any}
  def verify("ES256K-BSM", sig, message, %Key{type: "EC", params: %{crv: "secp256k1", x: <<x::big-size(256)>>, y: <<y::big-size(256)>>}}) do
    pubkey = Curvy.Key.from_point(%Curvy.Point{x: x, y: y})
    case Curvy.verify(sig, message_digest(message), pubkey, hash: false) do
      :error -> {:error, "Ivalid signature"}
      result -> result
    end
  end

  def verify(_alg, _sig, _message, _key),
    do: {:error, :invalid_key}


  # Returns a digest of the given message using the Bitcoin Signed Message algo
  defp message_digest(msg) do
    prefix = "Bitcoin Signed Message:\n"
    BSV.Crypto.Hash.sha256_sha256(<<
      BSV.Util.VarBin.serialize_bin(prefix)::binary,
      BSV.Util.VarBin.serialize_bin(msg)::binary
    >>)
  end

end
