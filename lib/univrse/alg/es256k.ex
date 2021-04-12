defmodule Univrse.Alg.ES256K do
  @moduledoc """
  ES256K algorithm module.

  Signs and verifies messages using ECDSA signatures on the secp256k1 curve.
  """
  alias Univrse.Key


  @doc """
  Signs the message with the key using the specified algorithm.
  """
  @spec sign(String.t, binary, Key.t) :: binary | {:error, any}
  def sign("ES256K", message, %Key{type: "EC", params: %{crv: "secp256k1", d: d}}),
    do: Curvy.sign(message, d, compact: true)

  def sign(_alg, _message, _key),
    do: {:error, :invalid_key}


  @doc """
  Verifies the signature with the message and key, using the specified algorithm.
  """
  @spec verify(String.t, binary, binary, Key.t) :: boolean | {:error, any}
  def verify("ES256K", sig, message, %Key{type: "EC", params: %{crv: "secp256k1", x: <<x::big-size(256)>>, y: <<y::big-size(256)>>}}) do
    pubkey = Curvy.Key.from_point(%Curvy.Point{x: x, y: y})
    case Curvy.verify(sig, message, pubkey) do
      :error -> {:error, "Ivalid signature"}
      result -> result
    end
  end

  def verify(_alg, _sig, _message, _key),
    do: {:error, :invalid_key}

end
