defmodule Univrse.Alg.HMAC do
  @moduledoc """
  HMAC algorithm module.

  Signs and verifies messages using hash-based message authentication.
  """
  alias Univrse.Key


  @doc """
  Signs the message with the key using the specified algorithm.
  """
  @spec sign(String.t, binary, Key.t) :: binary | {:error, any}
  def sign("HS256", message, %Key{type: "oct", params: %{k: k}}),
    do: :crypto.mac(:hmac, :sha256, k, message)

  def sign("HS512", message, %Key{type: "oct", params: %{k: k}}),
    do: :crypto.mac(:hmac, :sha512, k, message)

  def sign(_alg, _message, _key),
    do: {:error, :invalid_key}


  @doc """
  Verifies the signature with the message and key, using the specified algorithm.
  """
  @spec verify(String.t, binary, binary, Key.t) :: boolean | {:error, any}
  def verify("HS256", sig, message, %Key{type: "oct", params: %{k: k}}),
    do: :crypto.mac(:hmac, :sha256, k, message) == sig

  def verify("HS512", sig, message, %Key{type: "oct", params: %{k: k}}),
    do: :crypto.mac(:hmac, :sha512, k, message) == sig

  def verify(_alg, _sig, _message, _key),
    do: {:error, :invalid_key}

end
