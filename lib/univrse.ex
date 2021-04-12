defmodule Univrse do
  @moduledoc """
  Documentation for `Univrse`.

  TODO
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
