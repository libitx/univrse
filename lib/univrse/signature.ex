defmodule Univrse.Signature do
  @moduledoc """
  A Univrse Signature is a structure attached to an `t:Univrse.Envelope.t/0`,
  containing a set of headers and a cryptographic signature (or MAC).

  An Envelope may contain one or multiple Signature structures.

  The Signature structure headers must contain an `alg` header and may contain a
  `kid` header, to help other parties understand what key and algorithm was used
  to generate the signature or MAC. Once understood, the observing party can
  verify the signature contained in the structure.
  """
  alias Univrse.{Alg, Envelope, Header, Key}
  import Univrse.Util, only: [tag_binary: 1]

  defstruct header: %Header{},
            signature: nil

  @typedoc "Signature struct"
  @type t :: %__MODULE__{
    header: Header.t,
    signature: binary
  }


  @doc """
  Signs the Envelope payload using the given key or array of keys.

  A map of headers must be given including at least the signature `alg` value.

  Where a list of keys is given, it is possible to specify different algorithms
  for each key by giving a list of tuple pairs. The first element of each pair
  is the key and the second is a map of headers.

  ## Examples

  Creates a signature using a single key:

      Signature.sign(env, oct_key, %{"alg" => "HS256"})

  Creates multiple signatures using the same algorithm:

      Signature.sign(env, [oct_key, app_key], %{"alg" => "HS256"})

  Creates multiple signatures using different algorithms:

      Signature.sign(env, [
        oct_key,
        {ec_key_1, %{"alg" => "ES256K"}},
        {ec_key_2, %{"alg" => "ES256K"}}
      ], %{"alg" => "HS256"})
  """
  @spec sign(Envelope.t, Key.t | list(Key.t) | list({Key.t, map}), map) :: {:ok, Envelope.t} | {:error, any}
  def sign(env, key, headers \\ %{})

  def sign(%Envelope{} = env, keys, headers) when is_list(keys) do
    Enum.reduce_while(keys, env, fn key, env ->
      {key, headers} = merge_key_headers(key, headers)
      case sign(env, key, headers) do
        {:ok, env} ->
          {:cont, env}
        {:error, error} ->
          {:halt, {:error, error}}
      end
    end)
    |> case do
      %Envelope{} = env ->
        {:ok, env}
      {:error, error} ->
        {:error, error}
    end
  end

  def sign(%Envelope{header: header, payload: payload} = env, %Key{} = key, headers)
    when is_map(headers)
  do
    alg = Map.merge(header.headers, headers) |> Map.get("alg")
    payload
    |> Envelope.wrap(header)
    |> Envelope.encode()
    |> Alg.sign(alg, key)
    |> case do
      {:ok, sig} ->
        signature = wrap(sig, headers)
        {:ok, Envelope.push(env, signature)}
      {:error, error} ->
        {:error, error}
    end
  end


  @doc """
  Verifies the Envelope signature(s) using the given Key or list of Keys.
  """
  @spec verify(Envelope.t, Key.t | list(Key.t)) :: boolean | {:error, String.t}
  def verify(%Envelope{header: header, payload: payload, signature: signatures}, keys)
    when is_list(signatures) and is_list(keys) and length(signatures) == length(keys)
  do
    n = length(keys) - 1
    Enum.reduce_while 0..n, true, fn i, _result ->
      signature = Enum.at(signatures, i)
      key = Enum.at(keys, i)

      payload
      |> Envelope.wrap(header)
      |> Envelope.push(signature)
      |> verify(key)
      |> case do
        true -> {:cont, true}
        result -> {:halt, result}
      end
    end
  end

  def verify(%Envelope{header: h1, payload: payload, signature: %__MODULE__{header: h2, signature: sig}}, %Key{} = key) do
    alg = Map.merge(h1.headers, h2.headers) |> Map.get("alg")
    payload
    |> Envelope.wrap(h1)
    |> Envelope.encode()
    |> Alg.verify(sig, alg, key)
  end


  @doc """
  Wraps the given signature and headers in a new Signature struct.
  """
  @spec wrap(binary, map | Header.t) :: t
  def wrap(sig, headers \\ %{})
  def wrap(sig, %Header{} = header),
    do: %__MODULE__{header: header, signature: sig}
  def wrap(sig, %{} = headers),
    do: %__MODULE__{header: Header.wrap(headers), signature: sig}


  # Merges key headers with signature headers
  defp merge_key_headers({key, key_headers}, headers),
    do: {key, Map.merge(headers, key_headers)}
  defp merge_key_headers(key, headers), do: {key, headers}


  defimpl CBOR.Encoder do
    alias Univrse.Signature
    def encode_into(%Signature{header: header, signature: signature}, acc) do
      CBOR.Encoder.encode_into([header, tag_binary(signature)], acc)
    end
  end

end
