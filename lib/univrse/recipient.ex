defmodule Univrse.Recipient do
  @moduledoc """
  Recipient module.
  """
  alias Univrse.{Alg, Envelope, Header, Key}
  import Univrse.Util, only: [tag_binary: 1]

  defstruct header: %Header{},
            key: nil

  @typedoc "Recipient struct"
  @type t :: %__MODULE__{
    header: Header.t,
    key: binary | Key.t | nil
  }


  @doc """
  Decrypts the Envelope or Recipient, using the given encryption key.

  If an Envelope is being decrypted and it contains multiple recipients, it is
  assumed the key belongs to the first recipient. Otherwise, see
  `Envelope.decrypt_at/4`.

  A keyword list of options can be given for the relevant encryption algorithm.
  """
  @spec decrypt(t | Envelope.t, Key.t, keyword) :: {:ok, t | Envelope.t} | {:error, any}
  def decrypt(envelope_or_recipient, key, opts \\ [])

  def decrypt(%__MODULE__{header: header, key: encrypted} = recipient, %Key{} = key, opts)
    when is_binary(encrypted)
  do
    alg = Map.get(header.headers, "alg")
    opts = header.headers
    |> Map.take(["epk", "iv", "tag"])
    |> Enum.map(fn {k, v} -> {String.to_atom(k), v} end)
    |> Keyword.merge(opts)

    recipient.key
    |> Alg.decrypt(alg, key, opts)
    |> case do
      {:ok, result} ->
        with {:ok, %Key{} = key} <- Key.decode(result) do
          {:ok, Map.put(recipient, :key, key)}
        end

      {:error, error} ->
        {:error, error}
    end
  end

  def decrypt(%Envelope{payload: payload, recipient: recipient} = env, %Key{} = key, opts)
    when is_binary(payload) and not is_nil(recipient)
  do
    # Get the first header if list of recipients
    header = case recipient do
      %__MODULE__{header: header, key: nil} -> header
      [%__MODULE__{header: header, key: nil} | _] -> header
    end

    alg = Map.get(header.headers, "alg")
    aad = CBOR.encode(["enc", env.header, Keyword.get(opts, :aad, "")])
    opts = header.headers
    |> Map.take(["epk", "iv", "tag"])
    |> Enum.map(fn {k, v} -> {String.to_atom(k), v} end)
    |> Keyword.merge(opts)
    |> Keyword.put(:aad, aad)

    env.payload
    |> Alg.decrypt(alg, key, opts)
    |> case do
      {:ok, payload} ->
        Envelope.decode_payload(env, payload)
      {:error, error} ->
        {:error, error}
    end
  end


  @doc """
  Encrypts the Envelope payload using the given key or list of keys.

  A map of headersmust be given including at least the encryption `alg` value.
  A keyword list of options can be given for the relevant encryption algorithm.

  Where a list of keys is given, the first key is taken as the content key and
  used to encrypt the payload. The content key is then encrypted by each
  subsequent key and included in the Recipient structs that are attached to the
  Envelope.

  When encrypting to multiple recipients, it is possible to specify different
  algorithms for each key by giving a list of tuple pairs. The first element of
  each pair is the key and the second is a map of headers.

  ## Examples

  Encrypts for a single recipient:

      Recipient.encrypt(env, aes_key, %{"alg" => "A128GCM"})

  Encrypts for a multiple recipients using the same algorithm:

      Recipient.encrypt(env, [aes_key, rec_key], %{"alg" => "A128GCM"})

  Encrypts for a multiple recipients using different algorithms:

      Recipient.encrypt(env, [
        aes_key,
        {rec1_key, %{"alg" => "ECDH-ES+A128GCM"}},
        {rec2_key, %{"alg" => "ECDH-ES+A128GCM"}}
      ], %{"alg" => "A128GCM"})
  """
  @spec encrypt(Envelope.t | Key.t, Key.t | list(Key.t) | list({Key.t, map}), map, keyword) ::
    {:ok, Envelope.t | t | list(t)} |
    {:error, any}

  def encrypt(envelope_or_key, key, headers, opts \\ [])

  def encrypt(%Envelope{} = env, [master | keys], headers, opts) do
    {mkey, mheaders} = merge_key_headers(master, headers)
    with {:ok, env} <- encrypt(env, mkey, mheaders, opts),
         {:ok, recipients} <- encrypt(mkey, keys, headers, opts)
    do
      env = Enum.reduce(recipients, env, & Envelope.push(&2, &1))
      {:ok, env}
    end
  end

  def encrypt(%Envelope{header: header} = env, %Key{} = key, %{"alg" => alg} = headers, opts) do
    aad = CBOR.encode(["enc", header, Keyword.get(opts, :aad, "")])
    opts = headers
    |> Map.take(["iv"])
    |> Enum.map(fn {k, v} -> {String.to_atom(k), v} end)
    |> Keyword.merge(opts)
    |> Keyword.put(:aad, aad)

    env
    |> Envelope.encode_payload()
    |> Alg.encrypt(alg, key, opts)
    |> case do
      {:ok, encrypted, new_headers} ->
        headers = Map.merge(headers, new_headers)
        recipient = wrap(nil, headers)
        env = env
        |> Map.put(:payload, encrypted)
        |> Envelope.push(recipient)
        {:ok, env}

      {:error, error} ->
        {:error, error}
    end
  end

  def encrypt(%Key{} = rkey, keys, headers, opts) when is_list(keys) do
    Enum.reduce_while(keys, [], fn key, result ->
      {key, headers} = merge_key_headers(key, headers)
      case encrypt(rkey, key, headers, opts) do
        {:ok, %__MODULE__{} = recipient} ->
          {:cont, [recipient | result]}
        {:error, error} ->
          {:halt, {:error, error}}
      end
    end)
    |> case do
      result when is_list(result) ->
        {:ok, Enum.reverse(result)}
      {:error, error} ->
        {:error, error}
    end
  end

  def encrypt(%Key{} = rkey, key, %{"alg" => alg} = headers, opts) do
    aad = Keyword.get(opts, :add, "")
    opts = headers
    |> Map.take(["iv"])
    |> Enum.map(fn {k, v} -> {String.to_atom(k), v} end)
    |> Keyword.merge(opts)
    |> Keyword.put(:aad, aad)

    rkey
    |> Key.encode()
    |> Alg.encrypt(alg, key, opts)
    |> case do
      {:ok, encrypted, new_headers} ->
        headers = Map.merge(headers, new_headers)
        recipient = wrap(encrypted, headers)
        {:ok, recipient}
      {:error, error} ->
        {:error, error}
    end
  end


  @doc """
  Wraps the given key and headers in a new Recipient struct.
  """
  @spec wrap(binary | nil, map | Header.t) :: t
  def wrap(key, headers \\ %{})
  def wrap(key, %Header{} = header),
    do: %__MODULE__{header: header, key: key}
  def wrap(key, %{} = headers),
    do: %__MODULE__{header: Header.wrap(headers), key: key}


  # Merges key headers with recipient headers
  defp merge_key_headers({key, key_headers}, headers),
    do: {key, Map.merge(headers, key_headers)}
  defp merge_key_headers(key, headers), do: {key, headers}


  defimpl CBOR.Encoder do
    alias Univrse.Recipient
    def encode_into(%Recipient{header: header, key: key}, acc) do
      CBOR.Encoder.encode_into([header, tag_binary(key)], acc)
    end
  end

end
