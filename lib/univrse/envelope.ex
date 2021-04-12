defmodule Univrse.Envelope do
  @moduledoc """
  TODO
  """
  alias Univrse.{Header, Key, Signature, Recipient}
  import Univrse.Util, only: [tag_binary: 1, untag: 1]


  defdelegate decrypt(env, key, opts \\ []), to: Recipient
  defdelegate encrypt(env, key, headers, opts \\ []), to: Recipient
  defdelegate sign(env, key, headers \\ %{}), to: Signature
  defdelegate verify(env, key), to: Signature


  defstruct header: %Header{},
            payload: nil,
            signature: nil,
            recipient: nil


  @typedoc "Envelope struct"
  @type t :: %__MODULE__{
    header: Header.t,
    payload: any,
    signature: Signature.t | list(Signature.t) | nil,
    recipient: nil
  }

  @typedoc "Envelope encoding"
  @type encoding :: :cbor | :base64

  @base64regex ~r/^([a-zA-Z0-9_-]+\.?){2,4}$/
  @univrse_prefix "UNIV"


  @doc """
  Decodes the given binary into an Envelope structure.

  Automatically detects the correct encoding from the binary, assuming it is
  a supported `t:encoding()`.
  """
  @spec decode(binary) :: {:ok, t} | {:error, any}
  def decode(binary) do
    case Regex.match?(@base64regex, binary) do
      true -> decode(binary, :base64)
      false -> decode(binary, :cbor)
    end
  end


  @doc """
  Decodes the given binary into an Envelope structure, using the specified
  `t:encoding()`.
  """
  @spec decode(binary, encoding) :: {:ok, t} | {:error, any}
  def decode(data, :cbor) when is_binary(data) do
    with {:ok, parts, _rest} <- CBOR.decode(data) do
      env = parts
      |> untag()
      |> from_list()
      {:ok, env}
    end
  end

  def decode(data, :base64) when is_binary(data) do
    parts = String.split(data, ".")

    with {:ok, parts} <- b64_decode_all(parts),
         {:ok, parts} <- cbor_decode_all(parts)
    do
      env = parts
      |> untag()
      |> from_list()
      {:ok, env}
    end
  end


  @doc """
  Decodes the given CBOR encoded payload and puts it in the envelope struct.
  """
  @spec decode_payload(t, binary) :: {:ok, t} | {:error, any}
  def decode_payload(%__MODULE__{} = env, payload) do
    with {:ok, payload, _rest} <- CBOR.decode(payload) do
      {:ok, Map.put(env, :payload, payload)}
    end
  end


  @doc """
  Decrypts the envelope payload by first decrypting the content key for the
  recipient at the specified index with the given key.

  The envelope must contain multiple recipients.
  """
  @spec decrypt_at(t, integer, Key.t, keyword) :: {:ok, t} | {:error, any}
  def decrypt_at(env, idx, key, opts \\ [])

  def decrypt_at(%__MODULE__{recipient: recipients} = env, idx, %Key{} = key, opts)
    when is_list(recipients)
    and is_integer(idx)
    and idx < length(recipients)
  do
    recipient = Enum.at(recipients, idx)
    with {:ok, %Recipient{key: key}} <- decrypt(recipient, key, opts) do
      decrypt(env, key, opts)
    end
  end

  def decrypt_at(%__MODULE__{}, _idx, %Key{}, _opts),
    do: {:error, "Invalid recipient index"}


  @doc """
  Decodes the Envelope into a binary using the specified `t:encoding()`.

  Default encoding is `:cbor`.
  """
  @spec encode(t, encoding) :: binary | String.t
  def encode(env, encoding \\ :cbor)

  def encode(%__MODULE__{} = env, :cbor) do
    env
    |> Map.update!(:payload, &tag_binary/1)
    |> to_list()
    |> CBOR.encode()
  end

  def encode(%__MODULE__{} = env, :base64) do
    env
    |> Map.update!(:payload, &tag_binary/1)
    |> to_list
    |> Enum.map(&CBOR.encode/1)
    |> Enum.map(& Base.url_encode64(&1, padding: false))
    |> Enum.join(".")
  end


  @doc """
  CBOR encodes the Envelope payload and returns the encoded binary.
  """
  @spec encode_payload(t) :: binary
  def encode_payload(%__MODULE__{payload: payload}) do
    payload
    |> tag_binary()
    |> CBOR.encode()
  end


  @doc """
  Parses the given Bitcoin Script and returns an Envelope structure.
  """
  @spec parse_script(BSV.Script.t) :: {:ok, t} | {:error, any}
  def parse_script(%BSV.Script{chunks: chunks}) do
    with [_ | _] = parts <- slice_univrse_op_return(chunks),
         {:ok, parts} <- cbor_decode_all(parts)
    do
      env = parts
      |> untag()
      |> from_list()
      {:ok, env}
    else
      _ ->
        {:error, "Invalid Univrse script"}
    end
  end


  @doc """
  Pushes the given `t:Signature.t` or `t:Recipient.t` into the Envelope.
  """
  @spec push(t, Signature.t | Recipient.t) :: t
  def push(%__MODULE__{} = env, %Signature{} = signature) do
    case env.signature do
      nil ->
        Map.put(env, :signature, signature)
      %Signature{} ->
        update_in(env.signature, & [&1, signature])
      sigs when is_list(sigs) ->
        update_in(env.signature, & &1 ++ [signature])
    end
  end

  def push(%__MODULE__{} = env, %Recipient{} = recipient) do
    case env.recipient do
      nil ->
        Map.put(env, :recipient, recipient)
      %Recipient{} ->
        update_in(env.recipient, & [&1, recipient])
      recipients when is_list(recipients) ->
        update_in(env.recipient, & &1 ++ [recipient])
    end
  end


  @doc """
  Encodes the envelope into a valid Univrse OP_RETURN script and returns the
  script.
  """
  @spec to_script(t, boolean) :: BSV.Script.t
  def to_script(env, false_return \\ true)

  def to_script(%__MODULE__{} = env, true) do
    env
    |> to_script(false)
    |> Map.update!(:chunks, & [:OP_FALSE | &1])
  end

  def to_script(%__MODULE__{} = env, false) do
    chunks = env
    |> to_list()
    |> Enum.map(&CBOR.encode/1)

    %BSV.Script{chunks: [:OP_RETURN, @univrse_prefix | chunks]}
  end


  @doc """
  Wraps the given payload and headers in a new Envelope structure.
  """
  @spec wrap(any, map | Header.t) :: t
  def wrap(payload, headers \\ %{})
  def wrap(payload, %Header{} = header),
    do: %__MODULE__{header: header, payload: payload}
  def wrap(payload, %{} = headers),
    do: %__MODULE__{header: Header.wrap(headers), payload: payload}


  # Converts the given list of elements to a Envelope struct.
  defp from_list([header, payload]),
    do: %__MODULE__{header: Header.wrap(header), payload: payload}

  defp from_list([header, payload, signature]),
    do: from_list([header, payload]) |> Map.put(:signature, decode_signature(signature))

  defp from_list([header, payload, signature, recipient]),
    do: from_list([header, payload, signature]) |> Map.put(:recipient, decode_recipient(recipient))


  # Decodes the signatures
  defp decode_signature([headers, sig]) when is_map(headers) and is_binary(sig),
    do: Signature.wrap(sig, headers)

  defp decode_signature(signatures) when is_list(signatures),
    do: Enum.map(signatures, &decode_signature/1)

  defp decode_signature(nil), do: nil


  # Decodes the recipients
  defp decode_recipient([headers, cek]) when is_map(headers),
    do: Recipient.wrap(cek, headers)

  defp decode_recipient(signatures) when is_list(signatures),
    do: Enum.map(signatures, &decode_recipient/1)

  defp decode_recipient(nil), do: nil


  # Converts the envelope to a list of elements prior to encoding.
  defp to_list(%__MODULE__{signature: nil, recipient: nil} = env),
    do: [env.header, env.payload]

  defp to_list(%__MODULE__{signature: signature, recipient: nil} = env)
    when not is_nil(signature),
    do: [env.header, env.payload, signature]

  defp to_list(%__MODULE__{signature: signature, recipient: recipient} = env)
    when not is_nil(recipient),
    do: [env.header, env.payload, signature, recipient]


  # Base64 decodes all parts
  defp b64_decode_all(parts, result \\ [])

  defp b64_decode_all([head | tail], result) do
    with {:ok, data} <- Base.url_decode64(head, padding: false) do
      b64_decode_all(tail, [data | result])
    end
  end

  defp b64_decode_all([], result), do: {:ok, Enum.reverse(result)}


  # CBOR decodes all parts
  defp cbor_decode_all(parts, result \\ [])

  defp cbor_decode_all([head | tail], result) do
    with {:ok, data, ""} <- CBOR.decode(head) do
      cbor_decode_all(tail, [data | result])
    end
  end

  defp cbor_decode_all([], result), do: {:ok, Enum.reverse(result)}


  # Slices the script chunks to return the envelope elements priro to decoding
  defp slice_univrse_op_return([]), do: []
  defp slice_univrse_op_return([:OP_RETURN, @univrse_prefix | chunks]), do: chunks
  defp slice_univrse_op_return([_ | chunks]), do: slice_univrse_op_return(chunks)


end
