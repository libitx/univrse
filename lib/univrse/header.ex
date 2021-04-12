defmodule Univrse.Header do
  @moduledoc """
  Header module.

  A Universe Header is simply an map of arbitrary key-value pairs. Headers
  can be found in the `t:Univrse.Envelope.t`, `t:Univrse.Signature.t` and
  `t:Univrse.Recipient.t` structs.

  Known header parameters include:

  * `alg` - Signature or encryption algorithm (Signature, Recipient)
  * `crit` - An array of critical headers (Envelope)
  * `cty` - Content type (Envelope)
  * `iv` - Initialisation vector (Recipient)
  * `kid` - Key identifier (Signature, Recipient)
  * `proto` - Protocol identifier (Envelope)
  * `zip` - Compression algorithm (Envelope)
  """
  import Univrse.Util, only: [tag_binary: 1]

  defstruct headers: %{}

  @typedoc """
  Header struct.

  A simple wrapper around a map of key-value pairs.
  """
  @type t :: %__MODULE__{
    headers: map
  }


  @doc """
  Wraps the given map of headers in a Header struct.
  """
  @spec wrap(map) :: t
  def wrap(headers), do: %__MODULE__{headers: headers}


  @doc """
  Unwraps the Header struct and returns the map of headers.
  """
  @spec unwrap(t) :: map
  def unwrap(%__MODULE__{headers: headers}), do: headers


  defimpl CBOR.Encoder do
    alias Univrse.Header
    def encode_into(%Header{headers: headers}, acc) do
      headers
      |> tag_binary()
      |> CBOR.Encoder.encode_into(acc)
    end
  end

end
