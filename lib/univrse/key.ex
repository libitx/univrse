defmodule Univrse.Key do
  @moduledoc """
  A Univrse Key is a CBOR data structure that represents a cryptographic key.
  Univrse Keys closely mirror JSON Web Keys, and it should prove simple to
  convert keys between the two specifications.

  Keys are used in the `t:Univrse.Signature.t/0` and `t:Univrse.Recipient.t/0`
  specifications.
  """
  alias Univrse.Recipient
  import Univrse.Util, only: [tag_binary: 1, untag: 1]

  defdelegate decrypt(env, key, opts \\ []), to: Recipient
  defdelegate encrypt(env, key, headers, opts \\ []), to: Recipient

  defstruct type: nil,
            params: %{}


  @typedoc "Key struct"
  @type t :: %__MODULE__{
    type: String.t,
    params: ec_params | oct_params
  }

  @typedoc "Elliptic curve key params"
  @type ec_params :: %{
    crv: String.t,
    x: binary,
    y: binary,
    d: binary
  } | %{
    crv: String.t,
    x: binary,
    y: binary
  }

  @typedoc "Octet sequence key params"
  @type oct_params :: %{
    k: binary
  }

  @typedoc "Key initialisation params"
  @type init_params :: {:ec, atom} | {:oct, integer}


  @doc """
  Decodes the given CBOR encoded key into a Key struct.
  """
  @spec decode(binary) :: {:ok, t} | {:error, any}
  def decode(data) when is_binary(data) do
    with {:ok, map, _rest} <- CBOR.decode(data) do
      %{"kty" => type} = params = untag(map)
      params = params
      |> Map.take(["crv", "x", "y", "d", "k"])
      |> Enum.reduce(%{}, fn {k, v}, p -> Map.put(p, String.to_atom(k), v) end)
      {:ok, %__MODULE__{type: type, params: params}}
    end
  end


  @doc """
  Encodes the Key as a CBOR encoded binary.
  """
  @spec encode(t) :: binary
  def encode(%__MODULE__{type: type, params: params}) do
    params
    |> Map.put(:kty, type)
    |> tag_binary()
    |> CBOR.encode()
  end


  @doc """
  Securely generates a new key of the given `t:init_params`.

  ## Supported key types

  * `{:ec, :secp256k1}` - Eliptic curve key on the `secp256k1` curve
  * `{:oct, 128}` - Octet sequence key of 128 bits
  * `{:oct, 256}` - Octet sequence key of 256 bits
  * `{:oct, 512}` - Octet sequence key of 512 bits
  """
  @spec generate_key(init_params | t) :: t
  def generate_key({:ec, :secp256k1}) do
    {pubkey, privkey} = :crypto.generate_key(:ecdh, :secp256k1)
    <<_::size(8), x::binary-size(32), y::binary-size(32)>> = pubkey
    params = %{
      crv: "secp256k1",
      x: x,
      y: y,
      d: privkey
    }
    %__MODULE__{type: "EC", params: params}
  end

  def generate_key({:oct, bits})
    when is_number(bits) and bits in [128, 256, 512]
  do
    params = %{
      k: :crypto.strong_rand_bytes(div(bits, 8))
    }
    %__MODULE__{type: "oct", params: params}
  end

  def generate_key(%__MODULE__{type: "EC", params: %{crv: "secp256k1"}}),
    do: generate_key({:ec, :secp256k1})
  def generate_key(%__MODULE__{type: "oct", params: %{k: k}}),
    do: generate_key({:oct, bit_size(k)})


  @doc """
  Returns a public key from the current key, which can be safely shared with
  other parties.

  Only for use with `EC` key types.
  """
  @spec to_public(t) :: t
  def to_public(%__MODULE__{type: "EC"} = key),
    do: update_in(key.params, & Map.take(&1, [:crv, :x, :y]))

end
