defmodule Univrse.Util do
  @moduledoc """
  Utility module of commonly used shared helper functions.
  """

  @doc """
  Recursively iterrates over a value and tags any binary values prior to CBOR
  encoding.
  """
  @spec tag_binary(any) :: any
  def tag_binary(value) when is_binary(value) do
    case String.valid?(value) do
      true  -> value
      false -> %CBOR.Tag{tag: :bytes, value: value}
    end
  end

  def tag_binary(value) when is_map(value) do
    Enum.reduce value, %{}, fn {key, value}, result ->
      Map.put(result, tag_binary(key), tag_binary(value))
    end
  end

  def tag_binary([head | tail]), do: [tag_binary(head) | tag_binary(tail)]

  def tag_binary(value), do: value


  @doc """
  Recursively iterrates over a value and untags any binary values after CBOR
  decoding.
  """
  def untag(%CBOR.Tag{tag: _any, value: value}), do: value

  def untag(value) when is_map(value) do
    Enum.reduce value, %{}, fn {key, value}, result ->
      Map.put(result, untag(key), untag(value))
    end
  end

  def untag([head | tail]), do: [untag(head) | untag(tail)]

  def untag(value), do: value

end
