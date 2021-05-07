defmodule Univrse.Alg do
  @moduledoc """
  Proxy module for calling crypto functions on supported algorithms.

  ## Supported algorithms

  * `A128CBC-HS256`
  * `A256CBC-HS512`
  * `A128GCM`
  * `A256GCM`
  * `ECDH-ES+A128GCM`
  * `ECDH-ES+A256GCM`
  * `ES256K`
  * `HS256`
  * `HS512`
  """
  alias __MODULE__.AES_CBC_HMAC
  alias __MODULE__.AES_GCM
  alias __MODULE__.ECDH_AES
  alias __MODULE__.ES256K
  alias __MODULE__.ES256K_BSM
  alias __MODULE__.HMAC

  @alg_modules %{
    "A128CBC-HS256"   => AES_CBC_HMAC,
    "A256CBC-HS512"   => AES_CBC_HMAC,
    "A128GCM"         => AES_GCM,
    "A256GCM"         => AES_GCM,
    "ECDH-ES+A128GCM" => ECDH_AES,
    "ECDH-ES+A256GCM" => ECDH_AES,
    "ES256K"          => ES256K,
    "ES256K-BSM"      => ES256K_BSM,
    "HS256"           => HMAC,
    "HS512"           => HMAC
  }

  @algs Map.keys(@alg_modules)


  @doc """
  Calls the function with the given arguments on the specified algorithm module.
  """
  @spec call(binary, atom, list) :: any | {:error, any}
  def call(alg, func, args \\ [])

  def call(alg, func, args) when alg in @algs do
    case apply(@alg_modules[alg], func, [alg | args]) do
      {:error, :invalid_key} ->
        {:error, "Invalid key for #{alg} algorithm"}
      {:error, error} ->
        {:error, error}
      result ->
        result
    end
  end

  def call(alg, _func, _args), do: {:error, "Unsupported algorithm: #{alg}"}


  @doc """
  Calls `decrypt()` on the given algorithm, passing the arguments through.
  """
  @spec decrypt(binary, binary, Key.t, keyword) :: {:ok, binary} | {:error, any}
  def decrypt(encrypted, alg, key, opts \\ []) do
    call(alg, :decrypt, [encrypted, key, opts])
  end


  @doc """
  Calls `encrypt()` on the given algorithm, passing the arguments through.
  """
  @spec encrypt(binary, binary, Key.t, keyword) :: {:ok, binary, map} | {:error, any}
  def encrypt(message, alg, key, opts \\ []) do
    call(alg, :encrypt, [message, key, opts])
  end


  @doc """
  Calls `sign()` on the given algorithm, passing the arguments through.
  """
  @spec sign(binary, binary, Key.t) :: {:ok, binary} | {:error, any}
  def sign(message, alg, key) do
    case call(alg, :sign, [message, key]) do
      sig when is_binary(sig) ->
        {:ok, sig}
      {:error, error} ->
        {:error, error}
    end
  end


  @doc """
  Calls `verify()` on the given algorithm, passing the arguments through.
  """
  @spec verify(binary, binary, binary, Key.t) :: boolean | {:error, any}
  def verify(message, sig, alg, key) do
    call(alg, :verify, [sig, message, key])
  end

end
