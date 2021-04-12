defmodule Univrse.KeyTest do
  use ExUnit.Case, async: true
  alias Univrse.Key
  doctest Key

  @ec_key Key.generate_key({:ec, :secp256k1})
  @oct_key Key.generate_key({:oct, 256})


  describe "generate_key/1" do
    test "generate new key from EC key params" do
      assert %Key{type: "EC", params: params} = Key.generate_key({:ec, :secp256k1})
      assert %{crv: "secp256k1", d: <<_::size(256)>>, x: <<_::size(256)>>, y: <<_::size(256)>>} = params
    end

    test "generate new key from OCT key params" do
      assert %Key{type: "oct", params: %{k: <<_::binary-size(16)>>}} = Key.generate_key({:oct, 128})
      assert %Key{type: "oct", params: %{k: <<_::binary-size(32)>>}} = Key.generate_key({:oct, 256})
      assert %Key{type: "oct", params: %{k: <<_::binary-size(64)>>}} = Key.generate_key({:oct, 512})
    end

    test "generate new key from EC key" do
      assert %Key{type: "EC", params: params} = Key.generate_key(@ec_key)
      assert params.crv == @ec_key.params.crv
      refute params.x == @ec_key.params.x
      refute params.y == @ec_key.params.y
      refute params.d == @ec_key.params.d
    end

    test "generate new key from OCT key" do
      assert %Key{type: "oct", params: params} = Key.generate_key(@oct_key)
      refute params.k == @oct_key.params.k
    end
  end


  describe "encode/1 and decode/1" do
    test "encodes and decodes a EC key" do
      assert key = Key.encode(@ec_key)
      assert is_binary(key)
      assert {:ok, key} = Key.decode(key)
      assert key == @ec_key
    end

    test "encodes and decodes a OCT key" do
      assert key = Key.encode(@oct_key)
      assert is_binary(key)
      assert {:ok, key} = Key.decode(key)
      assert key == @oct_key
    end
  end


  describe "to_public/1" do
    test "converts EC key to public key" do
      assert %Key{type: "EC", params: params} = Key.to_public(@ec_key)
      assert params.crv == @ec_key.params.crv
      assert params.x == @ec_key.params.x
      assert params.y == @ec_key.params.y
      refute Map.has_key?(params, :d)
    end
  end
end
