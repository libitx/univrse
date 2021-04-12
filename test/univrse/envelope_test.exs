defmodule Univrse.EnvelopeTest do
  use ExUnit.Case, async: true
  alias Univrse.{Envelope, Header, Key}
  doctest Envelope

  @header %Header{headers: %{"proto" => "test"}}
  @env1 %Envelope{header: @header, payload: "Hello world!"}
  @env2 %Envelope{header: @header, payload: %{"data" => "Hello world!"}}
  @bin1 <<130, 161, 101, 112, 114, 111, 116, 111, 100, 116, 101, 115, 116, 108, 72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 33>>
  @bin2 <<130, 161, 101, 112, 114, 111, 116, 111, 100, 116, 101, 115, 116, 161, 100, 100, 97, 116, 97, 108, 72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 33>>
  @str1 "oWVwcm90b2R0ZXN0.bEhlbGxvIHdvcmxkIQ"
  @str2 "oWVwcm90b2R0ZXN0.oWRkYXRhbEhlbGxvIHdvcmxkIQ"

  describe "decode/1" do
    test "automatically decodes the binary with the correct encoding" do
      assert {:ok, %Envelope{payload: "Hello world!"}} = Envelope.decode(@bin1)
      assert {:ok, %Envelope{payload: "Hello world!"}} = Envelope.decode(@str1)
    end
  end


  describe "decode/2" do
    test "decodes the CBOR binary to envelope struct" do
      assert {:ok, %Envelope{payload: "Hello world!"}} = Envelope.decode(@bin1, :cbor)
      assert {:ok, %Envelope{payload: %{"data" => "Hello world!"}}} = Envelope.decode(@bin2, :cbor)
    end

    test "decodes the Base64 string to envelope struct" do
      assert {:ok, %Envelope{payload: "Hello world!"}} = Envelope.decode(@str1, :base64)
      assert {:ok, %Envelope{payload: %{"data" => "Hello world!"}}} = Envelope.decode(@str2, :base64)
    end
  end


  describe "encode/2" do
    test "defaults to CBOR encoding" do
      assert Envelope.encode(@env1) == @bin1
    end

    test "encodes the envelope as a CBOR encoded binary" do
      assert Envelope.encode(@env1, :cbor) == @bin1
      assert Envelope.encode(@env2, :cbor) == @bin2
    end

    test "encodes the envelope as a Base64 encoded string" do
      assert Envelope.encode(@env1, :base64) == @str1
      assert Envelope.encode(@env2, :base64) == @str2
    end
  end


  describe "encode_payload/1" do
    test "returns the payload as CBOR encoded binary" do
      assert {:ok, "Hello world!", _} = Envelope.encode_payload(@env1) |> CBOR.decode()
      assert {:ok, %{"data" => "Hello world!"}, _} = Envelope.encode_payload(@env2) |> CBOR.decode()
    end
  end


  describe "decrypt_at/4" do
    setup do
      secret  = Key.generate_key({:oct, 256})
      sender  = Key.generate_key({:ec, :secp256k1})
      alice   = Key.generate_key({:ec, :secp256k1})
      bob     = Key.generate_key({:ec, :secp256k1})
      enc_keys = [
        {secret, %{"alg" => "A256GCM"}},
        Key.to_public(alice),
        Key.to_public(bob)
      ]
      env = %Univrse.Envelope{header: @header, payload: "this is a secret message"}
      assert {:ok, %Envelope{} = env} = Univrse.sign(env, sender, %{"alg" => "ES256K"})
      assert {:ok, %Envelope{recipient: recipients} = env} = Envelope.encrypt(env, enc_keys, %{"alg" => "ECDH-ES+A256GCM"})
      refute env.payload == "this is a secret message"
      assert length(recipients) == 3
      %{env: env, sender: Key.to_public(sender), alice: alice, bob: bob}
    end

    test "decrypts for each party at the given index", %{env: env, alice: alice, bob: bob} do
      assert {:ok, %Envelope{payload: "this is a secret message"}} = Envelope.decrypt_at(env, 1, alice)
      assert {:ok, %Envelope{payload: "this is a secret message"}} = Envelope.decrypt_at(env, 2, bob)
    end

    test "encodes and serializes in CBOR and decrypts for Alice", %{env: env, sender: sender, alice: alice} do
      assert {:ok, env} = Envelope.encode(env, :cbor) |> Envelope.decode()
      assert {:ok, %Envelope{payload: "this is a secret message"} = env} = Envelope.decrypt_at(env, 1, alice)
      assert Univrse.verify(env, sender)
    end

    test "encodes and serializes in Base64 and decrypts for Bob", %{env: env, sender: sender, bob: bob} do
      assert {:ok, env} = Envelope.encode(env, :base64) |> Envelope.decode()
      assert {:ok, %Envelope{payload: "this is a secret message"} = env} = Envelope.decrypt_at(env, 2, bob)
      assert Univrse.verify(env, sender)
    end
  end


  describe "parse_script/1" do
    test "parse the script to envelope struct" do
      s1 = Envelope.to_script(@env1)
      s2 = Envelope.to_script(@env2, false)
      assert {:ok, e1} = Envelope.parse_script(s1)
      assert {:ok, e2} = Envelope.parse_script(s2)
      assert e1 == @env1
      assert e2 == @env2
    end
  end


  describe "to_script/2" do
    test "encodes the envelope as a bitcoin op_return script" do
      assert %BSV.Script{chunks: [:OP_FALSE | _]} = s1 = Envelope.to_script(@env1)
      assert %BSV.Script{chunks: [:OP_RETURN | _]} = s2 = Envelope.to_script(@env2, false)
      assert length(s1.chunks) == 5
      assert length(s2.chunks) == 4
    end
  end


  describe "wrap/2" do
    test "wraps the given payload into an envelope" do
      assert %Envelope{payload: "Hello world!"} = Envelope.wrap("Hello world!")
    end

    test "wraps the given payload and headers into an envelope" do
      assert Envelope.wrap("Hello world!", %{"proto" => "test"}) == @env1
      assert Envelope.wrap("Hello world!", @header) == @env1
    end
  end

end
