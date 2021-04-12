defmodule Univrse.SignatureTest do
  use ExUnit.Case, async: true
  alias Univrse.{Envelope, Header, Key, Signature}
  doctest Signature

  @header %Header{headers: %{"proto" => "test"}}
  @env %Envelope{header: @header, payload: "Hello world!"}
  @ec_str     "oWVwcm90b2R0ZXN0.bEhlbGxvIHdvcmxkIQ.gqFjYWxnZkVTMjU2S1hBH_D1cARfCqgwJC3CFUM_s1-FI8M8IVM7pB6K1S6Q-z6OH9UTlDyssAQ15NIfhd-_XGJN_UJPZZeRLfjBuSCXbYg"
  @oct_str_2  "oWVwcm90b2R0ZXN0.bEhlbGxvIHdvcmxkIQ.gqFjYWxnZUhTMjU2WCDzHu06NttxBEl_bF9W7OWFkCVPSZmLHBWZWg5o7YUNnQ"
  @oct_str_5  "oWVwcm90b2R0ZXN0.bEhlbGxvIHdvcmxkIQ.gqFjYWxnZUhTNTEyWECDg60rjMXJPUYvlz4I8pmcWdjBInk6-R7SMeXS9p9eWx-e4ld4ySpg5oK3XpiwFwMZ0xSdC1MBqLP0cWr5Yv68"

  @ec_key %Key{
    type: "EC",
    params: %{
      crv: "secp256k1",
      x: <<
        197, 214, 24, 161, 240, 252, 2, 55, 178, 103, 45, 132, 103, 111, 208,
        254, 110, 111, 91, 227, 69, 131, 238, 90, 79, 47, 112, 233, 251, 167, 92,
        91>>,
      y: <<125, 175, 246, 180, 252, 145, 14, 33, 255, 1, 93, 25, 3, 231, 199, 183,
        238, 187, 175, 87, 3, 207, 21, 129, 176, 124, 177, 195, 1, 162, 97, 140>>,
      d: <<
        88, 159, 176, 120, 175, 186, 246, 14, 81, 191, 103, 182, 27, 61, 106, 68,
        42, 32, 23, 42, 228, 54, 170, 109, 176, 120, 34, 196, 26, 223, 95, 201>>,
    }
  }
  @oct_key %Key{
    type: "oct",
    params: %{
      k: <<
        205, 34, 46, 245, 207, 202, 223, 84, 37, 48, 241, 120, 47, 215, 155, 254,
        126, 216, 64, 3, 216, 156, 121, 163, 203, 108, 215, 21, 51, 119, 38, 210>>
    }
  }


  describe "sign/3" do
    test "signs the envelope with the ES256K alg" do
      assert {:ok, %Envelope{signature: %Signature{}} = env} = Envelope.sign(@env, @ec_key, %{"alg" => "ES256K"})
      assert Envelope.encode(env, :base64) == @ec_str
    end

    test "signs the envelope with the HS256 alg" do
      assert {:ok, %Envelope{signature: %Signature{}} = env} = Envelope.sign(@env, @oct_key, %{"alg" => "HS256"})
      assert Envelope.encode(env, :base64) == @oct_str_2
    end

    test "signs the envelope with the HS512 alg" do
      assert {:ok, %Envelope{signature: %Signature{}} = env} = Envelope.sign(@env, @oct_key, %{"alg" => "HS512"})
      assert Envelope.encode(env, :base64) == @oct_str_5
    end

    test "signs the envelope twice" do
      assert {:ok, %Envelope{signature: signatures}} = Envelope.sign(@env, [@oct_key, @oct_key], %{"alg" => "HS256"})
      assert length(signatures) == 2
    end

    test "signs the envelope twice with key specific headers" do
      assert {:ok, %Envelope{signature: signatures}} = Envelope.sign(@env, [{@oct_key, %{"foo" => "a"}}, {@oct_key, %{"foo" => "b"}}], %{"alg" => "HS256"})
      assert length(signatures) == 2
      assert Enum.at(signatures, 0) |> Map.get(:header) |> Header.unwrap() |> Map.get("foo") == "a"
      assert Enum.at(signatures, 1) |> Map.get(:header) |> Header.unwrap() |> Map.get("foo") == "b"
    end

    test "returns error if alg not recognised" do
      assert {:error, "Unsupported algorithm: FOOBAR"} = Envelope.sign(@env, @ec_key, %{"alg" => "FOOBAR"})
    end

    test "returns error if key and alg mismatch" do
      assert {:error, "Invalid key for HS256 algorithm"} = Envelope.sign(@env, @ec_key, %{"alg" => "HS256"})
    end
  end


  describe "verify/4" do
    test "verifies the envelope signed with the ES256K alg" do
      {:ok, env} = Envelope.decode(@ec_str)
      assert Envelope.verify(env, @ec_key)
    end

    test "verifies the envelope signed with the HS256 alg" do
      {:ok, env} = Envelope.decode(@oct_str_2)
      assert Envelope.verify(env, @oct_key)
    end

    test "verifies the envelope signed with the HS512 alg" do
      {:ok, env} = Envelope.decode(@oct_str_5)
      assert Envelope.verify(env, @oct_key)
    end

    test "verifies the envelope signed twice with the HS512 alg" do
      {:ok, env} = Envelope.sign(@env, [@oct_key, @oct_key], %{"alg" => "HS256"})
      assert Envelope.verify(env, [@oct_key, @oct_key])
    end

    test "verifies the envelope signed twice with different keys" do
      {:ok, env} = Envelope.sign(@env, [{@ec_key, %{"alg" => "ES256K"}}, {@oct_key, %{"alg" => "HS256"}}])
      assert Envelope.verify(env, [@ec_key, @oct_key])
    end

    test "returns error if key and alg mismatch" do
      {:ok, env} = Envelope.decode(@oct_str_2)
      assert {:error, "Invalid key for HS256 algorithm"} = Envelope.verify(env, @ec_key)
    end
  end

end
