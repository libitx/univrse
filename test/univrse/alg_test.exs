defmodule Univrse.AlgTest do
  use ExUnit.Case, async: true
  alias Univrse.{Alg, Key}
  doctest Alg

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
        42, 32, 23, 42, 228, 54, 170, 109, 176, 120, 34, 196, 26, 223, 95, 201>>
    }
  }
  @oct_128_key %Key{
    type: "oct",
    params: %{
      k:  <<250, 126, 24, 75, 127, 133, 111, 142, 107, 4, 205, 10, 72, 61, 249, 0>>
    }
  }
  @oct_256_key %Key{
    type: "oct",
    params: %{
      k: <<
        205, 34, 46, 245, 207, 202, 223, 84, 37, 48, 241, 120, 47, 215, 155, 254,
        126, 216, 64, 3, 216, 156, 121, 163, 203, 108, 215, 21, 51, 119, 38, 210>>
    }
  }
  @oct_512_key %Key{
    type: "oct",
    params: %{
      k: <<
        102, 163, 155, 242, 130, 52, 132, 60, 80, 152, 205, 43, 218, 103, 174,
        176, 13, 26, 25, 171, 7, 111, 203, 111, 245, 169, 121, 187, 239, 14, 253,
        118, 200, 84, 18, 231, 163, 199, 5, 238, 136, 94, 127, 102, 35, 196, 126,
        240, 181, 37, 163, 121, 105, 110, 88, 70, 208, 248, 224, 10, 89, 209, 150,
        131>>
    }
  }

  @es256k_sig <<
    32, 16, 194, 9, 63, 13, 122, 78, 39, 16, 18, 139, 242, 58, 137, 10, 177, 213,
    48, 68, 143, 4, 146, 67, 196, 237, 227, 211, 93, 214, 113, 101, 170, 98, 109,
    159, 12, 228, 57, 187, 236, 185, 163, 90, 135, 218, 62, 80, 208, 157, 5, 141,
    228, 8, 215, 148, 101, 233, 242, 6, 62, 95, 8, 52, 198>>
  @hs256_sig <<
    26, 61, 97, 208, 153, 53, 69, 235, 105, 51, 91, 10, 56, 62, 201, 79, 109, 174,
    65, 171, 226, 37, 213, 101, 90, 172, 82, 13, 250, 134, 119, 91>>
  @hs512_sig <<
    244, 57, 145, 234, 205, 200, 237, 33, 242, 229, 58, 153, 175, 148, 159, 98,
    13, 87, 79, 255, 236, 232, 207, 142, 199, 197, 70, 51, 208, 175, 75, 242, 115,
    0, 206, 209, 63, 224, 209, 98, 51, 168, 166, 70, 115, 5, 9, 64, 150, 100, 147,
    117, 107, 221, 133, 24, 248, 206, 163, 216, 50, 93, 181, 184>>

  @gcm_iv <<254, 83, 226, 198, 180, 6, 208, 104, 179, 81, 188, 197>>
  @gcm128_enc <<34, 12, 62, 38, 218, 224, 165, 167, 186, 23, 67, 255>>
  @gcm256_enc <<122, 118, 227, 209, 232, 74, 73, 45, 24, 184, 7, 36>>


  describe "encrypt/4 and decrypt/4" do
    test "encrypts and decrypts the message with the A128CBC-HS256 alg" do
      assert {:ok, encrypted, %{"iv" => iv, "tag" => tag}} = Alg.encrypt("Hello world!", "A128CBC-HS256", @oct_256_key)
      assert {:ok, "Hello world!"} = Alg.decrypt(encrypted, "A128CBC-HS256", @oct_256_key, iv: iv, tag: tag)
    end

    test "encrypts and decrypts the message with the A256CBC-HS512 alg" do
      assert {:ok, encrypted, %{"iv" => iv, "tag" => tag}} = Alg.encrypt("Hello world!", "A256CBC-HS512", @oct_512_key)
      assert {:ok, "Hello world!"} = Alg.decrypt(encrypted, "A256CBC-HS512", @oct_512_key, iv: iv, tag: tag)
    end

    test "encrypts and decrypts the message with the A128GCM alg" do
      assert {:ok, encrypted, %{"iv" => iv, "tag" => tag}} = Alg.encrypt("Hello world!", "A128GCM", @oct_128_key)
      assert {:ok, "Hello world!"} = Alg.decrypt(encrypted, "A128GCM", @oct_128_key, iv: iv, tag: tag)
    end

    test "encrypts and decrypts the message with the A256GCM alg" do
      assert {:ok, encrypted, %{"iv" => iv, "tag" => tag}} = Alg.encrypt("Hello world!", "A256GCM", @oct_256_key)
      assert {:ok, "Hello world!"} = Alg.decrypt(encrypted, "A256GCM", @oct_256_key, iv: iv, tag: tag)
    end

    test "encrypts and decrypts the message with the ECDH-ES+A128GCM alg" do
      assert {:ok, encrypted, %{"iv" => iv, "epk" => epk, "tag" => tag}} = Alg.encrypt("Hello world!", "ECDH-ES+A128GCM", @ec_key)
      assert {:ok, "Hello world!"} = Alg.decrypt(encrypted, "ECDH-ES+A128GCM", @ec_key, iv: iv, epk: epk, tag: tag)
    end
  end


  describe "encrypt/4" do
    test "encrypts the message with the A128GCM alg and known iv" do
      assert {:ok, res, _headers} = Alg.encrypt("Hello world!", "A128GCM", @oct_128_key, iv: @gcm_iv)
      assert res == @gcm128_enc
    end

    test "encrypts the message with the A256GCM alg and known iv" do
      assert {:ok, res, _headers} = Alg.encrypt("Hello world!", "A256GCM", @oct_256_key, iv: @gcm_iv)
      assert res == @gcm256_enc
    end

    test "returns error if alg not recognised" do
      assert {:error, "Unsupported algorithm: FOOBAR"} = Alg.encrypt("Hello world!", "FOOBAR", @oct_256_key)
    end

    test "returns error if key and alg mismatch" do
      assert {:error, "Invalid key for A128CBC-HS256 algorithm"} = Alg.encrypt("Hello world!", "A128CBC-HS256", @oct_128_key)
    end
  end


  describe "sign/3" do
    test "signs the message with the ES256K alg" do
      assert {:ok, sig} = Alg.sign("Hello world!", "ES256K", @ec_key)
      assert sig == @es256k_sig
    end

    test "signs the message with the HS256 alg" do
      assert {:ok, sig} = Alg.sign("Hello world!", "HS256", @oct_256_key)
      assert sig == @hs256_sig
    end

    test "signs the message with the HS512 alg" do
      assert {:ok, sig} = Alg.sign("Hello world!", "HS512", @oct_256_key)
      assert sig == @hs512_sig
    end

    test "returns error if alg not recognised" do
      assert {:error, "Unsupported algorithm: FOOBAR"} = Alg.sign("Hello world!", "FOOBAR", @oct_256_key)
    end

    test "returns error if key and alg mismatch" do
      assert {:error, "Invalid key for ES256K algorithm"} = Alg.sign("Hello world!", "ES256K", @oct_256_key)
    end
  end


  describe "verify/4" do
    test "verifies the message signed with the ES256K alg" do
      assert Alg.verify("Hello world!", @es256k_sig, "ES256K", @ec_key)
    end

    test "verifies the message signed with the HS256 alg" do
      assert Alg.verify("Hello world!", @hs256_sig, "HS256", @oct_256_key)
    end

    test "verifies the message signed with the HS512 alg" do
      assert Alg.verify("Hello world!", @hs512_sig, "HS512", @oct_256_key)
    end

    test "returns error if alg not recognised" do
      assert {:error, "Unsupported algorithm: FOOBAR"} = Alg.verify("Hello world!", @hs256_sig, "FOOBAR", @oct_256_key)
    end

    test "returns error if key and alg mismatch" do
      assert {:error, "Invalid key for ES256K algorithm"} = Alg.verify("Hello world!", @hs256_sig, "ES256K", @oct_256_key)
    end
  end

end
