defmodule Univrse.RecipientTest do
  use ExUnit.Case, async: true
  alias Univrse.{Envelope, Header, Key, Recipient}
  doctest Recipient


  @header %Header{headers: %{"proto" => "test"}}
  @env %Envelope{header: @header, payload: "Hello world!"}
  @aead256str "oWVwcm90b2R0ZXN0.TfJ3p_l8QhO45YETV7E.9g.gqNjYWxnZ0EyNTZHQ01iaXZMh9vFGKa1ZO7VuC7jY3RhZ1DwrPseCoOkmNJZES_P7_1q9g"

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

  describe "encrypt/4 envelope" do
    test "encrypts the envelope with the A128CBC-HS256 alg" do
      assert {:ok, %Envelope{recipient: %Recipient{}} = env} = Recipient.encrypt(@env, @oct_256_key, %{"alg" => "A128CBC-HS256"})
      assert env.payload != "Hello world!"
    end

    test "encrypts the envelope with the A256GCM alg" do
      assert {:ok, %Envelope{recipient: %Recipient{}} = env} = Recipient.encrypt(@env, @oct_256_key, %{"alg" => "A256GCM"})
      assert env.payload != "Hello world!"
    end

    test "encrypts the envelope with the A256GCM alg and given IV" do
      iv = <<135, 219, 197, 24, 166, 181, 100, 238, 213, 184, 46, 227>>
      assert {:ok, %Envelope{recipient: %Recipient{}} = env} = Recipient.encrypt(@env, @oct_256_key, %{"alg" => "A256GCM", "iv" => iv})
      assert Envelope.encode(env, :base64) == @aead256str
    end

    test "encrypts the envelope with the ECDH-ES+A128GCM alg" do
      assert {:ok, %Envelope{recipient: %Recipient{}} = env} = Recipient.encrypt(@env, @ec_key, %{"alg" => "ECDH-ES+A128GCM"})
      assert env.payload != "Hello world!"
    end

    test "encrypts the envelope with multiple keys with the A256GCM alg" do
      assert {:ok, %Envelope{recipient: recipients}} = Recipient.encrypt(@env, [@oct_256_key, @oct_256_key, @oct_256_key], %{"alg" => "A256GCM"})
      assert length(recipients) == 3
    end
  end


  describe "encrypt/4 key" do
    test "encrypts the key with the A128CBC-HS256 alg" do
      assert {:ok, %Recipient{} = recipient} = Recipient.encrypt(@ec_key, @oct_256_key, %{"alg" => "A128CBC-HS256"})
      assert is_binary(recipient.key)
      assert %{"iv" => _iv, "tag" => _tag} = recipient.header.headers
    end

    test "encrypts the key with the A256GCM alg" do
      assert {:ok, %Recipient{} = recipient} = Recipient.encrypt(@ec_key, @oct_256_key, %{"alg" => "A256GCM"})
      assert is_binary(recipient.key)
      assert %{"iv" => _iv, "tag" => _tag} = recipient.header.headers
    end

    test "encrypts the key with the ECDH-ES+A128GCM alg" do
      assert {:ok, %Recipient{} = recipient} = Recipient.encrypt(@oct_256_key, @ec_key, %{"alg" => "ECDH-ES+A128GCM"})
      assert is_binary(recipient.key)
      assert %{"iv" => _iv, "tag" => _tag} = recipient.header.headers
    end
  end

  describe "encrypt/4 and decrypt/4" do
    test "encrypts and decrypts envelope using the ECDH-ES+A128GCM alg" do
      pubkey = Key.to_public(@ec_key)
      assert {:ok, %Envelope{recipient: %Recipient{}} = env} = Recipient.encrypt(@env, pubkey, %{"alg" => "ECDH-ES+A128GCM"})
      refute env.payload == "Hello world!"
      assert {:ok, %Envelope{} = env} = Recipient.decrypt(env, @ec_key)
      assert env.payload == "Hello world!"
    end

    test "encrypts and decrypts envelope using the A128CBC-HS256 alg" do
      assert {:ok, %Envelope{recipient: %Recipient{}} = env} = Recipient.encrypt(@env, @oct_256_key, %{"alg" => "A128CBC-HS256"})
      refute env.payload == "Hello world!"
      assert {:ok, %Envelope{} = env} = Recipient.decrypt(env, @oct_256_key)
      assert env.payload == "Hello world!"
    end

    test "encrypts and decrypts envelope using the A256CBC-HS512 alg" do
      assert {:ok, %Envelope{recipient: %Recipient{}} = env} = Recipient.encrypt(@env, @oct_512_key, %{"alg" => "A256CBC-HS512"})
      refute env.payload == "Hello world!"
      assert {:ok, %Envelope{} = env} = Recipient.decrypt(env, @oct_512_key)
      assert env.payload == "Hello world!"
    end

    test "encrypts and decrypts envelope using the A128GCM alg" do
      assert {:ok, %Envelope{recipient: %Recipient{}} = env} = Recipient.encrypt(@env, @oct_128_key, %{"alg" => "A128GCM"})
      refute env.payload == "Hello world!"
      assert {:ok, %Envelope{} = env} = Recipient.decrypt(env, @oct_128_key)
      assert env.payload == "Hello world!"
    end

    test "encrypts and decrypts envelope using the A256GCM alg" do
      assert {:ok, %Envelope{recipient: %Recipient{}} = env} = Recipient.encrypt(@env, @oct_256_key, %{"alg" => "A256GCM"})
      refute env.payload == "Hello world!"
      assert {:ok, %Envelope{} = env} = Recipient.decrypt(env, @oct_256_key)
      assert env.payload == "Hello world!"
    end

    test "encrypts and decrypts envelope using the ECDH-ES+A256GCM alg" do
      assert {:ok, %Envelope{recipient: %Recipient{}} = env} = Recipient.encrypt(@env, @ec_key, %{"alg" => "ECDH-ES+A256GCM"})
      refute env.payload == "Hello world!"
      assert {:ok, %Envelope{} = env} = Recipient.decrypt(env, @ec_key)
      assert env.payload == "Hello world!"
    end
  end
end
