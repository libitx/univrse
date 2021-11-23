defmodule Univrse.CompatTest do
  use ExUnit.Case
  alias Univrse.{Envelope, Key}

  #@alice "a561645820dfef448a64826dfe935e494ce97d506945b4e672b29d16c10f76479738f9cf85617858208f3f5d9918af7327a4fbbe77a30fd87ced99f756abb8ad708a577b27bf4d16dd6179582090421b41892a286e6eddbe8fc64119812de58c0197d8c7ed6dfb885a30fbeb9f6363727669736563703235366b31636b7479624543"
  @alice_pub "a4617858208f3f5d9918af7327a4fbbe77a30fd87ced99f756abb8ad708a577b27bf4d16dd6179582090421b41892a286e6eddbe8fc64119812de58c0197d8c7ed6dfb885a30fbeb9f6363727669736563703235366b31636b7479624543"
  @bob "a5616458204bf0b781ab1cb2e2f29fd97cbd2612c5073dff842f672c780d70dc40aabee58b61785820d29cb7587b6466f7a5e2c30229cc7a56f62c6ffc833f9731942ce7cc11ec7f5b61795820810b81386d7215c52ead717cda91f2042c19d330aa136c7bb3a856f6573a92306363727669736563703235366b31636b7479624543"
  #@bob_pub "a461785820d29cb7587b6466f7a5e2c30229cc7a56f62c6ffc833f9731942ce7cc11ec7f5b61795820810b81386d7215c52ead717cda91f2042c19d330aa136c7bb3a856f6573a92306363727669736563703235366b31636b7479624543"

  @b64_env "oWVwcm90b2R0ZXN0.WB3OcabyFvLfgxwdPdNSA05Gqv6B2G6JezineQnJ-A.gqJjYWxnZkVTMjU2S2NraWRlYWxpY2VYQSDfDFgOHo-qHlJET51yeA8m6HNGGslAHOlgFOFMRZojmwK0VXmUXM-c75YPV29VKnVx3nxOBDAXw8NUb-eOElek.goKjYml2TA-Qvly4XKNOi__6OWNhbGdnQTEyOEdDTWN0YWdQLULMJygfAxA7-cbLotC4L_aCpWJpdkzzgZh2WJQRQFBKMZxjYWxnb0VDREgtRVMrQTEyOEdDTWNlcGtYIQKVWbi1wbJpuqW61qu0DF0nkOFvnqX7yKSKUUN_gx8j8mNraWRjYm9iY3RhZ1DY27RiiVLJfNB7NOxPiL2uWBzAQNdCdWu_C4F0w0KxysjGhJEeeq76fOwGtwb9"
  @script_env "006a04554e49560ca16570726f746f64746573741f581dce71a6f216f2df831c1d3dd352034e46aafe81d86e897b38a77909c9f84c5a82a263616c676645533235364b636b696465616c696365584120df0c580e1e8faa1e52444f9d72780f26e873461ac9401ce96014e14c459a239b02b45579945ccf9cef960f576f552a7571de7c4e043017c3c3546fe78e1257a44cbd8282a36269764c0f90be5cb85ca34e8bfffa3963616c67674131323847434d63746167502d42cc27281f03103bf9c6cba2d0b82ff682a56269764cf381987658941140504a319c63616c676f454344482d45532b4131323847434d6365706b5821029559b8b5c1b269baa5bad6abb40c5d2790e16f9ea5fbc8a48a51437f831f23f2636b696463626f626374616750d8dbb4628952c97cd07b34ec4f88bdae581cc040d742756bbf0b8174c342b1cac8c684911e7aaefa7cec06b706fd"


  describe "parses envelopes created in JS" do
    setup do
      {:ok, alice_pub_key} = @alice_pub |> Base.decode16!(case: :lower) |> Key.decode()
      {:ok, bob_key} = @bob |> Base.decode16!(case: :lower) |> Key.decode()
      %{
        alice_pub_key: alice_pub_key,
        bob_key: bob_key
      }
    end

    test "parses base64, decrypts and verifies sigs", ctx do
      # Decode envelope
      assert {:ok, env} = Univrse.decode(@b64_env)
      assert env.header.headers["proto"] == "test"

      # Inspect signature
      assert env.signature.header.headers["alg"] == "ES256K"
      assert env.signature.header.headers["kid"] == "alice"

      # Inspect recipients
      assert length(env.recipient) == 2
      r1 = Enum.at(env.recipient, 0)
      r2 = Enum.at(env.recipient, 1)
      assert r1.header.headers["alg"] == "A128GCM"
      assert r2.header.headers["alg"] == "ECDH-ES+A128GCM"
      assert r2.header.headers["kid"] == "bob"

      # Decrypt
      assert {:ok, env} = Envelope.decrypt_at(env, 1, ctx.bob_key)
      assert env.payload == %{"data" => "Some data from JS land"}

      # Verify
      assert Univrse.verify(env, ctx.alice_pub_key)
    end

    test "parses script, decrypts and verifies sigs", ctx do
      # Decode envelope
      assert {:ok, script} = BSV.Script.from_binary(@script_env, encoding: :hex)
      assert {:ok, env} = Envelope.parse_script(script)
      assert env.header.headers["proto"] == "test"

      # Inspect signature
      assert env.signature.header.headers["alg"] == "ES256K"
      assert env.signature.header.headers["kid"] == "alice"

      # Inspect recipients
      assert length(env.recipient) == 2
      r1 = Enum.at(env.recipient, 0)
      r2 = Enum.at(env.recipient, 1)
      assert r1.header.headers["alg"] == "A128GCM"
      assert r2.header.headers["alg"] == "ECDH-ES+A128GCM"
      assert r2.header.headers["kid"] == "bob"

      # Decrypt
      assert {:ok, env} = Envelope.decrypt_at(env, 1, ctx.bob_key)
      assert env.payload == %{"data" => "Some data from JS land"}

      # Verify
      assert Univrse.verify(env, ctx.alice_pub_key)
    end
  end


  #describe "create envelopes for testing externally" do
  #  setup do
  #    {:ok, alice_key} = @alice |> Base.decode16!(case: :lower) |> Key.decode()
  #    {:ok, bob_pub_key} = @bob_pub |> Base.decode16!(case: :lower) |> Key.decode()
  #    %{
  #      alice_key: alice_key,
  #      bob_pub_key: bob_pub_key
  #    }
  #  end
  #
  #  test "creates the envelope", ctx do
  #    key = Key.generate_key({:oct, 128})
  #    env = Envelope.wrap(%{"data" => "Some data from Elixir land"}, %{"proto" => "test"})
  #    {:ok, env} = Envelope.sign(env, ctx.alice_key, %{"alg" => "ES256K", "kid" => "alice"})
  #    {:ok, env} = Envelope.encrypt(env, [
  #      {key, %{"alg" => "A128GCM"}},
  #      {ctx.bob_pub_key, %{"alg" => "ECDH-ES+A128GCM", "kid" => "bob"}}
  #    ], %{})
  #
  #    IO.inspect env
  #    IO.inspect Envelope.encode(env, :base64)
  #    IO.inspect Envelope.to_script(env) |> BSV.Script.serialize(encoding: :hex)
  #  end
  #end
end
