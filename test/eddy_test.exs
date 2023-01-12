defmodule EddyTest do
  use ExUnit.Case, async: true
  #doctest Eddy

  setup_all do
    privkey = Eddy.generate_key()
    pubkey = Eddy.get_pubkey(privkey)
    sig = Eddy.sign("test", privkey)
    {:ok, privkey: privkey, pubkey: pubkey, sig: sig}
  end

  describe "params/0" do
    test "returns a map curve params" do
      params = Eddy.params()
      assert is_map(params)
      assert is_integer(params.p)
      assert is_integer(params.l)
      assert match?(%Eddy.Point{}, params[:G])
    end
  end

  describe "generate_key/1" do
    test "generates and returns a privkey struct" do
      assert %Eddy.PrivKey{} = Eddy.generate_key()
    end

    test "generates and returns a binary privkey" do
      key = Eddy.generate_key(encoding: :raw)
      assert is_binary(key) and byte_size(key) == 32
    end

    test "generates and returns a hex privkey" do
      key = Eddy.generate_key(encoding: :hex)
      assert String.match?(key, ~r/[a-f0-9]{64}/)
    end
  end

  describe "get_pubkey/2" do
    test "computes and returns the corresponding pubkey", %{privkey: key} do
      assert %Eddy.PubKey{} = Eddy.get_pubkey(key)
    end

    test "accepts a binary privkey" do
      key = Eddy.generate_key(encoding: :raw)
      assert %Eddy.PubKey{} = Eddy.get_pubkey(key)
    end

    test "returns a binary pubkey", %{privkey: key} do
      pubkey = Eddy.get_pubkey(key, encoding: :raw)
      assert is_binary(pubkey) and byte_size(pubkey) == 32
    end

    test "returns a hex pubkey", %{privkey: key} do
      pubkey = Eddy.get_pubkey(key, encoding: :hex)
      assert String.match?(pubkey, ~r/[a-f0-9]{64}/)
    end
  end

  describe "get_shared_secret/3" do
    setup do
      prv_a = Eddy.generate_key()
      pub_a = Eddy.get_pubkey(prv_a)
      prv_b = Eddy.generate_key()
      pub_b = Eddy.get_pubkey(prv_b)
      {:ok, prv_a: prv_a, pub_a: pub_a, prv_b: prv_b, pub_b: pub_b}
    end

    test "returns a binary shared secret", ctx do
      secret = Eddy.get_shared_secret(ctx.prv_a, ctx.pub_b)
      assert is_binary(secret) and byte_size(secret) == 32
    end

    test "returns a hex shared secret", ctx do
      secret = Eddy.get_shared_secret(ctx.prv_a, ctx.pub_b, encoding: :hex)
      assert String.match?(secret, ~r/[a-f0-9]{64}/)
    end

    for i <- 1..128 do
      test "is commutative (test #{i})", ctx do
        secret_a = Eddy.get_shared_secret(ctx.prv_a, ctx.pub_b)
        secret_b = Eddy.get_shared_secret(ctx.prv_b, ctx.pub_a)
        assert secret_a == secret_b
      end
    end
  end

  describe "sign/3" do
    test "signs the message and returns a signature", %{privkey: key} do
      assert %Eddy.Sig{} = Eddy.sign("test", key)
    end

    test "accepts a binary privkey" do
      key = Eddy.generate_key(encoding: :raw)
      assert %Eddy.Sig{} = Eddy.sign("test", key)
    end

    test "returns a binary signature", %{privkey: key} do
      sig = Eddy.sign("test", key, encoding: :raw)
      assert is_binary(sig) and byte_size(sig) == 64
    end

    test "returns a base64 signature", %{privkey: key} do
      sig = Eddy.sign("test", key, encoding: :base64)
      assert is_binary(sig) and byte_size(sig) == 88
    end

    test "returns a hex signature", %{privkey: key} do
      sig = Eddy.sign("test", key, encoding: :hex)
      assert String.match?(sig, ~r/[a-f0-9]{128}/)
    end
  end

  describe "verify/4" do
    test "returns true for a valid signature", %{pubkey: key, sig: sig} do
      assert Eddy.verify(sig, "test", key) == true
    end

    test "returns false with incorrect pubkey", %{sig: sig} do
      key = Eddy.generate_key() |> Eddy.get_pubkey()
      assert Eddy.verify(sig, "test", key) == false
    end

    test "returns false with incorrect message", %{pubkey: key, sig: sig} do
      assert Eddy.verify(sig, "wrong", key) == false
    end

    test "accepts a binary signature", %{pubkey: key, sig: sig} do
      sig = Eddy.Sig.to_bin(sig)
      assert Eddy.verify(sig, "test", key) == true
    end

    test "accepts a base64 signature", %{pubkey: key, sig: sig} do
      sig = Eddy.Sig.to_bin(sig, :base64)
      assert Eddy.verify(sig, "test", key, encoding: :base64) == true
    end

    test "accepts a hex signature", %{pubkey: key, sig: sig} do
      sig = Eddy.Sig.to_bin(sig, :hex)
      assert Eddy.verify(sig, "test", key, encoding: :hex) == true
    end

    test "returns error with incorrect encoding", %{pubkey: key, sig: sig} do
      sig = Eddy.Sig.to_bin(sig, :hex)
      assert {:error, _} = Eddy.verify(sig, "test", key, encoding: :base64)
    end
  end
end
