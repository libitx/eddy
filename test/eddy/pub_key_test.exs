defmodule Eddy.PubKeyTest do
  use ExUnit.Case, async: true
  alias Eddy.PubKey

  setup_all do
    key = Eddy.generate_key()
    pubkey = Eddy.get_pubkey(key)
    pubkey_bin = Eddy.get_pubkey(key, encoding: :bin)
    {:ok, pubkey: pubkey, pubkey_bin: pubkey_bin}
  end

  describe "from_bin/2" do
    test "converts raw binary to a public key", ctx do
      assert {:ok, pubkey} = PubKey.from_bin(ctx.pubkey_bin)
      assert pubkey == ctx.pubkey
    end

    test "converts hex binary to a public key", ctx do
      pubkey_hex = Base.encode16(ctx.pubkey_bin, case: :lower)
      assert {:ok, pubkey} = PubKey.from_bin(pubkey_hex, :hex)
      assert pubkey == ctx.pubkey
    end
  end

  describe "to_bin/2" do
    test "converts public key to a raw binary", ctx do
      assert PubKey.to_bin(ctx.pubkey) == ctx.pubkey_bin
    end

    test "converts public key to a hex binary", ctx do
      assert PubKey.to_bin(ctx.pubkey, :hex) == Base.encode16(ctx.pubkey_bin, case: :lower)
    end
  end
end
