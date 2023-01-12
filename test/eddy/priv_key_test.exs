defmodule Eddy.PrivKeyTest do
  use ExUnit.Case, async: true
  alias Eddy.PrivKey

  setup_all do
    d = Eddy.generate_key(encoding: :raw)
    {:ok, d: d, privkey: %PrivKey{d: d}}
  end

  describe "from_bin/2" do
    test "converts raw binary to a private key", ctx do
      assert {:ok, privkey} = PrivKey.from_bin(ctx.d)
      assert privkey == ctx.privkey
    end

    test "converts hex binary to a private key", ctx do
      privkey_hex = Base.encode16(ctx.d, case: :lower)
      assert {:ok, privkey} = PrivKey.from_bin(privkey_hex, :hex)
      assert privkey == ctx.privkey
    end
  end

  describe "to_bin/2" do
    test "converts private key to a raw binary", ctx do
      assert PrivKey.to_bin(ctx.privkey) == ctx.d
    end

    test "converts private key to a hex binary", ctx do
      assert PrivKey.to_bin(ctx.privkey, :hex) == Base.encode16(ctx.d, case: :lower)
    end
  end
end
