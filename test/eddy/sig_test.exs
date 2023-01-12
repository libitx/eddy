defmodule Eddy.SigTest do
  use ExUnit.Case, async: true
  alias Eddy.Sig

  setup_all do
    key = Eddy.generate_key()
    sig = Eddy.sign("test", key)
    sig_bin = Eddy.sign("test", key, encoding: :bin)
    {:ok, sig: sig, sig_bin: sig_bin}
  end

  describe "from_bin/2" do
    test "converts raw binary to a signature", ctx do
      assert {:ok, sig} = Sig.from_bin(ctx.sig_bin)
      assert sig == ctx.sig
    end

    test "converts hex binary to a signature", ctx do
      sig_hex = Base.encode16(ctx.sig_bin, case: :lower)
      assert {:ok, sig} = Sig.from_bin(sig_hex, :hex)
      assert sig == ctx.sig
    end
  end

  describe "to_bin/2" do
    test "converts signature to a raw binary", ctx do
      assert Sig.to_bin(ctx.sig) == ctx.sig_bin
    end

    test "converts signature to a hex binary", ctx do
      assert Sig.to_bin(ctx.sig, :hex) == Base.encode16(ctx.sig_bin, case: :lower)
    end
  end
end
