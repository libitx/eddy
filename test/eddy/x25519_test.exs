defmodule Eddy.X25519Test do
  use ExUnit.Case, async: true
  alias Eddy.X25519

  @base "0900000000000000000000000000000000000000000000000000000000000000"

  test "converts base point to montgomery X25519" do
    %{ G: base } = Eddy.params()
    u = X25519.from_point(base)
    assert Base.encode16(u) == @base
  end

  describe "X25519.scalar_mult/2" do
    x25519_vectors = [{
      "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
      "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
      "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
    }, {
      "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
      "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
      "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
    }]

    for {vector, i} <- Enum.with_index(x25519_vectors) do
      test "single pass vector #{i}" do
        [k, u, ku] =
          unquote(Macro.escape(vector))
          |> Tuple.to_list()
          |> Enum.map(& Base.decode16!(&1, case: :lower))
        assert X25519.scalar_mult(k, u) == ku
      end
    end

    recursive_vectors = [
      {1,     "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"},
      {1000,  "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"},
      #{1000000, "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424"},
    ]

    for {vector, i} <- Enum.with_index(recursive_vectors) do
      test "recursive vector #{i}" do
        {iters, res} = unquote(Macro.escape(vector))
        k = Base.decode16!(@base, case: :lower)
        {k, _u} = Enum.reduce(1..iters, {k, k}, fn _i, {k, u} ->
          {X25519.scalar_mult(k, u), k}
        end)
        assert Base.encode16(k, case: :lower) == res
      end
    end

    test "test 2" do
      base  = Base.decode16!(@base, case: :lower)
      apriv = Base.decode16!("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", case: :lower)
      apub  = Base.decode16!("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", case: :lower)
      bpriv = Base.decode16!("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", case: :lower)
      bpub  = Base.decode16!("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", case: :lower)
      k     = Base.decode16!("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", case: :lower)

      assert X25519.scalar_mult(apriv, base) == apub
      assert X25519.scalar_mult(bpriv, base) == bpub
      assert X25519.scalar_mult(apriv, bpub) == k
      assert X25519.scalar_mult(bpriv, apub) == k
    end
  end
end
