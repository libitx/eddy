defmodule Eddy.X25519 do
  @moduledoc """
  Module supporting the X25519 key exchange protocol.

  X25519 is an ECDH key exchange protocol using the same elliptic curve as
  Ed25519. Ed25519 points must be converted from Twisted Edwards to Montgomery
  curves, as per [rfc7748](https://datatracker.ietf.org/doc/html/rfc7748).

  This module is provided to support the implementation of `Eddy.get_shared_secret/3`.
  """
  import Bitwise
  alias Eddy.{Point, Util}

  @params Eddy.params()

  # The constant a24 is (486662 - 2) / 4 = 121665 for curve25519/X25519
  @a24 121665

  @doc false
  defdelegate inv(number, modulo \\ @params.p), to: Util
  @doc false
  defdelegate mod(number, modulo \\ @params.p), to: Util
  @doc false
  defdelegate pow2(number, power, modulo \\ @params.p), to: Util

  @doc """
  Adjusts the given 32 random bytes by X25519.

  Set the three least significant bits of the first byte and the most
  significant bit of the last to zero. Set the second most significant bit of
  the last byte to 1.
  """
  @spec adjust_bytes(binary()) :: binary()
  def adjust_bytes(<<first, middle::binary-30, last, _rest::binary>>) do
    first = band(first, 248)
    last = band(last, 127) |> bor(64)
    <<first, middle::binary, last>>
  end

  @doc """
  Converts an Ed25519 (Twisted Edwards) point to an X25519 (Montgomery) binary.
  """
  @spec from_point(Point.t()) :: binary()
  def from_point(%Point{y: y}) do
    u = mod((1 + y) * inv(1 - y))
    <<u::little-256>>
  end

  @doc """
  Computes an ECDH shared secret from the given X25519 private and public keys.
  """
  @spec scalar_mult(binary(), binary()) :: binary()
  def scalar_mult(privkey, pubkey)
    when is_binary(privkey)
    and is_binary(pubkey)
  do
    u = decode_u(pubkey)
    p = decode_scalar(privkey)
    case montgomery_ladder(u, p) do
      0 ->
        raise "invalid private or public key"
      pu ->
        <<mod(pu)::little-256>>
    end
  end

  # Converts a X25519 pubkey to an integer
  @spec decode_u(binary()) :: integer()
  defp decode_u(<<data::binary-31, last>>) do
    last = band(last, 127)
    <<u::little-256>> = <<data::binary, last>>
    u
  end

  # Converts a binary to an X25519 scalar
  @spec decode_scalar(binary()) :: integer()
  defp decode_scalar(data) do
    <<p::little-256>> = adjust_bytes(data)
    p
  end

  @spec montgomery_ladder(integer(), integer()) :: integer()
  defp montgomery_ladder(u, scalar) do
    u = Util.normalize_scalar(u, @params.p)
    k = Util.normalize_scalar(scalar, @params.p)

    {x, z} = montgomery_ladder_it({u, 1, 0, u, 1, 0}, k)

    {pow_p58, b2} = Util.pow2_252_3(z, @params.p)
    xp2 = mod(pow2(pow_p58, 3) * b2)
    mod(x * xp2)
  end

  @spec montgomery_ladder_it(tuple(), integer(), integer()) :: {integer(), integer()}
  defp montgomery_ladder_it(params_tuple, k, t \\ 254)

  defp montgomery_ladder_it({x, x2, z2, x3, z3, swap}, k, t) when t >= 0 do
    kt = bsr(k, t) |> band(1)
    swap = bxor(swap, kt)
    {x2, x3} = cswap(swap, x2, x3)
    {z2, z3} = cswap(swap, z2, z3)
    swap = kt

    a = x2 + z2
    b = x2 - z2
    c = x3 + z3
    d = x3 - z3
    aa = mod(a * a)
    bb = mod(b * b)
    da = mod(d * a)
    cb = mod(c * b)
    e = aa - bb
    dacb = da + cb
    da_cb = da - cb
    montgomery_ladder_it({
      x,
      mod(aa * bb),                   # x2
      mod(e * (aa + mod(@a24 * e))),  # z2
      mod(dacb * dacb),               # x3
      mod(x * mod(da_cb * da_cb)),   # z3
      swap
    }, k, t - 1)
  end

  defp montgomery_ladder_it({_x, x2, z2, x3, z3, swap}, _k, _t) do
    {x2, _x3} = cswap(swap, x2, x3)
    {z2, _z3} = cswap(swap, z2, z3)
    {x2, z2}
  end

  @spec cswap(integer(), integer(), integer()) :: {integer(), integer()}
  defp cswap(swap, x2, x3) do
    dummy = mod(swap * (x2 - x3))
    {mod(x2 - dummy), mod(x3 + dummy)}
  end
end
