defmodule Eddy.Util do
  @moduledoc """
  Utility module for common and shared functions.
  """

  @doc """
  Decodes the given binary with the specified [`encoding`](`t:Eddy.encoding/0`) scheme.
  """
  @spec decode(binary, atom) :: {:ok, binary} | {:error, any}
  def decode(data, encoding)
  def decode(data, :base16), do: Base.decode16(data)
  def decode(data, :base64), do: Base.decode64(data)
  def decode(data, :hex), do: Base.decode16(data, case: :lower)
  def decode(data, _), do: {:ok, data}

  @doc """
  Encodes the given binary with the specified [`encoding`](`t:Eddy.encoding/0`) scheme.
  """
  @spec encode(binary, atom) :: binary
  def encode(data, encoding)
  def encode(data, :base16), do: Base.encode16(data)
  def encode(data, :base64), do: Base.encode64(data)
  def encode(data, :hex), do: Base.encode16(data, case: :lower)
  def encode(data, _), do: data

  @doc """
  Invert operation.
  """
  @spec inv(integer, integer) :: integer
  def inv(x, _n) when x == 0, do: 0
  def inv(x, n), do: inv_op(1, 0, mod(x, n), n)

  @doc """
  Modulo operation. Returns the remainder after x is divided by n.
  """
  @spec mod(integer, integer) :: integer
  def mod(x, n) do
    case rem(x, n) do
      r when r < 0 -> r + n
      r -> r
    end
  end

  @doc """
  Checks the scalar is within range.
  """
  @spec normalize_scalar(integer(), integer(), boolean()) :: integer()
  def normalize_scalar(n, max, strict \\ true)
  def normalize_scalar(n, max, true) when n < max and 0 < n, do: n
  def normalize_scalar(n, max, false) when n < max and 0 <= n, do: n
  def normalize_scalar(_n, _max, _strict), do: raise "invalid scalar"

  @doc """
  Computes `x ^ (2 ^ power) mod p`
  """
  @spec pow2(integer(), integer(), integer()) :: integer()
  def pow2(x, power, p) when power > 0,
    do: rem(x * x, p) |> pow2(power-1, p)

  def pow2(x, _power, _p), do: x

  @doc """
  Computes `x ^ (2 ^ 252-3) mod p`
  """
  @spec pow2_252_3(integer(), integer()) :: {integer(), integer()}
  def pow2_252_3(x, p) do
    x2 = rem(x * x, p)
    b2 = rem(x2 * x, p)
    b4 = rem(pow2(b2, 2, p) * b2, p)
    b5 = rem(pow2(b4, 1, p) * x, p)
    b10 = rem(pow2(b5, 5, p) * b5, p)
    b20 = rem(pow2(b10, 10, p) * b10, p)
    b40 = rem(pow2(b20, 20, p) * b20, p)
    b80 = rem(pow2(b40, 40, p) * b40, p)
    b160 = rem(pow2(b80, 80, p) * b80, p)
    b240 = rem(pow2(b160, 80, p) * b80, p)
    b250 = rem(pow2(b240, 10, p) * b10, p)
    {rem(pow2(b250, 2, p) * x, p), b2}
  end

  # Recursive inv function
  defp inv_op(lm, hm, low, high) when low > 1 do
    r = div(high, low)
    inv_op(hm - lm * r, lm, high - low * r, low)
  end

  defp inv_op(lm, _hm, _low, _high), do: lm

  @doc false
  @spec camelize(atom() | String.t()) :: String.t()
  def camelize(name) when is_atom(name), do: camelize(Atom.to_string(name))
  def camelize(name) when is_binary(name) do
    name
    |> String.split("_")
    |> Enum.map(fn <<char, rest::binary>> -> String.upcase(<<char>>) <> rest end)
    |> Enum.join()
  end

end
