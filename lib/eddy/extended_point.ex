defmodule Eddy.ExtendedPoint do
  @moduledoc false
  import Bitwise
  alias Eddy.{Point, Util}

  defstruct [:x, :y, :z, :t]

  @type t() :: %__MODULE__{
    x: integer(),
    y: integer(),
    z: integer(),
    t: integer(),
  }

  @params Eddy.params()

  defdelegate inv(number, modulo \\ @params.p), to: Util
  defdelegate mod(number, modulo \\ @params.p), to: Util

  # Convert from affine point to extended
  @spec from_point(Point.t()) :: t()
  def from_point(%Point{x: 0, y: 1}), do: %__MODULE__{x: 0, y: 1, z: 1, t: 0}
  def from_point(%Point{x: x, y: y}), do: %__MODULE__{x: x, y: y, z: 1, t: mod(x * y)}

  # Convert from extended point to affine
  @spec to_point(t()) :: Point.t()
  def to_point(%__MODULE__{x: 0, y: 1, z: 1, t: 0}), do: %Point{x: 0, y: 1}
  def to_point(%__MODULE__{z: z} = point), do: to_point(point, inv(z))
  def to_point(%__MODULE__{x: x, y: y, z: z}, inv_z) when is_integer(inv_z) do
    ax = mod(x * inv_z)
    ay = mod(y * inv_z)
    case mod(z * inv_z) do
      1 -> %Point{x: ax, y: ay}
      _ -> raise "inv_z was invalid"
    end
  end

  # Add two extended points
  @spec add(t(), t()) :: t()
  def add(
    %__MODULE__{x: x1, y: y1, z: z1, t: t1} = point,
    %__MODULE__{x: x2, y: y2, z: z2, t: t2}
  ) do
    a = mod((y1 - x1) * (y2 + x2))
    b = mod((y1 + x1) * (y2 - x2))
    case mod(b - a) do
      0 -> double(point)
      f ->
        c = mod(z1 * 2 * t2)
        d = mod(t1 * 2 * z2)
        e = d + c
        g = b + a
        h = d - c
        x = mod(e * f)
        y = mod(g * h)
        t = mod(e * h)
        z = mod(f * g)
        %__MODULE__{x: x, y: y, z: z, t: t}
    end
  end

  # Double the extend point
  @spec double(t()) :: t()
  def double(%__MODULE__{x: x1, y: y1, z: z1}) do
    a = mod(x1 * x1)
    b = mod(y1 * y1)
    c = mod(2 * mod(z1 * z1))
    d = mod(@params.a * a)
    xy = x1+ y1
    e = mod(mod(xy * xy) - a - b)
    g = d + b
    f = g - c
    h = d - b
    x = mod(e * f)
    y = mod(g * h)
    t = mod(e * h)
    z = mod(f * g)
    %__MODULE__{x: x, y: y, z: z, t: t}
  end

  # Compare to extended points
  @spec eq(t(), t()) :: boolean()
  def eq(%__MODULE__{x: x1, y: y1, z: z1}, %__MODULE__{x: x2, y: y2, z: z2}) do
    mod(x1 * z2) == mod(x2 * z1) and mod(y1 * z2) == mod(y2 * z1)
  end

  # Multiplies an extended point with a scalar
  # Unsafe! Not constant time - #todo
  @spec mul!(t(), integer()) :: t()
  def mul!(%__MODULE__{x: 0, y: 1, z: 1, t: 0} = point, _scalar), do: point
  def mul!(point, scalar) do
    case Util.normalize_scalar(scalar, @params.l, false) do
      0 -> %{x: 0, y: 1, z: 1, t: 0}
      1 -> point
      n ->
        mul_it(point, %__MODULE__{x: 0, y: 1, z: 1, t: 0}, n)
    end
  end

  # Negates an extended point
  @spec neg(t()) :: t()
  def neg(%__MODULE__{x: x, y: y, z: z, t: t}) do
    %__MODULE__{x: mod(-x), y: y, z: z, t: mod(-t)}
  end

  # Subtract second extended point from the first
  @spec sub(t(), t()) :: t()
  def sub(%__MODULE__{} = point, %__MODULE__{} = other) do
    add(point, neg(other))
  end

  @spec mul_it(t(), t(), integer()) :: t()
  defp mul_it(d, p, n) when n > 0 do
    p = case band(n, 1) do
      0 -> p
      _ -> add(p, d)
    end

    mul_it(double(d), p, bsr(n, 1))
  end

  defp mul_it(_d, p, _n), do: p

end
