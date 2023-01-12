defmodule Eddy.Point do
  @moduledoc """
  Module for manipulating elliptic curve points, using EdDSA mathematics on the
  Ed25519 curve.
  """
  import Bitwise
  use Eddy.Serializable
  alias Eddy.{ExtendedPoint, Util}

  @enforce_keys [:x, :y]
  defstruct [:x, :y]

  @typedoc """
  EdDSA Point

  A Point is a pair of coordinates (x, y) on an elliptic curve. Specifically,
  the Ed25519 curve, as defined by the equation:

  ```text
  y^2 = x^3 + 486662x^2 + x
  ```
  """
  @type t() :: %__MODULE__{
    x: integer(),
    y: integer(),
  }

  @params Eddy.params()

  @doc false
  defdelegate mod(number, modulo \\ @params.p), to: Util

  @doc """
  Adds two elliptic curve points.
  """
  @spec add(t(), t()) :: t()
  def add(%__MODULE__{} = point, %__MODULE__{} = other) do
    point
    |> ExtendedPoint.from_point()
    |> ExtendedPoint.add(ExtendedPoint.from_point(other))
    |> ExtendedPoint.to_point()
  end

  @doc """
  Doubles an elliptic curve point.
  """
  @spec double(t()) :: t()
  def double(%__MODULE__{} = point) do
    point
    |> ExtendedPoint.from_point()
    |> ExtendedPoint.double()
    |> ExtendedPoint.to_point()
  end

  @doc """
  Compares two elliptic curve points.
  """
  @spec eq(t(), t()) :: boolean()
  def eq(%__MODULE__{} = point, %__MODULE__{} = other) do
    point.x == other.x and point.y == other.y
  end

  @doc """
  Mutiplies an elliptic curve point with the given scalar.
  """
  @spec mul(t(), integer()) :: t()
  def mul(%__MODULE__{} = point, scalar) when is_integer(scalar) do
    point
    |> ExtendedPoint.from_point()
    |> ExtendedPoint.mul!(scalar)
    |> ExtendedPoint.to_point()
  end

  @doc """
  Negates an elliptic curve point.
  """
  @spec neg(t()) :: t()
  def neg(%__MODULE__{} = point) do
    %__MODULE__{x: mod(-point.x), y: point.y}
  end

  @doc """
  Subtracts the second elliptic curve point from the first.
  """
  @spec sub(t(), t()) :: t()
  def sub(%__MODULE__{} = point, %__MODULE__{} = other) do
    add(point, neg(other))
  end

  serializable name: :point, include_fns: false do
    @params Eddy.params()
    @sqrt_m1 0x2B8324804FC1DF0B2B4D00993DFBD7A72F431806AD2FE478C4EE1B274A0EA0B0

    defdelegate mod(number, modulo \\ @params.p), to: Util

    @impl true
    def parse(point, data) do
      with <<_::binary-31, last, rest::binary>> = y <- data,
           {:ok, y} <- normalize_y(y),
           {:ok, x} <- recover_x(y)
      do
        is_x_odd = band(x, 1) == 1
        is_last_odd = band(last, 0x80) != 0
        x = if is_x_odd != is_last_odd, do: mod(-x), else: x
        {:ok, struct(point, x: x, y: y), rest}
      else
        bin when is_binary(bin) -> {:error, {:decode_error, "invalid point length"}}
        {:error, _} -> {:error, {:decode_error, "invalid y"}}
      end
    end

    @impl true
    def serialize(%{x: x, y: y}) do
      <<bytes::binary-31, last>> = <<y::little-256>>
      last = if band(x, 1) == 1, do: bor(last, 0x80), else: last
      <<bytes::binary, last>>
    end

    @spec normalize_y(binary()) :: {:ok, integer()} | {:error, term()}
    defp normalize_y(<<bytes::binary-31, last>>) do
      last = last |> band(bnot(0x80))
      <<y::little-256>> = <<bytes::binary, last>>
      if y >= @params.p, do: {:error, :invalid_y}, else: {:ok, y}
    end

    @spec recover_x(integer()) :: {:ok, integer()} | {:error, term()}
    defp recover_x(y) do
      y2 = mod(y * y)
      u = mod(y2 - 1)
      v = mod(@params.d * y2 + 1)
      v3 = mod(v * v * v)
      v7 = mod(v3 * v3 * v)
      {pow, _b} = Util.pow2_252_3(u * v7, @params.p)
      x = mod(u * v3 * pow)
      vx2 = mod(v * x * x)

      response = cond do
        vx2 == u -> {:ok, x}
        vx2 == mod(-u) -> {:ok, mod(x * @sqrt_m1)}
        vx2 == mod(-u * @sqrt_m1) -> {:error, mod(x * @sqrt_m1)}
        true -> {:error, nil}
      end

      case response do
        {:ok, x} ->
          x = if mod(x) |> band(1) == 1, do: mod(-x), else: x
          {:ok, x}

        {:error, _} ->
          {:error, :invalid_y}
      end
    end
  end

end
