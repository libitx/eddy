defmodule Eddy.Sig do
  @moduledoc """
  Module for working with signatures.

  [`Sig`](`t:t/0`) structs can be encoded to and from binary data, using any
  [`encoding`](`t:Eddy.encoding/0`).
  """
  use Eddy.Serializable
  alias Eddy.{Point, Util}

  @enforce_keys [:r, :s]
  defstruct [:r, :s]

  @typedoc """
  Signature

  An EdDSA signature is a pair of values (r, s) computed from the private key
  and a hash of the message being signed.
  """
  @type t() :: %__MODULE__{
    r: Point.t(),
    r: integer(),
  }

  serializable name: :signature do
    @impl true
    def parse(sig, data) do
      with <<rbin::binary-32, s::little-256, rest::binary>> <- data,
           {:ok, point, _rest} <- Encoder.parse(struct(Point), rbin)
      do
        {:ok, struct(sig, r: point, s: s), rest}
      else
        bin when is_binary(bin) -> {:error, {:decode_error, "invalid sig length"}}
        {:error, error} -> {:error, error}
      end
    end

    @impl true
    def serialize(%{r: r, s: s}), do: Encoder.serialize(r) <> <<s::little-256>>
  end
end
