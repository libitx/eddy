defmodule Eddy.PubKey do
  @moduledoc """
  Module for working with public keys.

  [`PubKey`](`t:t/0`) structs can be encoded to and from binary data, using any
  [`encoding`](`t:Eddy.encoding/0`).
  """
  use Eddy.Serializable
  alias Eddy.Point

  @enforce_keys [:point]
  defstruct [:point]

  @typedoc """
  Public Key

  An EdDSA public key consists of a [`Point`](`t:Eddy.Point.t`) (x and y
  co-ordinates on an elliptic curve), derived from its corresponding private key.
  """
  @type t() :: %__MODULE__{
    point: Point.t()
  }

  serializable name: :pub_key do
    @impl true
    def parse(pubkey, data) do
      with {:ok, point, rest} <- Encoder.parse(struct(Point), data) do
        {:ok, struct(pubkey, point: point), rest}
      end
    end

    @impl true
    def serialize(%{point: point}), do: Encoder.serialize(point)
  end

end
