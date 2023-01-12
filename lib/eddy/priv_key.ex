defmodule Eddy.PrivKey do
  @moduledoc """
  Module for working with private keys.

  [`PrivKey`](`t:t/0`) structs can be encoded to and from binary data, using any
  [`encoding`](`t:Eddy.encoding/0`).
  """
  use Eddy.Serializable

  @enforce_keys [:d]
  defstruct [:d]

  @typedoc """
  Private Key

  An Ed25519 private key is 256 bits of cryptographically secure random data.
  """
  @type t() :: %__MODULE__{
    d: <<_::256>>
  }

  serializable name: :priv_key do
    @impl true
    def parse(privkey, data) do
      with <<d::binary-32, rest::binary>> <- data do
        {:ok, struct(privkey, d: d), rest}
      else
        _ -> {:error, {:decode_error, "invalid privkey length"}}
      end
    end

    @impl true
    def serialize(%{d: d}), do: d
  end
end
