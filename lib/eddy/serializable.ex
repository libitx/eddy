defmodule Eddy.Serializable do
  @moduledoc false

  defprotocol Encoder do
    @moduledoc false

    @spec parse(t(), binary()) :: {:ok, t(), binary()} | {:error, term()}
    def parse(type, data)

    @spec serialize(t()) :: binary()
    def serialize(type)
  end

  defmacro __using__(_) do
    quote do
      import Eddy.Serializable, only: [serializable: 2]
    end
  end

  defmacro serializable(opts, [do: block]) do
    name = Keyword.get(opts, :name, :item)
    include_fns = Keyword.get(opts, :include_fns, true)

    quote do
      alias Eddy.Util
      alias Eddy.Serializable.Encoder

      if unquote(include_fns) do
        @doc """
        Converts the given binary data to a [`#{ Util.camelize(unquote(name)) }`](`t:t/0`)
        struct, optionally with the specified [`encoding`](`t:Eddy.encoding/0`).

        Returns the result in an `:ok` / `:error` tuple pair.
        """
        @spec from_bin(binary(), Eddy.encoding() | nil) :: {:ok, t()} | {:error, term()}
        def from_bin(data, encoding \\ nil) do
          with {:ok, data} <- Util.decode(data, encoding),
              {:ok, unquote(Macro.var(name, __MODULE__)), _} <- Encoder.parse(struct(__MODULE__), data)
          do
            {:ok, unquote(Macro.var(name, __MODULE__))}
          end
        end

        @doc """
        Converts the given [`#{ Util.camelize(unquote(name)) }`](`t:t/0`) struct
        to a binary, optionally with the specified [`encoding`](`t:Eddy.encoding/0`).
        """
        @spec to_bin(t(), Eddy.encoding() | nil) :: binary()
        def to_bin(unquote(Macro.var(name, __MODULE__)), encoding \\ nil) do
          unquote(Macro.var(name, __MODULE__))
          |> Encoder.serialize()
          |> Util.encode(encoding)
        end
      end

      defimpl Encoder do
        unquote(block)
      end
    end
  end
end
