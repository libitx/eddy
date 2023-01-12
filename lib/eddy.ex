defmodule Eddy do
  @moduledoc """
  ![Curvy](https://raw.githubusercontent.com/libitx/eddy/main/media/poster.png)

  ![License](https://img.shields.io/github/license/libitx/eddy?color=i

  Eddy is a pure elixir implementation of `Ed25519`, an elliptic curve that can
  be used in signature schemes and ECDH shared secrets.

  ## Highlights

  - Pure Elixir implementation of `Ed25519` - no external dependencies
  - Secure generation of EdDSA key pairs
  - Ed25519 signature schemes and X25519 ECDH shared secrets
  - Build your own crypto - customisable hash function

  ## Instalation

  The package can be installed by adding `eddy` to your list of dependencies in
  `mix.exs`.

  ```elixir
  def deps do
    [
      {:eddy, "~> 1.0.0"}
    ]
  end
  ```

  ## Quick start

  ### 1. Key generation

  Generate new EdDSA keypairs.

  ```elixir
  iex> privkey = Eddy.generate_key()
  %Eddy.PrivKey{}

  iex> pubkey = Eddy.get_pubkey(privkey)
  %Eddy.PubKey{}
  ```

  ### 2. Sign messages

  Sign messages with a private key.

  ```elixir
  iex> sig = Eddy.sign("test", privkey)
  %Eddy.Sig{}
  ```

  ### 3. Verify messages

  Verify a signature against the message and a public key.

  ```elixir
  iex> Eddy.verify(sig, "test", pubkey)
  true

  iex> Eddy.verify(sig, "test", wrong_pubkey)
  false
  ```

  ### 4. X25519 shared secrets

  ECDH shared secrets are computed by multiplying a public key with a private
  key. The operation yields the same result in both directions.

  ```elixir
  iex> s1 = Eddy.get_shared_secret(priv_a, pubkey_b)
  iex> s2 = Eddy.get_shared_secret(priv_b, pubkey_a)
  iex> s1 == s2
  true
  ```

  ## Custom hash function

  As per the [rfc8032 spec](https://www.rfc-editor.org/rfc/rfc8032#section-5.1),
  by default Eddy uses the `sha512` hash function internally. Optionally,
  a custom hash function can be configured in your application's
  `config/config.exs`.

  *The custom hash function **must** return 64 bytes.*

  ```elixir
  import Config

  # The hash function will be invoked as `:crypto.hash(:sha3_512, payload)`
  config :eddy, hash_fn: {:crypto, :hash, [:sha3_512], []}

  # The hash function will be invoked as `B3.hash(payload, length: 64)`
  config :eddy, hash_fn: {B3, :hash, [], [[length: 64]]}
  ```
  """
  use Eddy.Hash
  alias Eddy.{
    ExtendedPoint,
    Point,
    PrivKey,
    PubKey,
    Serializable,
    Sig,
    Util,
    X25519,
  }
  alias Serializable.Encoder

  @typedoc """
  Private Key.

  Are represented as [`PrivKey structs`](`t:Eddy.PrivKey.t/0`) or 32 byte binaries.
  """
  @type privkey() :: PrivKey.t() | binary()

  @typedoc """
  Public Key.

  Are represented as [`PubKey structs`](`t:Eddy.PubKey.t/0`) or 32 byte binaries.
  """
  @type pubkey() :: PubKey.t() | binary()

  @typedoc """
  Signature.

  Are represented as [`Sig structs`](`t:Eddy.Sig.t/0`) or 64 byte binaries.
  """
  @type sig() :: Sig.t() | binary()

  @typedoc """
  Binary encoding format.

  Eddy can encoding keys and signatures in raw, base16 or base64 encodings.
  Hex is as base16, but with lower case letters.
  """
  @type encoding() :: :raw | :base16 | :base64 | :hex

  @typedoc false
  @type encodable() :: Point.t() | PrivKey.t() | PubKey.t() | Sig.t()

  @params %{
    p: 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED,
    a: -0x01,
    d: 0x52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3,
    G: %Point{
      x: 0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A,
      y: 0x6666666666666666666666666666666666666666666666666666666666666658,
    },
    l: 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED,
    h: 0x08,
  }

  @doc false
  defdelegate mod(number, modulo \\ @params.p), to: Util

  @doc """
  Returns the `Ed25519` elliptic curve parameters.
  """
  @spec params() :: map()
  def params(), do: @params

  @doc """
  Generates a new random private key.

  The private key can optionally be returned as a raw or encoded binary.

  ## Options

  - `:encoding` - Optionally encode with a binary `t:encoding/0`.

  ## Examples

  ```elixir
  iex> privkey = Eddy.generate_key()
  %Eddy.PrivKey{}

  iex> privkey = Eddy.generate_key(encoding: :raw)
  <<182, 7, 194, 105, 23, 114, 238, 195, 188, 101, 41, 99, 155, 2, 174, 52, 187,
  235, 72, 4, 221, 189, 111, 49, 33, 240, 224, 53, 161, 77, 253, 50>>

  iex> privkey = Eddy.generate_key(encoding: :hex)
  "3056ade0bc0215aa21db1dfddd3ea6786a4127b28efddb7e9b6af9845b8ef57a"
  ```
  """
  @spec generate_key(keyword()) :: privkey()
  def generate_key(opts \\ []) do
    d = :crypto.strong_rand_bytes(32)

    case Keyword.get(opts, :encoding) do
      nil -> %PrivKey{ d: d }
      enc -> encode(d, enc)
    end
  end

  @doc """
  Takes a private key and returns the corresponding public key.

  Acceps a private key struct or raw binary. The public key can optionally be
  returned as a raw or encoded binary.

  ## Options

  - `:encoding` - Optionally encode with a binary `t:encoding/0`.

  ## Examples

  ```elixir
  iex> pubkey = Eddy.get_pubkey(privkey)
  %Eddy.PubKey{}

  iex> pubkey = Eddy.get_pubkey(privkey, encoding: :hex)
  "9dcfaa3dca4a02da72c500885dd6824a7c9abb76b88f9e3f10378f33c56d2465"
  ```
  """
  @spec get_pubkey(privkey(), keyword()) :: pubkey()
  def get_pubkey(privkey, opts \\ [])
  def get_pubkey(%PrivKey{d: d}, opts), do: get_pubkey(d, opts)
  def get_pubkey(privkey, opts)
    when is_binary(privkey)
    and byte_size(privkey) == 32
  do
    {point, _, _, _} = calculate_point(privkey)

    case Keyword.get(opts, :encoding) do
      nil -> %PubKey{point: point}
      enc -> encode(point, enc)
    end
  end

  @doc """
  Computes an ECDH shared secret from the given private and public keys.

  Acceps both keys as structs or raw binaries. Returns a 32 byte raw binary
  which can optionally be encoded.

  ## Options

  - `:encoding` - Optionally encode with a binary `t:encoding/0`.

  ## Examples

  ```elixir
  iex> secret = Eddy.get_shared_secret(privkey, pubkey)
  <<109, 226, 95, 89, 0, 39, 15, 239, 181, 187, 28, 242, 106, 214, 8, 227, 116,
  66, 47, 52, 133, 10, 111, 113, 107, 173, 191, 203, 207, 135, 18, 114>>

  iex> secret = Eddy.get_shared_secret(privkey, pubkey, encoding: :hex)
  "6de25f5900270fefb5bb1cf26ad608e374422f34850a6f716badbfcbcf871272"
  ```
  """
  @spec get_shared_secret(privkey(), pubkey(), keyword()) :: binary()
  def get_shared_secret(privkey, pubkey, opts \\ [])

  def get_shared_secret(%PrivKey{d: d}, pubkey, opts),
    do: get_shared_secret(d, pubkey, opts)

  def get_shared_secret(privkey, pubkey, opts)
    when is_binary(pubkey)
    and byte_size(pubkey) == 32
  do
    with {:ok, pubkey, _rest} <- Encoder.parse(struct(PubKey), pubkey) do
      get_shared_secret(privkey, pubkey, opts)
    else
      _ -> raise "invalid pubkey"
    end
  end

  def get_shared_secret(d, %PubKey{point: point}, opts)
    when is_binary(d)
    and byte_size(d) == 32
  do
    encoding = Keyword.get(opts, :encoding)
    {_, head, _, _} = calculate_point(d)
    u = X25519.from_point(point)
    head
    |> X25519.scalar_mult(u)
    |> encode(encoding)
  end

  @doc """
  Signs the message with the given private key.

  Acceps a private key struct or raw binary. The signature can optionally be
  returned as a raw or encoded binary.

  ## Options

  - `:encoding` - Optionally encode with a binary `t:encoding/0`.

  ## Examples

  ```elixir
  iex> sig = Eddy.sign("test", privkey)
  %Eddy.Sig{}

  iex> sig = Eddy.sign("test", privkey, encoding: :base)
  "uS5X1ek6+aHAYGMEMWLF5+O9W8rxK6HDHHI2QOoBOReVaAsf5sFSI3Dqvms4LUtecW/ILAOaWS1L737ye6dkBg=="
  ```
  """
  @spec sign(binary(), privkey(), keyword()) :: sig()
  def sign(message, privkey, opts \\ [])
  def sign(message, %PrivKey{d: d}, opts), do: sign(message, d, opts)
  def sign(message, privkey, opts)
    when is_binary(message)
    and is_binary(privkey)
    and byte_size(privkey) == 32
  do
    {point, _head, prefix, scalar} = calculate_point(privkey)

    r = hash(prefix <> message)
    |> :binary.decode_unsigned(:little)
    |> mod(@params.l)

    r_point = Point.mul(@params[:G], r)

    k = Encoder.serialize(r_point)
    |> Kernel.<>(Encoder.serialize(point))
    |> Kernel.<>(message)
    |> hash()
    |> :binary.decode_unsigned(:little)
    |> mod(@params.l)

    s = mod(r + k * scalar, @params.l)
    sig = %Sig{r: r_point, s: s}

    case Keyword.get(opts, :encoding) do
      nil -> sig
      enc -> encode(sig, enc)
    end
  end

  @doc """
  Verifies the signature against the given message and public key. Returns a
  boolean or error tuple.

  Acceps a public key struct or raw binary. The signature can optionally be
  decoded from a raw or encoded binary.

  ## Options

  - `:encoding` - Optionally decode from a binary `t:encoding/0`.

  ## Examples

  ```elixir
  iex> Eddy.verify(sig, "test", pubkey)
  true

  iex> sig = "uS5X1ek6+aHAYGMEMWLF5+O9W8rxK6HDHHI2QOoBOReVaAsf5sFSI3Dqvms4LUtecW/ILAOaWS1L737ye6dkBg=="
  iex> Eddy.verify(sig, "test", pubkey, encoding: :base64)
  true
  ```
  """
  @spec verify(sig(), binary(), pubkey(), keyword()) ::
    boolean() |
    {:error, term()}
  def verify(sig, message, pubkey, opts \\ [])

  def verify(sig, message, pubkey, opts)
    when is_binary(pubkey)
    and byte_size(pubkey) == 32
  do
    with {:ok, pubkey, _rest} <- Encoder.parse(struct(PubKey), pubkey) do
      verify(sig, message, pubkey, opts)
    end
  end

  def verify(sig, message, %PubKey{} = pubkey, opts) when is_binary(sig) do
    encoding = Keyword.get(opts, :encoding)
    with {:ok, sig} when byte_size(sig) == 64 <- Util.decode(sig, encoding),
         {:ok, sig, ""} <- Encoder.parse(struct(Sig), sig)
    do
      verify(sig, message, pubkey, opts)
    else
      {:ok, _} -> {:error, {:decode_error, "invalid sig length"}}
      {:ok, _, _} -> {:error, {:decode_error, "invalid sig length"}}
    end
  end

  def verify(%Sig{r: r_point, s: s}, message, %PubKey{point: point}, _opts)
    when is_binary(message)
  do
    sb = @params[:G]
    |> ExtendedPoint.from_point()
    |> ExtendedPoint.mul!(s)

    k = r_point
    |> Encoder.serialize()
    |> Kernel.<>(Encoder.serialize(point))
    |> Kernel.<>(message)
    |> hash()
    |> :binary.decode_unsigned(:little)
    |> mod(@params.l)

    ka = point
    |> ExtendedPoint.from_point()
    |> ExtendedPoint.mul!(k)

    r_point
    |> ExtendedPoint.from_point()
    |> ExtendedPoint.add(ka)
    |> ExtendedPoint.sub(sb)
    |> ExtendedPoint.mul!(@params.h)
    |> ExtendedPoint.eq(%ExtendedPoint{x: 0, y: 1, z: 1, t: 0})
  end

  # Calculates the point from a private key, along with additional info
  @spec calculate_point(binary()) :: {Point.t(), binary(), binary(), integer()}
  defp calculate_point(privkey) when is_binary(privkey) do
    <<head::binary-32, prefix::binary-32>> = hash(privkey)

    scalar = head
    |> X25519.adjust_bytes()
    |> :binary.decode_unsigned(:little)
    |> mod(@params.l)

    point = Point.mul(@params[:G], scalar)
    {point, head, prefix, scalar}
  end

  # Encode helper method
  @spec encode(encodable() | binary(), atom()) :: encodable() | binary()
  defp encode(item, enc) when is_binary(item), do: Util.encode(item, enc)
  defp encode(item, enc), do: Encoder.serialize(item) |> Util.encode(enc)

end
