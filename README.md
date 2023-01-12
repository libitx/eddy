# Eddy

![Hex.pm](https://img.shields.io/hexpm/v/eddy?color=informational)
![License](https://img.shields.io/github/license/libitx/eddy?color=informational)
![Build Status](https://img.shields.io/github/actions/workflow/status/libitx/eddy/elixir.yml?branch=main)

Eddy is a pure elixir implementation of `Ed25519`, an elliptic curve that can be
used in signature schemes and ECDH shared secrets.

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

For further examples, refer to the [full documentation](https://hexdocs.pm/eddy).

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

ECDH shared secrets are computed by multiplying a public key with a private key.
The operation yields the same result in both directions.

```elixir
iex> s1 = Eddy.get_shared_secret(priv_a, pubkey_b)
iex> s2 = Eddy.get_shared_secret(priv_b, pubkey_a)
iex> s1 == s2
true
```

## Custom hash function

As per the [rfc8032 spec](https://www.rfc-editor.org/rfc/rfc8032#section-5.1),
by default Eddy uses the `sha512` hash function internally. Optionally, a custom
hash function can be configured in your application's
`config/config.exs`.

*The custom hash function **must** return 64 bytes.*

```elixir
import Config

# The hash function will be invoked as `:crypto.hash(:sha3_512, payload)`
config :eddy, hash_fn: {:crypto, :hash, [:sha3_512], []}

# The hash function will be invoked as `B3.hash(payload, length: 64)`
config :eddy, hash_fn: {B3, :hash, [], [[length: 64]]}
```

## Disclaimer

The code in this library is well tested against offical test vectors. That said,
I am not a cryptographer or mathemetician. The code has not been audited or
battle-tested against known attacks. Proceed at your own risk. If you're after
the most performant and battle tested code, consider using C or Rust bindings.

What this library offers is a simple and small interface for common
functionality. Written in pure Elixir, it is a lighter-weight option without the
compilation complexities of NIF bindings.

I am very grateful to the author of [noble-ed25519](https://github.com/paulmillr/noble-ed25519)
which has been an invaluable reference in creating the library.

## License

Eddy is open source and released under the [Apache-2 License](https://github.com/libitx/eddy/blob/master/LICENSE).

© Copyright 2023 [Chronos Labs Ltd](https://www.chronoslabs.net/).
