defmodule Eddy.PointTest do
  use ExUnit.Case, async: true
  alias Eddy.Point

  @base Map.get(Eddy.params(), :G)

  describe "mul/2" do
    vectors = [
      {0x90af56259a4b6bfbc4337980d5d75fbe3c074630368ff3804d33028e5dbfa77, "0f3b913371411b27e646b537e888f685bf929ea7aab93c950ed84433f064480d"},
      {0x364e8711a60780382a5d57b061c126f039940f28a9e91fe039d4d3094d8b88,  "ad545340b58610f0cd62f17d55af1ab11ecde9c084d5476865ddb4dbda015349"},
      {0xb9bf90ff3abec042752cac3a07a62f0c16cfb9d32a3fc2305d676ec2d86e941, "e097c4415fe85724d522b2e449e8fd78dd40d20097bdc9ae36fe8ec6fe12cb8c"},
      {0x69d896f02d79524c9878e080308180e2859d07f9f54454e0800e8db0847a46e, "f12cb7c43b59971395926f278ce7c2eaded9444fbce62ca717564cb508a0db1d"},
    ]

    for {vector, i} <- Enum.with_index(vectors) do
      test "calculates correct pubkey [#{i}]" do
        {scalar, pubkey_hex} = unquote(Macro.escape(vector))
        pubkey =
          Point.mul(@base, scalar)
          |> Eddy.Serializable.Encoder.serialize()

        assert Eddy.Util.encode(pubkey, :hex) == pubkey_hex
      end
    end
  end

end
