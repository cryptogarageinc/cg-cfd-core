#include "gtest/gtest.h"

#include "wally_core.h"
#include "cfdcore_secp256k1.h"
#include "cfdcore/cfdcore_exception.h"

using cfdcore::CfdException;
using cfdcore::ByteData;
using cfdcore::Secp256k1;

typedef struct {
  std::vector<ByteData> pubkeys;
  std::string expect;
} CombinePubkeyTestVector;

typedef struct {
  ByteData pubkey;
  ByteData tweak;
  bool is_check;
  std::string expect;
} AddTweakPubkeyTestVector;

// @formatter:off
const std::vector<CombinePubkeyTestVector> combine_test_vectors = {
    {
        {
            ByteData("03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9"),
            ByteData("0261e37f277f02a977b4f11eb5055abab4990bbf8dee701119d88df382fcc1fafe"),
        },
        "022a66efd1ea9b1ad3acfcc62a5ce8c756fa6fc3917fce3d4952a8701244ed1049"
    },
    {
        {
            ByteData("04fb82cb7d7bc1454f777582971473e702fbd058d40fe0958a9baecc37b89f7b0e92e67ae4804fc1da350f13d8be66dea93cbb2f8e78f178f661c30d7eead45a80"),
            ByteData("046a4f0992f7005360d32cfa9bcd3a1d46090e2420b1848844756f33d3ade4cb6f8f12dc43e8ccae87bd352156f727cde9c3f03e348928c1b20de8ee92e31f0078"),
        },
        "035ea9a4c685365c1c4bd74e1762f2c6c530d424389fc3b748d265811c9ed7263f"
    },
    {
        {
            ByteData("061282d671e177781d5eaa18526b12066a7cb24708372e4d1092c493b7bd3fa9c28d771e462289ae968b17e2a075ff8fa143371f04c77991c599bc8d8bafdf07ba"),
            ByteData("076468efc14b8512007bb720d6e7d4217a6686095a79b57e50dd48355110422955400e1a8f159b5dcea116049d09eb756b80d52aeaabb195b343cf713f62f01a73"),
        },
        "02022628a92f5f920dfc56242f5f6fc426c66541d02c212de583615843129d281f"
    },
    {
        {
            ByteData("03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9"),
            ByteData("04fb82cb7d7bc1454f777582971473e702fbd058d40fe0958a9baecc37b89f7b0e92e67ae4804fc1da350f13d8be66dea93cbb2f8e78f178f661c30d7eead45a80"),
        },
        "02239519ec61760ca0bae700d96581d417d9a37dddfc1eb54b9cd5da3788d387b3"
    },
    {
        {
            ByteData("046a4f0992f7005360d32cfa9bcd3a1d46090e2420b1848844756f33d3ade4cb6f8f12dc43e8ccae87bd352156f727cde9c3f03e348928c1b20de8ee92e31f0078"),
            ByteData("0261e37f277f02a977b4f11eb5055abab4990bbf8dee701119d88df382fcc1fafe"),
        },
        "0388ed12c2b6e97ce020b916872b3c7a6f1da1d21a5d21b567d167de0c1f3ff37f"
    },
    {
        {
            ByteData("0261e37f277f02a977b4f11eb5055abab4990bbf8dee701119d88df382fcc1fafe"),
            ByteData("061282d671e177781d5eaa18526b12066a7cb24708372e4d1092c493b7bd3fa9c28d771e462289ae968b17e2a075ff8fa143371f04c77991c599bc8d8bafdf07ba"),
        },
        "0369ff8964bb335ec84fa132ab7cb7878b28741e24ea8dc39017dc048f97f8a9ff"
    },
    {
        {
            ByteData("03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9"),
            ByteData("076468efc14b8512007bb720d6e7d4217a6686095a79b57e50dd48355110422955400e1a8f159b5dcea116049d09eb756b80d52aeaabb195b343cf713f62f01a73"),
        },
        "03d8d6501f1619206d947281f818d42f9a387339dcf614bdb0bdb0b02367d67021"
    },
    {
        {
            ByteData("046a4f0992f7005360d32cfa9bcd3a1d46090e2420b1848844756f33d3ade4cb6f8f12dc43e8ccae87bd352156f727cde9c3f03e348928c1b20de8ee92e31f0078"),
            ByteData("061282d671e177781d5eaa18526b12066a7cb24708372e4d1092c493b7bd3fa9c28d771e462289ae968b17e2a075ff8fa143371f04c77991c599bc8d8bafdf07ba"),
        },
        "02ed3801bf14c64a5822127a3686d35423abe4004fc069720fcbe5ddd1d09dde4a"
    },
    {
        {
            ByteData("076468efc14b8512007bb720d6e7d4217a6686095a79b57e50dd48355110422955400e1a8f159b5dcea116049d09eb756b80d52aeaabb195b343cf713f62f01a73"),
            ByteData("04fb82cb7d7bc1454f777582971473e702fbd058d40fe0958a9baecc37b89f7b0e92e67ae4804fc1da350f13d8be66dea93cbb2f8e78f178f661c30d7eead45a80"),
        },
        "026356a05be3fcf52a57e133b7fb1cdb52a1bf14ef43f7d053e79b2ac98d5c2dd3"
    },
    {
        {
            ByteData("0325bc01103946d17de22549fbc6e9b6a61d0e6a1043a219583a7b371163d139d4"),
            ByteData("03d9e6667b5e1bd4e9308fa4499aec7e9dcd0f35f1aa60e5adc66bd663abfdb98a"),
            ByteData("02a132258eb22f0bb943adf317aceeedb11eeab8a24bf205d1a5e1c8ba8149d347"),
        },
        "0245bd1dbb9ff255c42a421d38e99f9558bd19bfb28246dc73aca5bfdcfe699dc9"
    }
};
// @formatter:on

TEST(Secp256k1, CombinePubkeySecp256k1EcTest) {
  struct secp256k1_context_struct *cxt = wally_get_secp_context();
  Secp256k1 secp = Secp256k1(cxt);
  for (CombinePubkeyTestVector test_vector : combine_test_vectors) {
    ByteData actual;
    EXPECT_NO_THROW(
        actual = secp.CombinePubkeySecp256k1Ec(test_vector.pubkeys));
    EXPECT_EQ(test_vector.expect, actual.GetHex());
  }
}

// @formatter:off
const std::vector<CombinePubkeyTestVector> combine_error_vectors = {
    // pass less than two pubkeys
    {
        {
        },
        ""
    },
    {
        {
            ByteData("03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9"),
        },
        ""
    },
    // invalid Data size
    {
        {
            ByteData("03662a01c232918c9deb3b330272483c3e4e"),
            ByteData("0261e37f277f02a977b4f11eb5055abab499"),
        },
        ""
    },
    // invalid ec pubkey data
    {
        {
            ByteData("01662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9"),
            ByteData("0061e37f277f02a977b4f11eb5055abab4990bbf8dee701119d88df382fcc1fafe"),
        },
        ""
    },
};
// @formatter:on

TEST(Secp256k1, EmptyContextErrorTest) {
  struct secp256k1_context_struct *cxt = nullptr;
  Secp256k1 secp = Secp256k1(cxt);

  std::vector<ByteData> test_vector =
      { ByteData(
          "03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9"),
          ByteData(
              "0261e37f277f02a977b4f11eb5055abab4990bbf8dee701119d88df382fcc1fafe") };
  EXPECT_THROW(ByteData actual = secp.CombinePubkeySecp256k1Ec(test_vector),
               CfdException);
}

TEST(Secp256k1, CombinePubkeySecp256k1EcErrorCaseTest) {
  struct secp256k1_context_struct *cxt = wally_get_secp_context();
  Secp256k1 secp = Secp256k1(cxt);
  for (CombinePubkeyTestVector test_vector : combine_error_vectors) {
    EXPECT_THROW(
        ByteData actual = secp.CombinePubkeySecp256k1Ec(test_vector.pubkeys),
        CfdException);
  }
}


// @formatter:off
const std::vector<AddTweakPubkeyTestVector> tweak_test_vectors = {
    // pass less than two pubkeys
    {
        ByteData("03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9"),
        ByteData("03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5"),
        true,
        "02f7eb7db42b05503b0ab66523044044b0a1a96b73d41016da956b3483a1bbdd2f"
    },
    {
        ByteData("0261e37f277f02a977b4f11eb5055abab4990bbf8dee701119d88df382fcc1fafe"),
        ByteData("03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5"),
        false,
        "03b34e7d886ba9cccbe1f7ee2b021e99cd5a3c858c8f7af485409f3d6b839ce372"
    },
};

const std::vector<AddTweakPubkeyTestVector> tweak_error_vectors = {
  // invalid pubkey size(len isn't 33)
  {
    ByteData(""),
    ByteData("03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5"),
    true,
    ""
  },
  // empty pubkey
  {
    ByteData(""),
    ByteData("03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9"),
    true,
    ""
  },
  // invalid tweak size(len isn't 32)
  {
    ByteData("03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9"),
    ByteData("03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9"),
    true,
    ""
  },
  // empty tweak
  {
    ByteData("03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9"),
    ByteData(""),
    true,
    ""
  },
};
// @formatter:on

TEST(Secp256k1, AddTweakPubkeySecp256k1EcTest) {
  struct secp256k1_context_struct *cxt = wally_get_secp_context();
  Secp256k1 secp = Secp256k1(cxt);
  for (AddTweakPubkeyTestVector test_vector : tweak_test_vectors) {
    ByteData actual;
    EXPECT_NO_THROW(
        actual = secp.AddTweakPubkeySecp256k1Ec(test_vector.pubkey,
            test_vector.tweak, test_vector.is_check));
    EXPECT_EQ(test_vector.expect, actual.GetHex());
  }
}

TEST(Secp256k1, AddTweakPubkeySecp256k1EcErrorTest) {
  struct secp256k1_context_struct *cxt = wally_get_secp_context();
  Secp256k1 secp = Secp256k1(cxt);
  for (AddTweakPubkeyTestVector test_vector : tweak_error_vectors) {
    EXPECT_THROW(
        ByteData actual = secp.AddTweakPubkeySecp256k1Ec(test_vector.pubkey,
            test_vector.tweak, test_vector.is_check),
        CfdException);
  }
}
