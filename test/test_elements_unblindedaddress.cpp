#ifndef CFD_DISABLE_ELEMENTS

#include "gtest/gtest.h"
#include <string>
#include <vector>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_elements_address.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_script.h"
#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_util.h"
#include "cfdcore/cfdcore_exception.h"

using cfdcore::ElementsNetType;
using cfdcore::ElementsAddressType;
using cfdcore::AbstractElementsAddress;
using cfdcore::ElementsUnblindedAddress;
using cfdcore::Pubkey;
using cfdcore::Script;
using cfdcore::ByteData160;
using cfdcore::HashUtil;
using cfdcore::CfdException;

typedef struct {
  std::string address;
  ElementsNetType net_type;
  ElementsAddressType addr_type;
  Pubkey pubkey;
  Script script;
} ElementsUnblindedAddressTestVector;

// @formatter:off
const std::vector<ElementsUnblindedAddressTestVector> test_vectors = {
  // mainnet p2pkh address
  {
    "QBF1353wcFYkri4efzX9HLjsoc2Tx6Lxfd",
    ElementsNetType::kLiquidV1,
    ElementsAddressType::kElementsP2pkhAddress,
    Pubkey("02d21c625759280111907a06df050cccbc875b11a50bdafa71dae5d1e8695ba82e"),
    Script(),
  },
  {
    "Q58YfnS7p1NVZDTp9wTcrB5pveMbVae3Lh",
    ElementsNetType::kLiquidV1,
    ElementsAddressType::kElementsP2pkhAddress,
    Pubkey("0345a0bab3022003ed107cd91b6fb6e3479d5ebdd2da8af6ddc29ab39f51a04d97"),
    Script(),
  },
  // mainnet p2sh address
  // p2sh-segwit
  {
    "GzYc1b58torxLcWAnSDGhzqiJZAv29eFVS",
    ElementsNetType::kLiquidV1,
    ElementsAddressType::kElementsP2shAddress,
    Pubkey(),
    Script("0014994ee81a59f1ada3f4c3997c54f0401b5f539df0"),
  },
  // multisig
  {
    "GjGb5o2GnTisuL8aiWkwdsRvKh7bPQS4Tv",
    ElementsNetType::kLiquidV1,
    ElementsAddressType::kElementsP2shAddress,
    Pubkey(),
    Script("522103a7bd50beb3aff9238336285c0a790169eca90b7ad807abc4b64897ca1f6dedb621039cbaf938d050dd2582e4c2f56d1f75cfc9d165f2f3270532363d9871fb7be14252ae"),
  },
  // regtest p2pkh address
  {
    "2dwGUKGZVKiRRN9TG5NeEgCqHT5PGjMqKTW",
    ElementsNetType::kElementsRegtest,
    ElementsAddressType::kElementsP2pkhAddress,
    Pubkey("03b301154568626491d4a698aa01768d7a273415646512edb5757c5c6cf5fb9f89"),
    Script(),
  },
  {
    "2dZq5CkTo2S6ejf9XSuuHSY8JsJDnaja542",
    ElementsNetType::kElementsRegtest,
    ElementsAddressType::kElementsP2pkhAddress,
    Pubkey("02d1337e4c15717a32a199cd4502d7c6b55f1b2534df21859363e4f24780974981"),
    Script(),
  },
  // regtest p2sh address
  // p2sh-segwit
  {
    "XBvES4D9QH2dXjcoe5KQFT8kG6d3n7zcJ2",
    ElementsNetType::kElementsRegtest,
    ElementsAddressType::kElementsP2shAddress,
    Pubkey(),
    Script("0014ef919b362c325291d3f24a3aff28ec811964f078"),
  },
  // p2sh multisig
  {
    "XTfKFxkeC83awc3HnPFbZxgMRdBAjDpDbc",
    ElementsNetType::kElementsRegtest,
    ElementsAddressType::kElementsP2shAddress,
    Pubkey(),
    Script("522102723d9fb5ad0c7f7d70c897731bcf6a58a4dee8113d7d848bff9f6f7bc01ff36621023bf567600a7972e22ac50eef693f05935cbcf48fb7bb550d7ab7e050f98567e352ae"),
  },
};
// @formatter:on

TEST(ElementsUnblindedAddress, StringConstructorTest) {
  for (ElementsUnblindedAddressTestVector test : test_vectors) {
    // string constructor
    {
      ElementsUnblindedAddress addr = ElementsUnblindedAddress(test.address);

      EXPECT_FALSE(AbstractElementsAddress::IsConfidentialAddress(test.address));
      EXPECT_FALSE(addr.IsBlinded());
      EXPECT_STREQ(test.address.c_str(), addr.GetAddress().c_str());
      EXPECT_EQ(test.net_type, addr.GetNetType());
      EXPECT_EQ(test.addr_type, addr.GetAddressType());
      ByteData160 hash;
      if (addr.GetAddressType() == ElementsAddressType::kElementsP2pkhAddress) {
        hash = HashUtil::Hash160(test.pubkey);
      } else if (addr.GetAddressType()
          == ElementsAddressType::kElementsP2shAddress) {
        hash = HashUtil::Hash160(test.script);
      } else {
        // invalid address type
        ASSERT_FALSE(true);
      }
      EXPECT_STREQ(hash.GetHex().c_str(), addr.GetHash().GetHex().c_str());
    }
  }
}

TEST(ElementsUnblindedAddress, SourceDataConstructorTest) {
  for (ElementsUnblindedAddressTestVector test : test_vectors) {
    // pubkey/script constructor
    {
      ElementsUnblindedAddress addr;
      ByteData160 hash;
      // p2pkh constructor
      if (!test.pubkey.GetHex().empty()) {
        addr = ElementsUnblindedAddress(test.net_type, test.pubkey);

        hash = HashUtil::Hash160(test.pubkey);
      }
      // p2sh constructor
      else if (!test.script.GetHex().empty()) {
        addr = ElementsUnblindedAddress(test.net_type, test.script);

        hash = HashUtil::Hash160(test.script);
      }

      EXPECT_FALSE(AbstractElementsAddress::IsConfidentialAddress(test.address));
      EXPECT_FALSE(addr.IsBlinded());
      EXPECT_STREQ(test.address.c_str(), addr.GetAddress().c_str());
      EXPECT_EQ(test.net_type, addr.GetNetType());
      EXPECT_EQ(test.addr_type, addr.GetAddressType());
      EXPECT_STREQ(hash.GetHex().c_str(), addr.GetHash().GetHex().c_str());
    }
  }
}

TEST(ElementsUnblindedAddress, HashDataConstructorTest) {
  for (ElementsUnblindedAddressTestVector test : test_vectors) {
    // hash data constructor
    {
      ElementsNetType net_type = test.net_type;
      ElementsAddressType addr_type = ElementsAddressType::kUnknownElementsAddressType;
      ByteData160 hash;
      // p2pkh constructor
      if (!test.pubkey.GetHex().empty()) {
        addr_type = ElementsAddressType::kElementsP2pkhAddress;
        hash = HashUtil::Hash160(test.pubkey);
      }
      // p2sh constructor
      else if (!test.script.GetHex().empty()) {
        addr_type = ElementsAddressType::kElementsP2shAddress;
        hash = HashUtil::Hash160(test.script);
      }
      ElementsUnblindedAddress addr = ElementsUnblindedAddress(net_type, addr_type,
                                                           hash);

      EXPECT_FALSE(AbstractElementsAddress::IsConfidentialAddress(test.address));
      EXPECT_FALSE(addr.IsBlinded());
      EXPECT_STREQ(test.address.c_str(), addr.GetAddress().c_str());
      EXPECT_EQ(test.net_type, addr.GetNetType());
      EXPECT_EQ(test.addr_type, addr.GetAddressType());
      EXPECT_STREQ(hash.GetHex().c_str(), addr.GetHash().GetHex().c_str());
    }
  }
}

TEST(ElementsUnblindedAddressErrorCase, InvalidAddressTest) {
  ElementsUnblindedAddress addr;
  // invalid address prefix [base58(01 + pubkey hash)]
  EXPECT_THROW(ElementsUnblindedAddress("C76uVp7JJqeUKht3wQXajaaGvUJAfEDnPx"),
      CfdException)<< "pref";
  // invalid hash length (10byte)
  EXPECT_THROW(ElementsUnblindedAddress("7bJDuZXuDVSiYB6QXb5fn"), CfdException)<< "len";

  ByteData160 hash =
      HashUtil::Hash160(
          Pubkey(
              "02d21c625759280111907a06df050cccbc875b11a50bdafa71dae5d1e8695ba82e"));
  // invalid net type
  EXPECT_THROW(ElementsUnblindedAddress(ElementsNetType::kElementsNetTypeNum, ElementsAddressType::kElementsP2pkhAddress, hash), CfdException)<< "net";
  // invalid address type
  EXPECT_THROW(ElementsUnblindedAddress(ElementsNetType::kElementsRegtest, ElementsAddressType::kUnknownElementsAddressType, hash), CfdException)<< "addr";
}

#endif  // CFD_DISABLE_ELEMENTS
