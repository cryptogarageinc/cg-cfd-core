#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_util.h"
#include "cfdcore/cfdcore_address.h"

using cfdcore::Address;
using cfdcore::NetType;
using cfdcore::WitnessVersion;
using cfdcore::AddressType;
using cfdcore::Pubkey;
using cfdcore::ByteData;
using cfdcore::ByteData160;
using cfdcore::ByteData256;
using cfdcore::HashUtil;
using cfdcore::Script;
using cfdcore::ScriptBuilder;
using cfdcore::ScriptOperator;
using cfdcore::CfdException;
using cfdcore::NetParams;

TEST(Address, EmptyAddressTest) {
  Address empty_address;
  EXPECT_STREQ("", empty_address.GetAddress().c_str());

  EXPECT_THROW((empty_address = Address("")), CfdException);
}

TEST(Address, P2pkhAddressTest) {
  const Pubkey pubkey = Pubkey(
      "027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af");
  Address address;
  EXPECT_NO_THROW((address = Address(NetType::kMainnet, pubkey)));
  EXPECT_STREQ("1ELuNB5fLNUcrLzb93oJDPmjxjnsVwhNHn", address.GetAddress().c_str());
  EXPECT_EQ(NetType::kMainnet, address.GetNetType());
  EXPECT_EQ(AddressType::kP2pkhAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersionNone, address.GetWitnessVersion());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af",
               address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("", address.GetScript().GetHex().c_str());

  EXPECT_NO_THROW((address = Address(NetType::kTestnet, pubkey)));
  EXPECT_STREQ("mtrrfEAe9PusdTUCrcmg3Jz4pjPaSnTiCc",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kTestnet, address.GetNetType());

  EXPECT_NO_THROW((address = Address(NetType::kRegtest, pubkey)));
  EXPECT_STREQ("mtrrfEAe9PusdTUCrcmg3Jz4pjPaSnTiCc",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kRegtest, address.GetNetType());
}

TEST(Address, P2shAddressTest) {
  const Pubkey pubkey = Pubkey(
      "027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af");
  ByteData160 pubkey_hash = HashUtil::Hash160(pubkey);
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_DUP);
  builder.AppendOperator(ScriptOperator::OP_HASH160);
  builder.AppendData(pubkey_hash);
  builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
  const Script &script = builder.Build();

  Address address;
  EXPECT_NO_THROW((address = Address(NetType::kMainnet, script)));
  EXPECT_STREQ("3K4cCA6U45jhvBcgc8qEdjHGDGyUMuVRpG",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kMainnet, address.GetNetType());
  EXPECT_EQ(AddressType::kP2shAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersionNone, address.GetWitnessVersion());
  EXPECT_STREQ("be8f7ae2233fc122be82f2cf9fe3cc2c6196218a",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("", address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("76a914925d4028880bd0c9d68fbc7fc7dfee976698629c88ac",
               address.GetScript().GetHex().c_str());

  EXPECT_NO_THROW((address = Address(NetType::kTestnet, script)));
  EXPECT_STREQ("2NAcpFu2VfYF47yFEHGT7FgGXRdBeBHNfHU",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kTestnet, address.GetNetType());

  EXPECT_NO_THROW((address = Address(NetType::kRegtest, script)));
  EXPECT_STREQ("2NAcpFu2VfYF47yFEHGT7FgGXRdBeBHNfHU",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kRegtest, address.GetNetType());
}

TEST(Address, P2wpkhAddressTest) {
  const Pubkey pubkey = Pubkey(
      "027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af");
  Address address;
  EXPECT_NO_THROW((address = Address(NetType::kMainnet,
                   WitnessVersion::kVersion0, pubkey)));
  EXPECT_STREQ("bc1qjfw5q2ygp0gvn450h3lu0hlwjanfsc5uax7v9q",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kMainnet, address.GetNetType());
  EXPECT_EQ(AddressType::kP2wpkhAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersion0, address.GetWitnessVersion());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af",
               address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("", address.GetScript().GetHex().c_str());

  EXPECT_NO_THROW((address = Address(NetType::kTestnet,
                   WitnessVersion::kVersion0, pubkey)));
  EXPECT_STREQ("tb1qjfw5q2ygp0gvn450h3lu0hlwjanfsc5uhq9l7n",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kTestnet, address.GetNetType());

  EXPECT_NO_THROW((address = Address(NetType::kRegtest,
                   WitnessVersion::kVersion0, pubkey)));
  EXPECT_STREQ("bcrt1qjfw5q2ygp0gvn450h3lu0hlwjanfsc5u4fujf6",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kRegtest, address.GetNetType());
}

TEST(Address, P2wshAddressTest) {
  const Pubkey pubkey = Pubkey(
      "027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af");
  ByteData160 pubkey_hash = HashUtil::Hash160(pubkey);
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_DUP);
  builder.AppendOperator(ScriptOperator::OP_HASH160);
  builder.AppendData(pubkey_hash);
  builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
  const Script &script = builder.Build();

  Address address;
  EXPECT_NO_THROW((address = Address(NetType::kMainnet,
                   WitnessVersion::kVersion0, script)));
  EXPECT_STREQ("bc1qcc5c9wnzly8zj2dcsvxv83kupsu0uamx69u0y9lsmw7shuns2gqszafymy",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kMainnet, address.GetNetType());
  EXPECT_EQ(AddressType::kP2wshAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersion0, address.GetWitnessVersion());
  EXPECT_STREQ("c62982ba62f90e2929b8830cc3c6dc0c38fe7766d178f217f0dbbd0bf2705201",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("", address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("76a914925d4028880bd0c9d68fbc7fc7dfee976698629c88ac",
               address.GetScript().GetHex().c_str());

  EXPECT_NO_THROW((address = Address(NetType::kTestnet,
                   WitnessVersion::kVersion0, script)));
  EXPECT_STREQ("tb1qcc5c9wnzly8zj2dcsvxv83kupsu0uamx69u0y9lsmw7shuns2gqs44ltpt",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kTestnet, address.GetNetType());

  EXPECT_NO_THROW((address = Address(NetType::kRegtest,
                   WitnessVersion::kVersion0, script)));
  EXPECT_STREQ("bcrt1qcc5c9wnzly8zj2dcsvxv83kupsu0uamx69u0y9lsmw7shuns2gqscv4d53",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kRegtest, address.GetNetType());
}

TEST(Address, NoSegwitAddressFromHashTest) {
  const Pubkey pubkey = Pubkey(
      "027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af");
  ByteData160 pubkey_hash = HashUtil::Hash160(pubkey);
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_DUP);
  builder.AppendOperator(ScriptOperator::OP_HASH160);
  builder.AppendData(pubkey_hash);
  builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
  const Script &script = builder.Build();
  ByteData160 script_hash = HashUtil::Hash160(script);

  Address address;
  EXPECT_NO_THROW((address = Address(NetType::kMainnet,
                   AddressType::kP2pkhAddress, pubkey_hash)));
  EXPECT_STREQ("1ELuNB5fLNUcrLzb93oJDPmjxjnsVwhNHn",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kMainnet, address.GetNetType());
  EXPECT_EQ(AddressType::kP2pkhAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersionNone, address.GetWitnessVersion());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("", address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("", address.GetScript().GetHex().c_str());

  EXPECT_NO_THROW((address = Address(NetType::kTestnet,
                   AddressType::kP2shAddress, script_hash)));
  EXPECT_STREQ("2NAcpFu2VfYF47yFEHGT7FgGXRdBeBHNfHU",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kTestnet, address.GetNetType());
  EXPECT_EQ(AddressType::kP2shAddress, address.GetAddressType());

  EXPECT_NO_THROW((address = Address(NetType::kRegtest,
                   AddressType::kP2pkhAddress, pubkey_hash)));
  EXPECT_STREQ("mtrrfEAe9PusdTUCrcmg3Jz4pjPaSnTiCc",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kRegtest, address.GetNetType());
  EXPECT_EQ(AddressType::kP2pkhAddress, address.GetAddressType());

  // Illegal data
  EXPECT_THROW((address = Address(NetType::kTestnet,
                   AddressType::kP2wshAddress, script_hash)),
               CfdException);
}

TEST(Address, SegwitAddressFromHashTest) {
  const Pubkey pubkey = Pubkey(
      "027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af");
  ByteData160 pubkey_hash = HashUtil::Hash160(pubkey);
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_DUP);
  builder.AppendOperator(ScriptOperator::OP_HASH160);
  builder.AppendData(pubkey_hash);
  builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
  const Script &script = builder.Build();
  ByteData256 script_hash = HashUtil::Sha256(script);

  Address address;
  EXPECT_NO_THROW((address = Address(NetType::kMainnet,
                   WitnessVersion::kVersion0,
                   ByteData(pubkey_hash.GetBytes()))));
  EXPECT_STREQ("bc1qjfw5q2ygp0gvn450h3lu0hlwjanfsc5uax7v9q",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kMainnet, address.GetNetType());
  EXPECT_EQ(AddressType::kP2wpkhAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersion0, address.GetWitnessVersion());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("", address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("", address.GetScript().GetHex().c_str());

  EXPECT_NO_THROW((address = Address(NetType::kTestnet,
                   WitnessVersion::kVersion0,
                   ByteData(script_hash.GetBytes()))));
  EXPECT_STREQ("tb1qcc5c9wnzly8zj2dcsvxv83kupsu0uamx69u0y9lsmw7shuns2gqs44ltpt",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kTestnet, address.GetNetType());
  EXPECT_EQ(AddressType::kP2wshAddress, address.GetAddressType());

  EXPECT_NO_THROW((address = Address(NetType::kRegtest,
                   WitnessVersion::kVersion0,
                   ByteData(pubkey_hash.GetBytes()))));
  EXPECT_STREQ("bcrt1qjfw5q2ygp0gvn450h3lu0hlwjanfsc5u4fujf6",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kRegtest, address.GetNetType());
  EXPECT_EQ(AddressType::kP2wpkhAddress, address.GetAddressType());

  // Illegal data
  EXPECT_THROW((address = Address(NetType::kRegtest,
                   WitnessVersion::kVersion0, ByteData())),
               CfdException);
}

TEST(Address, NoSegwitAddressFromStringTest) {
  Address address;
  // P2PKH
  EXPECT_NO_THROW((address = Address("1ELuNB5fLNUcrLzb93oJDPmjxjnsVwhNHn")));
  EXPECT_STREQ("1ELuNB5fLNUcrLzb93oJDPmjxjnsVwhNHn",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kMainnet, address.GetNetType());
  EXPECT_EQ(AddressType::kP2pkhAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersionNone, address.GetWitnessVersion());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("", address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("", address.GetScript().GetHex().c_str());

  EXPECT_NO_THROW((address = Address("mtrrfEAe9PusdTUCrcmg3Jz4pjPaSnTiCc")));
  EXPECT_STREQ("mtrrfEAe9PusdTUCrcmg3Jz4pjPaSnTiCc",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kTestnet, address.GetNetType());
  EXPECT_EQ(AddressType::kP2pkhAddress, address.GetAddressType());

  // regtest prefix is equals testnet prefix

  // P2SH
  EXPECT_NO_THROW((address = Address("3K4cCA6U45jhvBcgc8qEdjHGDGyUMuVRpG")));
  EXPECT_STREQ("3K4cCA6U45jhvBcgc8qEdjHGDGyUMuVRpG",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kMainnet, address.GetNetType());
  EXPECT_EQ(AddressType::kP2shAddress, address.GetAddressType());

  EXPECT_NO_THROW((address = Address("2NAcpFu2VfYF47yFEHGT7FgGXRdBeBHNfHU")));
  EXPECT_STREQ("2NAcpFu2VfYF47yFEHGT7FgGXRdBeBHNfHU",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kTestnet, address.GetNetType());
  EXPECT_EQ(AddressType::kP2shAddress, address.GetAddressType());

  // Illegal data
  EXPECT_THROW((address = Address("2NAcpFu2VfYF47yFEHGT7FgGXRdBeBHXfHU")),
               CfdException);
}

TEST(Address, SegwitAddressFromStringTest) {
  Address address;
  EXPECT_NO_THROW((address = Address("bc1qjfw5q2ygp0gvn450h3lu0hlwjanfsc5uax7v9q")));
  EXPECT_STREQ("bc1qjfw5q2ygp0gvn450h3lu0hlwjanfsc5uax7v9q",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kMainnet, address.GetNetType());
  EXPECT_EQ(AddressType::kP2wpkhAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersion0, address.GetWitnessVersion());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("", address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("", address.GetScript().GetHex().c_str());

  EXPECT_NO_THROW((address = Address("tb1qcc5c9wnzly8zj2dcsvxv83kupsu0uamx69u0y9lsmw7shuns2gqs44ltpt")));
  EXPECT_STREQ("tb1qcc5c9wnzly8zj2dcsvxv83kupsu0uamx69u0y9lsmw7shuns2gqs44ltpt",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kTestnet, address.GetNetType());
  EXPECT_EQ(AddressType::kP2wshAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersion0, address.GetWitnessVersion());

  EXPECT_NO_THROW((address = Address("bcrt1qjfw5q2ygp0gvn450h3lu0hlwjanfsc5u4fujf6")));
  EXPECT_STREQ("bcrt1qjfw5q2ygp0gvn450h3lu0hlwjanfsc5u4fujf6",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kRegtest, address.GetNetType());
  EXPECT_EQ(AddressType::kP2wpkhAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersion0, address.GetWitnessVersion());

  // Illegal data
  EXPECT_THROW((address = Address("bcrt1qjfw5q2ygp0gvn450h3lu0hlwjanfsc5u4fujx6")),
               CfdException);
}

TEST(Address, ElementsP2wpkhAddressTest) {
  const Pubkey pubkey = Pubkey(
      "027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af");
  NetParams net_param = {"mainnet", NetType::kMainnet, 235, 75, "ert"};
  Address address;

  EXPECT_NO_THROW((address = Address(NetType::kCustomChain,
                   WitnessVersion::kVersion0, pubkey, net_param.bech32_hrp)));
  EXPECT_STREQ("ert1qjfw5q2ygp0gvn450h3lu0hlwjanfsc5udafvh6",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kCustomChain, address.GetNetType());
  EXPECT_EQ(AddressType::kP2wpkhAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersion0, address.GetWitnessVersion());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af",
               address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("", address.GetScript().GetHex().c_str());

  EXPECT_NO_THROW((address = Address(NetType::kCustomChain,
                   WitnessVersion::kVersion0, pubkey, net_param)));
  EXPECT_STREQ("ert1qjfw5q2ygp0gvn450h3lu0hlwjanfsc5udafvh6",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kCustomChain, address.GetNetType());
  EXPECT_EQ(AddressType::kP2wpkhAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersion0, address.GetWitnessVersion());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af",
               address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("", address.GetScript().GetHex().c_str());
}

TEST(Address, ElementsP2wshAddressTest) {
  const Pubkey pubkey = Pubkey(
      "027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af");
  ByteData160 pubkey_hash = HashUtil::Hash160(pubkey);
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_DUP);
  builder.AppendOperator(ScriptOperator::OP_HASH160);
  builder.AppendData(pubkey_hash);
  builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
  const Script &script = builder.Build();
  NetParams net_param = {"mainnet", NetType::kMainnet, 235, 75, "ert"};

  Address address;
  EXPECT_NO_THROW((address = Address(NetType::kMainnet,
                   WitnessVersion::kVersion0, script, net_param.bech32_hrp)));
  EXPECT_STREQ("ert1qcc5c9wnzly8zj2dcsvxv83kupsu0uamx69u0y9lsmw7shuns2gqsflana4",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kCustomChain, address.GetNetType());
  EXPECT_EQ(AddressType::kP2wshAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersion0, address.GetWitnessVersion());
  EXPECT_STREQ("c62982ba62f90e2929b8830cc3c6dc0c38fe7766d178f217f0dbbd0bf2705201",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("", address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("76a914925d4028880bd0c9d68fbc7fc7dfee976698629c88ac",
               address.GetScript().GetHex().c_str());

  EXPECT_NO_THROW((address = Address(NetType::kMainnet,
                   WitnessVersion::kVersion0, script, net_param)));
  EXPECT_STREQ("ert1qcc5c9wnzly8zj2dcsvxv83kupsu0uamx69u0y9lsmw7shuns2gqsflana4",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kCustomChain, address.GetNetType());
  EXPECT_EQ(AddressType::kP2wshAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersion0, address.GetWitnessVersion());
  EXPECT_STREQ("c62982ba62f90e2929b8830cc3c6dc0c38fe7766d178f217f0dbbd0bf2705201",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("", address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("76a914925d4028880bd0c9d68fbc7fc7dfee976698629c88ac",
               address.GetScript().GetHex().c_str());
}

TEST(Address, ElementsP2pkhAddressTest) {
  const Pubkey pubkey = Pubkey(
      "027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af");
  NetParams net_param = {"mainnet", NetType::kMainnet, 235, 75, "ert"};

  Address address;
  EXPECT_NO_THROW((address = Address(NetType::kMainnet, pubkey, net_param.p2pkh_addr_id)));
  EXPECT_STREQ("2dnmekh8NBmNX3Ckwte5CArjcsHLYdthCg3", address.GetAddress().c_str());
  EXPECT_EQ(NetType::kCustomChain, address.GetNetType());
  EXPECT_EQ(AddressType::kP2pkhAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersionNone, address.GetWitnessVersion());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af",
               address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("", address.GetScript().GetHex().c_str());

  EXPECT_NO_THROW((address = Address(NetType::kMainnet, pubkey, net_param)));
  EXPECT_STREQ("2dnmekh8NBmNX3Ckwte5CArjcsHLYdthCg3", address.GetAddress().c_str());
  EXPECT_EQ(NetType::kCustomChain, address.GetNetType());
  EXPECT_EQ(AddressType::kP2pkhAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersionNone, address.GetWitnessVersion());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af",
               address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("", address.GetScript().GetHex().c_str());
}

TEST(Address, ElementsP2shAddressTest) {
  const Pubkey pubkey = Pubkey(
      "027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af");
  ByteData160 pubkey_hash = HashUtil::Hash160(pubkey);
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_DUP);
  builder.AppendOperator(ScriptOperator::OP_HASH160);
  builder.AppendData(pubkey_hash);
  builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
  const Script &script = builder.Build();
  NetParams net_param = {"mainnet", NetType::kMainnet, 235, 75, "ert"};

  Address address;
  EXPECT_NO_THROW((address = Address(NetType::kMainnet, script, net_param.p2sh_addr_id)));
  EXPECT_STREQ("XUiq7kxdkiB3AXNkKW9YaWLLGb1WBo9xcA",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kCustomChain, address.GetNetType());
  EXPECT_EQ(AddressType::kP2shAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersionNone, address.GetWitnessVersion());
  EXPECT_STREQ("be8f7ae2233fc122be82f2cf9fe3cc2c6196218a",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("", address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("76a914925d4028880bd0c9d68fbc7fc7dfee976698629c88ac",
               address.GetScript().GetHex().c_str());

  EXPECT_NO_THROW((address = Address(NetType::kMainnet, script, net_param)));
  EXPECT_STREQ("XUiq7kxdkiB3AXNkKW9YaWLLGb1WBo9xcA",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kCustomChain, address.GetNetType());
  EXPECT_EQ(AddressType::kP2shAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersionNone, address.GetWitnessVersion());
  EXPECT_STREQ("be8f7ae2233fc122be82f2cf9fe3cc2c6196218a",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("", address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("76a914925d4028880bd0c9d68fbc7fc7dfee976698629c88ac",
               address.GetScript().GetHex().c_str());
}

TEST(Address, ElementsNoSegwitAddressFromHashTest) {
  const Pubkey pubkey = Pubkey(
      "027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af");
  ByteData160 pubkey_hash = HashUtil::Hash160(pubkey);
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_DUP);
  builder.AppendOperator(ScriptOperator::OP_HASH160);
  builder.AppendData(pubkey_hash);
  builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
  const Script &script = builder.Build();
  ByteData160 script_hash = HashUtil::Hash160(script);
  NetParams net_param = {"mainnet", NetType::kMainnet, 235, 75, "ert"};

  Address address;
  EXPECT_NO_THROW((address = Address(NetType::kMainnet,
                   AddressType::kP2pkhAddress, pubkey_hash, net_param)));
  EXPECT_STREQ("2dnmekh8NBmNX3Ckwte5CArjcsHLYdthCg3",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kCustomChain, address.GetNetType());
  EXPECT_EQ(AddressType::kP2pkhAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersionNone, address.GetWitnessVersion());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("", address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("", address.GetScript().GetHex().c_str());

  EXPECT_NO_THROW((address = Address(NetType::kTestnet,
                   AddressType::kP2shAddress, script_hash, net_param)));
  EXPECT_STREQ("XUiq7kxdkiB3AXNkKW9YaWLLGb1WBo9xcA",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kCustomChain, address.GetNetType());
  EXPECT_EQ(AddressType::kP2shAddress, address.GetAddressType());
}

TEST(Address, ElementsSegwitAddressFromHashTest) {
  const Pubkey pubkey = Pubkey(
      "027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af");
  ByteData160 pubkey_hash = HashUtil::Hash160(pubkey);
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_DUP);
  builder.AppendOperator(ScriptOperator::OP_HASH160);
  builder.AppendData(pubkey_hash);
  builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
  const Script &script = builder.Build();
  ByteData256 script_hash = HashUtil::Sha256(script);
  NetParams net_param = {"mainnet", NetType::kMainnet, 235, 75, "ert"};

  Address address;
  EXPECT_NO_THROW((address = Address(NetType::kMainnet,
                   WitnessVersion::kVersion0,
                   ByteData(pubkey_hash.GetBytes()), net_param)));
  EXPECT_STREQ("ert1qjfw5q2ygp0gvn450h3lu0hlwjanfsc5udafvh6",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kCustomChain, address.GetNetType());
  EXPECT_EQ(AddressType::kP2wpkhAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersion0, address.GetWitnessVersion());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("", address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("", address.GetScript().GetHex().c_str());

  EXPECT_NO_THROW((address = Address(NetType::kTestnet,
                   WitnessVersion::kVersion0,
                   ByteData(script_hash.GetBytes()), net_param)));
  EXPECT_STREQ("ert1qcc5c9wnzly8zj2dcsvxv83kupsu0uamx69u0y9lsmw7shuns2gqsflana4",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kCustomChain, address.GetNetType());
  EXPECT_EQ(AddressType::kP2wshAddress, address.GetAddressType());
}

TEST(Address, ElementsNoSegwitAddressFromStringTest) {
  Address address;
  NetParams net_param0 = {"Test", NetType::kTestnet, 255, 255, "dmy"};
  NetParams net_param1 = {"mainnet", NetType::kRegtest, 235, 75, "ert"};
  std::vector<NetParams> params = {net_param0, net_param1};

  // P2PKH
  EXPECT_NO_THROW((address = Address("2dnmekh8NBmNX3Ckwte5CArjcsHLYdthCg3", params)));
  EXPECT_STREQ("2dnmekh8NBmNX3Ckwte5CArjcsHLYdthCg3",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kRegtest, address.GetNetType());
  EXPECT_EQ(AddressType::kP2pkhAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersionNone, address.GetWitnessVersion());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("", address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("", address.GetScript().GetHex().c_str());

  EXPECT_NO_THROW((address = Address("XUiq7kxdkiB3AXNkKW9YaWLLGb1WBo9xcA", params)));
  EXPECT_STREQ("XUiq7kxdkiB3AXNkKW9YaWLLGb1WBo9xcA",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kRegtest, address.GetNetType());
  EXPECT_EQ(AddressType::kP2shAddress, address.GetAddressType());

  // analyze fail data
  EXPECT_THROW((address = Address("XUiq7kxdkiB3AXNkKW9YaWLLGb1WBo9xcA")),
               CfdException);
}

TEST(Address, ElementsSegwitAddressFromStringTest) {
  Address address;
  NetParams net_param0 = {"Test", NetType::kTestnet, 255, 255, "dmy"};
  NetParams net_param1 = {"mainnet", NetType::kRegtest, 235, 75, "ert"};
  std::vector<NetParams> params = {net_param0, net_param1};

  EXPECT_NO_THROW((address = Address("ert1qjfw5q2ygp0gvn450h3lu0hlwjanfsc5udafvh6", params)));
  EXPECT_STREQ("ert1qjfw5q2ygp0gvn450h3lu0hlwjanfsc5udafvh6",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kRegtest, address.GetNetType());
  EXPECT_EQ(AddressType::kP2wpkhAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersion0, address.GetWitnessVersion());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("", address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("", address.GetScript().GetHex().c_str());

  EXPECT_NO_THROW((address = Address("ert1qcc5c9wnzly8zj2dcsvxv83kupsu0uamx69u0y9lsmw7shuns2gqsflana4", params)));
  EXPECT_STREQ("ert1qcc5c9wnzly8zj2dcsvxv83kupsu0uamx69u0y9lsmw7shuns2gqsflana4",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kRegtest, address.GetNetType());
  EXPECT_EQ(AddressType::kP2wshAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersion0, address.GetWitnessVersion());
}
