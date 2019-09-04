#ifndef CFD_DISABLE_ELEMENTS
#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_elements_address.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_util.h"

using cfdcore::CfdException;
using cfdcore::AbstractElementsAddress;
using cfdcore::ElementsConfidentialAddress;
using cfdcore::ElementsUnblindedAddress;
using cfdcore::ConfidentialKey;
using cfdcore::ElementsNetType;
using cfdcore::ElementsAddressType;
using cfdcore::Pubkey;
using cfdcore::ByteData160;
using cfdcore::ByteData256;
using cfdcore::ByteData;
using cfdcore::Script;
using cfdcore::ScriptOperator;
using cfdcore::ScriptBuilder;
using cfdcore::HashUtil;

TEST(ElementsConfidentialAddress, EmptyAddressTest) {
  ElementsConfidentialAddress empty_address;
  EXPECT_STREQ("",
               empty_address.GetUnblindedAddress().GetHash().GetHex().c_str());
  EXPECT_STREQ("", empty_address.GetConfidentialKey().GetHex().c_str());

  ElementsUnblindedAddress unblind_addr;
  ConfidentialKey key;
  EXPECT_THROW((empty_address = ElementsConfidentialAddress("")), CfdException);
  EXPECT_THROW((empty_address = ElementsConfidentialAddress(unblind_addr, key)),
               CfdException);
}

TEST(ElementsConfidentialAddress, P2pkhAddress) {
  const Pubkey pubkey = Pubkey(
      "027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af");
  ConfidentialKey key = ConfidentialKey(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16");
  ElementsConfidentialAddress address;
  ElementsUnblindedAddress unblind_addr;

  unblind_addr = ElementsUnblindedAddress(ElementsNetType::kLiquidV1, pubkey);
  EXPECT_NO_THROW((address = ElementsConfidentialAddress(unblind_addr, key)));
  EXPECT_STREQ(
      "VTpyoufXeg8LByRmUeHt1zyzFm1RjEP7PvWYHsjGtj9Ef1ibxgVoGkPsUPDNvkKog17K7Qn5eQ3B7g9w",
      address.GetAddress().c_str());
  EXPECT_STREQ(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16",
      address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("QAcHVN55oetZU3wXXxnTrYHaqVUe35UhwJ",
               address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      AbstractElementsAddress::IsConfidentialAddress(address.GetAddress()));
  EXPECT_TRUE(address.IsBlinded());
  EXPECT_EQ(ElementsNetType::kLiquidV1, address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kElementsP2pkhAddress, address.GetAddressType());

  unblind_addr = ElementsUnblindedAddress(ElementsNetType::kElementsRegtest, pubkey);
  EXPECT_NO_THROW((address = ElementsConfidentialAddress(unblind_addr, key)));
  EXPECT_STREQ(
      "CTEqTvCZtF8yBn4JeRxJKDjsVWk7m9mMuzThGzwTgn9G8cLBqjmqc5YkyheitzBooX7XBVNmAS34Be8o",
      address.GetAddress().c_str());
  EXPECT_STREQ(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16",
      address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("2dnmekh8NBmNX3Ckwte5CArjcsHLYdthCg3",
               address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      AbstractElementsAddress::IsConfidentialAddress(address.GetAddress()));
  EXPECT_TRUE(address.IsBlinded());
  EXPECT_EQ(ElementsNetType::kElementsRegtest, address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kElementsP2pkhAddress, address.GetAddressType());

  // uncompress pubkey
  ConfidentialKey uc_key =
      ConfidentialKey(
          "04d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16e50cd61e20eb14e59a0c763d9cda790becb868ceeb00e5f74da0d15ff8381534");
  EXPECT_THROW((address = ElementsConfidentialAddress(unblind_addr, uc_key)),
               CfdException);
}

TEST(ElementsConfidentialAddress, P2shAddress) {
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
  ConfidentialKey key = ConfidentialKey(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16");
  ElementsConfidentialAddress address;
  ElementsUnblindedAddress unblind_addr;

  unblind_addr = ElementsUnblindedAddress(ElementsNetType::kLiquidV1, script);
  EXPECT_NO_THROW((address = ElementsConfidentialAddress(unblind_addr, key)));
  EXPECT_STREQ(
      "VJLBL3rkCh19CDi889GPXkn1BYqUih5DF2p8ViS2J4Tr2cnoKqrKf3qi2c9KJdah9d62ovTckv5uzzZC",
      address.GetAddress().c_str());
  EXPECT_STREQ(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16",
      address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("be8f7ae2233fc122be82f2cf9fe3cc2c6196218a",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("GzZ7frEGCDVVivMdSQA57zY1cRjYVu1g2r",
               address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      AbstractElementsAddress::IsConfidentialAddress(address.GetAddress()));
  EXPECT_TRUE(address.IsBlinded());
  EXPECT_EQ(ElementsNetType::kLiquidV1, address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kElementsP2shAddress, address.GetAddressType());

  unblind_addr = ElementsUnblindedAddress(ElementsNetType::kElementsRegtest, script);
  EXPECT_NO_THROW((address = ElementsConfidentialAddress(unblind_addr, key)));
  EXPECT_STREQ(
      "AzppkWN3gNvcnBu2Pm4Nsi8EdCmugMU2zjbpsMQZGBfMDmBprXEMfscpFfYRqjkT2CjY7QAxtAv5PHkX",
      address.GetAddress().c_str());
  EXPECT_STREQ(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16",
      address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("be8f7ae2233fc122be82f2cf9fe3cc2c6196218a",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("XUiq7kxdkiB3AXNkKW9YaWLLGb1WBo9xcA",
               address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      AbstractElementsAddress::IsConfidentialAddress(address.GetAddress()));
  EXPECT_TRUE(address.IsBlinded());
  EXPECT_EQ(ElementsNetType::kElementsRegtest, address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kElementsP2shAddress, address.GetAddressType());
}

TEST(ElementsConfidentialAddress, P2shWrappedP2wpkhAddress) {
  const Pubkey pubkey = Pubkey(
      "027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af");
  // locking_script = ScriptUtil::CreateP2wpkhLockingScript(pubkey);
  ByteData160 pubkey_hash = HashUtil::Hash160(pubkey);
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_0);
  builder.AppendData(pubkey_hash);
  const Script &script = builder.Build();
  ConfidentialKey key = ConfidentialKey(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16");
  ElementsConfidentialAddress address;
  ElementsUnblindedAddress unblind_addr;

  unblind_addr = ElementsUnblindedAddress(ElementsNetType::kLiquidV1, script);
  EXPECT_NO_THROW((address = ElementsConfidentialAddress(unblind_addr, key)));
  EXPECT_STREQ(
      "VJLBL3rkCh19CDi889GPXkn1BYqUih5DF2p8ViS2J4Tr2cnYHZSM3ydLeZvFxSQ1MK8cXrXdQYVwx3i1",
      address.GetAddress().c_str());
  EXPECT_STREQ(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16",
      address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("19970f64fb36fe3b7b21eca335ff70dde51eb8c8",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("GjWqFsdByr7TVs1SFiMmAaFwgSPAz5xzQm",
               address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      AbstractElementsAddress::IsConfidentialAddress(address.GetAddress()));
  EXPECT_TRUE(address.IsBlinded());
  EXPECT_EQ(ElementsNetType::kLiquidV1, address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kElementsP2shAddress, address.GetAddressType());

  unblind_addr = ElementsUnblindedAddress(ElementsNetType::kElementsRegtest, script);
  EXPECT_NO_THROW((address = ElementsConfidentialAddress(unblind_addr, key)));
  EXPECT_STREQ(
      "AzppkWN3gNvcnBu2Pm4Nsi8EdCmugMU2zjbpsMQZGBfMDmBZpEpP4oQSsdKNVYZmDtn7qLEyXoK7qUrY",
      address.GetAddress().c_str());
  EXPECT_STREQ(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16",
      address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("19970f64fb36fe3b7b21eca335ff70dde51eb8c8",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("XDgYhnMZYLnzwU2Z8pMEd64GLbf8W9A5vA",
               address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      AbstractElementsAddress::IsConfidentialAddress(address.GetAddress()));
  EXPECT_TRUE(address.IsBlinded());
  EXPECT_EQ(ElementsNetType::kElementsRegtest, address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kElementsP2shAddress, address.GetAddressType());
}

TEST(ElementsConfidentialAddress, P2shWrappedP2wshAddress) {
  const Pubkey pubkey = Pubkey(
      "027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af");
  ByteData160 pubkey_hash = HashUtil::Hash160(pubkey);
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_DUP);
  builder.AppendOperator(ScriptOperator::OP_HASH160);
  builder.AppendData(pubkey_hash);
  builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
  const Script &redeem_script = builder.Build();
  // locking_script = ScriptUtil::CreateP2wshLockingScript(pubkey);
  ByteData256 script_hash = HashUtil::Sha256(redeem_script);
  builder = ScriptBuilder();
  builder.AppendOperator(ScriptOperator::OP_0);
  builder.AppendData(script_hash);
  const Script &script = builder.Build();
  ConfidentialKey key = ConfidentialKey(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16");
  ElementsConfidentialAddress address;
  ElementsUnblindedAddress unblind_addr;

  unblind_addr = ElementsUnblindedAddress(ElementsNetType::kLiquidV1, script);
  EXPECT_NO_THROW((address = ElementsConfidentialAddress(unblind_addr, key)));
  EXPECT_STREQ(
      "VJLBL3rkCh19CDi889GPXkn1BYqUih5DF2p8ViS2J4Tr2cnZNmgEuyWyLvABqzeNyjtqWNNx3NTXMxXp",
      address.GetAddress().c_str());
  EXPECT_STREQ(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16",
      address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("258b7b985398033523194e96d9509bc04d011645",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("Gkc3VmVBsUoojntzW5zBvoETXm1zv6Bibz",
               address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      AbstractElementsAddress::IsConfidentialAddress(address.GetAddress()));
  EXPECT_TRUE(address.IsBlinded());
  EXPECT_EQ(ElementsNetType::kLiquidV1, address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kElementsP2shAddress, address.GetAddressType());

  unblind_addr = ElementsUnblindedAddress(ElementsNetType::kElementsRegtest, script);
  EXPECT_NO_THROW((address = ElementsConfidentialAddress(unblind_addr, key)));
  EXPECT_STREQ(
      "AzppkWN3gNvcnBu2Pm4Nsi8EdCmugMU2zjbpsMQZGBfMDmBauT4GvoJ5ZyZJP6p8rKYLor6JAdFoaoYJ",
      address.GetAddress().c_str());
  EXPECT_STREQ(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16",
      address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("258b7b985398033523194e96d9509bc04d011645",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("XEmkwgDZRyVMBPv7PByfPK2nBvHxWJXpBQ",
               address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      AbstractElementsAddress::IsConfidentialAddress(address.GetAddress()));
  EXPECT_TRUE(address.IsBlinded());
  EXPECT_EQ(ElementsNetType::kElementsRegtest, address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kElementsP2shAddress, address.GetAddressType());
}

TEST(ElementsConfidentialAddress, P2pkhAddressFromString) {
  ElementsConfidentialAddress address;

  EXPECT_NO_THROW(
      (address =
          ElementsConfidentialAddress(
              "VTpyoufXeg8LByRmUeHt1zyzFm1RjEP7PvWYHsjGtj9Ef1ibxgVoGkPsUPDNvkKog17K7Qn5eQ3B7g9w")));
  EXPECT_STREQ(
      "VTpyoufXeg8LByRmUeHt1zyzFm1RjEP7PvWYHsjGtj9Ef1ibxgVoGkPsUPDNvkKog17K7Qn5eQ3B7g9w",
      address.GetAddress().c_str());
  EXPECT_STREQ(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16",
      address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("QAcHVN55oetZU3wXXxnTrYHaqVUe35UhwJ",
               address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      AbstractElementsAddress::IsConfidentialAddress(address.GetAddress()));
  EXPECT_TRUE(address.IsBlinded());
  EXPECT_EQ(ElementsNetType::kLiquidV1, address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kElementsP2pkhAddress, address.GetAddressType());

  EXPECT_NO_THROW(
      (address =
          ElementsConfidentialAddress(
              "CTEqTvCZtF8yBn4JeRxJKDjsVWk7m9mMuzThGzwTgn9G8cLBqjmqc5YkyheitzBooX7XBVNmAS34Be8o")));
  EXPECT_STREQ(
      "CTEqTvCZtF8yBn4JeRxJKDjsVWk7m9mMuzThGzwTgn9G8cLBqjmqc5YkyheitzBooX7XBVNmAS34Be8o",
      address.GetAddress().c_str());
  EXPECT_STREQ(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16",
      address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("2dnmekh8NBmNX3Ckwte5CArjcsHLYdthCg3",
               address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      AbstractElementsAddress::IsConfidentialAddress(address.GetAddress()));
  EXPECT_TRUE(address.IsBlinded());
  EXPECT_EQ(ElementsNetType::kElementsRegtest, address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kElementsP2pkhAddress, address.GetAddressType());
}

TEST(ElementsConfidentialAddress, P2shAddressFromString) {
  ElementsConfidentialAddress address;

  EXPECT_NO_THROW(
      (address =
          ElementsConfidentialAddress(
              "VJLBL3rkCh19CDi889GPXkn1BYqUih5DF2p8ViS2J4Tr2cnoKqrKf3qi2c9KJdah9d62ovTckv5uzzZC")));
  EXPECT_STREQ(
      "VJLBL3rkCh19CDi889GPXkn1BYqUih5DF2p8ViS2J4Tr2cnoKqrKf3qi2c9KJdah9d62ovTckv5uzzZC",
      address.GetAddress().c_str());
  EXPECT_STREQ(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16",
      address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("be8f7ae2233fc122be82f2cf9fe3cc2c6196218a",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("GzZ7frEGCDVVivMdSQA57zY1cRjYVu1g2r",
               address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      AbstractElementsAddress::IsConfidentialAddress(address.GetAddress()));
  EXPECT_TRUE(address.IsBlinded());
  EXPECT_EQ(ElementsNetType::kLiquidV1, address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kElementsP2shAddress, address.GetAddressType());

  EXPECT_NO_THROW(
      (address =
          ElementsConfidentialAddress(
              "AzppkWN3gNvcnBu2Pm4Nsi8EdCmugMU2zjbpsMQZGBfMDmBprXEMfscpFfYRqjkT2CjY7QAxtAv5PHkX")));
  EXPECT_STREQ(
      "AzppkWN3gNvcnBu2Pm4Nsi8EdCmugMU2zjbpsMQZGBfMDmBprXEMfscpFfYRqjkT2CjY7QAxtAv5PHkX",
      address.GetAddress().c_str());
  EXPECT_STREQ(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16",
      address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("be8f7ae2233fc122be82f2cf9fe3cc2c6196218a",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("XUiq7kxdkiB3AXNkKW9YaWLLGb1WBo9xcA",
               address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      AbstractElementsAddress::IsConfidentialAddress(address.GetAddress()));
  EXPECT_TRUE(address.IsBlinded());
  EXPECT_EQ(ElementsNetType::kElementsRegtest, address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kElementsP2shAddress, address.GetAddressType());
}

TEST(ElementsConfidentialAddress, P2shWrappedP2wpkhAddressFromString) {
  ElementsConfidentialAddress address;

  EXPECT_NO_THROW(
      (address =
          ElementsConfidentialAddress(
              "VJLBL3rkCh19CDi889GPXkn1BYqUih5DF2p8ViS2J4Tr2cnYHZSM3ydLeZvFxSQ1MK8cXrXdQYVwx3i1")));
  EXPECT_STREQ(
      "VJLBL3rkCh19CDi889GPXkn1BYqUih5DF2p8ViS2J4Tr2cnYHZSM3ydLeZvFxSQ1MK8cXrXdQYVwx3i1",
      address.GetAddress().c_str());
  EXPECT_STREQ(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16",
      address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("19970f64fb36fe3b7b21eca335ff70dde51eb8c8",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("GjWqFsdByr7TVs1SFiMmAaFwgSPAz5xzQm",
               address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      AbstractElementsAddress::IsConfidentialAddress(address.GetAddress()));
  EXPECT_TRUE(address.IsBlinded());
  EXPECT_EQ(ElementsNetType::kLiquidV1, address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kElementsP2shAddress, address.GetAddressType());

  EXPECT_NO_THROW(
      (address =
          ElementsConfidentialAddress(
              "AzppkWN3gNvcnBu2Pm4Nsi8EdCmugMU2zjbpsMQZGBfMDmBZpEpP4oQSsdKNVYZmDtn7qLEyXoK7qUrY")));
  EXPECT_STREQ(
      "AzppkWN3gNvcnBu2Pm4Nsi8EdCmugMU2zjbpsMQZGBfMDmBZpEpP4oQSsdKNVYZmDtn7qLEyXoK7qUrY",
      address.GetAddress().c_str());
  EXPECT_STREQ(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16",
      address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("19970f64fb36fe3b7b21eca335ff70dde51eb8c8",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("XDgYhnMZYLnzwU2Z8pMEd64GLbf8W9A5vA",
               address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      AbstractElementsAddress::IsConfidentialAddress(address.GetAddress()));
  EXPECT_TRUE(address.IsBlinded());
  EXPECT_EQ(ElementsNetType::kElementsRegtest, address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kElementsP2shAddress, address.GetAddressType());
}

TEST(ElementsConfidentialAddress, P2shWrappedP2wshAddressFromString) {
  ElementsConfidentialAddress address;

  EXPECT_NO_THROW(
      (address =
          ElementsConfidentialAddress(
              "VJLBL3rkCh19CDi889GPXkn1BYqUih5DF2p8ViS2J4Tr2cnZNmgEuyWyLvABqzeNyjtqWNNx3NTXMxXp")));
  EXPECT_STREQ(
      "VJLBL3rkCh19CDi889GPXkn1BYqUih5DF2p8ViS2J4Tr2cnZNmgEuyWyLvABqzeNyjtqWNNx3NTXMxXp",
      address.GetAddress().c_str());
  EXPECT_STREQ(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16",
      address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("258b7b985398033523194e96d9509bc04d011645",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("Gkc3VmVBsUoojntzW5zBvoETXm1zv6Bibz",
               address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      AbstractElementsAddress::IsConfidentialAddress(address.GetAddress()));
  EXPECT_TRUE(address.IsBlinded());
  EXPECT_EQ(ElementsNetType::kLiquidV1, address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kElementsP2shAddress, address.GetAddressType());

  EXPECT_NO_THROW(
      (address =
          ElementsConfidentialAddress(
              "AzppkWN3gNvcnBu2Pm4Nsi8EdCmugMU2zjbpsMQZGBfMDmBauT4GvoJ5ZyZJP6p8rKYLor6JAdFoaoYJ")));
  EXPECT_STREQ(
      "AzppkWN3gNvcnBu2Pm4Nsi8EdCmugMU2zjbpsMQZGBfMDmBauT4GvoJ5ZyZJP6p8rKYLor6JAdFoaoYJ",
      address.GetAddress().c_str());
  EXPECT_STREQ(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16",
      address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("258b7b985398033523194e96d9509bc04d011645",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("XEmkwgDZRyVMBPv7PByfPK2nBvHxWJXpBQ",
               address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      AbstractElementsAddress::IsConfidentialAddress(address.GetAddress()));
  EXPECT_TRUE(address.IsBlinded());
  EXPECT_EQ(ElementsNetType::kElementsRegtest, address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kElementsP2shAddress, address.GetAddressType());
}
#endif  // CFD_DISABLE_ELEMENTS
