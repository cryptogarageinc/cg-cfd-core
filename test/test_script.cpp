#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_script.h"
#include "cfdcore/cfdcore_exception.h"

// https://qiita.com/yohm/items/477bac065f4b772127c7

// The main function are using gtest's main().

// TEST(test_suite_name, test_name)

using cfdcore::Script;
using cfdcore::ScriptBuilder;
using cfdcore::ScriptOperator;
using cfdcore::ScriptHash;
using cfdcore::ScriptElement;
using cfdcore::ByteData;
using cfdcore::Privkey;
using cfdcore::Pubkey;
using cfdcore::NetType;

TEST(Script, Script) {
  size_t size = 0;
  Script script;
  EXPECT_STREQ(script.GetHex().c_str(), "");
  EXPECT_EQ(script.IsEmpty(), true);
  EXPECT_EQ(script.GetData().GetDataSize(), size);
  EXPECT_EQ(script.GetElementList().size(), size);
}

TEST(Script, Script_hex) {
  size_t size = 5;
  std::string hex("76a91498e977b2259a85278aa51188bd863a3df0ad31ba88ac");
  Script script(hex);
  EXPECT_STREQ(script.GetHex().c_str(),
               "76a91498e977b2259a85278aa51188bd863a3df0ad31ba88ac");
  EXPECT_EQ(script.IsEmpty(), false);
  EXPECT_EQ(script.GetElementList().size(), size);
}

TEST(Script, Script_hex_exception) {
  try {
    std::string hex("xxxx");
    Script script(hex);
  } catch (const cfdcore::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "hex to byte convert error.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(Script, Script_bytedata) {
  size_t size = 5;
  ByteData bytedata("76a91498e977b2259a85278aa51188bd863a3df0ad31ba88ac");
  Script script(bytedata);
  EXPECT_STREQ(script.GetHex().c_str(),
               "76a91498e977b2259a85278aa51188bd863a3df0ad31ba88ac");
  EXPECT_EQ(script.IsEmpty(), false);
  EXPECT_EQ(script.GetElementList().size(), size);
}

TEST(Script, SetStackData_OP0) {
  // script作成
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_0);
  builder.AppendData(
      "96376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
  Script script = builder.Build();

  // OP_0 <hash160(pubkey)>
  size_t size = 2;
  EXPECT_EQ(script.IsEmpty(), false);
  EXPECT_EQ(script.GetElementList().size(), size);
  EXPECT_STREQ(
      script.GetHex().c_str(),
      "002096376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
  EXPECT_STREQ(
      script.ToString().c_str(),
      "0 96376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
}

TEST(Script, SetStackData_kUseScriptNum1) {
  // script作成
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_IF);
  builder.AppendData(
      "0211dcbf6768e8eff85d7b294776f046a5294a64158586cd2bc6da4b0740eacd2f");
  builder.AppendOperator(ScriptOperator::OP_ELSE);
  builder.AppendData(144);
  builder.AppendOperator(ScriptOperator::OP_CHECKSEQUENCEVERIFY);
  builder.AppendOperator(ScriptOperator::OP_DROP);
  builder.AppendData(
      "03f7cfe9da8101afb6a6894cac696c7e1ba74fba3ed4caab5eb66c7df4c9558621");
  builder.AppendOperator(ScriptOperator::OP_ENDIF);
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
  Script script = builder.Build();

  // OP_IF pubkeyA OP_ELSE delay OP_CHECKSEQUENCEVERIFY OP_DROP pubkeyB OP_ENDIF OP_CHECKSIG
  size_t size = 9;
  EXPECT_EQ(script.IsEmpty(), false);
  EXPECT_EQ(script.GetElementList().size(), size);
  EXPECT_STREQ(
      script.ToString().c_str(),
      "OP_IF 0211dcbf6768e8eff85d7b294776f046a5294a64158586cd2bc6da4b0740eacd2f OP_ELSE 144 OP_CHECKSEQUENCEVERIFY OP_DROP 03f7cfe9da8101afb6a6894cac696c7e1ba74fba3ed4caab5eb66c7df4c9558621 OP_ENDIF OP_CHECKSIG");
}

TEST(Script, SetStackData_kUseScriptNum2) {
  // script作成
  ScriptBuilder builder;
  builder.AppendData(5);
  builder.AppendData(2);
  builder.AppendOperator(ScriptOperator::OP_ADD);
  builder.AppendData(7);
  builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
  Script script = builder.Build();

  // OP_5 OP_2 OP_ADD OP_7 OP_EQUALVERIFY
  size_t size = 5;
  EXPECT_EQ(script.IsEmpty(), false);
  EXPECT_EQ(script.GetElementList().size(), size);
  EXPECT_STREQ(script.GetHex().c_str(), "5552935788");
  EXPECT_STREQ(script.ToString().c_str(), "5 2 OP_ADD 7 OP_EQUALVERIFY");
}

TEST(Script, SetStackData_kUseScriptNum3) {
  // script作成
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_SIZE);
  builder.AppendOperator(ScriptOperator::OP_TUCK);
  builder.AppendData(0x20);
  builder.AppendData(0x23);
  builder.AppendOperator(ScriptOperator::OP_WITHIN);
  builder.AppendOperator(ScriptOperator::OP_VERIFY);
  Script script = builder.Build();

  // OP_SIZE OP_TUCK 20 23 OP_WITHIN OP_VERIFY
  size_t size = 6;
  EXPECT_EQ(script.IsEmpty(), false);
  EXPECT_EQ(script.GetElementList().size(), size);
  EXPECT_STREQ(script.GetHex().c_str(), "827d01200123a569");
  EXPECT_STREQ(script.ToString().c_str(),
               "OP_SIZE OP_TUCK 32 35 OP_WITHIN OP_VERIFY");
}

TEST(Script, SetStackData_kOpPushData1) {
  // script作成
  ScriptBuilder builder;
  std::vector<uint8_t> bytes(255, 1);
  builder.AppendData(ByteData(bytes));
  Script script = builder.Build();

  size_t size = 1;
  EXPECT_EQ(script.IsEmpty(), false);
  EXPECT_EQ(script.GetElementList().size(), size);
  EXPECT_EQ(script.GetData().GetBytes()[0], 0x4c);
}

TEST(Script, SetStackData_kOpPushData2) {
  // script作成
  ScriptBuilder builder;
  std::vector<uint8_t> bytes(256, 1);
  builder.AppendData(ByteData(bytes));
  Script script = builder.Build();

  size_t size = 1;
  EXPECT_EQ(script.IsEmpty(), false);
  EXPECT_EQ(script.GetElementList().size(), size);
  EXPECT_EQ(script.GetData().GetBytes()[0], 0x4d);
}

TEST(Script, SetStackData_kOpPushData4) {
  // script作成
  // Builderではサイズエラーになるので、bytedataを自作
  std::vector<uint8_t> bytes(65541, 1);
  bytes[0] = 0x4e;
  bytes[1] = 0x00;
  bytes[2] = 0x00;
  bytes[3] = 0x01;
  bytes[4] = 0x00;
  Script script(bytes);

  size_t size = 1;
  EXPECT_EQ(script.IsEmpty(), false);
  EXPECT_EQ(script.GetElementList().size(), size);
  EXPECT_EQ(script.GetData().GetBytes()[0], 0x4e);
}

TEST(Script, SetStackData_kOpPushData1_error) {
  try {
    std::vector<uint8_t> bytes(2, 0xff);
    bytes[0] = 0x4c;
    Script script(bytes);
  } catch (const cfdcore::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "OP_PUSHDATA1 is incorrect size.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(Script, SetStackData_kOpPushData2_error) {
  try {
    std::vector<uint8_t> bytes(2, 0xff);
    bytes[0] = 0x4d;
    Script script(bytes);
  } catch (const cfdcore::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "OP_PUSHDATA2 is incorrect size.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(Script, SetStackData_kOpPushData4_error) {
  try {
    std::vector<uint8_t> bytes(2, 0xff);
    bytes[0] = 0x4e;
    Script script(bytes);
  } catch (const cfdcore::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "OP_PUSHDATA4 is incorrect size.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(Script, SetStackData_size_error) {
  try {
    std::vector<uint8_t> bytes(10, 0x1);
    bytes[0] = 0x4e;
    Script script(bytes);
  } catch (const cfdcore::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "buffer is incorrect size.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(Script, GetScript) {
  ScriptBuilder builder;
  std::vector<uint8_t> bytes(255, 1);
  builder.AppendData(ByteData(bytes));
  Script script = builder.Build();

  Script script2 = script.GetScript();
  EXPECT_STREQ(script.GetHex().c_str(), script2.GetHex().c_str());
  EXPECT_STREQ(script.ToString().c_str(), script2.ToString().c_str());
}

TEST(Script, GetScriptHash) {
  Script script(
      "002096376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
  ScriptHash script_hash = script.GetScriptHash();
  EXPECT_STREQ(script_hash.GetHex().c_str(),
               "a9145528d5065b3f370375a651128077eaf3258531d887");
}

TEST(Script, GetWitnessScriptHash) {
  Script script(
      "002096376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
  ScriptHash script_hash = script.GetWitnessScriptHash();
  EXPECT_STREQ(
      script_hash.GetHex().c_str(),
      "00206bb5cc76cdbd684cb6f7c43a98c61c5aa789368d5e319e6c8258de3fec796562");
}

TEST(Script, GetData) {
  Script script(
      "002096376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
  ByteData byte_data = script.GetData();
  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "002096376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
}

TEST(Script, GetHex) {
  Script script(
      "002096376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
  std::string hex = script.GetHex();
  EXPECT_STREQ(
      hex.c_str(),
      "002096376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
}

TEST(Script, IsEmpty_true) {
  Script script;
  EXPECT_EQ(script.IsEmpty(), true);
}

TEST(Script, IsEmpty_false) {
  Script script(
      "002096376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
  EXPECT_EQ(script.IsEmpty(), false);
}

TEST(Script, GetElementList) {
  ScriptBuilder builder;
  builder.AppendData(5);
  builder.AppendData(2);
  builder.AppendOperator(ScriptOperator::OP_ADD);
  builder.AppendData(7);
  builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
  Script script = builder.Build();

  size_t size = 5;
  std::vector<ScriptElement> list = script.GetElementList();
  EXPECT_EQ(list.size(), size);
}

TEST(Script, ToString) {
  Script script(
      "002096376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
  EXPECT_STREQ(
      script.ToString().c_str(),
      "0 96376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
}

TEST(Script, ToString_empty) {
  Script script;
  EXPECT_STREQ(script.ToString().c_str(), "");
}

TEST(Script, IsPushOnly_true) {
  ScriptBuilder builder;
  builder.AppendData(5);
  Script script = builder.Build();
  EXPECT_EQ(script.IsPushOnly(), true);
}

TEST(Script, IsPushOnly_false) {
  ScriptBuilder builder;
  builder.AppendData(5);
  builder.AppendData(2);
  builder.AppendOperator(ScriptOperator::OP_ADD);
  builder.AppendData(7);
  builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
  Script script = builder.Build();
  EXPECT_EQ(script.IsPushOnly(), false);
}

TEST(Script, IsPushOnly_empty) {
  Script script;
  EXPECT_EQ(script.IsPushOnly(), true);
}
