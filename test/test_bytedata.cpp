#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_exception.h"

// https://qiita.com/yohm/items/477bac065f4b772127c7

// The main function are using gtest's main().

// TEST(test_suite_name, test_name)

using cfdcore::ByteData;

TEST(ByteData, DefaultConstructor) {
  ByteData byte_data;
  size_t size = 0;

  EXPECT_STREQ(byte_data.GetHex().c_str(), "");
  EXPECT_EQ(byte_data.GetDataSize(), size);
}

TEST(ByteData, HexConstructor) {
  std::string target(
      "123456789012345678901234567890123456789012345678901234567890123456");
  ByteData byte_data = ByteData(target);

  EXPECT_STREQ(byte_data.GetHex().c_str(), target.c_str());
  EXPECT_EQ(byte_data.GetDataSize(), (target.size() / 2));
}

TEST(ByteData, BytesConstructor) {
  std::vector<uint8_t> target(20);
  uint8_t byte = 1;
  for (size_t i = 0; i < target.size(); i++) {
    target[i] = byte;
    byte++;
    if (byte > 9) {
      byte = 0;
    }
  }
  ByteData byte_data = ByteData(target);
  bool is_equals = (byte_data.GetBytes() == target);

  EXPECT_STREQ(byte_data.GetHex().c_str(),
               "0102030405060708090001020304050607080900");
  EXPECT_TRUE(is_equals);
  EXPECT_EQ(byte_data.GetDataSize(), target.size());
}

TEST(ByteData, EqualsMatch) {
  ByteData byte_data1 = ByteData(
      "1234567890123456789012345678901234567890123456789012345678901234");
  ByteData byte_data2 = ByteData(
      "1234567890123456789012345678901234567890123456789012345678901234");
  bool is_equals = byte_data1.Equals(byte_data2);

  EXPECT_TRUE(is_equals);
}

TEST(ByteData, EqualsUnMatch) {
  ByteData byte_data1 = ByteData(
      "1234567890123456789012345678901234567890123456789012345678901234");
  ByteData byte_data2 = ByteData(
      "0234567890123456789012345678901234567890123456789012345678901234");
  bool is_equals = byte_data1.Equals(byte_data2);

  EXPECT_FALSE(is_equals);
}
