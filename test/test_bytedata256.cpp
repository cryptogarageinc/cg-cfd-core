#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_exception.h"

// https://qiita.com/yohm/items/477bac065f4b772127c7

// The main function are using gtest's main().

// TEST(test_suite_name, test_name)

using cfdcore::ByteData256;

TEST(ByteData256, DefaultConstructor) {
  ByteData256 byte_data;

  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "0000000000000000000000000000000000000000000000000000000000000000");
}

TEST(ByteData256, HexConstructor) {
  std::string target(
      "1234567890123456789012345678901234567890123456789012345678901234");
  ByteData256 byte_data = ByteData256(target);

  EXPECT_STREQ(byte_data.GetHex().c_str(), target.c_str());
}

TEST(ByteData256, BytesConstructor) {
  std::vector<uint8_t> target(32);
  uint8_t byte = 1;
  for (size_t i = 0; i < target.size(); i++) {
    target[i] = byte;
    byte++;
    if (byte > 9) {
      byte = 0;
    }
  }
  ByteData256 byte_data = ByteData256(target);
  bool is_equals = (byte_data.GetBytes() == target);

  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "0102030405060708090001020304050607080900010203040506070809000102");
  EXPECT_TRUE(is_equals);
}

TEST(ByteData256, HexConstructorException) {
  try {
    ByteData256 byte_data = ByteData256(
        "123456789012345678901234567890123456789000");
  } catch (const cfdcore::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "ByteData256 size unmatch.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(ByteData256, BytesConstructorException) {
  try {
    std::vector<uint8_t> target(25);
    ByteData256 byte_data = ByteData256(target);
  } catch (const cfdcore::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "ByteData256 size unmatch.");
    return;
  }
  ASSERT_TRUE(false);
}

