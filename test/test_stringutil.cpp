#include "gtest/gtest.h"
#include <map>
#include <vector>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_util.h"
#include "cfdcore/cfdcore_exception.h"

// https://qiita.com/yohm/items/477bac065f4b772127c7

// The main function are using gtest's main().

// TEST(test_suite_name, test_name)

using cfdcore::StringUtil;
using cfdcore::ByteData;

TEST(StringUtil, StringToByte) {
  std::string target(
      "6af0d7adef48de1e90dde0423d4b1ecc72b60ec0a33c716c397bc50f9662b581");
  std::vector<uint8_t> bytes = StringUtil::StringToByte(target);
  EXPECT_STREQ(
      ByteData(bytes).GetHex().c_str(),
      "6af0d7adef48de1e90dde0423d4b1ecc72b60ec0a33c716c397bc50f9662b581");
  EXPECT_EQ(bytes.size(), (target.size() / 2));
}

TEST(StringUtil, StringToByteEmpty) {
  std::string target;
  std::vector<uint8_t> bytes = StringUtil::StringToByte(target);
  EXPECT_EQ(bytes.size(), target.size());
}

TEST(StringUtil, StringToByteLengthError) {
  try {
    std::string target(
        "6af0d7adef48de1e90dde0423d4b1ecc72b60ec0a33c716c397bc50f9662b58");
    std::vector<uint8_t> bytes = StringUtil::StringToByte(target);
  } catch (const cfdcore::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "hex to byte convert error.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(StringUtil, StringToByteError) {
  try {
    std::string target("hello!");
    std::vector<uint8_t> bytes = StringUtil::StringToByte(target);
  } catch (const cfdcore::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "hex to byte convert error.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(StringUtil, ByteToString) {
  std::vector<uint8_t> bytes(5);
  bytes[0] = 0x6a;
  bytes[1] = 0xcd;
  bytes[2] = 0x7a;
  bytes[3] = 0xde;
  bytes[4] = 0xf4;
  std::string result = StringUtil::ByteToString(bytes);
  EXPECT_STREQ(result.c_str(), "6acd7adef4");
}

TEST(StringUtil, ByteToStringEmpty) {
  std::vector<uint8_t> bytes;
  std::string result = StringUtil::ByteToString(bytes);

  EXPECT_STREQ(result.c_str(), "");
}

TEST(StringUtil, SplitTest) {
  std::vector<std::string> expect_vec = {
    "The", "quick", "brown", "fox", "jumps", "over", "the", "lazy", "dog"
  };
  std::map<std::string, char> test_vector = {
    {
      "The quick brown fox jumps over the lazy dog",
      ' '
    },
    {
      "The_quick_brown_fox_jumps_over_the_lazy_dog",
      '_'
    },
    {
      "The%quick%brown%fox%jumps%over%the%lazy%dog",
      '%'
    },
    {
      "The%quick%brown%fox%jumps%over%the%lazy%dog%",
      '%'
    }
  };

  std::vector<std::string> actual;
  for (auto vec : test_vector) {
    EXPECT_NO_THROW(actual = StringUtil::Split(vec.first, vec.second));
    EXPECT_EQ(actual, expect_vec);
  }
}

TEST(StringUtil, SplitEmptyStringTest) {
  struct TestVector {
    std::string str;
    char delimiter;
    std::vector<std::string> expect;
  };
  std::vector<TestVector> test_vector = {
    {
      " ",
      '*',
      {" "}
    },
    {
      "**",
      '*',
      {"", ""}
    },
    {
      "",
      '*',
      {}
    }
  };

  std::vector<std::string> actual;
  for (auto vec : test_vector) {
    EXPECT_NO_THROW(actual = StringUtil::Split(vec.str, vec.delimiter));
    EXPECT_EQ(actual, vec.expect);
  }
}
