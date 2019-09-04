#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_util.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_script.h"
#include "cfdcore/cfdcore_exception.h"

using cfdcore::ByteData;
using cfdcore::ByteData160;
using cfdcore::ByteData256;
using cfdcore::CryptoUtil;
using cfdcore::SigHashType;
using cfdcore::SigHashAlgorithm;

// AES256 tool
// http://extranet.cryptomathic.com/aescalc/index
// EncryptAes256--------------------------------------------------------------
TEST(CryptoUtil, EncryptAes256String32) {
  ByteData key(
      "616975656F616975656F616975656F616975656F616975656F616975656F6169");
  ByteData byte_data = CryptoUtil::EncryptAes256(
      key.GetBytes(), "aiueoaiueoaiueoaiueoaiueoaiueoai");
  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "6af0d7adef48de1e90dde0423d4b1ecc72b60ec0a33c716c397bc50f9662b581");
}

TEST(CryptoUtil, EncryptAes256String19) {
  ByteData key(
      "616975656F616975656F616975656F616975656F616975656F616975656F6169");
  ByteData byte_data = CryptoUtil::EncryptAes256(key.GetBytes(),
                                                 "test test test test");
  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "752fe203af4a4d427997e5d2c8b246530e0546b66d2982a49e333e77295dccea");
}

TEST(CryptoUtil, EncryptAes256KeyEmpty) {
  try {
    std::vector<uint8_t> key;
    ByteData byte_data = CryptoUtil::EncryptAes256(key, "test test test test");
  } catch (const cfdcore::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "EncryptAes256 key size error.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(CryptoUtil, EncryptAes256DataEmpty) {
  try {
    ByteData key(
        "616975656F616975656F616975656F616975656F616975656F616975656F6169");
    ByteData byte_data = CryptoUtil::EncryptAes256(key.GetBytes(), "");
  } catch (const cfdcore::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "EncryptAes256 error.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(CryptoUtil, EncryptAes256KeyLengthError) {
  try {
    ByteData key("0123456789abcdef");
    ByteData byte_data = CryptoUtil::EncryptAes256(
        key.GetBytes(), "aiueoaiueoaiueoaiueoaiueoaiueoai");
  } catch (const cfdcore::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "EncryptAes256 key size error.");
    return;
  }
  ASSERT_TRUE(false);
}

// DecryptAes256ToString-------------------------------------------------------
TEST(CryptoUtil, DecryptAes256ToString) {
  ByteData key(
      "616975656F616975656F616975656F616975656F616975656F616975656F6169");
  ByteData data(
      "6af0d7adef48de1e90dde0423d4b1ecc72b60ec0a33c716c397bc50f9662b581");
  std::string result = CryptoUtil::DecryptAes256ToString(key.GetBytes(), data);

  EXPECT_STREQ(result.c_str(), "aiueoaiueoaiueoaiueoaiueoaiueoai");
}

TEST(CryptoUtil, DecryptAes256ToString2) {
  ByteData key(
      "616975656F616975656F616975656F616975656F616975656F616975656F6169");
  ByteData data(
      "752fe203af4a4d427997e5d2c8b246530e0546b66d2982a49e333e77295dccea");
  std::string result = CryptoUtil::DecryptAes256ToString(key.GetBytes(), data);

  EXPECT_STREQ(result.c_str(), "test test test test");
}

TEST(CryptoUtil, DecryptAes256ToStringKeyEmpty) {
  try {
    std::vector<uint8_t> key;
    ByteData data(
        "752fe203af4a4d427997e5d2c8b246530e0546b66d2982a49e333e77295dccea");
    std::string result = CryptoUtil::DecryptAes256ToString(key, data);
  } catch (const cfdcore::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "DecryptAes256 key size error.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(CryptoUtil, DecryptAes256ToStringDataEmpty) {
  try {
    ByteData key(
        "616975656F616975656F616975656F616975656F616975656F616975656F6169");
    ByteData data("");
    std::string result = CryptoUtil::DecryptAes256ToString(key.GetBytes(),
                                                           data);
  } catch (const cfdcore::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "DecryptAes256 error.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(CryptoUtil, DecryptAes256ToStringKeyLengthError) {
  try {
    ByteData key("0123456789abcdef");
    ByteData data(
        "2b0094f5b8ef347d59e502ce123f308fae6cd6dc11567fbf013687620c4135b4");
    std::string result = CryptoUtil::DecryptAes256ToString(key.GetBytes(),
                                                           data);
  } catch (const cfdcore::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "DecryptAes256 key size error.");
    return;
  }
  ASSERT_TRUE(false);
}

// AES256CBC tool
// https://www.devglan.com/online-tools/aes-encryption-decryption
// EncryptAes256Cbc------------------------------------------------------------
TEST(CryptoUtil, EncryptAes256Cbc) {
  ByteData key(
      "3334353637383930313233343536373833343536373839303132333435363738");
  ByteData iv("33343536373839303132333435363738");
  ByteData byte_data = CryptoUtil::EncryptAes256Cbc(
      key.GetBytes(), iv.GetBytes(), "aiueoaiueoaiueoaiueoaiueoaiueoai");
  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "aaf07c2bce50048b41e931898ad647a38d91324abd47121aa4d625fbc2aeb3a8d57df4f18f25599a4c40a9a7c547479c");
}

TEST(CryptoUtil, EncryptAes256Cbc2) {
  ByteData key(
      "616975656F616975656F616975656F616975656F616975656F616975656F6169");
  ByteData iv("33343536373839303132333435363738");
  ByteData byte_data = CryptoUtil::EncryptAes256Cbc(key.GetBytes(),
                                                    iv.GetBytes(),
                                                    "test test test test");
  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "2ef199bb7d160f94fc17fa5f01b220c630d6b19a5973f4b313868c921fc10d22");
}

TEST(CryptoUtil, EncryptAes256CbcKeyEmpty) {
  try {
    std::vector<uint8_t> key;
    ByteData iv("33343536373839303132333435363738");
    ByteData byte_data = CryptoUtil::EncryptAes256Cbc(
        key, iv.GetBytes(), "aiueoaiueoaiueoaiueoaiueoaiueoai");
  } catch (const cfdcore::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "EncryptAes256Cbc key size error.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(CryptoUtil, EncryptAes256CbcIvEmpty) {
  try {
    ByteData key(
        "616975656F616975656F616975656F616975656F616975656F616975656F6169");
    std::vector<uint8_t> iv;
    ByteData byte_data = CryptoUtil::EncryptAes256Cbc(
        key.GetBytes(), iv, "aiueoaiueoaiueoaiueoaiueoaiueoai");
  } catch (const cfdcore::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "EncryptAes256Cbc error.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(CryptoUtil, EncryptAes256CbcDataEmpty) {
  try {
    ByteData key(
        "616975656F616975656F616975656F616975656F616975656F616975656F6169");
    ByteData iv("34567890123456789012345678901234");
    std::string data;
    ByteData byte_data = CryptoUtil::EncryptAes256Cbc(key.GetBytes(),
                                                      iv.GetBytes(), data);
  } catch (const cfdcore::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "EncryptAes256Cbc data isEmpty.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(CryptoUtil, EncryptAes256CbcKeyLengthError) {
  try {
    ByteData key("0123456789abcdef");
    ByteData iv("33343536373839303132333435363738");
    ByteData byte_data = CryptoUtil::EncryptAes256Cbc(
        key.GetBytes(), iv.GetBytes(), "aiueoaiueoaiueoaiueoaiueoaiueoai");
  } catch (const cfdcore::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "EncryptAes256Cbc key size error.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(CryptoUtil, EncryptAes256CbcIvLengthError) {
  try {
    ByteData key(
        "616975656F616975656F616975656F616975656F616975656F616975656F6169");
    ByteData iv("1234");
    ByteData byte_data = CryptoUtil::EncryptAes256Cbc(
        key.GetBytes(), iv.GetBytes(), "aiueoaiueoaiueoaiueoaiueoaiueoai");
  } catch (const cfdcore::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "EncryptAes256Cbc error.");
    return;
  }
  ASSERT_TRUE(false);
}

// DecryptAes256CbcToString----------------------------------------------------
TEST(CryptoUtil, DecryptAes256CbcToString) {
  ByteData key(
      "3334353637383930313233343536373833343536373839303132333435363738");
  ByteData iv("33343536373839303132333435363738");
  ByteData data(
      "aaf07c2bce50048b41e931898ad647a38d91324abd47121aa4d625fbc2aeb3a8d57df4f18f25599a4c40a9a7c547479c");

  std::string result = CryptoUtil::DecryptAes256CbcToString(key.GetBytes(),
                                                            iv.GetBytes(),
                                                            data);
  EXPECT_STREQ(result.c_str(), "aiueoaiueoaiueoaiueoaiueoaiueoai");
}

TEST(CryptoUtil, DecryptAes256CbcToString2) {
  ByteData key(
      "616975656F616975656F616975656F616975656F616975656F616975656F6169");
  ByteData iv("33343536373839303132333435363738");
  ByteData data(
      "2ef199bb7d160f94fc17fa5f01b220c630d6b19a5973f4b313868c921fc10d22");

  std::string result = CryptoUtil::DecryptAes256CbcToString(key.GetBytes(),
                                                            iv.GetBytes(),
                                                            data);
  EXPECT_STREQ(result.c_str(), "test test test test");
}

TEST(CryptoUtil, DecryptAes256CbcToStringKeyEmpty) {
  try {
    std::vector<uint8_t> key;
    ByteData iv("33343536373839303132333435363738");
    ByteData data(
        "2ef199bb7d160f94fc17fa5f01b220c630d6b19a5973f4b313868c921fc10d22");
    std::string result = CryptoUtil::DecryptAes256CbcToString(key,
                                                              iv.GetBytes(),
                                                              data);
  } catch (const cfdcore::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "DecryptAes256Cbc key size error.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(CryptoUtil, DecryptAes256CbcToStringIvEmpty) {
  try {
    ByteData key(
        "616975656F616975656F616975656F616975656F616975656F616975656F6169");
    std::vector<uint8_t> iv;
    ByteData data(
        "2ef199bb7d160f94fc17fa5f01b220c630d6b19a5973f4b313868c921fc10d22");
    std::string result = CryptoUtil::DecryptAes256CbcToString(key.GetBytes(),
                                                              iv, data);
  } catch (const cfdcore::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "DecryptAes256Cbc error.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(CryptoUtil, DecryptAes256CbcToStringDataEmpty) {
  try {
    ByteData key(
        "616975656F616975656F616975656F616975656F616975656F616975656F6169");
    ByteData iv("33343536373839303132333435363738");
    ByteData data;
    std::string result = CryptoUtil::DecryptAes256CbcToString(key.GetBytes(),
                                                              iv.GetBytes(),
                                                              data);
  } catch (const cfdcore::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "DecryptAes256Cbc error.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(CryptoUtil, DecryptAes256CbcToStringDataSizeError) {
  try {
    ByteData key(
        "616975656F616975656F616975656F616975656F616975656F616975656F6169");
    ByteData iv("33343536373839303132333435363738");
    ByteData data(
        "2ef199bb7d160f94fc17fa5f01b220c630d6b19a5973f4b313868c921fc10d");
    std::string result = CryptoUtil::DecryptAes256CbcToString(key.GetBytes(),
                                                              iv.GetBytes(),
                                                              data);
  } catch (const cfdcore::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "DecryptAes256Cbc error.");
    return;
  }
  ASSERT_TRUE(false);
}

// HmacSha256 tool
// https://cryptii.com/pipes/hmac
// HmacSha256------------------------------------------------------------------
TEST(CryptoUtil, HmacSha256) {
  ByteData key(
      "616975656F616975656F616975656F616975656F616975656F616975656F6169");
  ByteData data(
      "2ef199bb7d160f94fc17fa5f01b220c630d6b19a5973f4b313868c921fc10d22");
  ByteData256 byte_data = CryptoUtil::HmacSha256(key.GetBytes(), data);
  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "5af1c9ec83a512db8ea42f288b82c8a07ed05685c28e3c4c8d4c4e1b2f40b212");
}

TEST(CryptoUtil, HmacSha256KeyEmpty) {
  try {
    std::vector<uint8_t> key;
    ByteData data(
        "2ef199bb7d160f94fc17fa5f01b220c630d6b19a5973f4b313868c921fc10d22");
    ByteData256 byte_data = CryptoUtil::HmacSha256(key, data);
  } catch (const cfdcore::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "HmacSha256 error.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(CryptoUtil, HmacSha256DataEmpty) {
  try {
    ByteData key(
        "616975656F616975656F616975656F616975656F616975656F616975656F6169");
    ByteData data;
    ByteData256 byte_data = CryptoUtil::HmacSha256(key.GetBytes(), data);
  } catch (const cfdcore::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "HmacSha256 error.");
    return;
  }
  ASSERT_TRUE(false);
}

// HmacSha512 tool
// https://cryptii.com/pipes/hmac
// HmacSha512------------------------------------------------------------------
TEST(CryptoUtil, HmacSha512) {
  ByteData key(
      "616975656F616975656F616975656F616975656F616975656F616975656F6169");
  ByteData data(
      "2ef199bb7d160f94fc17fa5f01b220c630d6b19a5973f4b313868c921fc10d22");
  ByteData byte_data = CryptoUtil::HmacSha512(key.GetBytes(), data);
  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "33611e4155b594294dac7c61034b5c6f5e49a87167b32ec5ee4bbd7150b6a9357d3021acad45dac9227f458d9576855493ed190fb657cd7a7735c95fc6aa6ba0");
}

TEST(CryptoUtil, HmacSha512KeyEmpty) {
  try {
    std::vector<uint8_t> key;
    ByteData data(
        "2ef199bb7d160f94fc17fa5f01b220c630d6b19a5973f4b313868c921fc10d22");
    ByteData byte_data = CryptoUtil::HmacSha512(key, data);
  } catch (const cfdcore::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "HmacSha512 error.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(CryptoUtil, HmacSha512DataEmpty) {
  try {
    ByteData key(
        "616975656F616975656F616975656F616975656F616975656F616975656F6169");
    ByteData data;
    ByteData byte_data = CryptoUtil::HmacSha512(key.GetBytes(), data);
  } catch (const cfdcore::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "HmacSha512 error.");
    return;
  }
  ASSERT_TRUE(false);
}

// poc transaction test
// ConvertSignatureToDer-------------------------------------------------------
TEST(CryptoUtil, ConvertSignatureToDer) {
  std::string hex_sig =
      "773420c0ded41a55b1f1205cfb632f08f3f911a53e7338a0dac73ec6cbe3ca471907434d046185abedc5afddc2761a642bccc70af6d22b46394f1d04a8b24226";
  SigHashType sig_type(SigHashAlgorithm::kSigHashAll);
  ByteData byte_data = CryptoUtil::ConvertSignatureToDer(hex_sig, sig_type);
  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "30440220773420c0ded41a55b1f1205cfb632f08f3f911a53e7338a0dac73ec6cbe3ca4702201907434d046185abedc5afddc2761a642bccc70af6d22b46394f1d04a8b2422601");
}

TEST(CryptoUtil, ConvertSignatureToDerHexEmpty) {
  try {
    std::string hex_sig;
    SigHashType sig_type(SigHashAlgorithm::kSigHashAll);
    ByteData byte_data = CryptoUtil::ConvertSignatureToDer(hex_sig, sig_type);
  } catch (const cfdcore::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "der encode error.");
    return;
  }
  ASSERT_TRUE(false);
}

// Base64 encode tool
// https://cryptii.com/pipes/base64-to-hex
// EncodeBase64----------------------------------------------------------------
TEST(CryptoUtil, EncodeBase64) {
  ByteData data(
      "54686520717569636b2062726f776e20666f78206a756d7073206f766572203133206c617a7920646f67732e");
  std::string result = CryptoUtil::EncodeBase64(data);
  EXPECT_STREQ(result.c_str(),
               "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIDEzIGxhenkgZG9ncy4=");
}

TEST(CryptoUtil, EncodeBase64DataEmpty) {
  ByteData data;
  std::string result = CryptoUtil::EncodeBase64(data);
  EXPECT_STREQ(result.c_str(), "");
}

// DecodeBase64----------------------------------------------------------------
TEST(CryptoUtil, DecodeBase64) {
  std::string data(
      "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIDEzIGxhenkgZG9ncy4=");
  ByteData byte_data = CryptoUtil::DecodeBase64(data);
  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "54686520717569636b2062726f776e20666f78206a756d7073206f766572203133206c617a7920646f67732e");
}

TEST(CryptoUtil, DecodeBase64DataEmpty) {
  std::string data;
  ByteData byte_data = CryptoUtil::DecodeBase64(data);
  EXPECT_STREQ(byte_data.GetHex().c_str(), "");
}

// Base58 decode tool
// https://bc-2.jp/tools/txeditor2.html
// EncodeBase58----------------------------------------------------------------
TEST(CryptoUtil, DecodeBase58Check) {
  std::string data(
      "xpub6FZeZ5vwcYiT6r7ZYKJhyUqBxMBvzSmb6SpPQCsSenGPrVjKk5SGW4JJpc7cKERN8w9KnJZcMgJA4B2cHnpGq5TahYrDvZSBY2EMLKPRMTT");
  ByteData byte_data = CryptoUtil::DecodeBase58Check(data);
  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "0488b21e051431616f00000000e6ba4088246b104837c62bd01fd8ba1cf2931ad1a5376c2360a1f112f2cfc63c02acf89ab4e3daa79bceef2ebecee2af92712e6bf5e4b0d10c74bbecc27ac13da8");
}

TEST(CryptoUtil, DecodeBase58CheckDataEmpty) {
  try {
    std::string data;
    ByteData byte_data = CryptoUtil::DecodeBase58Check(data);
  } catch (const cfdcore::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "Decode base58 error.");
    return;
  }
  ASSERT_TRUE(false);
}
