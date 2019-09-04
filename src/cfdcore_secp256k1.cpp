// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_secp256k1.cpp
 *
 * @brief secp256k1関連クラス定義
 */

#include <vector>

#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore_secp256k1.h"  // NOLINT
#include "secp256k1.h"          // NOLINT

namespace cfdcore {

using logger::warn;

Secp256k1::Secp256k1(void* context) : secp256k1_context_(context) {
  // do nothing
}

ByteData Secp256k1::CombinePubkeySecp256k1Ec(
    const std::vector<ByteData>& pubkey_list) {
  secp256k1_context* context =
      static_cast<secp256k1_context*>(secp256k1_context_);

  if (secp256k1_context_ == NULL) {
    warn(CFD_LOG_SOURCE, "Secp256k1 context is NULL.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Secp256k1 context is NULL.");
  }

  if (pubkey_list.size() < 2) {
    warn(CFD_LOG_SOURCE, "Invalid Argument pubkey list.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid Pubkey List data.");
  }

  std::vector<secp256k1_pubkey> key_array(pubkey_list.size());
  std::vector<secp256k1_pubkey*> ptr_array(pubkey_list.size());
  int ret;

  for (size_t i = 0; i < pubkey_list.size(); ++i) {
    // ByteDataをsecp256k1_pubkey型に変換
    ret = secp256k1_ec_pubkey_parse(
        context, &key_array[i], pubkey_list[i].GetBytes().data(),
        pubkey_list[i].GetBytes().size());

    if (ret != 1) {
      warn(CFD_LOG_SOURCE, "Secp256k1 pubkey parse Error.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "Secp256k1 pubkey parse Error.");
    }
    ptr_array[i] = &key_array[i];
  }

  // Pubkeyを合成
  secp256k1_pubkey combine_key;
  ret = secp256k1_ec_pubkey_combine(
      context, &combine_key, ptr_array.data(), key_array.size());
  if (ret != 1) {
    warn(CFD_LOG_SOURCE, "Secp256k1 pubkey combine Error.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Secp256k1 pubkey combine Error.");
  }

  std::vector<uint8_t> byte_data(65);
  size_t byte_size = byte_data.size();
  // ByteDataに変換
  ret = secp256k1_ec_pubkey_serialize(
      context, byte_data.data(), &byte_size, &combine_key,
      SECP256K1_EC_COMPRESSED);

  if (ret != 1) {
    warn(CFD_LOG_SOURCE, "Secp256k1 pubkey serialize Error.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Secp256k1 pubkey serialize Error.");
  }

  byte_data.resize(byte_size);
  return ByteData(byte_data);
}

ByteData Secp256k1::AddTweakPubkeySecp256k1Ec(
    const ByteData& pubkey, const ByteData& tweak, bool is_tweak_check) {
  secp256k1_context* context =
      static_cast<secp256k1_context*>(secp256k1_context_);

  if (secp256k1_context_ == NULL) {
    warn(CFD_LOG_SOURCE, "Secp256k1 context is NULL.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Secp256k1 context is NULL.");
  }
  if (pubkey.GetDataSize() != 33) {
    warn(CFD_LOG_SOURCE, "Invalid Argument pubkey size.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid Pubkey size.");
  }
  if (tweak.GetDataSize() != 32) {
    warn(CFD_LOG_SOURCE, "Invalid Argument tweak size.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid tweak size.");
  }

  int ret;
  std::vector<uint8_t> pubkey_data = pubkey.GetBytes();
  std::vector<uint8_t> tweak_data = tweak.GetBytes();
  secp256k1_pubkey tweaked;
  secp256k1_pubkey watchman;
  ret = secp256k1_ec_pubkey_parse(
      context, &tweaked, pubkey_data.data(), pubkey_data.size());
  if (ret != 1) {
    warn(CFD_LOG_SOURCE, "secp256k1_ec_pubkey_parse Error.({})", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Secp256k1 pubkey parse Error.");
  }
  memcpy(&watchman, &tweaked, sizeof(watchman));

  ret = secp256k1_ec_pubkey_tweak_add(context, &tweaked, tweak_data.data());
  if (ret != 1) {
    warn(CFD_LOG_SOURCE, "secp256k1_ec_pubkey_tweak_add Error.({})", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Secp256k1 pubkey tweak Error.");
  }

  std::vector<uint8_t> byte_data(65);
  size_t byte_size = byte_data.size();
  ret = secp256k1_ec_pubkey_serialize(
      context, byte_data.data(), &byte_size, &tweaked,
      SECP256K1_EC_COMPRESSED);
  if (ret != 1) {
    warn(CFD_LOG_SOURCE, "secp256k1_ec_pubkey_serialize Error.({})", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Secp256k1 pubkey serialize Error.");
  }

  if (byte_size != 33) {
    warn(
        CFD_LOG_SOURCE,
        "secp256k1_ec_pubkey_serialize pubkey length Error.({})", byte_size);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Secp256k1 pubkey length Error.");
  }
  byte_data.resize(byte_size);

  if (is_tweak_check) {
    // check: `tweaked - watchman = tweak`
    secp256k1_pubkey tweaked2;
    ret = secp256k1_ec_pubkey_create(context, &tweaked2, tweak_data.data());
    if (ret != 1) {
      warn(CFD_LOG_SOURCE, "secp256k1_ec_pubkey_parse Error.({})", ret);
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "Secp256k1 pubkey parse Error.");
    }
    ret = secp256k1_ec_pubkey_negate(context, &watchman);
    if (ret != 1) {
      warn(CFD_LOG_SOURCE, "secp256k1_ec_pubkey_negate Error.({})", ret);
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Secp256k1 pubkey negate Error.");
    }

    secp256k1_pubkey* pubkey_combined[2];
    pubkey_combined[0] = &watchman;
    pubkey_combined[1] = &tweaked;
    secp256k1_pubkey maybe_tweaked2;
    ret = secp256k1_ec_pubkey_combine(
        context, &maybe_tweaked2, pubkey_combined, 2);
    if (ret != 1) {
      warn(CFD_LOG_SOURCE, "secp256k1_ec_pubkey_combine Error.({})", ret);
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Secp256k1 pubkey combine Error.");
    }
    if (memcmp(&maybe_tweaked2, &tweaked2, 64) != 0) {
      warn(CFD_LOG_SOURCE, "tweak check Error.");
      throw CfdException(
          CfdError::kCfdIllegalStateError, "Secp256k1 tweak check Error.");
    }
  }
  return ByteData(byte_data);
}

}  // namespace cfdcore
