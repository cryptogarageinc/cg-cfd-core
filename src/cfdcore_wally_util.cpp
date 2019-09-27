// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_wally_util.cpp
 *
 * @brief libwally internal utility.
 *
 */
#include <exception>
#include <string>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore_secp256k1.h"   // NOLINT
#include "cfdcore_wally_util.h"  // NOLINT

#include "wally_address.h"      // NOLINT
#include "wally_bip32.h"        // NOLINT
#include "wally_bip38.h"        // NOLINT
#include "wally_bip39.h"        // NOLINT
#include "wally_core.h"         // NOLINT
#include "wally_crypto.h"       // NOLINT
#include "wally_script.h"       // NOLINT
#include "wally_transaction.h"  // NOLINT

namespace cfdcore {

using logger::warn;

//////////////////////////////////
/// WallyUtil
//////////////////////////////////
std::string WallyUtil::ConvertStringAndFree(char* wally_string) {
  try {
    std::string result = std::string(wally_string);
    wally_free_string(wally_string);
    return result;
  } catch (const std::exception& except) {
    wally_free_string(wally_string);
    warn(CFD_LOG_SOURCE, "system error. except={}.", except.what());
    throw except;
  } catch (...) {
    wally_free_string(wally_string);
    warn(CFD_LOG_SOURCE, "unknown error.");
    throw CfdException();
  }
}

ByteData WallyUtil::CombinePubkeySecp256k1Ec(
    const std::vector<ByteData>& pubkey_list) {
  struct secp256k1_context_struct* context = wally_get_secp_context();

  Secp256k1 secp256k1(context);
  return secp256k1.CombinePubkeySecp256k1Ec(pubkey_list);
}

ByteData WallyUtil::AddTweakPubkey(
    const ByteData& pubkey, const ByteData256& tweak, bool is_tweak_check) {
  struct secp256k1_context_struct* context = wally_get_secp_context();
  Secp256k1 secp256k1(context);
  return secp256k1.AddTweakPubkeySecp256k1Ec(
      pubkey, ByteData(tweak.GetBytes()), is_tweak_check);
}

ByteData256 WallyUtil::AddTweakPrivkey(
    const ByteData256& privkey, const ByteData256& tweak) {
  struct secp256k1_context_struct* context = wally_get_secp_context();
  Secp256k1 secp256k1(context);
  return secp256k1.AddTweakPrivkeySecp256k1Ec(privkey, tweak);
}

std::vector<uint8_t> WallyUtil::CreateScriptDataFromBytes(
    const std::vector<uint8_t>& bytes, int32_t flags) {
  size_t write_max_size = bytes.size() + kMaxVarIntSize;
  std::vector<uint8_t> ret_bytes(write_max_size);
  size_t written = 0;

  int ret = wally_script_push_from_bytes(
      bytes.data(), bytes.size(), flags, ret_bytes.data(), write_max_size,
      &written);
  if (ret == WALLY_OK && write_max_size < written) {
    // サイズ不足の場合はresizeしてリトライ
    ret_bytes.resize(written);
    ret = wally_script_push_from_bytes(
        bytes.data(), bytes.size(), flags, ret_bytes.data(), ret_bytes.size(),
        &written);
  }

  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "Script push error.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Script push error.");
  }
  ret_bytes.resize(written);
  return ret_bytes;
}

ByteData WallyUtil::NegatePubkey(const ByteData& pubkey) {
  struct secp256k1_context_struct* context = wally_get_secp_context();
  Secp256k1 secp256k1(context);
  return secp256k1.NegatePubkeySecp256k1Ec(pubkey);
}

void WallyUtil::RangeProofInfo(
    const ByteData& bytes, int* exponent, int* mantissa, uint64_t* min_value,
    uint64_t* max_value) {
  struct secp256k1_context_struct* context = wally_get_secp_context();

  Secp256k1 secp256k1(context);
  secp256k1.RangeProofInfoSecp256k1(
      bytes, exponent, mantissa, min_value, max_value);
}

ByteData WallyUtil::SignWhitelist(
    const ByteData& offline_pubkey, const ByteData256& online_privkey,
    const ByteData256& tweak_sum, const std::vector<ByteData>& online_keys,
    const std::vector<ByteData>& offline_keys, uint32_t whitelist_index) {
  struct secp256k1_context_struct* context = wally_get_secp_context();
  Secp256k1 secp256k1(context);
  return secp256k1.SignWhitelistSecp256k1Ec(
      offline_pubkey, online_privkey, tweak_sum, online_keys, offline_keys,
      whitelist_index);
}

}  // namespace cfdcore