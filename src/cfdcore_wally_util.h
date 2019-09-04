// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_wally_util.h
 *
 * @brief libwally internal utility.
 *
 */
#ifndef CFD_CORE_SRC_CFDCORE_WALLY_UTIL_H_
#define CFD_CORE_SRC_CFDCORE_WALLY_UTIL_H_
#ifdef __cplusplus

#include <string>
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"

#include "wally_address.h"      // NOLINT
#include "wally_bip32.h"        // NOLINT
#include "wally_bip38.h"        // NOLINT
#include "wally_bip39.h"        // NOLINT
#include "wally_core.h"         // NOLINT
#include "wally_crypto.h"       // NOLINT
#include "wally_transaction.h"  // NOLINT
#ifndef CFDCORE_NOT_USE_LIBWALLY_SCRIPT
//#include "wally_script.h"       // NOLINT
#endif  // CFDCORE_NOT_USE_LIBWALLY_SCRIPT

namespace cfdcore {

/**
 * @brief libwally utility.
 */
class WallyUtil {
 public:
  /**
   * @brief VarIntサイズ
   */
  static constexpr uint8_t kMaxVarIntSize = 5;
  /**
   * @brief converts char* to std::string, and call wally_free_string.
   * @param[in] wally_string    libwally created string buffer.
   * @result std::string object.
   */
  static std::string ConvertStringAndFree(char* wally_string);

  /**
   * @brief Pubkey合成処理
   * @param[in] pubkey_list 合成するPubkeyリスト
   * @return 合成したPubkeyデータ
   */
  static ByteData CombinePubkeySecp256k1Ec(
      const std::vector<ByteData>& pubkey_list);

  /**
   * @brief Pubkey調整処理
   * @param[in] pubkey            Pubkey
   * @param[in] byte_data         調整値
   * @param[in] is_tweak_check    pubkey調整チェック実施有無
   * @return 調整後のPubkeyデータ
   */
  static ByteData AddTweakPubkey(
      const ByteData& pubkey, const ByteData& byte_data, bool is_tweak_check);

  /**
   * @brief Scriptにpushするデータを生成する
   * @param[in] bytes 追加データ
   * @param[in] flags hashフラグ(@see wally_script_push_from_bytes)
   * @return 生成データ
   */
  static std::vector<uint8_t> CreateScriptDataFromBytes(
      const std::vector<uint8_t>& bytes, int32_t flags = 0);

 private:
  /**
   * @brief default constructor.
   */
  WallyUtil();
};

}  // namespace cfdcore

#endif  // __cplusplus
#endif  // CFD_CORE_SRC_CFDCORE_WALLY_UTIL_H_
