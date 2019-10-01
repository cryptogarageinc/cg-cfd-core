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
#include "cfdcore_secp256k1.h"  // NOLINT

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
   * @param[in] tweak             調整値
   * @param[in] is_tweak_check    pubkey調整チェック実施有無
   * @return 調整後のPubkeyデータ
   */
  static ByteData AddTweakPubkey(
      const ByteData& pubkey, const ByteData256& tweak,
      bool is_tweak_check = false);

  /**
   * @brief Privkey調整処理
   * @param[in] privkey           Privkey
   * @param[in] tweak             調整値
   * @return 調整後のPrivkeyデータ
   */
  static ByteData256 AddTweakPrivkey(
      const ByteData256& privkey, const ByteData256& tweak);

  /**
   * @brief Scriptにpushするデータを生成する
   * @param[in] bytes 追加データ
   * @param[in] flags hashフラグ(@see wally_script_push_from_bytes)
   * @return 生成データ
   */
  static std::vector<uint8_t> CreateScriptDataFromBytes(
      const std::vector<uint8_t>& bytes, int32_t flags = 0);

  /**
   * @brief Pubkey negate処理
   * @param[in] pubkey            Pubkey
   * @return 加工後のPubkeyデータ
   */
  static ByteData NegatePubkey(const ByteData& pubkey);

  /**
   * @brief Decode range-proof and extract some information.
   * @param[in]  range_proof  ByteData of range-proof
   * @param[out] exponent     exponent value in the proof
   * @param[out] mantissa     Number of bits covered by the proof
   * @param[out] min_value    the minimum value that commit could have
   * @param[out] max_value    the maximum value that commit could have
   */
  static void RangeProofInfo(
      const ByteData& range_proof, int* exponent, int* mantissa,
      uint64_t* min_value, uint64_t* max_value);

  /**
   * @brief Whitelist 証明情報生成処理
   * @param[in] offline_pubkey    offline pubkey
   * @param[in] online_privkey    online private key
   * @param[in] tweak_sum         tweak sum data
   * @param[in] online_keys       whitelist online key list
   * @param[in] offline_keys      whitelist offline key list
   * @param[in] whitelist_index   whitelist target index
   * @return Whitelist proof
   */
  static ByteData SignWhitelist(
      const ByteData& offline_pubkey, const ByteData256& online_privkey,
      const ByteData256& tweak_sum, const std::vector<ByteData>& online_keys,
      const std::vector<ByteData>& offline_keys, uint32_t whitelist_index);

 private:
  /**
   * @brief default constructor.
   */
  WallyUtil();
};

}  // namespace cfdcore

#endif  // __cplusplus
#endif  // CFD_CORE_SRC_CFDCORE_WALLY_UTIL_H_
