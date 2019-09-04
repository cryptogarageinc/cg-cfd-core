// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_secp256k1.h
 * @brief secp256k1 utility.
 *
 */
#ifndef CFD_CORE_SRC_CFDCORE_SECP256K1_H_
#define CFD_CORE_SRC_CFDCORE_SECP256K1_H_

#include <vector>
#include "cfdcore/cfdcore_bytedata.h"

namespace cfdcore {

/**
 * @brief secp256k1クラス.
 */
class Secp256k1 {
 public:
  /**
   * @brief コンストラクタ
   * @param[in] context Secp256k1コンテキスト
   */
  explicit Secp256k1(void* context);

  /**
   * @brief Pubkey合成処理
   * @param[in] pubkey_list 合成するPubkeyリスト
   * @return 合成したPubkeyデータ
   */
  ByteData CombinePubkeySecp256k1Ec(const std::vector<ByteData>& pubkey_list);

  /**
   * @brief Pubkey調整処理
   * @param[in] pubkey            Pubkey
   * @param[in] tweak             調整値
   * @param[in] is_tweak_check    pubkey調整チェック実施有無
   * @return 調整後のPubkeyデータ
   */
  ByteData AddTweakPubkeySecp256k1Ec(
      const ByteData& pubkey, const ByteData& tweak, bool is_tweak_check);

 private:
  /**
   * @brief Secp256k1コンテキスト
   */
  void* secp256k1_context_;
};

}  // namespace cfdcore
#endif  // CFD_CORE_SRC_CFDCORE_SECP256K1_H_
