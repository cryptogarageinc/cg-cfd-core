// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_hdwallet.h
 *
 * @brief BIP32/BIP39/BIP44関連クラス
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_HDWALLET_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_HDWALLET_H_

#include <string>
#include <vector>

#include "cfdcore/cfdcore_common.h"

namespace cfdcore {

/**
 * @brief HDWalletを表現するデータクラス
 */
class CFD_CORE_EXPORT HDWallet {
 public:
  /**
   * @brief デフォルトコンストラクタ
   */
  HDWallet();

  /**
   * @brief BIP39 で利用できる Wordlist を取得する.
   * @param[in] language 取得するWordlistの言語
   * @return Wordlist vector
   */
  static std::vector<std::string> Bip39GetWordlist(std::string language);

 private:
};

}  // namespace cfdcore

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_HDWALLET_H_
