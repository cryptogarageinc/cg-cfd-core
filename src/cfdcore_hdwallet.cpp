// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_hdwallet.cpp
 *
 * @brief BIP32/BIP39/BIP44関連クラスの実装
 */

#include <string>
#include <vector>

#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_hdwallet.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore_wally_util.h"  // NOLINT

namespace cfdcore {

using logger::warn;

std::vector<std::string> HDWallet::GetMnemonicWordlist(std::string language) {
  return WallyUtil::GetMnemonicWordlist(language);
}

}  // namespace cfdcore
