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

std::vector<std::string> HDWallet::GetMnemonicWordlist(
    const std::string& language) {
  if (!CheckSupportedLanguages(language)) {
    warn(
        CFD_LOG_SOURCE, "Not support language passed. language=[{}]",
        language);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Not support language passed.");
  }

  return WallyUtil::GetMnemonicWordlist(language);
}

ByteData HDWallet::ConvertMnemonicToSeed(
    const std::vector<std::string>& mnemonic, const std::string& passphrase,
    bool use_ideographic_space) {
  return WallyUtil::ConvertMnemonicToSeed(
      mnemonic, passphrase, use_ideographic_space);
}

std::vector<std::string> HDWallet::ConvertEntropyToMnemonic(
    const ByteData& entropy, const std::string& language) {
  if (!CheckSupportedLanguages(language)) {
    warn(
        CFD_LOG_SOURCE, "Not support language passed. language=[{}]",
        language);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Not support language passed.");
  }

  return WallyUtil::ConvertEntropyToMnemonic(entropy, language);
}

ByteData HDWallet::ConvertMnemonicToEntropy(
    const std::vector<std::string>& mnemonic, const std::string& language) {
  if (!CheckSupportedLanguages(language)) {
    warn(
        CFD_LOG_SOURCE, "Not support language passed. language=[{}]",
        language);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Not support language passed.");
  }

  return WallyUtil::ConvertMnemonicToEntropy(mnemonic, language);
}

bool HDWallet::CheckValidMnemonic(
    const std::vector<std::string>& mnemonic, const std::string& language,
    bool use_ideographic_space) {
  if (!CheckSupportedLanguages(language)) {
    warn(
        CFD_LOG_SOURCE, "Not support language passed. language=[{}]",
        language);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Not support language passed.");
  }

  return WallyUtil::CheckValidMnemonic(
      mnemonic, language, use_ideographic_space);
}

bool HDWallet::CheckSupportedLanguages(const std::string& language) {
  std::vector<std::string> slangs = WallyUtil::GetSupportedMnemonicLanguages();
  return (
      std::find(slangs.cbegin(), slangs.cend(), language) != slangs.cend());
}

}  // namespace cfdcore
