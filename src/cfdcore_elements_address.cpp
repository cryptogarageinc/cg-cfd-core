// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_elements_address.cpp
 *
 * @brief Elements対応したAddressクラス定義
 */
#ifndef CFD_DISABLE_ELEMENTS

#include <algorithm>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_elements_address.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore/cfdcore_script.h"
#include "cfdcore/cfdcore_util.h"
#include "cfdcore_wally_util.h"  // NOLINT

namespace cfdcore {

using logger::info;
using logger::warn;

// @formatter:off
/// ElementsNetTypeごとの固定値(prefix等)
const ElementsNetParams kElementsNetParams[kElementsNetTypeNum] = {
    // mainet
    {
        "liquidv1",  // liquid mainnet
        0x39,        // P2PKH address prefix
        0x27,        // P2SH address prefix
        0x0c,        // Confidential address prefix
                     //        "ex"       // bech32 human-readable part
    },
    // testnet/regtest
    {
        "regtest",  // testnet/regtest
        0xeb,       // P2PKH address prefix
        0x4b,       // P2SH address prefix
        0x04,       // Confidential address prefix
                    //        "erp"            // bech32 human-readable part
    },
};
// @formatter:on

// -----------------------------------------------------------------------------
// AbstractElementsAddress
// -----------------------------------------------------------------------------
AbstractElementsAddress::AbstractElementsAddress(
    bool is_blinded, std::string address)
    : is_blinded_(is_blinded),
      address_(address),
      type_(kLiquidV1),
      addr_type_(kUnknownElementsAddressType),
      hash_() {
  // do nothing
}

AbstractElementsAddress::AbstractElementsAddress(
    bool is_blinded, std::string address, ElementsNetType type,
    ElementsAddressType addr_type, const ByteData160& hash)
    : is_blinded_(is_blinded),
      address_(address),
      type_(type),
      addr_type_(addr_type),
      hash_(ByteData(hash.GetBytes())) {
  // do nothing
}

bool AbstractElementsAddress::IsConfidentialAddress(std::string address) {
  std::vector<uint8_t> data_part(128);
  size_t written = 0;

  int ret = -1;
  ret = wally_base58_to_bytes(
      address.data(), BASE58_FLAG_CHECKSUM, data_part.data(), data_part.size(),
      &written);
  if (ret != WALLY_OK) {
    warn(
        CFD_LOG_SOURCE,
        "IsConfidentialAddress wally_base58_to_bytes error. : ret={}"
        " address={}",
        ret, address);
    if (ret == WALLY_EINVAL) {
      throw CfdException(kCfdIllegalArgumentError, "Base58 decode error.");
    } else {
      throw CfdException(kCfdInternalError, "Base58 decode error.");
    }
  }
  data_part.resize(written);

  return (
      (data_part[0] == kElementsNetParams[kLiquidV1].confidential_addr_id ||
       data_part[0] == kElementsNetParams[kElementsRegtest]
                           .confidential_addr_id)  // NOLINT
      && data_part.size() > 34);
}

// -----------------------------------------------------------------------------
// ElementsUnblindedAddress
// -----------------------------------------------------------------------------
ElementsUnblindedAddress::ElementsUnblindedAddress()
    : AbstractElementsAddress(false, "") {
  // do nothing
}

ElementsUnblindedAddress::ElementsUnblindedAddress(
    const std::string& address_string)
    : AbstractElementsAddress(false, address_string) {
  DecodeAddress(address_string);
}

ElementsUnblindedAddress::ElementsUnblindedAddress(
    ElementsNetType type, const Pubkey& pubkey)
    : ElementsUnblindedAddress(
          type, ElementsAddressType::kElementsP2pkhAddress,
          HashUtil::Hash160(pubkey)) {
  // do nothing
}

ElementsUnblindedAddress::ElementsUnblindedAddress(
    ElementsNetType type, const Script& redeem_script)
    : ElementsUnblindedAddress(
          type, ElementsAddressType::kElementsP2shAddress,
          HashUtil::Hash160(redeem_script)) {
  // do nothing
}

ElementsUnblindedAddress::ElementsUnblindedAddress(
    ElementsNetType type, ElementsAddressType addr_type,
    const ByteData160& hash)
    : AbstractElementsAddress(false, "", type, addr_type, hash) {
  CalculateAddress();
}

void ElementsUnblindedAddress::CalculateAddress() {
  if (type_ < 0 || ElementsNetType::kElementsNetTypeNum <= type_) {
    warn(
        CFD_LOG_SOURCE,
        "CalculateAddress error. Invalid ElementsNetType. : net_type_={}.",
        type_);
    throw CfdException(
        kCfdIllegalStateError,
        "ElementsUnblindedAddress set unknown network type.");
  }

  switch (addr_type_) {
    case ElementsAddressType::kElementsP2shAddress:
      CalculateAddress(kElementsNetParams[type_].p2sh_addr_id, hash_);
      break;
    case ElementsAddressType::kElementsP2pkhAddress:
      CalculateAddress(kElementsNetParams[type_].p2pkh_addr_id, hash_);
      break;
    case ElementsAddressType::kUnknownElementsAddressType:
    default:
      warn(
          CFD_LOG_SOURCE,
          "CalculateAddress error. Invalid AddressType. : addr_type_={}.",
          addr_type_);
      throw CfdException(
          kCfdIllegalStateError,
          "ElementsUnblindedAddress set unknown address type.");
  }
}

void ElementsUnblindedAddress::CalculateAddress(
    const uint8_t prefix, const ByteData& hash_data) {
  std::vector<uint8_t> address_data = hash_data.GetBytes();

  // 先頭にAddress Prefixを追加
  address_data.insert(address_data.begin(), prefix);

  char* output = NULL;
  int ret = wally_base58_from_bytes(
      address_data.data(), address_data.size(), BASE58_FLAG_CHECKSUM, &output);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_base58_from_bytes error. ret={}.", ret);
    info(
        CFD_LOG_SOURCE, "input hash={}",
        StringUtil::ByteToString(address_data));
    if (ret == WALLY_EINVAL) {
      throw CfdException(
          kCfdIllegalArgumentError,
          "ElementsUnblindedAddress base58 encode error.");
    } else {
      throw CfdException(
          kCfdInternalError, "ElementsUnblindedAddress base58 encode error.");
    }
  }

  address_ = WallyUtil::ConvertStringAndFree(output);
}

void ElementsUnblindedAddress::DecodeAddress(std::string unblinded_address) {
  std::vector<uint8_t> data_part(128);
  size_t written = 0;

  int ret = -1;
  ret = wally_base58_to_bytes(
      unblinded_address.data(), BASE58_FLAG_CHECKSUM, data_part.data(),
      data_part.size(), &written);
  if (ret != WALLY_OK) {
    warn(
        CFD_LOG_SOURCE,
        "DecodeAddress wally_base58_to_bytes error. : ret={}"
        " unblinded_address={}",
        ret, unblinded_address);
    if (ret == WALLY_EINVAL) {
      throw CfdException(
          kCfdIllegalArgumentError,
          "ElementsUnblindedAddress Base58 decode error.");
    } else {
      throw CfdException(
          kCfdInternalError, "ElementsUnblindedAddress Base58 decode error.");
    }
  }

  data_part.resize(written);

  if (data_part[0] == kElementsNetParams[kLiquidV1].p2pkh_addr_id) {
    type_ = kLiquidV1;
    addr_type_ = ElementsAddressType::kElementsP2pkhAddress;
  } else if (data_part[0] == kElementsNetParams[kLiquidV1].p2sh_addr_id) {
    type_ = kLiquidV1;
    addr_type_ = ElementsAddressType::kElementsP2shAddress;
  } else if (
      data_part[0] ==
      kElementsNetParams[kElementsRegtest].p2pkh_addr_id) {  // NOLINT
    type_ = kElementsRegtest;
    addr_type_ = ElementsAddressType::kElementsP2pkhAddress;
  } else if (
      data_part[0] ==
      kElementsNetParams[kElementsRegtest].p2sh_addr_id) {  // NOLINT
    type_ = kElementsRegtest;
    addr_type_ = ElementsAddressType::kElementsP2shAddress;
  } else {
    warn(
        CFD_LOG_SOURCE,
        "DecodeAddress error. Unknown AddressPrefix found. : address={}"
        " prefix={}.",
        unblinded_address, data_part[0]);
    throw CfdException(
        kCfdIllegalArgumentError,
        "DecodeAddress received unknown address prefix.");
  }
  // 0byte:prefixを削除
  data_part.erase(data_part.cbegin());

  if (data_part.size() != kByteData160Length) {
    warn(
        CFD_LOG_SOURCE,
        "DecodeAddress error. Invalid hash data found. : address={}"
        " hash_data={}.",
        unblinded_address, StringUtil::ByteToString(data_part));
    throw CfdException(
        kCfdIllegalArgumentError,
        "DecodeAddress failed to decode address."
        " UnblinedAddress contains unknown hash data.");
  }

  // Hash設定
  hash_ = ByteData(data_part);
}

// -----------------------------------------------------------------------------
// ElementsConfidentialAddress
// -----------------------------------------------------------------------------
ElementsConfidentialAddress::ElementsConfidentialAddress()
    : AbstractElementsAddress(true, ""),
      unblinded_address_(),
      confidential_key_() {
  // do nothing
}

ElementsConfidentialAddress::ElementsConfidentialAddress(
    const ElementsUnblindedAddress& unblinded_address,
    const ConfidentialKey& confidential_key)
    : AbstractElementsAddress(true, ""),
      unblinded_address_(unblinded_address),
      confidential_key_(confidential_key) {
  CalculateAddress(unblinded_address_, confidential_key_);
}

ElementsConfidentialAddress::ElementsConfidentialAddress(
    const std::string& confidential_address)
    : AbstractElementsAddress(true, confidential_address),
      unblinded_address_(),
      confidential_key_() {
  DecodeAddress(confidential_address);
}

void ElementsConfidentialAddress::DecodeAddress(
    const std::string& confidential_address) {
  // decode base58 confidential address
  std::vector<uint8_t> data_part(128);
  size_t written = 0;

  int ret = -1;
  ret = wally_base58_to_bytes(
      confidential_address.data(), BASE58_FLAG_CHECKSUM, data_part.data(),
      data_part.size(), &written);
  if (ret != WALLY_OK) {
    warn(
        CFD_LOG_SOURCE,
        "DecodeAddress wally_base58_to_bytes error."
        " : ret={}, confidential_address={} .",
        ret, confidential_address);
    if (ret == WALLY_EINVAL) {
      throw CfdException(
          kCfdIllegalArgumentError,
          "ElementsUnblindedAddress Base58 decode error.");
    } else {
      throw CfdException(
          kCfdInternalError, "ElementsUnblindedAddress Base58 decode error.");
    }
  }
  data_part.resize(written);

  // check confidential address prefix
  if (data_part[0] == kElementsNetParams[kLiquidV1].confidential_addr_id) {
    type_ = kLiquidV1;
  } else if (
      data_part[0] ==
      kElementsNetParams[kElementsRegtest].confidential_addr_id) {
    type_ = kElementsRegtest;
  } else {
    warn(
        CFD_LOG_SOURCE,
        "DecodeAddress error. Unknown confidential address prefix found."
        " : address={}, prefix={}.",
        confidential_address, data_part[0]);
    throw CfdException(
        kCfdIllegalArgumentError,
        "DecodeAddress received unknown address prefix.");
  }
  // 0byte:confidential address prefixを削除
  auto itr = data_part.erase(data_part.cbegin());

  // check unblinded address prefix
  if (data_part[0] == kElementsNetParams[type_].p2pkh_addr_id) {
    addr_type_ = ElementsAddressType::kElementsP2pkhAddress;
  } else if (data_part[0] == kElementsNetParams[type_].p2sh_addr_id) {
    addr_type_ = ElementsAddressType::kElementsP2shAddress;
  } else {
    warn(
        CFD_LOG_SOURCE,
        "DecodeAddress error. Unknown unblinded address prefix found."
        " : address={}, prefix={}.",
        confidential_address, data_part[0]);
    throw CfdException(
        kCfdIllegalArgumentError,
        "DecodeAddress received unknown address prefix.");
  }
  // 1byte: unblinded address prefixを削除
  itr = data_part.erase(itr);

  // extract confidential key byte
  std::vector<uint8_t> ckey_bytes(Pubkey::kCompressedPubkeySize);
  std::copy(itr, (itr + Pubkey::kCompressedPubkeySize), ckey_bytes.begin());
  confidential_key_ = ConfidentialKey(ByteData(ckey_bytes));
  // check confidential key is compressed
  if (!confidential_key_.IsCompress()) {
    warn(
        CFD_LOG_SOURCE,
        "DecodeAddress error. Contained confidential key is not compressed."
        " : address={}, confidential_key={}.",
        confidential_address, confidential_key_.GetHex());
    throw CfdException(
        kCfdIllegalArgumentError,
        "DecodeAddress error. contained confidential key is not compressed.");
  }
  // 33byte: confidential_keyを削除
  itr = data_part.erase(itr, (itr + Pubkey::kCompressedPubkeySize));

  // check remaining byte size
  if (data_part.size() != kByteData160Length) {
    warn(
        CFD_LOG_SOURCE,
        "DecodeAddress error. Invalid contained hash data size."
        " : address={}, hash data size={}.",
        confidential_address, data_part.size());
    throw CfdException(
        kCfdIllegalArgumentError,
        "DecodeAddress error. Invalid contained hash data size.");
  }
  std::vector<uint8_t> hash_data_bytes;
  std::copy(
      data_part.cbegin(), data_part.cend(),
      std::back_inserter(hash_data_bytes));
  hash_ = ByteData(hash_data_bytes);

  // set unblinded address
  unblinded_address_ = ElementsUnblindedAddress(
      type_, addr_type_, ByteData160(hash_data_bytes));
}

void ElementsConfidentialAddress::CalculateAddress(
    const ElementsUnblindedAddress& unblinded_address,
    const ConfidentialKey& confidential_key) {
  type_ = unblinded_address.GetNetType();
  if (type_ == ElementsNetType::kElementsNetTypeNum) {
    warn(
        CFD_LOG_SOURCE,
        "CalculateAddress error. Invalid ElementsNetType of unblinded address."
        " : unblinded_address={}, ElementsNetType={}.",
        unblinded_address.GetAddress(), type_);
    throw CfdException(
        kCfdIllegalArgumentError,
        "CalculateAddress error. Invalid ElementsNetType of unblinded "
        "address.");  // NOLINT
  }

  std::vector<uint8_t> addr_data;
  addr_data.reserve(128);

  // 2bytes: confidential address prefix
  addr_data.push_back(kElementsNetParams[type_].confidential_addr_id);

  // 2bytes: address prefix
  addr_type_ = unblinded_address.GetAddressType();
  uint8_t address_prefix;
  if (addr_type_ == ElementsAddressType::kElementsP2pkhAddress) {
    address_prefix = kElementsNetParams[type_].p2pkh_addr_id;
  } else if (addr_type_ == ElementsAddressType::kElementsP2shAddress) {
    address_prefix = kElementsNetParams[type_].p2sh_addr_id;
  } else {
    warn(
        CFD_LOG_SOURCE,
        "CalculateAddress error. Invalid ElementsAddressType of"
        " unblinded address. : unblinded_address={}, ElementsNetType={}.",
        unblinded_address.GetAddress(), type_);
    throw CfdException(
        kCfdIllegalArgumentError,
        "CalculateAddress error. Invalid ElementsNetType of unblinded "
        "address.");  // NOLINT
  }
  addr_data.push_back(address_prefix);

  // 33bytes: ConfidentialKey
  if (!confidential_key.IsCompress()) {
    warn(
        CFD_LOG_SOURCE,
        "CalculateAddress error. Confidential key is not compressed."
        " : confidential_key={}, size={}.",
        confidential_key.GetHex(), confidential_key.GetData().GetDataSize());
    throw CfdException(
        kCfdIllegalArgumentError,
        "CalculateAddress error. Confidential key is not compressed.");
  }
  std::vector<uint8_t> key_bytes = confidential_key.GetData().GetBytes();
  std::copy(
      key_bytes.cbegin(), key_bytes.cend(), std::back_inserter(addr_data));

  // 20bytes: hashed pubkey or script
  hash_ = unblinded_address.GetHash();
  std::vector<uint8_t> hash_data = hash_.GetBytes();
  std::copy(
      hash_data.cbegin(), hash_data.cend(), std::back_inserter(addr_data));

  // Base58 encode
  char* output = NULL;
  uint32_t flags = BASE58_FLAG_CHECKSUM;
  int ret = wally_base58_from_bytes(
      addr_data.data(), addr_data.size(), flags, &output);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_base58_from_bytes error. ret={}.", ret);
    info(CFD_LOG_SOURCE, "input hash={}", StringUtil::ByteToString(addr_data));
    if (ret == WALLY_EINVAL) {
      throw CfdException(
          kCfdIllegalArgumentError, "UnblindedAddress base58 encode error.");
    } else {
      throw CfdException(
          kCfdInternalError, "UnblindedAddress base58 encode error.");
    }
  }

  address_ = WallyUtil::ConvertStringAndFree(output);
}

}  // namespace cfdcore

#endif  // CFD_DISABLE_ELEMENTS
