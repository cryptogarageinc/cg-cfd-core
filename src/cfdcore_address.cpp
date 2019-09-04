// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_address.cpp
 *
 */
#include <algorithm>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore/cfdcore_script.h"
#include "cfdcore/cfdcore_util.h"
#include "cfdcore_wally_util.h"  // NOLINT

namespace cfdcore {

using logger::info;
using logger::warn;

// @formatter:off
/// NetTypeごとの固定値(prefix等)
const NetParams kNetParams[kNetTypeNum] = {
    // mainet
    {
        "mainnet",  // mainnet
        kMainnet,   // mainnet
        0x00,       // First byte of a P2PKH address
        0x05,       // First byte of a P2SH address
        "bc"        // bech32 human-readable part
    },
    // testnet
    {
        "testnet",  // testnet
        kTestnet,   // testnet
        0x6f,       // First byte of a P2PKH address
        0xc4,       // First byte of a P2SH address
        "tb"        // bech32 human-readable part
    },
    // regtest
    {
        "regtest",  // regtest
        kRegtest,   // regtest
        0x6f,       // First byte of a P2PKH address
        0xc4,       // First byte of a P2SH address
        "bcrt"      // bech32 human-readable part
    }};
// @formatter:on

Address::Address()
    : type_(kMainnet),
      addr_type_(kP2shAddress),
      witness_ver_(kVersionNone),
      address_(""),
      hash_(),
      pubkey_(),
      redeem_script_() {
  memset(checksum_, 0, sizeof(checksum_));
  info(CFD_LOG_SOURCE, "call Address()");
}

Address::Address(const std::string& address_string)
    : type_(kMainnet),
      addr_type_(kP2shAddress),
      witness_ver_(kVersionNone),
      address_(address_string),
      hash_(),
      pubkey_(),
      redeem_script_() {
  memset(checksum_, 0, sizeof(checksum_));
  DecodeAddress(address_string);
}

Address::Address(
    const std::string& address_string,
    const std::vector<NetParams>& network_parameters)
    : type_(kMainnet),
      addr_type_(kP2shAddress),
      witness_ver_(kVersionNone),
      address_(address_string),
      hash_(),
      pubkey_(),
      redeem_script_() {
  memset(checksum_, 0, sizeof(checksum_));
  const std::vector<NetParams>* params = nullptr;
  if (!network_parameters.empty()) {
    params = &network_parameters;
  }
  DecodeAddress(address_string, params);
}

Address::Address(NetType type, const Pubkey& pubkey)
    : Address(type, pubkey, 0) {
  // do nothing
}

Address::Address(NetType type, const Pubkey& pubkey, uint8_t prefix)
    : type_((prefix != 0) ? kCustomChain : type),
      addr_type_(AddressType::kP2pkhAddress),
      witness_ver_(kVersionNone),
      address_(""),
      hash_(),
      pubkey_(pubkey),
      redeem_script_() {
  memset(checksum_, 0, sizeof(checksum_));
  CalculateP2PKH(prefix);
  info(
      CFD_LOG_SOURCE, "call Address({},{},{})", type_,
      AddressType::kP2pkhAddress, prefix);
}

Address::Address(
    NetType type, const Pubkey& pubkey, const NetParams& network_parameter)
    : Address(type, pubkey, network_parameter.p2pkh_addr_id) {
  // do nothing
}

Address::Address(NetType type, const Script& script)
    : Address(type, script, 0) {
  // do nothing
}

Address::Address(NetType type, const Script& script, uint8_t prefix)
    : type_((prefix != 0) ? kCustomChain : type),
      addr_type_(AddressType::kP2shAddress),
      witness_ver_(kVersionNone),
      address_(""),
      hash_(),
      pubkey_(),
      redeem_script_(script) {
  memset(checksum_, 0, sizeof(checksum_));
  CalculateP2SH(prefix);
  info(
      CFD_LOG_SOURCE, "call Address({},{},{})", type_,
      AddressType::kP2shAddress, prefix);
}

Address::Address(
    NetType type, const Script& script, const NetParams& network_parameter)
    : Address(type, script, network_parameter.p2sh_addr_id) {
  // do nothing
}

Address::Address(
    NetType type, WitnessVersion witness_ver, const Pubkey& pubkey)
    : Address(type, witness_ver, pubkey, "") {
  // do nothing
}

Address::Address(
    NetType type, WitnessVersion witness_ver, const Pubkey& pubkey,
    const std::string& bech32_hrp)
    : type_((!bech32_hrp.empty()) ? kCustomChain : type),
      addr_type_(AddressType::kP2wpkhAddress),
      witness_ver_(witness_ver),
      address_(""),
      hash_(),
      pubkey_(pubkey),
      redeem_script_() {
  memset(checksum_, 0, sizeof(checksum_));
  CalculateP2WPKH(bech32_hrp);
  info(
      CFD_LOG_SOURCE, "call Address({},{},{})", type_,
      AddressType::kP2wpkhAddress, bech32_hrp);
}

Address::Address(
    NetType type, WitnessVersion witness_ver, const Pubkey& pubkey,
    const NetParams& network_parameter)
    : Address(type, witness_ver, pubkey, network_parameter.bech32_hrp) {
  // do nothing
}

Address::Address(
    NetType type, WitnessVersion witness_ver, const Script& script)
    : Address(type, witness_ver, script, "") {
  // do nothing
}

Address::Address(
    NetType type, WitnessVersion witness_ver, const Script& script,
    const std::string& bech32_hrp)
    : type_((!bech32_hrp.empty()) ? kCustomChain : type),
      addr_type_(AddressType::kP2wshAddress),
      witness_ver_(witness_ver),
      address_(""),
      hash_(),
      pubkey_(),
      redeem_script_(script) {
  memset(checksum_, 0, sizeof(checksum_));
  CalculateP2WSH(bech32_hrp);
  info(
      CFD_LOG_SOURCE, "call Address({},{},{})", type_,
      AddressType::kP2wshAddress, bech32_hrp);
}

Address::Address(
    NetType type, WitnessVersion witness_ver, const Script& script,
    const NetParams& network_parameter)
    : Address(type, witness_ver, script, network_parameter.bech32_hrp) {
  // do nothing
}

Address::Address(NetType type, AddressType addr_type, const ByteData160& hash)
    : type_(type),
      addr_type_(addr_type),
      witness_ver_(kVersionNone),
      address_(""),
      hash_(hash.GetBytes()),
      pubkey_(),
      redeem_script_() {
  memset(checksum_, 0, sizeof(checksum_));
  if (addr_type == kP2pkhAddress) {
    CalculateP2PKH(hash);
  } else if (addr_type == kP2shAddress) {
    CalculateP2SH(hash);
  } else {
    throw CfdException(
        kCfdIllegalArgumentError, "Support addressType is p2pkh or p2sh");
  }
}

Address::Address(
    NetType type, AddressType addr_type, const ByteData160& hash,
    const NetParams& network_parameter)
    : type_(type),
      addr_type_(addr_type),
      witness_ver_(kVersionNone),
      address_(""),
      hash_(hash.GetBytes()),
      pubkey_(),
      redeem_script_() {
  memset(checksum_, 0, sizeof(checksum_));
  if (addr_type == kP2pkhAddress) {
    CalculateP2PKH(hash, network_parameter.p2pkh_addr_id);
    type_ = (network_parameter.p2pkh_addr_id != 0) ? kCustomChain : type_;
  } else if (addr_type == kP2shAddress) {
    CalculateP2SH(hash, network_parameter.p2sh_addr_id);
    type_ = (network_parameter.p2sh_addr_id != 0) ? kCustomChain : type_;
  } else {
    throw CfdException(
        kCfdIllegalArgumentError, "Support addressType is p2pkh or p2sh");
  }
}

Address::Address(
    NetType type, WitnessVersion witness_ver, const ByteData& hash)
    : type_(type),
      addr_type_(AddressType::kP2wshAddress),
      witness_ver_(witness_ver),
      address_(""),
      hash_(hash),
      pubkey_(),
      redeem_script_() {
  memset(checksum_, 0, sizeof(checksum_));

  if (witness_ver_ != WitnessVersion::kVersionNone) {
    if (hash.GetDataSize() == kByteData160Length) {
      addr_type_ = AddressType::kP2wpkhAddress;
      CalculateP2WPKH(ByteData160(hash.GetBytes()));
    } else if (hash.GetDataSize() == kByteData256Length) {
      addr_type_ = AddressType::kP2wshAddress;
      CalculateP2WSH(ByteData256(hash.GetBytes()));
    } else {
      // format error
      info(CFD_LOG_SOURCE, "illegal hash data. hash={}", hash.GetHex());
      throw CfdException(kCfdIllegalArgumentError, "hash value error.");
    }
  }
}

Address::Address(
    NetType type, WitnessVersion witness_ver, const ByteData& hash,
    const NetParams& network_parameter)
    : type_(type),
      addr_type_(AddressType::kP2wshAddress),
      witness_ver_(witness_ver),
      address_(""),
      hash_(hash),
      pubkey_(),
      redeem_script_() {
  memset(checksum_, 0, sizeof(checksum_));

  if (witness_ver_ != WitnessVersion::kVersionNone) {
    if (hash.GetDataSize() == kByteData160Length) {
      addr_type_ = AddressType::kP2wpkhAddress;
      CalculateP2WPKH(
          ByteData160(hash.GetBytes()), network_parameter.bech32_hrp);
      type_ = (!network_parameter.bech32_hrp.empty()) ? kCustomChain : type_;
    } else if (hash.GetDataSize() == kByteData256Length) {
      addr_type_ = AddressType::kP2wshAddress;
      CalculateP2WSH(
          ByteData256(hash.GetBytes()), network_parameter.bech32_hrp);
      type_ = (!network_parameter.bech32_hrp.empty()) ? kCustomChain : type_;
    } else {
      // format error
      info(CFD_LOG_SOURCE, "illegal hash data. hash={}", hash.GetHex());
      throw CfdException(kCfdIllegalArgumentError, "hash value error.");
    }
  }
}

std::string Address::GetAddress() const { return address_; }

void Address::CalculateP2SH(uint8_t prefix) {
  // scriptのHashを作成
  ByteData160 script_hash = HashUtil::Hash160(redeem_script_.GetData());
  CalculateP2SH(script_hash, prefix);
  hash_ = ByteData(script_hash.GetBytes());
}

void Address::CalculateP2SH(const ByteData160& hash_data, uint8_t prefix) {
  std::vector<uint8_t> address_data = hash_data.GetBytes();

  // 先頭にAddress Prefixを追加
  uint8_t addr_prefix = prefix;
  if ((addr_prefix == 0) && (kMainnet <= type_) && (type_ <= kRegtest)) {
    addr_prefix = kNetParams[type_].p2sh_addr_id;
  }
  address_data.insert(address_data.begin(), addr_prefix);

  char* output = NULL;
  uint32_t flags = BASE58_FLAG_CHECKSUM;
  int ret = wally_base58_from_bytes(
      address_data.data(), address_data.size(), flags, &output);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_base58_from_bytes error. ret={}.", ret);
    info(
        CFD_LOG_SOURCE, "input hash={}",
        StringUtil::ByteToString(address_data));
    if (ret == WALLY_EINVAL) {
      throw CfdException(kCfdIllegalArgumentError, "Base58 encode error.");
    } else {
      throw CfdException(kCfdInternalError, "Base58 encode error.");
    }
  }

  address_ = WallyUtil::ConvertStringAndFree(output);
}

void Address::CalculateP2PKH(uint8_t prefix) {
  ByteData160 pubkey_hash = HashUtil::Hash160(pubkey_.GetData());
  CalculateP2PKH(pubkey_hash, prefix);
  hash_ = ByteData(pubkey_hash.GetBytes());
}

void Address::CalculateP2PKH(const ByteData160& hash_data, uint8_t prefix) {
  std::vector<uint8_t> pubkey_hash = hash_data.GetBytes();

  // 0byte目にprefix P2PKH
  // - 任意prefixが0は無効(p2pkhのmainnet予約値)
  // - 任意prefixが無効かつtype値が夕刻ならbitcoinの定義(kNetParams)を参照する
  uint8_t addr_prefix = prefix;
  if ((addr_prefix == 0) && (kMainnet <= type_) && (type_ <= kRegtest)) {
    addr_prefix = kNetParams[type_].p2pkh_addr_id;
  }
  pubkey_hash.insert(pubkey_hash.begin(), addr_prefix);

  // Base58check
  char* output = NULL;
  uint32_t flags = BASE58_FLAG_CHECKSUM;
  int ret = wally_base58_from_bytes(
      pubkey_hash.data(), pubkey_hash.size(), flags, &output);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_base58_from_bytes error. ret={}.", ret);
    info(
        CFD_LOG_SOURCE, "input hash={}",
        StringUtil::ByteToString(pubkey_hash));
    if (ret == WALLY_EINVAL) {
      throw CfdException(kCfdIllegalArgumentError, "Base58 encode error.");
    } else {
      throw CfdException(kCfdInternalError, "Base58 encode error.");
    }
  }

  address_ = WallyUtil::ConvertStringAndFree(output);
}

void Address::CalculateP2WSH(const std::string& bech32_hrp) {
  ByteData256 script_hash = HashUtil::Sha256(redeem_script_.GetData());
  CalculateP2WSH(script_hash, bech32_hrp);
  hash_ = ByteData(script_hash.GetBytes());
}

void Address::CalculateP2WSH(
    const ByteData256& hash_data, const std::string& bech32_hrp) {
  const std::vector<uint8_t>& script_hash_byte = hash_data.GetBytes();
  std::vector<uint8_t> segwit_data;

  // 0byte目にwitness_version, 1byte目にhashサイズ
  segwit_data.push_back(witness_ver_);
  segwit_data.push_back(static_cast<uint8_t>(script_hash_byte.size()));
  std::copy(
      script_hash_byte.begin(), script_hash_byte.end(),
      std::back_inserter(segwit_data));

  std::string human_code = bech32_hrp;
  if (human_code.empty() && (kMainnet <= type_) && (type_ <= kRegtest)) {
    human_code = kNetParams[type_].bech32_hrp;
  }
  char* output = NULL;
  // segwit
  int ret = wally_addr_segwit_from_bytes(
      segwit_data.data(), segwit_data.size(), human_code.data(), 0, &output);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_addr_segwit_from_bytes error. ret={}.", ret);
    info(
        CFD_LOG_SOURCE, "input hash={}",
        StringUtil::ByteToString(segwit_data));
    if (ret == WALLY_EINVAL) {
      throw CfdException(
          kCfdIllegalArgumentError, "Segwit-address create error.");
    } else {
      throw CfdException(kCfdInternalError, "Segwit-address create error.");
    }
  }

  address_ = WallyUtil::ConvertStringAndFree(output);
}

void Address::CalculateP2WPKH(const std::string& bech32_hrp) {
  ByteData160 hash160 = HashUtil::Hash160(pubkey_.GetData());
  CalculateP2WPKH(hash160, bech32_hrp);
  hash_ = ByteData(hash160.GetBytes());
}

void Address::CalculateP2WPKH(
    const ByteData160& hash_data, const std::string& bech32_hrp) {
  // 0byte目にwitness_version, 1byte目にhashサイズ
  std::vector<uint8_t> pubkey_hash = hash_data.GetBytes();
  pubkey_hash.insert(pubkey_hash.begin(), HASH160_LEN);
  pubkey_hash.insert(pubkey_hash.begin(), witness_ver_);

  std::string human_code = bech32_hrp;
  if (human_code.empty() && (kMainnet <= type_) && (type_ <= kRegtest)) {
    human_code = kNetParams[type_].bech32_hrp;
  }
  char* output = NULL;
  // segwit
  int ret = wally_addr_segwit_from_bytes(
      pubkey_hash.data(), pubkey_hash.size(), human_code.data(), 0, &output);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_addr_segwit_from_bytes error. ret={}.", ret);
    info(
        CFD_LOG_SOURCE, "input hash={}",
        StringUtil::ByteToString(pubkey_hash));
    if (ret == WALLY_EINVAL) {
      throw CfdException(
          kCfdIllegalArgumentError, "Segwit-address create error.");
    } else {
      throw CfdException(kCfdInternalError, "Segwit-address create error.");
    }
  }

  address_ = WallyUtil::ConvertStringAndFree(output);
}

void Address::DecodeAddress(
    std::string bs58, const std::vector<NetParams>* network_parameters) {
  static const std::string kBech32Separator = "1";
  static const auto StartsWith = [](const std::string& message,
                                    const std::string& bech32_hrp) -> bool {
    return (message.find(bech32_hrp + kBech32Separator) == 0);
  };

  std::string segwit_prefix = "";
  int ret = -1;

  if (network_parameters != nullptr) {
    for (const NetParams& param : *network_parameters) {
      // カスタムパラメータ
      if ((!param.bech32_hrp.empty()) &&
          (param.bech32_hrp.length() < bs58.length()) &&
          (StartsWith(bs58, param.bech32_hrp))) {
        type_ = param.type;
        segwit_prefix = param.bech32_hrp;
        break;
      }
      //    else if ((!param.blech32_hrp.empty()) &&
      //        (param.blech32_hrp.length() < bs58.length()) &&
      //        (bs58.find(param.blech32_hrp) == 0)) {
      //      type_ = param.type;
      //      segwit_prefix = param.blech32_hrp;
      //    }
    }
  }

  if (!segwit_prefix.empty()) {
    // do nothing
  } else if (StartsWith(bs58, kNetParams[kRegtest].bech32_hrp)) {
    // bcrt から始まるアドレス
    type_ = kRegtest;
    segwit_prefix = kNetParams[kRegtest].bech32_hrp;
  } else if (StartsWith(bs58, kNetParams[kMainnet].bech32_hrp)) {
    // bc から始まるアドレス
    type_ = kMainnet;
    segwit_prefix = kNetParams[kMainnet].bech32_hrp;
  } else if (StartsWith(bs58, kNetParams[kTestnet].bech32_hrp)) {
    // tb から始まるアドレス
    type_ = kTestnet;
    segwit_prefix = kNetParams[kTestnet].bech32_hrp;
  }

  std::vector<uint8_t> data_part(128);
  size_t written = 0;

  if (!segwit_prefix.empty()) {
    // Bech32アドレス
    ret = wally_addr_segwit_to_bytes(
        bs58.data(), segwit_prefix.data(), 0, data_part.data(),
        data_part.size(), &written);

    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_addr_segwit_to_bytes error. ret={}.", ret);
      if (ret == WALLY_EINVAL) {
        throw CfdException(
            kCfdIllegalArgumentError, "Segwit-address decode error.");
      } else {
        throw CfdException(kCfdInternalError, "Segwit-address decode error.");
      }
    }

    data_part.resize(written);
    witness_ver_ = kVersion0;

    if (written == kScriptHashP2wpkhLength) {
      addr_type_ = kP2wpkhAddress;
    } else if (written == kScriptHashP2wshLength) {
      addr_type_ = kP2wshAddress;
    }

    // 0byte:WitnessVersionと1byte:データ長を削除
    data_part.erase(data_part.begin(), data_part.begin() + 2);

  } else {
    ret = wally_base58_to_bytes(
        bs58.data(), BASE58_FLAG_CHECKSUM, data_part.data(), data_part.size(),
        &written);
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_base58_to_bytes error. ret={}.", ret);
      if (ret == WALLY_EINVAL) {
        throw CfdException(kCfdIllegalArgumentError, "Base58 decode error.");
      } else {
        throw CfdException(kCfdInternalError, "Base58 decode error.");
      }
    }

    data_part.resize(written);

    bool find_address_type = false;
    if (data_part[0] == kNetParams[kMainnet].p2sh_addr_id) {
      type_ = kMainnet;
      addr_type_ = kP2shAddress;
      find_address_type = true;
    } else if (data_part[0] == kNetParams[kMainnet].p2pkh_addr_id) {
      type_ = kMainnet;
      addr_type_ = kP2pkhAddress;
      find_address_type = true;
    } else if (data_part[0] == kNetParams[kTestnet].p2sh_addr_id) {
      type_ = kTestnet;
      addr_type_ = kP2shAddress;
      find_address_type = true;
    } else if (data_part[0] == kNetParams[kTestnet].p2pkh_addr_id) {
      type_ = kTestnet;
      addr_type_ = kP2pkhAddress;
      find_address_type = true;
    } else if (network_parameters != nullptr) {
      for (const NetParams& param : *network_parameters) {
        if (data_part[0] == param.p2sh_addr_id) {
          type_ = param.type;
          addr_type_ = kP2shAddress;
          find_address_type = true;
          break;
        } else if (data_part[0] == param.p2pkh_addr_id) {
          type_ = param.type;
          addr_type_ = kP2pkhAddress;
          find_address_type = true;
          break;
        }
      }
    }
    if (!find_address_type) {
      warn(CFD_LOG_SOURCE, "Unknown address prefix.");
      throw CfdException(kCfdIllegalArgumentError, "Unknown address prefix.");
    }
    witness_ver_ = kVersionNone;

    // 0byte:prefixを削除
    data_part.erase(data_part.begin());
  }

  // Hash設定
  hash_ = ByteData(data_part);
}

}  // namespace cfdcore
