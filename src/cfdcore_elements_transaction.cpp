// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_elements_transaction.cpp
 *
 * @brief Confidential Transaction関連クラスの実装ファイルです。
 */
#ifndef CFD_DISABLE_ELEMENTS

#include <algorithm>
#include <limits>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_elements_address.h"
#include "cfdcore/cfdcore_elements_transaction.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore/cfdcore_util.h"
#include "cfdcore_wally_util.h"  // NOLINT
#include "wally_elements.h"      // NOLINT
// #include "wally_script.h" // NOLINT

namespace cfdcore {

using logger::info;
using logger::warn;

// -----------------------------------------------------------------------------
// ファイル内定数
// -----------------------------------------------------------------------------
/// ElementsTransactionの最小サイズ
static constexpr size_t kElementsTransactionMinimumSize = 11;
/// Transactionの最小Hexサイズ
static constexpr size_t kTransactionMinimumHexSize =
    kElementsTransactionMinimumSize * 2;
/// ConfidentialCommitmentのVersion1(unblind)定義
static constexpr uint8_t kConfidentialVersion_1 = 1;
/// TransactionのWitness非対応バージョン定義
static constexpr uint32_t kTransactionVersionNoWitness = 0x40000000;
/// Assetのunblind時のサイズ
static constexpr size_t kAssetSize = ASSET_TAG_LEN;
/// Nonceのunblind時のサイズ
static constexpr size_t kNonceSize = 32;
/// blind factordのサイズ
static constexpr size_t kBlindFactorSize = 32;
/// Confidentialサイズ
static constexpr size_t kConfidentialDataSize = WALLY_TX_ASSET_CT_LEN;
/// issuance entropyのサイズ
static constexpr size_t kEntropySize = 32;
// @formatter:off
/// Valueのunblind時のサイズ
static constexpr size_t kConfidentialValueSize =
    WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN;  // NOLINT
/// Valueのunblind時のサイズ(version byteなし)
static constexpr size_t kAssetValueSize =
    WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN - 1;  // NOLINT
/// voutのIndex値マスク
static constexpr uint32_t kTxInVoutMask = WALLY_TX_INDEX_MASK;
/// txin::featureのIssuanceフラグ
static constexpr uint8_t kTxInFeatureIssuance = WALLY_TX_IS_ISSUANCE;
/// txin::featureのPeginフラグ
static constexpr uint8_t kTxInFeaturePegin = WALLY_TX_IS_PEGIN;
// @formatter:on

// -----------------------------------------------------------------------------
// ConfidentialNonce
// -----------------------------------------------------------------------------
ConfidentialNonce::ConfidentialNonce() : data_(), version_(0) {
  // do nothing
}

ConfidentialNonce::ConfidentialNonce(const std::string &hex_string)
    : data_(hex_string), version_(kConfidentialVersion_1) {
  switch (data_.GetDataSize()) {
    case 0:
      // do nothing
      break;
    case kNonceSize: {
      std::vector<uint8_t> bytes;
      version_ = kConfidentialVersion_1;
      const std::vector<uint8_t> &data = data_.GetBytes();
      bytes.push_back(version_);
      std::copy(data.begin(), data.end(), std::back_inserter(bytes));
      data_ = ByteData(bytes);
      break;
    }
    case kConfidentialDataSize: {
      const std::vector<uint8_t> &data = data_.GetBytes();
      version_ = data[0];
      break;
    }
    default:
      warn(
          CFD_LOG_SOURCE, "Nonce size Invalid. size={}.", data_.GetDataSize());
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "Nonce size Invalid.");
  }
}

ConfidentialNonce::ConfidentialNonce(const ByteData &byte_data)
    : data_(), version_(0) {
  switch (byte_data.GetDataSize()) {
    case 0:
      // do nothing
      break;
    case kNonceSize: {
      version_ = kConfidentialVersion_1;
      std::vector<uint8_t> bytes;
      const std::vector<uint8_t> &data = byte_data.GetBytes();
      bytes.push_back(version_);
      std::copy(data.begin(), data.end(), std::back_inserter(bytes));
      data_ = ByteData(bytes);
      break;
    }
    case kConfidentialDataSize: {
      const std::vector<uint8_t> &data = byte_data.GetBytes();
      data_ = byte_data;
      version_ = data[0];
      break;
    }
    default:
      warn(
          CFD_LOG_SOURCE, "Nonce size Invalid. size={}.",
          byte_data.GetDataSize());
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "Nonce size Invalid.");
  }
}

ByteData ConfidentialNonce::GetData() const { return data_; }

std::string ConfidentialNonce::GetHex() const { return data_.GetHex(); }

bool ConfidentialNonce::HasBlinding() const {
  return (version_ != 0) && (version_ != kConfidentialVersion_1);
}

// -----------------------------------------------------------------------------
// ConfidentialAssetId
// -----------------------------------------------------------------------------
ConfidentialAssetId::ConfidentialAssetId() : data_(), version_(0) {
  // do nothing
}

ConfidentialAssetId::ConfidentialAssetId(const std::string &hex_string)
    : data_(hex_string), version_(kConfidentialVersion_1) {
  switch (data_.GetDataSize()) {
    case 0:
      warn(
          CFD_LOG_SOURCE, "Empty ConfidentialAssetId. hex_string={}.",
          hex_string);
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "Empty AssetId is invalid.");
      break;
    case kAssetSize: {
      // reverse
      const std::vector<uint8_t> &data = data_.GetBytes();
      std::vector<uint8_t> reverse_buffer(data.crbegin(), data.crend());
      data_ = ByteData(reverse_buffer);
      break;
    }
    case kConfidentialDataSize: {
      const std::vector<uint8_t> &data = data_.GetBytes();
      std::vector<uint8_t> buffer(data.cbegin() + 1, data.cend());
      data_ = ByteData(buffer);
      version_ = data[0];
      break;
    }
    default:
      warn(
          CFD_LOG_SOURCE, "AssetId size Invalid. size={}.",
          data_.GetDataSize());
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "AssetId size Invalid.");
  }
}

ConfidentialAssetId::ConfidentialAssetId(const ByteData &byte_data)
    : data_(), version_(0) {
  switch (byte_data.GetDataSize()) {
    case 0:
      warn(
          CFD_LOG_SOURCE, "Empty ConfidentialAssetId. byte_data={}.",
          StringUtil::ByteToString(byte_data.GetBytes()));
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "Empty AssetId is invalid.");
      break;
    case kAssetSize: {
      data_ = byte_data;
      version_ = kConfidentialVersion_1;
      break;
    }
    case kConfidentialDataSize: {
      const std::vector<uint8_t> &data = byte_data.GetBytes();
      std::vector<uint8_t> buffer(data.cbegin() + 1, data.cend());
      data_ = ByteData(buffer);
      version_ = data[0];
      break;
    }
    default:
      warn(
          CFD_LOG_SOURCE, "AssetId size Invalid. size={}.",
          byte_data.GetDataSize());
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "AssetId size Invalid.");
  }
}

ByteData ConfidentialAssetId::GetData() const {
  std::vector<uint8_t> byte_data;
  if (data_.GetDataSize() != 0) {
    const std::vector<uint8_t> &data = data_.GetBytes();
    byte_data.push_back(version_);
    std::copy(data.begin(), data.end(), std::back_inserter(byte_data));
  }
  return ByteData(byte_data);
}

std::string ConfidentialAssetId::GetHex() const {
  if (HasBlinding()) {
    return GetData().GetHex();
  } else {
    const std::vector<uint8_t> &data = data_.GetBytes();
    std::vector<uint8_t> reverse_buffer(data.crbegin(), data.crend());
    return StringUtil::ByteToString(reverse_buffer);
  }
}

bool ConfidentialAssetId::HasBlinding() const {
  return (version_ != 0) && (version_ != kConfidentialVersion_1);
}

ByteData ConfidentialAssetId::GetUnblindedData() const {
  if (!HasBlinding()) {
    return data_;
  }
  return GetData();
}

// -----------------------------------------------------------------------------
// ConfidentialValue
// -----------------------------------------------------------------------------
ConfidentialValue::ConfidentialValue() : data_(), version_(0) {
  // do nothing
}

ConfidentialValue::ConfidentialValue(const std::string &hex_string)
    : data_(hex_string), version_(0) {
  switch (data_.GetDataSize()) {
    case 0:
      // do nothing
      break;
    case kAssetValueSize: {
      std::vector<uint8_t> bytes;
      version_ = kConfidentialVersion_1;
      const std::vector<uint8_t> &data = data_.GetBytes();
      bytes.push_back(version_);
      std::copy(data.begin(), data.end(), std::back_inserter(bytes));
      data_ = ByteData(bytes);
      break;
    }
    case kConfidentialDataSize:
    case kConfidentialValueSize: {
      const std::vector<uint8_t> &data = data_.GetBytes();
      version_ = data[0];
      break;
    }
    default:
      warn(
          CFD_LOG_SOURCE, "Value size Invalid. size={}.", data_.GetDataSize());
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "Value size Invalid.");
  }
}

ConfidentialValue::ConfidentialValue(const ByteData &byte_data)
    : data_(), version_(0) {
  switch (byte_data.GetDataSize()) {
    case 0:
      // do nothing
      break;
    case kAssetValueSize: {
      version_ = kConfidentialVersion_1;
      std::vector<uint8_t> bytes;
      const std::vector<uint8_t> &data = byte_data.GetBytes();
      bytes.push_back(version_);
      std::copy(data.begin(), data.end(), std::back_inserter(bytes));
      data_ = ByteData(bytes);
      break;
    }
    case kConfidentialDataSize:
    case kConfidentialValueSize: {
      const std::vector<uint8_t> &data = byte_data.GetBytes();
      data_ = byte_data;
      version_ = data[0];
      break;
    }
    default:
      warn(
          CFD_LOG_SOURCE, "Value size Invalid. size={}.",
          byte_data.GetDataSize());
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "Value size Invalid.");
  }
}

ConfidentialValue::ConfidentialValue(const Amount &amount)
    : ConfidentialValue(ConvertToConfidentialValue(amount)) {
  // do nothing
}

ByteData ConfidentialValue::GetData() const { return data_; }

std::string ConfidentialValue::GetHex() const { return data_.GetHex(); }

Amount ConfidentialValue::GetAmount() const {
  Amount amount = Amount::CreateBySatoshiAmount(0);
  if (!HasBlinding()) {
    amount = ConvertFromConfidentialValue(GetData());
  }
  return amount;
}

bool ConfidentialValue::HasBlinding() const {
  return (version_ != 0) && (version_ != kConfidentialVersion_1);
}

ByteData ConfidentialValue::ConvertToConfidentialValue(  // force LF
    const Amount &value) {
  std::vector<uint8_t> buffer(kConfidentialValueSize);
  uint64_t satoshi = static_cast<uint64_t>(value.GetSatoshiValue());
  int ret = wally_tx_confidential_value_from_satoshi(
      satoshi, buffer.data(), buffer.size());
  if (ret != WALLY_OK) {
    warn(
        CFD_LOG_SOURCE, "wally_tx_confidential_value_from_satoshi NG[{}].",
        ret);
    throw CfdException(
        kCfdIllegalStateError, "generate confidential value error.");
  }
  return ByteData(buffer);
}

Amount ConfidentialValue::ConvertFromConfidentialValue(  // force LF
    const ByteData &value) {
  const std::vector<uint8_t> &buffer = value.GetBytes();
  uint64_t satoshi = 0;
  int ret = wally_tx_confidential_value_to_satoshi(
      buffer.data(), buffer.size(), &satoshi);
  if (ret != WALLY_OK) {
    warn(
        CFD_LOG_SOURCE, "wally_tx_confidential_value_to_satoshi NG[{}].", ret);
    throw CfdException(
        kCfdIllegalStateError, "convert from confidential value error.");
  }
  return Amount::CreateBySatoshiAmount(static_cast<int64_t>(satoshi));
}

// -----------------------------------------------------------------------------
// BlindFactor
// -----------------------------------------------------------------------------
BlindFactor::BlindFactor() : data_() {
  // do nothing
}
BlindFactor::BlindFactor(const std::string &hex_string) : data_() {
  if (hex_string.size() != (kByteData256Length * 2)) {
    warn(
        CFD_LOG_SOURCE, "Value hex-string-length Invalid. length={}.",
        hex_string.size());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Value hex string length Invalid.");
  }
  const std::vector<uint8_t> &data = StringUtil::StringToByte(hex_string);
  std::vector<uint8_t> reverse_buffer(data.crbegin(), data.crend());
  data_ = ByteData256(reverse_buffer);
}

BlindFactor::BlindFactor(const ByteData256 &byte_data) : data_(byte_data) {
  // do nothing
}

ByteData256 BlindFactor::GetData() const { return data_; }

std::string BlindFactor::GetHex() const {
  const std::vector<uint8_t> &data = data_.GetBytes();
  std::vector<uint8_t> reverse_buffer(data.crbegin(), data.crend());
  return StringUtil::ByteToString(reverse_buffer);
}

// -----------------------------------------------------------------------------
// ConfidentialTxIn
// -----------------------------------------------------------------------------
ConfidentialTxIn::ConfidentialTxIn(
    const Txid &txid, uint32_t index, uint32_t sequence)
    : AbstractTxIn(txid, index, sequence),
      blinding_nonce_(),
      asset_entropy_(),
      issuance_amount_(),
      inflation_keys_(),
      issuance_amount_rangeproof_(),
      inflation_keys_rangeproof_(),
      pegin_witness_() {
  // do nothing
}

ConfidentialTxIn::ConfidentialTxIn(
    const Txid &txid, uint32_t index, uint32_t sequence,
    const Script &unlocking_script)
    : AbstractTxIn(txid, index, sequence, unlocking_script),
      blinding_nonce_(),
      asset_entropy_(),
      issuance_amount_(),
      inflation_keys_(),
      issuance_amount_rangeproof_(),
      inflation_keys_rangeproof_(),
      pegin_witness_() {
  // do nothing
}

ConfidentialTxIn::ConfidentialTxIn(
    const Txid &txid, uint32_t index, uint32_t sequence,
    const Script &unlocking_script, const ScriptWitness &witness_stack,
    const ByteData256 &blinding_nonce, const ByteData256 &asset_entropy,
    const ConfidentialValue &issuance_amount,
    const ConfidentialValue &inflation_keys,
    const ByteData &issuance_amount_rangeproof,
    const ByteData &inflation_keys_rangeproof,
    const ScriptWitness &pegin_witness)
    : AbstractTxIn(txid, index, sequence, unlocking_script),
      blinding_nonce_(blinding_nonce),
      asset_entropy_(asset_entropy),
      issuance_amount_(issuance_amount),
      inflation_keys_(inflation_keys),
      issuance_amount_rangeproof_(issuance_amount_rangeproof),
      inflation_keys_rangeproof_(inflation_keys_rangeproof),
      pegin_witness_(pegin_witness) {
  script_witness_ = witness_stack;
}

void ConfidentialTxIn::SetIssuance(
    const ByteData256 &blinding_nonce, const ByteData256 &asset_entropy,
    const ConfidentialValue &issuance_amount,
    const ConfidentialValue &inflation_keys,
    const ByteData &issuance_amount_rangeproof,
    const ByteData &inflation_keys_rangeproof) {
  blinding_nonce_ = blinding_nonce;
  asset_entropy_ = asset_entropy;
  issuance_amount_ = issuance_amount;
  inflation_keys_ = inflation_keys;
  issuance_amount_rangeproof_ = issuance_amount_rangeproof;
  inflation_keys_rangeproof_ = inflation_keys_rangeproof;
}

ScriptWitness ConfidentialTxIn::AddPeginWitnessStack(const ByteData &data) {
  pegin_witness_.AddWitnessStack(data);
  return pegin_witness_;
}

ScriptWitness ConfidentialTxIn::SetPeginWitnessStack(
    uint32_t index, const ByteData &data) {
  pegin_witness_.SetWitnessStack(index, data);
  return pegin_witness_;
}

void ConfidentialTxIn::RemovePeginWitnessStackAll() {
  pegin_witness_ = ScriptWitness();
}

// -----------------------------------------------------------------------------
// ConfidentialTxInReference
// -----------------------------------------------------------------------------
ConfidentialTxInReference::ConfidentialTxInReference(
    const ConfidentialTxIn &tx_in)
    : AbstractTxInReference(tx_in),
      blinding_nonce_(tx_in.GetBlindingNonce()),
      asset_entropy_(tx_in.GetAssetEntropy()),
      issuance_amount_(tx_in.GetIssuanceAmount()),
      inflation_keys_(tx_in.GetInflationKeys()),
      issuance_amount_rangeproof_(tx_in.GetIssuanceAmountRangeproof()),
      inflation_keys_rangeproof_(tx_in.GetInflationKeysRangeproof()),
      pegin_witness_(tx_in.GetPeginWitness()) {
  // do nothing
}

ConfidentialTxInReference::ConfidentialTxInReference()
    : ConfidentialTxInReference(ConfidentialTxIn(Txid(), 0, 0)) {
  // do nothing
}

// -----------------------------------------------------------------------------
// ConfidentialTxOut
// -----------------------------------------------------------------------------
ConfidentialTxOut::ConfidentialTxOut()
    : AbstractTxOut(),
      asset_(),
      confidential_value_(),
      nonce_(),
      surjection_proof_(),
      range_proof_() {
  // do nothing
}

ConfidentialTxOut::ConfidentialTxOut(
    const Script &locking_script, const ConfidentialAssetId &asset,
    const ConfidentialValue &confidential_value)
    : AbstractTxOut(Amount::CreateBySatoshiAmount(0), locking_script),
      asset_(asset),
      confidential_value_(confidential_value),
      nonce_(),
      surjection_proof_(),
      range_proof_() {
  // do nothing
}

ConfidentialTxOut::ConfidentialTxOut(
    const Script &locking_script, const ConfidentialAssetId &asset,
    const ConfidentialValue &confidential_value,
    const ConfidentialNonce &nonce, const ByteData &surjection_proof,
    const ByteData &range_proof)
    : AbstractTxOut(Amount::CreateBySatoshiAmount(0), locking_script),
      asset_(asset),
      confidential_value_(confidential_value),
      nonce_(nonce),
      surjection_proof_(surjection_proof),
      range_proof_(range_proof) {
  // do nothing
}

ConfidentialTxOut::ConfidentialTxOut(
    const ConfidentialAssetId &asset,
    const ConfidentialValue &confidential_value)
    : AbstractTxOut(),
      asset_(asset),
      confidential_value_(confidential_value),
      nonce_(),
      surjection_proof_(),
      range_proof_() {
  // do nothing
}

void ConfidentialTxOut::SetCommitment(
    const ConfidentialAssetId &asset,
    const ConfidentialValue &confidential_value,
    const ConfidentialNonce &nonce, const ByteData &surjection_proof,
    const ByteData &range_proof) {
  asset_ = asset;
  confidential_value_ = confidential_value;
  nonce_ = nonce;
  surjection_proof_ = surjection_proof;
  range_proof_ = range_proof;
}

void ConfidentialTxOut::SetValue(const Amount &value) { value_ = value; }

// -----------------------------------------------------------------------------
// ConfidentialTxOutReference
// -----------------------------------------------------------------------------
ConfidentialTxOutReference::ConfidentialTxOutReference(
    const ConfidentialTxOut &tx_out)
    : AbstractTxOutReference(tx_out),
      asset_(tx_out.GetAsset()),
      confidential_value_(tx_out.GetConfidentialValue()),
      nonce_(tx_out.GetNonce()),
      surjection_proof_(tx_out.GetSurjectionProof()),
      range_proof_(tx_out.GetRangeProof()) {
  // do nothing
}

// -----------------------------------------------------------------------------
// ConfidentialTransaction
// -----------------------------------------------------------------------------

ConfidentialTransaction::ConfidentialTransaction()
    : ConfidentialTransaction(2, static_cast<uint32_t>(0)) {
  // do nothing
}

ConfidentialTransaction::ConfidentialTransaction(
    int32_t version, uint32_t lock_time)
    : vin_(), vout_() {
  struct wally_tx *tx_pointer = NULL;
  int ret = wally_tx_init_alloc(version, lock_time, 0, 0, &tx_pointer);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_init_alloc NG[{}] ", ret);
    throw CfdException(
        kCfdIllegalArgumentError, "transaction data generate error.");
  }
  wally_tx_pointer_ = tx_pointer;
}

ConfidentialTransaction::ConfidentialTransaction(const std::string &hex_string)
    : vin_(), vout_() {
  SetFromHex(hex_string);
}

ConfidentialTransaction::ConfidentialTransaction(
    const ConfidentialTransaction &transaction)
    : ConfidentialTransaction(transaction.GetHex()) {
  // copy constructor
}

void ConfidentialTransaction::SetFromHex(const std::string &hex_string) {
  void *original_address = wally_tx_pointer_;
  std::vector<ConfidentialTxIn> vin_work;
  std::vector<ConfidentialTxOut> vout_work;

  // tx情報は作成済みである前提とする。(作成済みじゃないと不整合を起こす)
  struct wally_tx *tx_pointer = NULL;
  uint32_t flag = WALLY_TX_FLAG_USE_ELEMENTS;
  int ret = wally_tx_from_hex(hex_string.c_str(), flag, &tx_pointer);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_from_hex NG[{}] ", ret);
    throw CfdException(kCfdIllegalArgumentError, "transaction data invalid.");
  }
  wally_tx_pointer_ = tx_pointer;

  try {
    // create ConfidentialTxIn and ConfidentialTxOut
    for (size_t index = 0; index < tx_pointer->num_inputs; ++index) {
      struct wally_tx_input *txin_item = &tx_pointer->inputs[index];
      std::vector<uint8_t> txid_buf(
          txin_item->txhash, txin_item->txhash + sizeof(txin_item->txhash));
      std::vector<uint8_t> script_buf(
          txin_item->script, txin_item->script + txin_item->script_len);
      Script unlocking_script = Script(ByteData(script_buf));
      if (!unlocking_script.IsPushOnly()) {
        warn(CFD_LOG_SOURCE, "IsPushOnly() false.");
        throw CfdException(
            kCfdIllegalArgumentError,
            "unlocking script error. "
            "The script needs to be push operator only.");
      }
      std::vector<uint8_t> blinding_buf(
          txin_item->blinding_nonce,
          txin_item->blinding_nonce + sizeof(txin_item->blinding_nonce));
      std::vector<uint8_t> entropy(
          txin_item->entropy, txin_item->entropy + sizeof(txin_item->entropy));
      ConfidentialTxIn txin(
          Txid(ByteData256(txid_buf)), txin_item->index, txin_item->sequence,
          unlocking_script, ScriptWitness(), ByteData256(blinding_buf),
          ByteData256(entropy),
          ConfidentialValue(ConvertToByteData(
              txin_item->issuance_amount, txin_item->issuance_amount_len)),
          ConfidentialValue(ConvertToByteData(
              txin_item->inflation_keys, txin_item->inflation_keys_len)),
          ConvertToByteData(
              txin_item->issuance_amount_rangeproof,
              txin_item->issuance_amount_rangeproof_len),
          ConvertToByteData(
              txin_item->inflation_keys_rangeproof,
              txin_item->inflation_keys_rangeproof_len),
          ScriptWitness());
      if ((txin_item->witness != NULL) &&
          (txin_item->witness->num_items != 0)) {
        struct wally_tx_witness_item *witness_stack;
        for (size_t w_index = 0; w_index < txin_item->witness->num_items;
             ++w_index) {
          witness_stack = &txin_item->witness->items[w_index];
          const std::vector<uint8_t> witness_buf(
              witness_stack->witness,
              witness_stack->witness + witness_stack->witness_len);
          txin.AddScriptWitnessStack(ByteData(witness_buf));
        }
      }
      if ((txin_item->pegin_witness != NULL) &&
          (txin_item->pegin_witness->num_items != 0)) {
        struct wally_tx_witness_item *witness_stack;
        for (size_t w_index = 0; w_index < txin_item->pegin_witness->num_items;
             ++w_index) {
          witness_stack = &txin_item->pegin_witness->items[w_index];
          const std::vector<uint8_t> witness_buf(
              witness_stack->witness,
              witness_stack->witness + witness_stack->witness_len);
          txin.AddPeginWitnessStack(ByteData(witness_buf));
        }
      }
      vin_work.push_back(txin);
    }

    info(CFD_LOG_SOURCE, "num_outputs={} ", tx_pointer->num_outputs);
    for (size_t index = 0; index < tx_pointer->num_outputs; ++index) {
      struct wally_tx_output *txout_item = &tx_pointer->outputs[index];
      ConfidentialTxOut txout(
          Script(
              ConvertToByteData(txout_item->script, txout_item->script_len)),
          ConfidentialAssetId(
              ConvertToByteData(txout_item->asset, txout_item->asset_len)),
          ConfidentialValue(
              ConvertToByteData(txout_item->value, txout_item->value_len)),
          ConfidentialNonce(
              ConvertToByteData(txout_item->nonce, txout_item->nonce_len)),
          ConvertToByteData(
              txout_item->surjectionproof, txout_item->surjectionproof_len),
          ConvertToByteData(
              txout_item->rangeproof, txout_item->rangeproof_len));
      vout_work.push_back(txout);
    }

    // コピー処理が成功したら、旧バッファを解放
    if (original_address != NULL) {
      wally_tx_free(static_cast<struct wally_tx *>(original_address));
      vin_.clear();
      vout_.clear();
    }
    vin_ = vin_work;
    vout_ = vout_work;
  } catch (const CfdException &exception) {
    // エラー時は解放
    wally_tx_free(tx_pointer);
    wally_tx_pointer_ = original_address;
    throw exception;
  } catch (...) {
    // エラー時は解放
    wally_tx_free(tx_pointer);
    wally_tx_pointer_ = original_address;
    throw CfdException(kCfdUnknownError);
  }
}

ConfidentialTransaction &ConfidentialTransaction::operator=(
    const ConfidentialTransaction &transaction) & {
  SetFromHex(transaction.GetHex());
  return *this;
}

const ConfidentialTxInReference ConfidentialTransaction::GetTxIn(
    uint32_t index) const {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  return ConfidentialTxInReference(vin_[index]);
}

uint32_t ConfidentialTransaction::GetTxInIndex(
    const Txid &txid, uint32_t vout) const {
  struct wally_tx *tx_pointer =
      static_cast<struct wally_tx *>(wally_tx_pointer_);
  size_t is_coinbase = 0;
  wally_tx_is_coinbase(tx_pointer, &is_coinbase);

  uint32_t index = (is_coinbase == 0) ? vout & kTxInVoutMask : vout;
  for (size_t i = 0; i < vin_.size(); ++i) {
    if (vin_[i].GetTxid().Equals(txid) && vin_[i].GetVout() == index) {
      return static_cast<uint32_t>(i);
    }
  }
  warn(CFD_LOG_SOURCE, "Txid is not found.");
  throw CfdException(kCfdIllegalArgumentError, "Txid is not found.");
}

uint32_t ConfidentialTransaction::GetTxInCount() const {
  return static_cast<uint32_t>(vin_.size());
}

const std::vector<ConfidentialTxInReference>  // force LF
ConfidentialTransaction::GetTxInList() const {
  std::vector<ConfidentialTxInReference> refs;
  for (ConfidentialTxIn tx_in : vin_) {
    refs.push_back(ConfidentialTxInReference(tx_in));
  }
  return refs;
}

uint32_t ConfidentialTransaction::AddTxIn(
    const Txid &txid, uint32_t index, uint32_t sequence,
    const Script &unlocking_script) {
  if (vin_.size() == std::numeric_limits<uint32_t>::max()) {
    warn(CFD_LOG_SOURCE, "vin maximum.");
    throw CfdException(kCfdIllegalStateError, "txin maximum.");
  }

  struct wally_tx *tx_pointer =
      static_cast<struct wally_tx *>(wally_tx_pointer_);
  const std::vector<uint8_t> &txid_buf = txid.GetData().GetBytes();
  std::vector<uint8_t> empty_data;
  const std::vector<uint8_t> &script_data =
      (unlocking_script.IsEmpty()) ? empty_data
                                   : unlocking_script.GetData().GetBytes();
  int ret = wally_tx_add_elements_raw_input(
      tx_pointer, txid_buf.data(), txid_buf.size(), index, sequence,
      script_data.data(), script_data.size(), NULL, NULL, 0, NULL, 0, NULL, 0,
      NULL, 0, NULL, 0, NULL, 0, NULL, 0);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_add_elements_raw_input NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "txin add error.");
  }

  size_t is_coinbase = 0;
  wally_tx_is_coinbase(tx_pointer, &is_coinbase);
  uint32_t set_index = (is_coinbase == 0) ? index & kTxInVoutMask : index;
  ConfidentialTxIn txin(txid, set_index, sequence);
  if (!unlocking_script.IsEmpty()) {
    txin = ConfidentialTxIn(txid, set_index, sequence, unlocking_script);
  }
  vin_.push_back(txin);
  return static_cast<uint32_t>(vin_.size() - 1);
}

void ConfidentialTransaction::RemoveTxIn(uint32_t index) {
  AbstractTransaction::RemoveTxIn(index);

  std::vector<ConfidentialTxIn>::const_iterator ite = vin_.cbegin();
  if (index != 0) {
    ite += index;
  }
  vin_.erase(ite);
}

void ConfidentialTransaction::SetUnlockingScript(
    uint32_t tx_in_index, const Script &unlocking_script) {
  AbstractTransaction::SetUnlockingScript(tx_in_index, unlocking_script);
  vin_[tx_in_index].SetUnlockingScript(unlocking_script);
}

void ConfidentialTransaction::SetUnlockingScript(
    uint32_t tx_in_index, const std::vector<ByteData> &unlocking_script) {
  Script generate_unlocking_script =
      AbstractTransaction::SetUnlockingScript(tx_in_index, unlocking_script);
  vin_[tx_in_index].SetUnlockingScript(generate_unlocking_script);
}

uint32_t ConfidentialTransaction::GetScriptWitnessStackNum(
    uint32_t tx_in_index) const {
  CheckTxInIndex(tx_in_index, __LINE__, __FUNCTION__);
  return vin_[tx_in_index].GetScriptWitnessStackNum();
}

const ScriptWitness ConfidentialTransaction::AddScriptWitnessStack(
    uint32_t tx_in_index, const ByteData &data) {
  return AddScriptWitnessStack(tx_in_index, data.GetBytes());
}

const ScriptWitness ConfidentialTransaction::AddScriptWitnessStack(
    uint32_t tx_in_index, const ByteData160 &data) {
  return AddScriptWitnessStack(tx_in_index, data.GetBytes());
}

const ScriptWitness ConfidentialTransaction::AddScriptWitnessStack(
    uint32_t tx_in_index, const ByteData256 &data) {
  return AddScriptWitnessStack(tx_in_index, data.GetBytes());
}

const ScriptWitness ConfidentialTransaction::AddScriptWitnessStack(
    uint32_t tx_in_index, const std::vector<uint8_t> &data) {
  AbstractTransaction::AddScriptWitnessStack(tx_in_index, data);

  const ScriptWitness &witness =
      vin_[tx_in_index].AddScriptWitnessStack(ByteData(data));
  return witness;
}

const ScriptWitness ConfidentialTransaction::SetScriptWitnessStack(
    uint32_t tx_in_index, uint32_t witness_index, const ByteData &data) {
  return SetScriptWitnessStack(tx_in_index, witness_index, data.GetBytes());
}

const ScriptWitness ConfidentialTransaction::SetScriptWitnessStack(
    uint32_t tx_in_index, uint32_t witness_index, const ByteData160 &data) {
  return SetScriptWitnessStack(tx_in_index, witness_index, data.GetBytes());
}

const ScriptWitness ConfidentialTransaction::SetScriptWitnessStack(
    uint32_t tx_in_index, uint32_t witness_index, const ByteData256 &data) {
  return SetScriptWitnessStack(tx_in_index, witness_index, data.GetBytes());
}

const ScriptWitness ConfidentialTransaction::SetScriptWitnessStack(
    uint32_t tx_in_index, uint32_t witness_index,
    const std::vector<uint8_t> &data) {
  AbstractTransaction::SetScriptWitnessStack(tx_in_index, witness_index, data);

  const ScriptWitness &witness =
      vin_[tx_in_index].SetScriptWitnessStack(witness_index, ByteData(data));
  return witness;
}

void ConfidentialTransaction::RemoveScriptWitnessStackAll(
    uint32_t tx_in_index) {
  AbstractTransaction::RemoveScriptWitnessStackAll(tx_in_index);

  vin_[tx_in_index].RemoveScriptWitnessStackAll();
}

void ConfidentialTransaction::SetIssuance(
    // force LF
    uint32_t tx_in_index, const ByteData256 blinding_nonce,
    const ByteData256 asset_entropy, const ConfidentialValue issuance_amount,
    const ConfidentialValue inflation_keys,
    const ByteData issuance_amount_rangeproof,
    const ByteData inflation_keys_rangeproof) {
  CheckTxInIndex(tx_in_index, __LINE__, __FUNCTION__);

  struct wally_tx *tx_pointer =
      static_cast<struct wally_tx *>(wally_tx_pointer_);
  const std::vector<uint8_t> &nonce = blinding_nonce.GetBytes();
  const std::vector<uint8_t> &entropy = asset_entropy.GetBytes();
  const std::vector<uint8_t> &issuance_amount_bytes =
      issuance_amount.GetData().GetBytes();
  const std::vector<uint8_t> &inflation_keys_bytes =
      inflation_keys.GetData().GetBytes();
  const std::vector<uint8_t> &issuance_amount_rangeproof_bytes =
      issuance_amount_rangeproof.GetBytes();
  const std::vector<uint8_t> &inflation_keys_rangeproof_bytes =
      inflation_keys_rangeproof.GetBytes();

  int ret = wally_tx_elements_input_issuance_set(
      &tx_pointer->inputs[tx_in_index], nonce.data(), nonce.size(),
      entropy.data(), entropy.size(), issuance_amount_bytes.data(),
      issuance_amount_bytes.size(), inflation_keys_bytes.data(),
      inflation_keys_bytes.size(), issuance_amount_rangeproof_bytes.data(),
      issuance_amount_rangeproof_bytes.size(),
      inflation_keys_rangeproof_bytes.data(),
      inflation_keys_rangeproof_bytes.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_elements_input_issuance_set NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "txin add error.");
  }
  SetElementsTxState();

  vin_[tx_in_index].SetIssuance(
      blinding_nonce, asset_entropy, issuance_amount, inflation_keys,
      issuance_amount_rangeproof, inflation_keys_rangeproof);
}

uint32_t ConfidentialTransaction::GetPeginWitnessStackNum(
    uint32_t tx_in_index) const {
  CheckTxInIndex(tx_in_index, __LINE__, __FUNCTION__);
  return vin_[tx_in_index].GetPeginWitnessStackNum();
}

const ScriptWitness ConfidentialTransaction::AddPeginWitnessStack(
    uint32_t tx_in_index, const ByteData &data) {
  return AddPeginWitnessStack(tx_in_index, data.GetBytes());
}

const ScriptWitness ConfidentialTransaction::AddPeginWitnessStack(
    uint32_t tx_in_index, const ByteData160 &data) {
  return AddPeginWitnessStack(tx_in_index, data.GetBytes());
}

const ScriptWitness ConfidentialTransaction::AddPeginWitnessStack(
    uint32_t tx_in_index, const ByteData256 &data) {
  return AddPeginWitnessStack(tx_in_index, data.GetBytes());
}

const ScriptWitness ConfidentialTransaction::AddPeginWitnessStack(
    uint32_t tx_in_index, const std::vector<uint8_t> &data) {
  CheckTxInIndex(tx_in_index, __LINE__, __FUNCTION__);

  struct wally_tx *tx_pointer =
      static_cast<struct wally_tx *>(wally_tx_pointer_);
  if (tx_pointer->num_inputs > tx_in_index) {
    int ret = WALLY_OK;
    bool is_alloc = false;
    struct wally_tx_witness_stack *stack_pointer = NULL;

    std::string function_name = "wally_tx_witness_stack_init_alloc";
    if (tx_pointer->inputs[tx_in_index].pegin_witness == NULL) {
      is_alloc = true;
      ret = wally_tx_witness_stack_init_alloc(1, &stack_pointer);
    } else {
      stack_pointer = tx_pointer->inputs[tx_in_index].pegin_witness;
    }

    if (ret == WALLY_OK) {
      try {
        // append witness stack
        function_name = "wally_tx_witness_stack_add";
        if (data.empty()) {
          ret = wally_tx_witness_stack_add(stack_pointer, NULL, 0);
        } else {
          ret = wally_tx_witness_stack_add(
              stack_pointer, data.data(), data.size());
        }

        // append tx input
        if (is_alloc && (ret == WALLY_OK)) {
          tx_pointer->inputs[tx_in_index].pegin_witness = stack_pointer;
          stack_pointer = nullptr;
        }
      } catch (...) {
        // internal error.
        warn(CFD_LOG_SOURCE, "system error.");
        ret = WALLY_ERROR;
      }

      if (is_alloc && stack_pointer) {
        wally_tx_witness_stack_free(stack_pointer);
      }
    }

    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "{} NG[{}].", function_name, ret);
      throw CfdException(kCfdIllegalStateError, "witness stack error.");
    }
  }
  SetElementsTxState();

  const ScriptWitness &witness =
      vin_[tx_in_index].AddPeginWitnessStack(ByteData(data));
  return witness;
}

const ScriptWitness ConfidentialTransaction::SetPeginWitnessStack(
    uint32_t tx_in_index, uint32_t witness_index, const ByteData &data) {
  return SetPeginWitnessStack(tx_in_index, witness_index, data.GetBytes());
}

const ScriptWitness ConfidentialTransaction::SetPeginWitnessStack(
    uint32_t tx_in_index, uint32_t witness_index, const ByteData160 &data) {
  return SetPeginWitnessStack(tx_in_index, witness_index, data.GetBytes());
}

const ScriptWitness ConfidentialTransaction::SetPeginWitnessStack(
    uint32_t tx_in_index, uint32_t witness_index, const ByteData256 &data) {
  return SetPeginWitnessStack(tx_in_index, witness_index, data.GetBytes());
}

const ScriptWitness ConfidentialTransaction::SetPeginWitnessStack(
    uint32_t tx_in_index, uint32_t witness_index,
    const std::vector<uint8_t> &data) {
  CheckTxInIndex(tx_in_index, __LINE__, __FUNCTION__);

  struct wally_tx *tx_pointer =
      static_cast<struct wally_tx *>(wally_tx_pointer_);
  if (tx_pointer->num_inputs > tx_in_index) {
    int ret = WALLY_EINVAL;
    struct wally_tx_witness_stack *stack_pointer = NULL;

    std::string function_name = "wally witness is NULL.";
    if (tx_pointer->inputs[tx_in_index].pegin_witness != NULL) {
      stack_pointer = tx_pointer->inputs[tx_in_index].pegin_witness;

      // append witness stack
      function_name = "wally_tx_witness_stack_set";
      if (data.empty()) {
        ret =
            wally_tx_witness_stack_set(stack_pointer, witness_index, NULL, 0);
      } else {
        ret = wally_tx_witness_stack_set(
            stack_pointer, witness_index, data.data(), data.size());
      }
    }

    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "{} NG[{}].", function_name, ret);
      throw CfdException(kCfdIllegalStateError, "witness stack set error.");
    }
  }
  SetElementsTxState();

  const ScriptWitness &witness =
      vin_[tx_in_index].SetPeginWitnessStack(witness_index, ByteData(data));
  return witness;
}

void ConfidentialTransaction::RemovePeginWitnessStackAll(
    uint32_t tx_in_index) {
  CheckTxInIndex(tx_in_index, __LINE__, __FUNCTION__);

  struct wally_tx *tx_pointer =
      static_cast<struct wally_tx *>(wally_tx_pointer_);
  if (tx_pointer->num_inputs > tx_in_index) {
    int ret = WALLY_OK;
    struct wally_tx_witness_stack *stack_pointer = NULL;
    if (tx_pointer->inputs[tx_in_index].pegin_witness != NULL) {
      stack_pointer = tx_pointer->inputs[tx_in_index].pegin_witness;
      ret = wally_tx_witness_stack_free(stack_pointer);
      tx_pointer->inputs[tx_in_index].pegin_witness = NULL;
      if (ret != WALLY_OK) {
        warn(CFD_LOG_SOURCE, "wally_tx_witness_stack_free NG[{}].", ret);
        throw CfdException(
            kCfdIllegalStateError, "pegin witness stack error.");
      }
    }
  }
  SetElementsTxState();

  vin_[tx_in_index].RemovePeginWitnessStackAll();
}

IssuanceParameter ConfidentialTransaction::SetAssetIssuance(
    uint32_t tx_in_index, const Amount &asset_amount,
    const Script &asset_locking_script, const ConfidentialNonce &asset_nonce,
    const Amount &token_amount, const Script &token_locking_script,
    const ConfidentialNonce &token_nonce, bool is_blind,
    const ByteData256 &contract_hash) {
  CheckTxInIndex(tx_in_index, __LINE__, __FUNCTION__);

  if ((vin_[tx_in_index].GetInflationKeys().GetData().GetDataSize() > 0) ||
      (vin_[tx_in_index].GetIssuanceAmount().GetData().GetDataSize() > 0)) {
    warn(CFD_LOG_SOURCE, "already set to issue parameter");
    throw CfdException(
        kCfdIllegalArgumentError, "already set to issue parameter");
  }
  if ((asset_amount.GetSatoshiValue() == 0) &&
      (token_amount.GetSatoshiValue() == 0)) {
    warn(CFD_LOG_SOURCE, "Issuance must have one non-zero amount.");
    throw CfdException(
        kCfdIllegalArgumentError, "Issuance must have one non-zero amount.");
  }

  IssuanceParameter param = CalculateIssuanceValue(
      vin_[tx_in_index].GetTxid(), vin_[tx_in_index].GetVout(), is_blind,
      contract_hash);

  // 指定されたTxInへの設定
  SetIssuance(
      tx_in_index, ByteData256(), contract_hash,
      ConfidentialValue(asset_amount), ConfidentialValue(token_amount),
      ByteData(), ByteData());

  // TxOut追加
  if (asset_amount.GetSatoshiValue() != 0) {
    AddTxOut(asset_amount, param.asset, asset_locking_script, asset_nonce);
  }
  if (token_amount.GetSatoshiValue() != 0) {
    AddTxOut(token_amount, param.token, token_locking_script, token_nonce);
  }
  return param;
}

IssuanceParameter ConfidentialTransaction::CalculateIssuanceValue(
    const Txid &txid, uint32_t vout, bool is_blind,
    const ByteData256 contract_hash) {
  IssuanceParameter result;
  const std::vector<uint8_t> &txid_byte = txid.GetData().GetBytes();
  const std::vector<uint8_t> &contract_hash_byte = contract_hash.GetBytes();
  std::vector<uint8_t> entropy(kEntropySize);
  // issue値の計算
  int ret = wally_tx_elements_issuance_generate_entropy(
      txid_byte.data(), txid_byte.size(), vout, contract_hash_byte.data(),
      contract_hash_byte.size(), entropy.data(), entropy.size());
  if (ret != WALLY_OK) {
    warn(
        CFD_LOG_SOURCE, "wally_tx_elements_issuance_generate_entropy NG[{}].",
        ret);
    throw CfdException(kCfdIllegalStateError, "entropy generate error.");
  }

  std::vector<uint8_t> asset(kAssetSize);
  ret = wally_tx_elements_issuance_calculate_asset(
      entropy.data(), entropy.size(), asset.data(), asset.size());
  if (ret != WALLY_OK) {
    warn(
        CFD_LOG_SOURCE, "wally_tx_elements_issuance_calculate_asset NG[{}].",
        ret);
    throw CfdException(kCfdIllegalStateError, "asset calculate error.");
  }

  std::vector<uint8_t> token(kAssetSize);
  uint32_t flag = (is_blind) ? WALLY_TX_FLAG_BLINDED_INITIAL_ISSUANCE : 0;
  ret = wally_tx_elements_issuance_calculate_reissuance_token(
      entropy.data(), entropy.size(), flag, token.data(), token.size());
  if (ret != WALLY_OK) {
    warn(
        CFD_LOG_SOURCE,
        "wally_tx_elements_issuance_calculate_reissuance_token NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "token calculate error.");
  }

  result.entropy = BlindFactor(ByteData256(entropy));
  result.asset = ConfidentialAssetId(ByteData(asset));
  result.token = ConfidentialAssetId(ByteData(token));
  return result;
}

const ConfidentialTxOutReference ConfidentialTransaction::GetTxOut(
    uint32_t index) const {
  CheckTxOutIndex(index, __LINE__, __FUNCTION__);
  return ConfidentialTxOutReference(vout_[index]);
}

uint32_t ConfidentialTransaction::GetTxOutCount() const {
  return static_cast<uint32_t>(vout_.size());
}

const std::vector<ConfidentialTxOutReference>  // force LF
ConfidentialTransaction::GetTxOutList() const {
  std::vector<ConfidentialTxOutReference> refs;
  for (ConfidentialTxOut tx_out : vout_) {
    refs.push_back(ConfidentialTxOutReference(tx_out));
  }
  return refs;
}

uint32_t ConfidentialTransaction::AddTxOut(
    const Amount &value, const ConfidentialAssetId &asset,
    const Script &locking_script) {
  return AddTxOut(
      value, asset, locking_script, ConfidentialNonce(), ByteData(),
      ByteData());
}

uint32_t ConfidentialTransaction::AddTxOut(
    const Amount &value, const ConfidentialAssetId &asset,
    const Script &locking_script, const ConfidentialNonce &nonce) {
  return AddTxOut(value, asset, locking_script, nonce, ByteData(), ByteData());
}

uint32_t ConfidentialTransaction::AddTxOut(
    const Amount &value, const ConfidentialAssetId &asset,
    const Script &locking_script, const ConfidentialNonce &nonce,
    const ByteData &surjection_proof, const ByteData &range_proof) {
  if (vout_.size() == std::numeric_limits<uint32_t>::max()) {
    warn(CFD_LOG_SOURCE, "vout maximum.");
    throw CfdException(kCfdIllegalStateError, "vout maximum.");
  }

  ConfidentialValue confidential_value = ConfidentialValue(value);
  const std::vector<uint8_t> &script_data =
      locking_script.GetData().GetBytes();
  const std::vector<uint8_t> &asset_data = asset.GetData().GetBytes();
  const std::vector<uint8_t> &value_data =
      confidential_value.GetData().GetBytes();
  const std::vector<uint8_t> &nonce_data = nonce.GetData().GetBytes();
  const std::vector<uint8_t> &surjection_data = surjection_proof.GetBytes();
  const std::vector<uint8_t> &range_data = range_proof.GetBytes();

  int ret = wally_tx_add_elements_raw_output(
      static_cast<struct wally_tx *>(wally_tx_pointer_), script_data.data(),
      script_data.size(), asset_data.data(), asset_data.size(),
      value_data.data(), value_data.size(),
      (nonce_data.size() == 0) ? nullptr : nonce_data.data(),
      nonce_data.size(),
      (surjection_data.size() == 0) ? nullptr : surjection_data.data(),
      surjection_data.size(),
      (range_data.size() == 0) ? nullptr : range_data.data(),
      range_data.size(), 0);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_add_elements_raw_output NG[{}].", ret);
    warn(CFD_LOG_SOURCE, "script_data.size[{}].", script_data.size());
    warn(CFD_LOG_SOURCE, "asset_data.size[{}].", asset_data.size());
    warn(CFD_LOG_SOURCE, "value_data.size[{}].", value_data.size());
    warn(CFD_LOG_SOURCE, "nonce_data.size[{}].", nonce_data.size());
    warn(CFD_LOG_SOURCE, "surjection_data.size[{}].", surjection_data.size());
    warn(CFD_LOG_SOURCE, "range_data.size[{}].", range_data.size());
    throw CfdException(kCfdIllegalStateError, "vout add error.");
  }

  ConfidentialTxOut out(
      locking_script, asset, confidential_value, nonce, surjection_proof,
      range_proof);
  out.SetValue(value);
  vout_.push_back(out);
  return static_cast<uint32_t>(vout_.size() - 1);
}

uint32_t ConfidentialTransaction::AddTxOutFee(
    const Amount &value, const ConfidentialAssetId &asset) {
  if (vout_.size() == std::numeric_limits<uint32_t>::max()) {
    warn(CFD_LOG_SOURCE, "vout maximum.");
    throw CfdException(kCfdIllegalStateError, "vout maximum.");
  }

  ConfidentialValue confidential_value = ConfidentialValue(value);
  const std::vector<uint8_t> &asset_data = asset.GetData().GetBytes();
  const std::vector<uint8_t> &value_data =
      confidential_value.GetData().GetBytes();

  int ret = wally_tx_add_elements_raw_output(
      static_cast<struct wally_tx *>(wally_tx_pointer_), nullptr, 0,
      asset_data.data(), asset_data.size(), value_data.data(),
      value_data.size(), nullptr, 0, nullptr, 0, nullptr, 0, 0);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_add_raw_output NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "vout fee add error.");
  }

  ConfidentialTxOut out(asset, confidential_value);
  vout_.push_back(out);
  return static_cast<uint32_t>(vout_.size() - 1);
}

void ConfidentialTransaction::SetTxOutCommitment(
    uint32_t index, const ConfidentialAssetId &asset,
    const ConfidentialValue &value, const ConfidentialNonce &nonce,
    const ByteData &surjection_proof, const ByteData &range_proof) {
  CheckTxOutIndex(index, __LINE__, __FUNCTION__);

  const std::vector<uint8_t> &asset_data = asset.GetData().GetBytes();
  const std::vector<uint8_t> &value_data = value.GetData().GetBytes();
  const std::vector<uint8_t> &nonce_data = nonce.GetData().GetBytes();
  const std::vector<uint8_t> &surjection_data = surjection_proof.GetBytes();
  const std::vector<uint8_t> &range_data = range_proof.GetBytes();

  struct wally_tx *tx = static_cast<struct wally_tx *>(wally_tx_pointer_);
  int ret = wally_tx_elements_output_commitment_set(
      &tx->outputs[index], asset_data.data(), asset_data.size(),
      value_data.data(), value_data.size(), nonce_data.data(),
      nonce_data.size(), surjection_data.data(), surjection_data.size(),
      range_data.data(), range_data.size());
  if (ret != WALLY_OK) {
    warn(
        CFD_LOG_SOURCE, "wally_tx_elements_output_commitment_set NG[{}].",
        ret);
    throw CfdException(kCfdIllegalStateError, "set commitment error.");
  }

  vout_[index].SetCommitment(
      asset, value, nonce, surjection_proof, range_proof);
}

void ConfidentialTransaction::RemoveTxOut(uint32_t index) {
  AbstractTransaction::RemoveTxOut(index);

  std::vector<ConfidentialTxOut>::const_iterator ite = vout_.cbegin();
  if (index != 0) {
    ite += index;
  }
  vout_.erase(ite);
}

void ConfidentialTransaction::BlindTxOut(
    const std::vector<Pubkey> &blind_pubkeys,
    const std::vector<ConfidentialAssetId> &asset_id_list,
    const std::vector<BlindFactor> &asset_blind_factor_list,
    const std::vector<BlindFactor> &value_blind_factor_list,
    const std::vector<Amount> &input_value_list, int64_t minimum_range_value,
    int exponent, int minimum_bits) {
  std::vector<uint8_t> input_generators;
  std::vector<uint64_t> input_values;
  std::vector<uint8_t> input_asset_ids;
  int ret;

  // create asset generator
  for (size_t index = 0; index < asset_id_list.size(); ++index) {
    const std::vector<uint8_t> &asset_id =
        asset_id_list[index].GetUnblindedData().GetBytes();
    const std::vector<uint8_t> &abf =
        asset_blind_factor_list[index].GetData().GetBytes();
    std::vector<uint8_t> generator(ASSET_GENERATOR_LEN);
    ret = wally_asset_generator_from_bytes(
        asset_id.data(), asset_id.size(), abf.data(), abf.size(),
        generator.data(), generator.size());
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_asset_generator_from_bytes NG[{}].", ret);
      throw CfdException(kCfdIllegalStateError, "asset generator error.");
    }
    input_generators.insert(
        input_generators.end(), std::begin(generator), std::end(generator));
    input_asset_ids.insert(
        input_asset_ids.end(), std::begin(asset_id), std::end(asset_id));
    info(CFD_LOG_SOURCE, "input asset=[{}]", ByteData(asset_id).GetHex());
  }
  for (const auto &value : input_value_list) {
    input_values.push_back(value.GetSatoshiValue());
  }

  size_t output_count = 0;
  for (const auto &output : vout_) {
    if (!output.GetLockingScript().IsEmpty()) {
      // fee以外の値
      Amount temp_amount = output.GetConfidentialValue().GetAmount();
      input_values.push_back(temp_amount.GetSatoshiValue());
      ++output_count;
    }
  }

  std::vector<uint8_t> input_abfs;
  std::vector<ByteData> output_abfs(output_count);
  std::vector<ByteData> output_vbfs(output_count - 1);

  std::vector<uint8_t> abfs;  // serialize
  for (const BlindFactor &abf : asset_blind_factor_list) {
    const std::vector<uint8_t> &data = abf.GetData().GetBytes();
    abfs.insert(abfs.end(), std::begin(data), std::end(data));
  }
  input_abfs = abfs;
  for (size_t index = 0; index < output_abfs.size(); ++index) {
    // generate random byte
    const std::vector<uint8_t> &data =
        RandomNumberUtil::GetRandomBytes(kBlindFactorSize);
    output_abfs[index] = ByteData(data);
    abfs.insert(abfs.end(), std::begin(data), std::end(data));
  }

  std::vector<uint8_t> vbfs;  // serialize
  for (const BlindFactor &vbf : value_blind_factor_list) {
    const std::vector<uint8_t> &data = vbf.GetData().GetBytes();
    vbfs.insert(vbfs.end(), std::begin(data), std::end(data));
  }
  for (size_t index = 0; index < output_vbfs.size(); ++index) {
    // generate random byte
    const std::vector<uint8_t> &data =
        RandomNumberUtil::GetRandomBytes(kBlindFactorSize);
    output_vbfs[index] = ByteData(data);
    vbfs.insert(vbfs.end(), std::begin(data), std::end(data));
  }

  std::vector<uint8_t> asset_data(kAssetSize);
  ret = wally_asset_final_vbf(
      input_values.data(), input_values.size(), input_value_list.size(),
      abfs.data(), abfs.size(), vbfs.data(), vbfs.size(), asset_data.data(),
      asset_data.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_asset_final_vbf NG[{}].", ret);
    throw CfdException(
        kCfdIllegalStateError, "asset value blind factor error.");
  }
  output_vbfs.push_back(ByteData(asset_data));

  uint32_t count = 0;
  for (uint32_t vout_index = 0; vout_index < vout_.size(); ++vout_index) {
    const auto &output = vout_[vout_index];
    if (output.GetLockingScript().IsEmpty()) {
      // feeは除外
      continue;
    }

    const std::vector<uint8_t> &pubkey_byte =
        blind_pubkeys[count].GetData().GetBytes();

    Amount amount = output.GetConfidentialValue().GetAmount();
    uint64_t value = static_cast<uint64_t>(amount.GetSatoshiValue());
    ConfidentialAssetId output_asset_id(output.GetAsset());
    std::vector<uint8_t> asset = output_asset_id.GetUnblindedData().GetBytes();
    const std::vector<uint8_t> &script =
        output.GetLockingScript().GetData().GetBytes();

    const std::vector<uint8_t> &abf = output_abfs[count].GetBytes();
    const std::vector<uint8_t> &vbf = output_vbfs[count].GetBytes();

    std::vector<uint8_t> generator(ASSET_GENERATOR_LEN);
    ret = wally_asset_generator_from_bytes(
        asset.data(), asset.size(), abf.data(), abf.size(), generator.data(),
        generator.size());
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_asset_generator_from_bytes NG[{}].", ret);
      throw CfdException(
          kCfdIllegalStateError, "output asset generator error.");
    }

    std::vector<uint8_t> commitment(ASSET_COMMITMENT_LEN);
    ret = wally_asset_value_commitment(
        value, vbf.data(), vbf.size(), generator.data(), generator.size(),
        commitment.data(), commitment.size());
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_asset_value_commitment NG[{}].", ret);
      throw CfdException(
          kCfdIllegalStateError, "calc asset commitment error.");
    }
    info(
        CFD_LOG_SOURCE, "generator=[{}] commitment=[{}]",
        ByteData(generator).GetHex(), ByteData(commitment).GetHex());

    Privkey key = Privkey::GenerageRandomKey();
    const std::vector<uint8_t> &privkey_byte = key.GetData().GetBytes();

    std::vector<uint8_t> range_proof(ASSET_RANGEPROOF_MAX_LEN);
    size_t size = 0;
    ret = wally_asset_rangeproof(
        value, pubkey_byte.data(), pubkey_byte.size(), privkey_byte.data(),
        privkey_byte.size(), asset.data(), asset.size(), abf.data(),
        abf.size(), vbf.data(), vbf.size(), commitment.data(),
        commitment.size(), script.data(), script.size(), generator.data(),
        generator.size(), static_cast<uint64_t>(minimum_range_value), exponent,
        minimum_bits, range_proof.data(), range_proof.size(), &size);
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_asset_rangeproof NG[{}].", ret);
      throw CfdException(
          kCfdIllegalStateError, "calc asset rangeproof error.");
    }
    range_proof.resize(size);

    size = 0;
    ret = wally_asset_surjectionproof_size(
        input_asset_ids.size() / kAssetSize, &size);
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_asset_surjectionproof_size NG[{}].", ret);
      throw CfdException(
          kCfdIllegalStateError, "calc asset surjectionproof size error.");
    }
    std::vector<uint8_t> surjection_proof(size);

    std::vector<uint8_t> bytes =
        RandomNumberUtil::GetRandomBytes(kBlindFactorSize);
    ret = wally_asset_surjectionproof(
        asset.data(), asset.size(), abf.data(), abf.size(), generator.data(),
        generator.size(), bytes.data(), bytes.size(), input_asset_ids.data(),
        input_asset_ids.size(), input_abfs.data(), input_abfs.size(),
        input_generators.data(), input_generators.size(),
        surjection_proof.data(), surjection_proof.size(), &size);
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_asset_surjectionproof NG[{}].", ret);
      throw CfdException(
          kCfdIllegalStateError, "calc asset surjectionproof error.");
    }
    surjection_proof.resize(size);

    SetTxOutCommitment(
        vout_index, ConfidentialAssetId(ByteData(generator)),
        ConfidentialValue(ByteData(commitment)),
        ConfidentialNonce(key.GeneratePubkey().GetData()),
        ByteData(surjection_proof), ByteData(range_proof));
    ++count;
  }
}

UnblindParameter ConfidentialTransaction::UnblindTxOut(
    uint32_t tx_out_index, const Privkey &blinding_key) {
  CheckTxOutIndex(tx_out_index, __LINE__, __FUNCTION__);

  ConfidentialTxOut tx_out(vout_[tx_out_index]);
  if (!tx_out.GetAsset().HasBlinding() || !tx_out.GetNonce().HasBlinding() ||
      !tx_out.GetConfidentialValue().HasBlinding() ||
      (tx_out.GetRangeProof().GetDataSize() == 0) ||
      (tx_out.GetSurjectionProof().GetDataSize() == 0)) {
    warn(
        CFD_LOG_SOURCE,
        "Failed to unblind TxOut. Target TxOut already unblinded.: "
        "tx_out_index=[{}]",
        tx_out_index);
    throw CfdException(
        kCfdIllegalStateError,
        "Failed to unblind TxOut. Target TxOut already unblinded.");
  }

  UnblindParameter result = CalculateUnblindData(
      tx_out.GetNonce(), blinding_key, tx_out.GetRangeProof(),
      tx_out.GetConfidentialValue(), tx_out.GetLockingScript(),
      tx_out.GetAsset());

  // clear and set unblind value to txout
  SetTxOutCommitment(
      tx_out_index, result.asset, result.value, ConfidentialNonce(),
      ByteData(), ByteData());

  return result;
}

std::vector<UnblindParameter> ConfidentialTransaction::UnblindTxOut(
    const std::vector<Privkey> &blinding_keys) {
  uint32_t output_cout = 0;
  for (const auto vout : vout_) {
    // count txouts without fee
    if (!vout.GetLockingScript().IsEmpty()) ++output_cout;
  }
  // validate input vector size
  if (output_cout != blinding_keys.size()) {
    warn(
        CFD_LOG_SOURCE,
        "Unmatch size blinding_keys and txouts.:"
        " txout num=[{}], blinding key num=[{}]",
        output_cout, blinding_keys.size());
    throw CfdException(
        kCfdIllegalArgumentError, "Unmatch size blinding_keys and txouts.");
  }

  uint32_t index = 0;
  std::vector<UnblindParameter> results;
  for (const ConfidentialTxOut vout : vout_) {
    // skip if vout is txout for fee
    if (vout.GetLockingScript().IsEmpty()) continue;

    results.push_back(UnblindTxOut(index, blinding_keys[index]));
    ++index;
  }

  return results;
}

UnblindParameter ConfidentialTransaction::CalculateUnblindData(
    const ConfidentialNonce &nonce, const Privkey &blinding_key,
    const ByteData &rangeproof, const ConfidentialValue &value_commitment,
    const Script &extra, const ConfidentialAssetId &asset) {
  const std::vector<uint8_t> nonce_bytes = nonce.GetData().GetBytes();
  const std::vector<uint8_t> blinding_key_bytes =
      blinding_key.GetData().GetBytes();
  const std::vector<uint8_t> rangeproof_bytes = rangeproof.GetBytes();
  const std::vector<uint8_t> commitment_bytes =
      value_commitment.GetData().GetBytes();
  const std::vector<uint8_t> extra_bytes = extra.GetData().GetBytes();
  const std::vector<uint8_t> entropy_bytes = asset.GetData().GetBytes();
  std::vector<uint8_t> abf_out(kBlindFactorSize);
  std::vector<uint8_t> vbf_out(kBlindFactorSize);
  std::vector<uint8_t> asset_out(kAssetSize);
  uint64_t value_out = 0;
  int ret = wally_asset_unblind(
      nonce_bytes.data(), nonce_bytes.size(), blinding_key_bytes.data(),
      blinding_key_bytes.size(), rangeproof_bytes.data(),
      rangeproof_bytes.size(), commitment_bytes.data(),
      commitment_bytes.size(), extra_bytes.data(), extra_bytes.size(),
      entropy_bytes.data(), entropy_bytes.size(), asset_out.data(),
      asset_out.size(), abf_out.data(), abf_out.size(), vbf_out.data(),
      vbf_out.size(), &value_out);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_asset_unblind NG[{}].", ret);
    throw CfdException(
        kCfdIllegalStateError, "unblind confidential data error.");
  }

  UnblindParameter result;
  result.asset = ConfidentialAssetId(asset_out);
  result.abf = BlindFactor(ByteData256(abf_out));
  result.vbf = BlindFactor(ByteData256(vbf_out));
  result.value = ConfidentialValue(Amount::CreateBySatoshiAmount(value_out));

  return result;
}

ByteData256 ConfidentialTransaction::GetElementsSignatureHash(
    uint32_t txin_index, const ByteData &script_data, SigHashType sighash_type,
    Amount txin_value, bool is_witness) {
  // AmountをConfidentialValueに変換
  std::vector<uint8_t> value(WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN);
  int ret = wally_tx_confidential_value_from_satoshi(
      txin_value.GetSatoshiValue(), value.data(), value.size());
  if (ret != WALLY_OK) {
    warn(
        CFD_LOG_SOURCE, "wally_tx_confidential_value_from_satoshi NG[{}] ",
        ret);
    throw CfdException(
        kCfdIllegalArgumentError, "satoshi to confidential value error.");
  }

  return GetElementsSignatureHash(
      txin_index, script_data, sighash_type, ByteData(value), is_witness);
}

ByteData256 ConfidentialTransaction::GetElementsSignatureHash(
    uint32_t txin_index, const ByteData &script_data, SigHashType sighash_type,
    const ByteData &value, bool is_witness) {
  std::vector<uint8_t> buffer(SHA256_LEN);
  const std::vector<uint8_t> &bytes = script_data.GetBytes();
  struct wally_tx *tx_pointer = NULL;
  int ret = WALLY_OK;

  // AbstractTransactionをwally_txに変換
  const std::vector<uint8_t> &tx_bytedata = GetData(HasWitness()).GetBytes();
  ret = wally_tx_from_bytes(
      tx_bytedata.data(), tx_bytedata.size(), GetWallyFlag(), &tx_pointer);
  if (ret != WALLY_OK || tx_pointer == NULL) {
    warn(CFD_LOG_SOURCE, "wally_tx_from_bytes NG[{}] ", ret);
    throw CfdException(kCfdIllegalArgumentError, "transaction data invalid.");
  }

  // signature hash算出
  try {
    uint32_t tx_flag = 0;
    if (is_witness) {
      tx_flag = GetWallyFlag() & WALLY_TX_FLAG_USE_WITNESS;
    }
    ret = wally_tx_get_elements_signature_hash(
        tx_pointer, txin_index, bytes.data(), bytes.size(),
        value.GetBytes().data(), value.GetBytes().size(),
        sighash_type.GetSigHashFlag(), tx_flag, buffer.data(), buffer.size());
    wally_tx_free(tx_pointer);
  } catch (...) {
    wally_tx_free(tx_pointer);
    warn(
        CFD_LOG_SOURCE, "wally_tx_get_elements_signature_hash exception[{}] ",
        ret);
    throw CfdException(
        kCfdIllegalArgumentError, "SignatureHash generate error.");
  }

  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_get_elements_signature_hash NG[{}] ", ret);
    throw CfdException(
        kCfdIllegalArgumentError, "SignatureHash generate error.");
  }
  return ByteData256(buffer);
}

void ConfidentialTransaction::RandomizeTxOut() {
  const std::vector<ConfidentialTxOutReference> &txout_list = GetTxOutList();
  // blind check
  for (size_t index = 0; index < txout_list.size(); ++index) {
    const ConfidentialValue &value = txout_list[index].GetConfidentialValue();
    if (value.HasBlinding()) {
      warn(CFD_LOG_SOURCE, "already blinded tx");
      throw CfdException(kCfdIllegalArgumentError, "already blinded tx");
    }
  }
  for (size_t index = txout_list.size(); index > 0; --index) {
    RemoveTxOut(static_cast<uint32_t>(index - 1));
  }

  std::vector<uint32_t> indexes = RandomNumberUtil::GetRandomIndexes(
      static_cast<uint32_t>(txout_list.size()));
  for (size_t index = 0; index < indexes.size(); ++index) {
    const ConfidentialTxOutReference &txout = txout_list[indexes[index]];
    AddTxOut(
        txout.GetConfidentialValue().GetAmount(), txout.GetAsset(),
        txout.GetLockingScript(), txout.GetNonce(), txout.GetSurjectionProof(),
        txout.GetRangeProof());
  }
}

ByteData ConfidentialTransaction::ConvertToByteData(
    const uint8_t *data, size_t size) {
  std::vector<uint8_t> buffer(size);
  if ((data != nullptr) && (size != 0)) {
    memcpy(buffer.data(), data, size);
  }
  return ByteData(buffer);
}

bool ConfidentialTransaction::HasWitness() const {
  size_t is_witness = 0;
  int ret = wally_tx_get_witness_count(
      static_cast<struct wally_tx *>(wally_tx_pointer_), &is_witness);
  if (ret == WALLY_OK) {
    return (is_witness != 0);
  }
  return false;
}

uint8_t *ConfidentialTransaction::CopyConfidentialCommitment(
    const void *buffer, size_t buffer_size, size_t explicit_size,
    uint8_t *address) {
  uint8_t *result = address;
  const uint8_t *buffer_addr = static_cast<const uint8_t *>(buffer);
  if ((!buffer_addr) || (buffer_size == 0) || (buffer_addr[0] == 0)) {
    *result = 0;  // version is 0
    ++result;
  } else {
    size_t max_size = kConfidentialDataSize;
    if (buffer_addr[0] == kConfidentialVersion_1) {
      max_size = explicit_size;
    }
    size_t copy_size = max_size;
    if (buffer_size <= copy_size) {
      copy_size = buffer_size;
    }
    // explicit value
    // confidential value
    uint8_t ct_buffer[kConfidentialDataSize];
    memset(ct_buffer, 0, sizeof(ct_buffer));
    memcpy(ct_buffer, buffer_addr, copy_size);
    memcpy(address, ct_buffer, max_size);
    result += max_size;
  }
  return result;
}

void ConfidentialTransaction::SetElementsTxState() {
  struct wally_tx *tx_pointer =
      static_cast<struct wally_tx *>(wally_tx_pointer_);
  if (tx_pointer != nullptr) {
    size_t is_coinbase = 0;
    // coinbase設定時はcoinbase優先
    int ret = wally_tx_is_coinbase(tx_pointer, &is_coinbase);
    if ((ret == WALLY_OK) && (is_coinbase == 0)) {
      for (uint32_t i = 0; i < tx_pointer->num_inputs; ++i) {
        struct wally_tx_input *input = tx_pointer->inputs + i;
        // pegin_witness
        if ((input->pegin_witness != nullptr) &&
            (input->pegin_witness->num_items != 0)) {
          input->features |= kTxInFeaturePegin;
        } else {
          input->features &= ~kTxInFeaturePegin;
        }

        // issuance
        if (((input->issuance_amount != nullptr) &&
             (input->issuance_amount_len != 0)) ||
            ((input->inflation_keys != nullptr) &&
             (input->inflation_keys_len != 0))) {
          input->features |= kTxInFeatureIssuance;
        } else {
          input->features &= ~kTxInFeatureIssuance;
        }
      }
    }
  }
}

ByteData ConfidentialTransaction::GetData(bool has_witness) const {
  struct wally_tx *tx_pointer =
      static_cast<struct wally_tx *>(wally_tx_pointer_);
  size_t size = 0;
  uint32_t flag = WALLY_TX_FLAG_USE_WITNESS;

  int ret = wally_tx_get_length(tx_pointer, flag, &size);
  if (ret != WALLY_OK) {
    warn(
        CFD_LOG_SOURCE, "wally_tx_get_length NG[{}]. wit[{}]", ret,
        has_witness);
    throw CfdException(kCfdIllegalStateError, "tx length calc error.");
  }
  // info(CFD_LOG_SOURCE, "wally_tx_get_length size[{}]", size);
  if (size < kElementsTransactionMinimumSize) {
    ret = WALLY_EINVAL;
    warn(CFD_LOG_SOURCE, "tx size low.[{}]", size);
  }
  std::vector<uint8_t> buffer(size);
  if (ret != WALLY_EINVAL) {
    size_t txsize = size;
    // flag |= WALLY_TX_FLAG_USE_ELEMENTS;
    ret = wally_tx_to_bytes(
        tx_pointer, flag, buffer.data(), buffer.size(), &txsize);
  }
  if (ret == WALLY_EINVAL) {
    /* objectとの変換について。
     * libwallyでは、txin/txoutが空のデータを許容していない。
     * そのためtxin/txoutが空の場合はobject to byteはエラーとなる。
     * よって特定状況下では独自の処理を実行する。
     */
    if ((tx_pointer->num_inputs == 0) || (tx_pointer->num_outputs == 0)) {
      info(CFD_LOG_SOURCE, "wally_tx_get_length size[{}]", size);
      bool has_txin_witness = false;
      bool has_txin_rangeproof = false;
      bool has_txout_witness = false;
      bool is_witness = false;
      // wally_tx_get_lengthが不正値の場合があるため必要サイズ計算 (多めに確保)
      size_t need_size = sizeof(struct wally_tx);
      need_size += tx_pointer->num_inputs * sizeof(struct wally_tx_input);
      need_size += tx_pointer->num_outputs * sizeof(struct wally_tx_output);
      for (uint32_t i = 0; i < tx_pointer->num_inputs; ++i) {
        const struct wally_tx_input *input = tx_pointer->inputs + i;
        need_size += sizeof(input->blinding_nonce);
        need_size += sizeof(input->entropy);
        if (input->issuance_amount) {
          need_size += input->issuance_amount_len + 10;
        }
        if (input->inflation_keys) {
          need_size += input->inflation_keys_len + 10;
        }
      }
      for (uint32_t i = 0; i < tx_pointer->num_outputs; ++i) {
        const struct wally_tx_output *output = tx_pointer->outputs + i;
        if (output->asset) need_size += output->asset_len + 10;
        if (output->value) need_size += output->value_len + 10;
        if (output->nonce) need_size += output->nonce_len + 10;
        if (output->script) need_size += output->script_len + 10;
        need_size += 10;
      }
      for (uint32_t i = 0; i < tx_pointer->num_inputs; ++i) {
        const struct wally_tx_input *input = tx_pointer->inputs + i;
        // issuance amount range proof
        if (input->issuance_amount_rangeproof) {
          need_size += input->issuance_amount_rangeproof_len + 10;
          has_txin_rangeproof = true;
        }
        // inflation keys range proof
        if (input->inflation_keys_rangeproof) {
          need_size += input->inflation_keys_rangeproof_len + 10;
          has_txin_rangeproof = true;
        }
        // witness
        size_t num_items = input->witness ? input->witness->num_items : 0;
        for (uint32_t j = 0; j < num_items; ++j) {
          const struct wally_tx_witness_item *stack;
          stack = input->witness->items + j;
          need_size += stack->witness_len + 10;
          has_txin_witness = true;
        }
        // pegin_witness
        num_items = input->pegin_witness ? input->pegin_witness->num_items : 0;
        for (uint32_t j = 0; j < num_items; ++j) {
          const struct wally_tx_witness_item *stack;
          stack = input->pegin_witness->items + j;
          need_size += stack->witness_len + 10;
          has_txin_witness = true;
        }
        need_size += 10;
      }
      for (uint32_t i = 0; i < tx_pointer->num_outputs; ++i) {
        const struct wally_tx_output *output = tx_pointer->outputs + i;
        if (output->surjectionproof) {
          need_size += output->surjectionproof_len + 10;
          has_txout_witness = true;
        }
        if (output->rangeproof) {
          need_size += output->rangeproof_len + 10;
          has_txout_witness = true;
        }
        need_size += 10;
      }
      if (need_size > buffer.size()) {
        buffer.resize(need_size);
        info(CFD_LOG_SOURCE, "buffer.resize[{}]", need_size);
      }

      uint8_t *address_pointer = buffer.data();
      memcpy(
          address_pointer, &tx_pointer->version, sizeof(tx_pointer->version));
      address_pointer += sizeof(tx_pointer->version);
      uint8_t witness_flag = 0;
      if ((tx_pointer->version & kTransactionVersionNoWitness) == 0) {
        if (has_txin_witness || has_txin_rangeproof || has_txout_witness) {
          is_witness = true;
          witness_flag = 1;
        }
      }
      *address_pointer = witness_flag;
      ++address_pointer;

      // txin
      address_pointer =
          CopyVariableInt(tx_pointer->num_inputs, address_pointer);
      for (uint32_t i = 0; i < tx_pointer->num_inputs; ++i) {
        const struct wally_tx_input *input = tx_pointer->inputs + i;
        memcpy(address_pointer, input->txhash, sizeof(input->txhash));
        address_pointer += sizeof(input->txhash);
        // pegin, issur時には別途対応が必要
        memcpy(address_pointer, &input->index, sizeof(input->index));
        address_pointer += sizeof(input->index);
        address_pointer = CopyVariableBuffer(
            input->script, input->script_len, address_pointer);
        memcpy(address_pointer, &input->sequence, sizeof(input->sequence));
        address_pointer += sizeof(input->sequence);
        if (has_txin_rangeproof) {
          // blinding_nonce
          memcpy(
              address_pointer, &input->blinding_nonce,
              sizeof(input->blinding_nonce));
          address_pointer += sizeof(input->blinding_nonce);
          // entropy
          memcpy(address_pointer, &input->entropy, sizeof(input->entropy));
          address_pointer += sizeof(input->entropy);
          // issuance amount
          address_pointer = CopyConfidentialCommitment(
              input->issuance_amount, input->issuance_amount_len,
              kConfidentialValueSize, address_pointer);
          // inflation keys
          address_pointer = CopyConfidentialCommitment(
              input->inflation_keys, input->inflation_keys_len,
              kConfidentialValueSize, address_pointer);
        }
      }

      // txout
      address_pointer =
          CopyVariableInt(tx_pointer->num_outputs, address_pointer);
      for (uint32_t i = 0; i < tx_pointer->num_outputs; ++i) {
        const struct wally_tx_output *output = tx_pointer->outputs + i;
        // asset (fix size)
        address_pointer = CopyConfidentialCommitment(
            output->asset, output->asset_len, kConfidentialDataSize,
            address_pointer);
        // value (fix size)
        address_pointer = CopyConfidentialCommitment(
            output->value, output->value_len, kConfidentialValueSize,
            address_pointer);
        // nonce (fix size)
        address_pointer = CopyConfidentialCommitment(
            output->nonce, output->nonce_len, kConfidentialDataSize,
            address_pointer);
        // script
        address_pointer = CopyVariableBuffer(
            output->script, output->script_len, address_pointer);
      }

      // locktime
      memcpy(
          address_pointer, &tx_pointer->locktime,
          sizeof(tx_pointer->locktime));
      address_pointer += sizeof(tx_pointer->locktime);

      // witness
      if (is_witness) {
        for (uint32_t i = 0; i < tx_pointer->num_inputs; ++i) {
          const struct wally_tx_input *input = tx_pointer->inputs + i;
          // issuance amount range proof
          address_pointer = CopyVariableBuffer(
              input->issuance_amount_rangeproof,
              input->issuance_amount_rangeproof_len, address_pointer);
          // inflation keys range proof
          address_pointer = CopyVariableBuffer(
              input->inflation_keys_rangeproof,
              input->inflation_keys_rangeproof_len, address_pointer);
          // witness
          size_t num_items = input->witness ? input->witness->num_items : 0;
          address_pointer = CopyVariableInt(num_items, address_pointer);
          for (uint32_t j = 0; j < num_items; ++j) {
            const struct wally_tx_witness_item *stack;
            stack = input->witness->items + j;
            address_pointer = CopyVariableBuffer(
                stack->witness, stack->witness_len, address_pointer);
          }
          // pegin_witness
          num_items = 0;
          if (input->pegin_witness)
            num_items = input->pegin_witness->num_items;
          address_pointer = CopyVariableInt(num_items, address_pointer);
          for (uint32_t j = 0; j < num_items; ++j) {
            const struct wally_tx_witness_item *stack;
            stack = input->pegin_witness->items + j;
            address_pointer = CopyVariableBuffer(
                stack->witness, stack->witness_len, address_pointer);
          }
        }

        for (uint32_t i = 0; i < tx_pointer->num_outputs; ++i) {
          const struct wally_tx_output *output = tx_pointer->outputs + i;
          // surjection proof
          address_pointer = CopyVariableBuffer(
              output->surjectionproof, output->surjectionproof_len,
              address_pointer);
          // range proof
          address_pointer = CopyVariableBuffer(
              output->rangeproof, output->rangeproof_len, address_pointer);
        }
      }

      unsigned char *start_address = buffer.data();
      size = address_pointer - start_address;
      if (buffer.size() > size) {
        buffer.resize(size);
        info(CFD_LOG_SOURCE, "set buffer size[{}]", size);
      }
    } else {
      // 例外エラー
      warn(
          CFD_LOG_SOURCE, "wally_tx_to_bytes NG[{}]. in/out={}/{}", ret,
          tx_pointer->num_inputs, tx_pointer->num_outputs);
      throw CfdException(kCfdIllegalStateError, "tx hex convert error.");
    }
  } else if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_to_bytes NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "tx hex convert error.");
  }

  return ByteData(buffer);
}

uint32_t ConfidentialTransaction::GetWallyFlag() const {
  return WALLY_TX_FLAG_USE_WITNESS | WALLY_TX_FLAG_USE_ELEMENTS;
}

ByteData ConfidentialTransaction::GetBitcoinTransaction(
    const ByteData &bitcoin_tx_data, bool is_remove_witness) {
  const std::vector<uint8_t> &byte_data = bitcoin_tx_data.GetBytes();
  struct wally_tx *tx_pointer = NULL;
  int ret =
      wally_tx_from_bytes(byte_data.data(), byte_data.size(), 0, &tx_pointer);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_from_bytes NG[{}] ", ret);
    throw CfdException(kCfdIllegalArgumentError, "transaction data invalid.");
  }

  ByteData result;
  try {
    uint32_t flag = (is_remove_witness) ? 0 : WALLY_TX_FLAG_USE_WITNESS;
    size_t size = 0;
    size_t vsize = 0;
    ret = wally_tx_get_length(tx_pointer, flag, &size);
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_tx_get_length NG[{}].", ret);
      throw CfdException(kCfdIllegalStateError, "bitcoin tx convert error.");
    }
    if (flag != 0) {
      ret = wally_tx_get_vsize(tx_pointer, &vsize);
      if (ret != WALLY_OK) {
        warn(CFD_LOG_SOURCE, "wally_tx_get_vsize NG[{}].", ret);
        throw CfdException(kCfdIllegalStateError, "bitcoin tx convert error.");
      }
      if (size == vsize) {
        flag = 0;
      }
    }
    std::vector<uint8_t> buffer(size);
    ret = wally_tx_to_bytes(
        tx_pointer, flag, buffer.data(), buffer.size(), &size);
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_tx_to_bytes NG[{}].", ret);
      throw CfdException(kCfdIllegalStateError, "bitcoin tx convert error.");
    }
    if (buffer.size() != size) {
      buffer.resize(size);
    }
    result = ByteData(buffer);
    wally_tx_free(tx_pointer);
    tx_pointer = nullptr;
  } catch (const CfdException &cfd_except) {
    wally_tx_free(tx_pointer);
    throw cfd_except;
  } catch (...) {
    wally_tx_free(tx_pointer);
    warn(CFD_LOG_SOURCE, "unknown exception.");
    throw CfdException(kCfdIllegalStateError, "bitcoin tx convert error.");
  }
  return result;
}

void ConfidentialTransaction::CheckTxInIndex(
    uint32_t index, int line, const char *caller) const {
  if (vin_.size() <= index) {
    spdlog::source_loc location = {CFD_LOG_FILE, line, caller};
    warn(location, "vin[{}] out_of_range.", index);
    throw CfdException(kCfdOutOfRangeError, "vin out_of_range error.");
  }
}

void ConfidentialTransaction::CheckTxOutIndex(
    uint32_t index, int line, const char *caller) const {
  if (vout_.size() <= index) {
    spdlog::source_loc location = {CFD_LOG_FILE, line, caller};
    warn(location, "vout[{}] out_of_range.", index);
    throw CfdException(kCfdOutOfRangeError, "vin out_of_range error.");
  }
}

}  // namespace cfdcore

#endif  // CFD_DISABLE_ELEMENTS
