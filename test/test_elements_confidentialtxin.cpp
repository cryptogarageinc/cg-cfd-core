#ifndef CFD_DISABLE_ELEMENTS
#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_elements_transaction.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_coin.h"
#include "cfdcore/cfdcore_util.h"

using cfdcore::CfdException;
using cfdcore::ByteData;
using cfdcore::ByteData256;
using cfdcore::BlindFactor;
using cfdcore::Txid;
using cfdcore::Script;
using cfdcore::ScriptWitness;
using cfdcore::ConfidentialValue;
using cfdcore::ConfidentialAssetId;
using cfdcore::ConfidentialNonce;
using cfdcore::ConfidentialTxIn;
using cfdcore::ConfidentialTxInReference;

static const Txid exp_txid(
    "56eb4a177459bae6d310cd117dde5ff86e0a6572d44dcf5e25e611435fff9b31");
static const uint32_t exp_index = 2;
static const uint32_t exp_sequence = 0xfffffffe;
static const Script exp_script("0014fd1cd5452a43ca210ba7153d64227dc32acf6dbb");

static const ByteData256 exp_blinding_nonce(
    "6f1a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3");
static const ByteData256 exp_asset_entropy(
    "6f2a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3");
static const ConfidentialValue exp_issuance_amount("000000000000112233");
static const ConfidentialValue exp_inflation_keys("000000000000112244");
static const ByteData exp_issuance_amount_rangeproof("0011001100110011");
static const ByteData exp_inflation_keys_rangeproof("0011001100110022");

static ScriptWitness GetExpectWitnessStack() {
  ScriptWitness exp_witness_stack;
  exp_witness_stack.AddWitnessStack(ByteData("3044022075282f574650e20c3a87d0d1f67d0bcd8f9319b26d244eb254c0aa5bc0284e8002205bddfd4e2f5e278de5f473804a1d061ed6f9bdbcb65fec9b20402879c5a9980901"));
  exp_witness_stack.AddWitnessStack(ByteData("025c36c65910268ee06421053cb9bab1c849c4bdd467d6e77a89d33ff213adc3ca"));
  return exp_witness_stack;
}

static ScriptWitness GetExpectPeginWitnessStack() {
  ScriptWitness exp_pegin_witness;
  exp_pegin_witness.AddWitnessStack(ByteData("00e1f50500000000"));
  exp_pegin_witness.AddWitnessStack(ByteData("c23bd031406aa9f7ac994f7385cd8d2605adaadf5a473c82557b4586192681d3"));
  exp_pegin_witness.AddWitnessStack(ByteData("06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f"));
  exp_pegin_witness.AddWitnessStack(ByteData("0014e8d28b573816ddfcf98578d7b28543e273f5a72a"));
  exp_pegin_witness.AddWitnessStack(ByteData("02000000014578ddc14da3e19445b6e7b4c61d4af711d29e2703161aa9c11e4e6b0ea08843010000006b483045022100eea27e89c3cf2867393263bece040f34c03e0cddfa93a1a18c0d2e4322a37df7022074273c0ab3836affba53737c83673ca6c0d69bffdf722b4accfd7c0a9b2ea4e60121020bfcdbda850cd250c3995dfdb426dc40a9c8a5b378be2bf39f6b0642a783daf2feffffff02281d2418010000001976a914b56872c7b363bfb3f5af84d071ff282cf2abfe3988ac00e1f5050000000017a9141d4796c6e855ae00acecb0c20f65dd8bbeffb1ec87d1000000"));
  exp_pegin_witness.AddWitnessStack(ByteData("03000030ffba1d575800bf37a1ee1962dee7e153c18bcfc93cd013e7c297d5363b36cc2d63d5c4a9fdc746b9d3f4f62995d611c34ee9740ff2b5193ce458fdac6d173800ec402e5affff7f200500000002000000027ce06590120cf8c2bef7726200f0fa655940cadcf62708d7dc9f8f2a417c890b81af4d4299758e7e7a0daa6e7e3d3ec37f97df4ef2392ae5e6d286fc5e7e01d90105"));
  return exp_pegin_witness;
}

TEST(ConfidentialTxIn, Constractor1) {
  ConfidentialTxIn txin1(exp_txid, exp_index, exp_sequence);
  EXPECT_EQ(txin1.GetVout(), exp_index);
  EXPECT_EQ(txin1.GetSequence(), exp_sequence);
  EXPECT_STREQ(txin1.GetTxid().GetHex().c_str(), exp_txid.GetHex().c_str());

  ConfidentialTxIn txin2(exp_txid, exp_index, exp_sequence, exp_script);
  EXPECT_EQ(txin2.GetVout(), exp_index);
  EXPECT_EQ(txin2.GetSequence(), exp_sequence);
  EXPECT_STREQ(txin2.GetTxid().GetHex().c_str(), exp_txid.GetHex().c_str());
  EXPECT_STREQ(txin2.GetUnlockingScript().GetHex().c_str(),
      exp_script.GetHex().c_str());
}

TEST(ConfidentialTxIn, Constractor2) {
  ScriptWitness exp_witness_stack = GetExpectWitnessStack();
  ScriptWitness exp_pegin_witness = GetExpectPeginWitnessStack();

  ConfidentialTxIn txin3(exp_txid, exp_index, exp_sequence, exp_script,
      exp_witness_stack, exp_blinding_nonce, exp_asset_entropy,
      exp_issuance_amount, exp_inflation_keys, exp_issuance_amount_rangeproof,
      exp_inflation_keys_rangeproof, exp_pegin_witness);
  EXPECT_EQ(txin3.GetVout(), exp_index);
  EXPECT_EQ(txin3.GetSequence(), exp_sequence);
  EXPECT_STREQ(txin3.GetTxid().GetHex().c_str(), exp_txid.GetHex().c_str());
  EXPECT_STREQ(txin3.GetUnlockingScript().GetHex().c_str(),
      exp_script.GetHex().c_str());
  EXPECT_STREQ(txin3.GetBlindingNonce().GetHex().c_str(),
      exp_blinding_nonce.GetHex().c_str());
  EXPECT_STREQ(txin3.GetAssetEntropy().GetHex().c_str(),
      exp_asset_entropy.GetHex().c_str());
  EXPECT_STREQ(txin3.GetIssuanceAmount().GetHex().c_str(),
      exp_issuance_amount.GetHex().c_str());
  EXPECT_STREQ(txin3.GetInflationKeys().GetHex().c_str(),
      exp_inflation_keys.GetHex().c_str());
  EXPECT_STREQ(txin3.GetIssuanceAmountRangeproof().GetHex().c_str(),
      exp_issuance_amount_rangeproof.GetHex().c_str());
  EXPECT_STREQ(txin3.GetInflationKeysRangeproof().GetHex().c_str(),
      exp_inflation_keys_rangeproof.GetHex().c_str());
  EXPECT_EQ(txin3.GetScriptWitnessStackNum(),
      exp_witness_stack.GetWitnessNum());
  const std::vector<ByteData>& test_vector = txin3.GetScriptWitness()
      .GetWitness();
  const std::vector<ByteData>& exp_vector = exp_witness_stack.GetWitness();
  for (size_t idx = 0; idx < test_vector.size(); ++idx) {
    EXPECT_STREQ(test_vector[idx].GetHex().c_str(),
        exp_vector[idx].GetHex().c_str());
  }
  EXPECT_EQ(txin3.GetPeginWitnessStackNum(),
      exp_pegin_witness.GetWitnessNum());
  const std::vector<ByteData>& test_peg_vector = txin3.GetPeginWitness()
      .GetWitness();
  const std::vector<ByteData>& exp_peg_vector = exp_pegin_witness.GetWitness();
  for (size_t idx = 0; idx < exp_peg_vector.size(); ++idx) {
    EXPECT_STREQ(test_peg_vector[idx].GetHex().c_str(),
        exp_peg_vector[idx].GetHex().c_str());
  }
}

TEST(ConfidentialTxIn, SetIssuance) {
  ConfidentialTxIn txin(exp_txid, exp_index, exp_sequence, exp_script);
  EXPECT_NO_THROW((txin.SetIssuance(exp_blinding_nonce, exp_asset_entropy,
      exp_issuance_amount, exp_inflation_keys, exp_issuance_amount_rangeproof,
      exp_inflation_keys_rangeproof)));

  EXPECT_EQ(txin.GetVout(), exp_index);
  EXPECT_EQ(txin.GetSequence(), exp_sequence);
  EXPECT_STREQ(txin.GetTxid().GetHex().c_str(), exp_txid.GetHex().c_str());
  EXPECT_STREQ(txin.GetUnlockingScript().GetHex().c_str(),
      exp_script.GetHex().c_str());
  EXPECT_STREQ(txin.GetBlindingNonce().GetHex().c_str(),
      exp_blinding_nonce.GetHex().c_str());
  EXPECT_STREQ(txin.GetAssetEntropy().GetHex().c_str(),
      exp_asset_entropy.GetHex().c_str());
  EXPECT_STREQ(txin.GetIssuanceAmount().GetHex().c_str(),
      exp_issuance_amount.GetHex().c_str());
  EXPECT_STREQ(txin.GetInflationKeys().GetHex().c_str(),
      exp_inflation_keys.GetHex().c_str());
  EXPECT_STREQ(txin.GetIssuanceAmountRangeproof().GetHex().c_str(),
      exp_issuance_amount_rangeproof.GetHex().c_str());
  EXPECT_STREQ(txin.GetInflationKeysRangeproof().GetHex().c_str(),
      exp_inflation_keys_rangeproof.GetHex().c_str());
}

TEST(ConfidentialTxIn, AddPeginWitnessStack) {
  ScriptWitness exp_witness_stack = GetExpectWitnessStack();
  ScriptWitness exp_pegin_witness = GetExpectPeginWitnessStack();
  const ByteData exp_data("1234567890");
  uint32_t target_index = 6;

  ConfidentialTxIn txin(exp_txid, exp_index, exp_sequence, exp_script,
      exp_witness_stack, exp_blinding_nonce, exp_asset_entropy,
      exp_issuance_amount, exp_inflation_keys, exp_issuance_amount_rangeproof,
      exp_inflation_keys_rangeproof, exp_pegin_witness);
  EXPECT_NO_THROW((txin.AddPeginWitnessStack(exp_data)));
  EXPECT_EQ(txin.GetPeginWitnessStackNum(),
      exp_pegin_witness.GetWitnessNum() + 1);
  const std::vector<ByteData>& test_peg_vector = txin.GetPeginWitness()
      .GetWitness();
  const std::vector<ByteData>& exp_peg_vector = exp_pegin_witness.GetWitness();
  for (size_t idx = 0; idx < exp_peg_vector.size(); ++idx) {
    EXPECT_STREQ(test_peg_vector[idx].GetHex().c_str(),
        exp_peg_vector[idx].GetHex().c_str());
  }
  EXPECT_STREQ(test_peg_vector[target_index].GetHex().c_str(),
      exp_data.GetHex().c_str());
}

TEST(ConfidentialTxIn, SetPeginWitnessStack) {
  ScriptWitness exp_witness_stack = GetExpectWitnessStack();
  ScriptWitness exp_pegin_witness = GetExpectPeginWitnessStack();
  const ByteData exp_data("1234567890");
  uint32_t target_index = 1;

  ConfidentialTxIn txin(exp_txid, exp_index, exp_sequence, exp_script,
      exp_witness_stack, exp_blinding_nonce, exp_asset_entropy,
      exp_issuance_amount, exp_inflation_keys, exp_issuance_amount_rangeproof,
      exp_inflation_keys_rangeproof, exp_pegin_witness);
  EXPECT_NO_THROW((txin.SetPeginWitnessStack(target_index, exp_data)));
  const std::vector<ByteData>& test_peg_vector = txin.GetPeginWitness()
      .GetWitness();
  EXPECT_STREQ(test_peg_vector[target_index].GetHex().c_str(),
      exp_data.GetHex().c_str());

  // fail case
  EXPECT_THROW((txin.SetPeginWitnessStack(9, exp_data)), CfdException);
}

TEST(ConfidentialTxIn, RemovePeginWitnessStackAll) {
  ScriptWitness exp_witness_stack = GetExpectWitnessStack();
  ScriptWitness exp_pegin_witness = GetExpectPeginWitnessStack();

  ConfidentialTxIn txin(exp_txid, exp_index, exp_sequence, exp_script,
      exp_witness_stack, exp_blinding_nonce, exp_asset_entropy,
      exp_issuance_amount, exp_inflation_keys, exp_issuance_amount_rangeproof,
      exp_inflation_keys_rangeproof, exp_pegin_witness);
  EXPECT_NO_THROW((txin.RemovePeginWitnessStackAll()));
  EXPECT_EQ(txin.GetPeginWitnessStackNum(), 0);
}

TEST(ConfidentialTxInReference, Constractor) {
  ScriptWitness exp_witness_stack = GetExpectWitnessStack();
  ScriptWitness exp_pegin_witness = GetExpectPeginWitnessStack();

  ConfidentialTxIn txin(exp_txid, exp_index, exp_sequence, exp_script,
      exp_witness_stack, exp_blinding_nonce, exp_asset_entropy,
      exp_issuance_amount, exp_inflation_keys, exp_issuance_amount_rangeproof,
      exp_inflation_keys_rangeproof, exp_pegin_witness);
  ConfidentialTxInReference txinref(txin);
  EXPECT_EQ(txinref.GetVout(), exp_index);
  EXPECT_EQ(txinref.GetSequence(), exp_sequence);
  EXPECT_STREQ(txinref.GetTxid().GetHex().c_str(), exp_txid.GetHex().c_str());
  EXPECT_STREQ(txinref.GetUnlockingScript().GetHex().c_str(),
      exp_script.GetHex().c_str());
  EXPECT_STREQ(txinref.GetBlindingNonce().GetHex().c_str(),
      exp_blinding_nonce.GetHex().c_str());
  EXPECT_STREQ(txinref.GetAssetEntropy().GetHex().c_str(),
      exp_asset_entropy.GetHex().c_str());
  EXPECT_STREQ(txinref.GetIssuanceAmount().GetHex().c_str(),
      exp_issuance_amount.GetHex().c_str());
  EXPECT_STREQ(txinref.GetInflationKeys().GetHex().c_str(),
      exp_inflation_keys.GetHex().c_str());
  EXPECT_STREQ(txinref.GetIssuanceAmountRangeproof().GetHex().c_str(),
      exp_issuance_amount_rangeproof.GetHex().c_str());
  EXPECT_STREQ(txinref.GetInflationKeysRangeproof().GetHex().c_str(),
      exp_inflation_keys_rangeproof.GetHex().c_str());
  EXPECT_EQ(txinref.GetScriptWitnessStackNum(),
      exp_witness_stack.GetWitnessNum());
  const std::vector<ByteData>& test_vector = txinref.GetScriptWitness()
      .GetWitness();
  const std::vector<ByteData>& exp_vector = exp_witness_stack.GetWitness();
  for (size_t idx = 0; idx < test_vector.size(); ++idx) {
    EXPECT_STREQ(test_vector[idx].GetHex().c_str(),
        exp_vector[idx].GetHex().c_str());
  }
  EXPECT_EQ(txinref.GetPeginWitnessStackNum(),
      exp_pegin_witness.GetWitnessNum());
  const std::vector<ByteData>& test_peg_vector = txinref.GetPeginWitness()
      .GetWitness();
  const std::vector<ByteData>& exp_peg_vector = exp_pegin_witness.GetWitness();
  for (size_t idx = 0; idx < test_peg_vector.size(); ++idx) {
    EXPECT_STREQ(test_peg_vector[idx].GetHex().c_str(),
        exp_peg_vector[idx].GetHex().c_str());
  }
}

#endif  // CFD_DISABLE_ELEMENTS
