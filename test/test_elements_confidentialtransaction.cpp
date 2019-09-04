#ifndef CFD_DISABLE_ELEMENTS
#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_elements_transaction.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_util.h"

using cfdcore::CfdException;
using cfdcore::ByteData;
using cfdcore::ByteData160;
using cfdcore::ByteData256;
using cfdcore::BlindFactor;
using cfdcore::Amount;
using cfdcore::Txid;
using cfdcore::Pubkey;
using cfdcore::Privkey;
using cfdcore::SigHashType;
using cfdcore::SigHashAlgorithm;
using cfdcore::HashUtil;
using cfdcore::Script;
using cfdcore::ScriptOperator;
using cfdcore::ScriptBuilder;
using cfdcore::ScriptWitness;
using cfdcore::ElementsUnblindedAddress;
using cfdcore::ConfidentialValue;
using cfdcore::ConfidentialAssetId;
using cfdcore::ConfidentialNonce;
using cfdcore::ConfidentialTxIn;
using cfdcore::ConfidentialTxInReference;
using cfdcore::ConfidentialTxOut;
using cfdcore::ConfidentialTxOutReference;
using cfdcore::ConfidentialTransaction;
using cfdcore::IssuanceParameter;

static const std::string exp_tx_hex =
    "020000000001319bff5f4311e6255ecf4dd472650a6ef85fde7d11cd10d3e6ba5974174aeb560100000000ffffffff0201f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f0100000bd2cc1584c002deb65cc52301e1622f482a2f588b9800d2b8386ffabf74d6b2d73d17503a2f921976a9146a98a3f2935718df72518c00768ec67c589e0b2888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f0100000000004c4b40000000000000";
static const std::string exp_tx_empty_hex = "0200000000000000000000";

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

static const Script exp_locking_script(
    "76a9146a98a3f2935718df72518c00768ec67c589e0b2888ac");
static const std::string exp_assetid =
    "6f1a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3";

static ScriptWitness GetExpectWitnessStack() {
  ScriptWitness exp_witness_stack;
  exp_witness_stack.AddWitnessStack(
      ByteData(
          "3044022075282f574650e20c3a87d0d1f67d0bcd8f9319b26d244eb254c0aa5bc0284e8002205bddfd4e2f5e278de5f473804a1d061ed6f9bdbcb65fec9b20402879c5a9980901"));
  exp_witness_stack.AddWitnessStack(
      ByteData(
          "025c36c65910268ee06421053cb9bab1c849c4bdd467d6e77a89d33ff213adc3ca"));
  return exp_witness_stack;
}

static ScriptWitness GetExpectPeginWitnessStack() {
  ScriptWitness exp_pegin_witness;
  exp_pegin_witness.AddWitnessStack(ByteData("00e1f50500000000"));
  exp_pegin_witness.AddWitnessStack(
      ByteData(
          "c23bd031406aa9f7ac994f7385cd8d2605adaadf5a473c82557b4586192681d3"));
  exp_pegin_witness.AddWitnessStack(
      ByteData(
          "06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f"));
  exp_pegin_witness.AddWitnessStack(
      ByteData("0014e8d28b573816ddfcf98578d7b28543e273f5a72a"));
  exp_pegin_witness.AddWitnessStack(
      ByteData(
          "02000000014578ddc14da3e19445b6e7b4c61d4af711d29e2703161aa9c11e4e6b0ea08843010000006b483045022100eea27e89c3cf2867393263bece040f34c03e0cddfa93a1a18c0d2e4322a37df7022074273c0ab3836affba53737c83673ca6c0d69bffdf722b4accfd7c0a9b2ea4e60121020bfcdbda850cd250c3995dfdb426dc40a9c8a5b378be2bf39f6b0642a783daf2feffffff02281d2418010000001976a914b56872c7b363bfb3f5af84d071ff282cf2abfe3988ac00e1f5050000000017a9141d4796c6e855ae00acecb0c20f65dd8bbeffb1ec87d1000000"));
  exp_pegin_witness.AddWitnessStack(
      ByteData(
          "03000030ffba1d575800bf37a1ee1962dee7e153c18bcfc93cd013e7c297d5363b36cc2d63d5c4a9fdc746b9d3f4f62995d611c34ee9740ff2b5193ce458fdac6d173800ec402e5affff7f200500000002000000027ce06590120cf8c2bef7726200f0fa655940cadcf62708d7dc9f8f2a417c890b81af4d4299758e7e7a0daa6e7e3d3ec37f97df4ef2392ae5e6d286fc5e7e01d90105"));
  return exp_pegin_witness;
}

TEST(ConfidentialTransaction, GetBitcoinTransactionTest) {
  // no witness
  ByteData no_witness_data(
      "010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000023220020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000");
  ByteData conv_nowit;
  EXPECT_NO_THROW(
      (conv_nowit = ConfidentialTransaction::GetBitcoinTransaction(
          no_witness_data)));
  EXPECT_STREQ(no_witness_data.GetHex().c_str(), conv_nowit.GetHex().c_str());

  // witness
  ByteData witness_data(
      "02000000000101d0b871d1a1c019d060e46878e6853c16a886fad7a7bdddcd199b1f4975952dcd0000000000ffffffff01b0069a3b0000000016001405dca32c20abe66ec786bc114fd67ad83e70868d024730440220533dda726705cbbae9cfb8e7a6ccbce581f3db9bb58ab923e71ae8de0e309280022004614f3bf2b7b11bbd02b382d206b9e0b7cba67c682dd88481f712cca2cc3f9d0121036b67e1bd3bd3efbc37fdc738ab159a4aa527057eae12a0c4b07d3132580dcdfd00000000");
  ByteData conv_wit;
  EXPECT_NO_THROW(
      (conv_wit = ConfidentialTransaction::GetBitcoinTransaction(witness_data,
                                                                 false)));
  EXPECT_STREQ(witness_data.GetHex().c_str(), conv_wit.GetHex().c_str());

  ByteData conv_rmwit;
  EXPECT_NO_THROW(
      (conv_rmwit = ConfidentialTransaction::GetBitcoinTransaction(witness_data,
                                                                   true)));
  EXPECT_STREQ(
      "0200000001d0b871d1a1c019d060e46878e6853c16a886fad7a7bdddcd199b1f4975952dcd0000000000ffffffff01b0069a3b0000000016001405dca32c20abe66ec786bc114fd67ad83e70868d00000000",
      conv_rmwit.GetHex().c_str());
}

TEST(ConfidentialTransaction, ConstructorTest) {
  uint32_t lock_time = 0;
  ConfidentialTransaction tx_null;
  EXPECT_STREQ(tx_null.GetHex().c_str(), "0200000000000000000000");

  const ConfidentialTransaction tx_empty(2, lock_time);
  EXPECT_STREQ(tx_empty.GetHex().c_str(), "0200000000000000000000");

  ConfidentialTransaction tx(exp_tx_hex);
  EXPECT_STREQ(tx.GetHex().c_str(), exp_tx_hex.c_str());

  EXPECT_NO_THROW((tx_null = tx));
  EXPECT_STREQ(
      tx_null.GetHex().c_str(),
      "020000000001319bff5f4311e6255ecf4dd472650a6ef85fde7d11cd10d3e6ba5974174aeb560100000000ffffffff0201f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f0100000bd2cc1584c002deb65cc52301e1622f482a2f588b9800d2b8386ffabf74d6b2d73d17503a2f921976a9146a98a3f2935718df72518c00768ec67c589e0b2888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f0100000000004c4b40000000000000");
  EXPECT_NO_THROW((tx = ConfidentialTransaction(tx_empty)));
  EXPECT_STREQ(tx.GetHex().c_str(), "0200000000000000000000");

  // illegal transaction
  //const std::string txout_empty = "";
  //EXPECT_NO_THROW((tx = ConfidentialTransaction(txout_empty)));
  //EXPECT_STREQ(tx.GetHex().c_str(), txout_empty.c_str());

  const std::string txin_empty =
      "020000000100020b6c4dbd4a5ede07d381fc4f0f69c4166d59da5557c627d8361c13dc28103bbeeb084922fb4232da7c9d12c88dcbf329175771bf4333bbbea23343e86023490253b4025cf9778d533b213387a1e8b68d2acea450ac5ce68c9a550ffefb448a98cec1511976a9146a98a3f2935718df72518c00768ec67c589e0b2888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f0100000000004c4b4000000000000043010001df8972dc12c7f680d8e1b95222c6e59a0e888d7b3eeea43f7ea41da798443f4034bd02edf6cc9d62cb17d119455f8448cc1e69b6000a6e981380311629ec2475fdcd0d602b000000000000000132af0c6c272999d7ea18001bcfd47a844970bd56b678f59302420fb180ccf25296953926cae9fd36f8ce6e169ab2e18e06175df111db4b55d6954cb8478dce9d847d6f1a57f8dd1c48194caab6d939a76843d154f7021b5b86230edf86366043c5d131a3a845c7470dfde074d7c453100975c0962af42d88da3d6364a7cf4a6123cb4f0e9f0d3d9a7eb96896e52d53bda4cabdd5225056855afcaa2464afc8c8d582d77dc1764b1b238b38e0550400282b33b3e3fbc15473a700aa7955f7f2f0a65ee384783dd173423c6637588a351df2ae60a7ed15e7740f4c77496f04a831e7b66755a354605c0c2eb1d5646483116e5155c384febacc2849b74c1c8d7163da96e5d510ff044ede7ec3a85f2dc32fd5991993ace8a0266726e6c2acca04667acd2b9cd8bf83e87927e06d608f6b22a90806d98e49fff37dfc018123b7b81a85dbfdc8cfb5ccbfa4cc987bf15bd1c927a0665d83cfd2ab9840066c638ace43a6818f7977d896e3612d491bad635c724bf453d5c397dc2b1dc3ed5d64fd9845f45f7af923cabdb32dc946f7c73f927644a141799838a759c918eccd7561144d825246fb84d4355a955c641fd339c0f79d3eb0a4754cff203897b124d1f27b3590acb97b934cfce48e9ce84d9d4078df9f1bd85ac138bc232026ec901e1e8873466d0cea38e1b4ea2c8e923bd301f59769cdc5c61a4b831bea0fb84ff9454a7e4f8f71d699d6927937c257a3c0ea29f9edf1e1fc2a1f22e6adacd711571fc55d548169a6440d83070c9c57b4954666d17fd1d914915e25fada803efb59f38748c77422fc979279f79d5d76a80421e7330989e873d1e5226273f0a4428595fd10f7e2449a216a32903e542fdf7313cc002c74caa676db4b4137d26b1e1a2789e45922556d0ddf0adc0ff15875900f7708a526ee7c4b226b1643d61f3d62de8a6921d4e4000a4c1f65e2507f97300bf18fbb4cef8ecb6add5b01b0c47fd52fd5f4811f1a04b5fcd2a0165cd4d9d9fafdfefca998f796f207d521ed338d2a0aae0c8c41eb51f385071ba2f8eced53f91673e7d756cee0cb9a4ac6335c389c2e138d696508fb9eaf90bbc4f50e9b091e87b1192b64ed0d61cdeaef8b7084c912388aa9c19f514a27597d88f966944298fc9006ae4236cb7d9f3eea7f48fa7b51826b74eaf67bd790a8c8cc3bf9a74db88341f634522b0ac035e016ba9a9e94d262a9899c41f20998f3523f8714e4ccf6b032122bfff0b0bd0a0829888a3d600ec6ba9b20d66ea0ed650e346bd74f590bc83ffc1c02f2091433cdb531c0ba9ac2f91dc0bd30988b11068dd976702544d6fa48235f974aca9b54b38cc8fd789d0f47b48bc9acae3ef585576c58eb846140aa4d703cd380b33ff06b34710871115634ff50c58807d2ed5461e7574775cd51667cd729d4d72f557db3e98d2816b02efb74ca52fb3cd9b15e792f8b33b14370723bbc454eeb70aa66b6d2f104d8519002eb335c9416bad7641dafffe4debec24ad435b9746d63dd2d76bbcaf415e90cfb51f3eddba9a649fb8462bd3627d261625fc95f83cb765f31ae8520129ca2c470b06ac7e5b41f023ad06f25ff0f7cbf9dad137010eb376e0cc3f99cbc716953e863364cd80d97b25988a9510dc617666d7a13da224364ebea7ca5ac03975752a979a21c73861b483165bd5bf4d2d3b402e43da34d58d9131e2207a8454666ac9d55eba79a2267ab5e731c1ce73f59782f5187a5e2f198598f0d86f18303177789830bc74d59167804f030a772753cf134932c880b7074ca7fa001a94f3c540e37e0e72d025106116b6df49fc24fe47200676025e0b45d594ac45c99ac3d481091ec7c4c218d1ad19e00a300be998f870f6252132d62820f0664afa88726b6f327da0c017bf6a9b34f152107524cee9140280acd704a0066cb5faa4e31ebbed5cea9497c573ac49ce32d99347b61f171d8bb431c7f25358e4da4213ea08886bf4691b060b2d2738ecabc2dc8459ebf64bc12d42105335d5e8bfe2bf7fd91db941c0921cd4bee04a3942b2dad6609a9c762e8ea9e28aeaa85758d0c8336da4c0f988e630e30522793e51a773bf509c761b347e98faf822e40aa62156364fb31153eb17d0a1b04792a9535169871378d301a525c8726d984c18bc9a83edf8a24997c20e1613d4144f07506e0f7fd97cee78b469eacfd0a6dcf5157b070a2d9ade2c3e3fd88413adc5e408bcdc75d8093a7aa12a08ea15dd57535073717ed3a1c2073703febca53c3fd048c992dfdeae58d7a91bd86cb30b4de40e4fccaca42db652d979225de33b17be881c95d65883a818f71118c4ae0f1d9d5044f729a2d71aacba8352b4b4ce4ec1b32f84b6eb899591ca0e15d8f6ba328fa0fb54a59445ddf934b55747d71795cc5f8ef9f2f020c9dbc5d3d668b0adb252d5dda38d93750a2d010fea412e32a8854ff464e945bc29ea8ec47f424928cebb920f7c159a5347fce9e034f4d50d680308f9ff6f93b88638f533a3728ddb715829e228c5269c8df3a381e1dc6605ed5a922d48532b6537fcfda1962a1eb4097321266826f10256178b98de34fda9327b379b38519d08a6a5dada265fa038772b706a0f65faf257c7d0d28fb7c2cc98203ad16b833a5dfb37601304c7752d959e2894584528860542b197d75ed7e7e2f412db8a3308f99e34a873e6f4ce21473ecd77d936faf07d1bd5e7c61c6bdc448ab7cb5a2811908ddfd39f9026dbaf67ad4ad12c59377fc0aedec2d6f21e2b3097753fec81ab749444b14c1e22b72fe89d92347e8be6ad9d966cacadff45f6ff517ea8c8be6df77acb4561ba87ee0eddd61f230ef177b84bc702fd0f882b19d5662517ce6f75432464eb9801f14b28a195ab1367282ed807665e8fa866751d32313e89bc30bb7bbeaba6edf78434b42eed146507bb594f2fac22bdfddb1b2dee48e4de07f56701f2f2821075b91ea3dfd5ac2a8e62db57d77d77afd1b55815f3d6978157f307e823f12991a222764997fd0e52f4788994b2649f9de558131d9145fcde4461f4a1d545cd8b385feebec31b43aebcaf40280b2de6101c350da43a97d72e9821e38e648a89363fe8ce4a7a5de1c226390943926e812d204ee22758bed6712d0a47f24ddbd1ee7080ea0e362252506852e3793ad00ec4dad89e210b240cff3132eb1e3834e1dadd56cef093786858c2ac8b55e2871e76e37c07ed23bbd3933c515a7a5b68a9c15e7acdf9deddeeadc98a0f5960e6ba76ccbf391884ceee470b3bbedc9e3fed2f277d9123bdd5435a5ba2522b984ea81eba2deb390d6e00f7acd7512d53c29014482976124593ecb13fd0630b08ae0005bb71eb56649ec8403f67942c17a024764f0dbb8dd4d463ce8ee6bb203fd8335f4940d0d46cd33e82ae87cc46921075a21ee17ad07e2e03c8fbd13b47e3b0018aa2bb77dacfee2ee66a807d10f1923ab673bcc92ecdf453910acecaaa471188d69ada006ae7de5cee5e48e1f64beb4763a945bd95aabeb3057b0a41ad544417d40fe8c915ac6f057fa5df28d056a1f4ca18a62c6d35eafbd766f0ad1d72c86b2305d6e3de0cffb40878a0cc1a1e4bf27d14197ff77516b56b657be3264559bca3654c95bfe7673a3c6dd831d088f0e758470ee69ca6f526938675fce01309f6377121c34429ca496bb89e4d091249dc7a2f5da35207ad7385c8f9d3a644ada38c3faabc0fbbc6a01021f612ef76f2e53ded390c36affa56d1365aeaaeb85469ce4d3619037196818e87e867532b1c417f19afe4795c5389803c30a064f42cfe68fbfb518f13bf84fc4f77c9d32df00818bcb831684a6149963c4851a3c7675a67f0111634abb3ed5d2995f4ff1cce9388e72e2be2e36efa28f29037a181ba09c2d30970024e9ca817d5c230a381d0402db6adaeb03375367eaad425b147b86211807b7ed68245ddc44bdbc32c818fad968e036fad46ca3d8c2a5b956c0228b61e1f66c0fbfd232e29fefbb51f2c68a7db0c3dd429db1a94277607c8323c288e596d53aec34c78c6db00370342c43354313ec4b012d3797d5ee23f38f91f2ac8c1e8043e4b84503e0c9e3fd0aa1c61d3f2c6e2202efd1f9a147ceaa456fffe841294e6ab1f055e5981217d8595bdf2254085656bf8686bf6972f3269de24e2afd82c159e38b97745c0cb6d5b584135c75ae86feff435d4d2071c5fb9b68e8a7ea4e2b987abe20811e1a99656ce5ff93260b6896812f6359ab5fa7fd6fb4066a158ac63abf39a8e1fa1d47e011ba33806c339078c6212e2c6fe794580bb27069fe70ff48c42e3bb2587bfa49650173d1991920ef8c3cd216f389ff2fb53fccaf88f9a8f1688aa4e2d577dc79ba41603721bdfe86073472d275d28896296c0e30842a85c06a6018b0a8d94bb72eeaba5fe09b0000ff7b29748e52ceb9088ab3224a2e6036932f484348cdf77dd326de421c0066d4b68102db6739347a19736cfe2dfaa90e488d4dc885d969f000f2e17bf9e52f7e870eb054d51ca9c435ed1378ecf8dd2541fc32ac662b588460b553e1820c6b1ca6d067442943a56806a6ea57c95bb013db6c474f049df048d322eaadb6a9fbfdd9f2c25511227787fe63fe4d0a80b1785d5d85c10398550cc2385e9bab225d58babe8268d3659fda6ccfdc23556ec27a924b9dee51b09ba03d1366704d63129f701c7e51cc80278faf69cdd7200f29f53f36094142677ce517e734b3b1bbf831548d2224b4dd0bd32370092f771e730f86dcc27fe80b663e95b51e33c0a303ca456e2ab688e84015ac29d8b782b3d79bdd69ce843af5e547616c4beba83c3b49e7041cbbda0545885864410353e581c657dd629646f43d4485d712cfaaf29ab15a023e6082e9b6ab21429fed74425d44eb7b00a0c9a5c6211a7041a31130ed92d1a2d385a540d827fe75cab210d8d508d55246a9143bcf24e8cddea3a5881d3814ada09e7685c9aee3caf7ea5855a79b0000";
  EXPECT_NO_THROW((tx = ConfidentialTransaction(txin_empty)));
  EXPECT_STREQ(tx.GetHex().c_str(), txin_empty.c_str());
}

TEST(ConfidentialTransaction, TxInTest) {
  ConfidentialTransaction tx(2, static_cast<uint32_t>(0));
  EXPECT_NO_THROW((tx = ConfidentialTransaction(exp_tx_hex)));
  EXPECT_EQ(tx.GetTxInCount(), 1);
  // GetTxIn
  ConfidentialTxInReference txin_ref;
  EXPECT_THROW((txin_ref = tx.GetTxIn(1)), CfdException);
  EXPECT_NO_THROW((txin_ref = tx.GetTxIn(0)));
  EXPECT_STREQ(
      txin_ref.GetTxid().GetHex().c_str(),
      "56eb4a177459bae6d310cd117dde5ff86e0a6572d44dcf5e25e611435fff9b31");
  EXPECT_EQ(txin_ref.GetVout(), 1);
  EXPECT_EQ(txin_ref.GetSequence(), 0xffffffff);
  EXPECT_STREQ(
      txin_ref.GetBlindingNonce().GetHex().c_str(),
      "0000000000000000000000000000000000000000000000000000000000000000");
  EXPECT_STREQ(
      txin_ref.GetAssetEntropy().GetHex().c_str(),
      "0000000000000000000000000000000000000000000000000000000000000000");
  EXPECT_STREQ(txin_ref.GetIssuanceAmount().GetHex().c_str(), "");
  EXPECT_STREQ(txin_ref.GetInflationKeys().GetHex().c_str(), "");
  EXPECT_STREQ(txin_ref.GetIssuanceAmountRangeproof().GetHex().c_str(), "");
  EXPECT_STREQ(txin_ref.GetInflationKeysRangeproof().GetHex().c_str(), "");

  // GetTxInIndex, AddTxIn
  uint32_t index = 0;
  uint32_t add_index;
  EXPECT_THROW((index = tx.GetTxInIndex(exp_txid, exp_index)), CfdException);

  EXPECT_NO_THROW(
      (add_index = tx.AddTxIn(exp_txid, exp_index, exp_sequence, exp_script)));
  EXPECT_NO_THROW((index = tx.GetTxInIndex(exp_txid, exp_index)));
  EXPECT_EQ(add_index, 1);
  EXPECT_EQ(index, 1);
  EXPECT_EQ(tx.GetTxInCount(), 2);
  // mask check
  EXPECT_NO_THROW((index = tx.GetTxInIndex(exp_txid, exp_index | 0x80000000)));
  EXPECT_EQ(index, 1);

  // GetTxInList
  std::vector<ConfidentialTxInReference> ref_list;
  EXPECT_NO_THROW((ref_list = tx.GetTxInList()));
  EXPECT_EQ(ref_list.size(), 2);
  EXPECT_STREQ(
      ref_list[0].GetTxid().GetHex().c_str(),
      "56eb4a177459bae6d310cd117dde5ff86e0a6572d44dcf5e25e611435fff9b31");
  EXPECT_EQ(ref_list[0].GetVout(), 1);
  EXPECT_EQ(ref_list[0].GetSequence(), 0xffffffff);
  EXPECT_STREQ(ref_list[1].GetTxid().GetHex().c_str(),
               exp_txid.GetHex().c_str());
  EXPECT_EQ(ref_list[1].GetVout(), exp_index);
  EXPECT_EQ(ref_list[1].GetSequence(), exp_sequence);

  // RemoveTxIn
  EXPECT_THROW((tx.RemoveTxIn(5)), CfdException);
  EXPECT_NO_THROW((tx.RemoveTxIn(1)));
  EXPECT_EQ(tx.GetTxInCount(), 1);
}

// coinbase tx

TEST(ConfidentialTransaction, SetIssuance) {
  ConfidentialTransaction tx(exp_tx_hex);
  uint32_t index = 0;
  EXPECT_NO_THROW(
      (index = tx.AddTxIn(exp_txid, exp_index, exp_sequence, exp_script)));

  EXPECT_NO_THROW(
      (tx.SetIssuance(index, exp_blinding_nonce, exp_asset_entropy,
                      exp_issuance_amount, exp_inflation_keys,
                      exp_issuance_amount_rangeproof,
                      exp_inflation_keys_rangeproof)));

  ConfidentialTxInReference txin;
  EXPECT_NO_THROW((txin = tx.GetTxIn(1)));

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

TEST(ConfidentialTransaction, PeginWitnessTest) {
  ScriptWitness exp_pegin_witness = GetExpectPeginWitnessStack();
  const ByteData exp_data("1234567890");
  const ByteData160 exp_data160("1234567890123456789012345678901234567890");
  const ByteData256 exp_data256(
      "1234567890123456789012345678901234567890123456789012345678901234");
  const std::vector<ByteData>& exp_peg_vector = exp_pegin_witness.GetWitness();

  ConfidentialTransaction tx(exp_tx_hex);
  uint32_t index = 0;
  EXPECT_NO_THROW(
      (index = tx.AddTxIn(exp_txid, exp_index, exp_sequence, exp_script)));
  EXPECT_NO_THROW(
      (tx.SetIssuance(index, exp_blinding_nonce, exp_asset_entropy,
                      exp_issuance_amount, exp_inflation_keys,
                      exp_issuance_amount_rangeproof,
                      exp_inflation_keys_rangeproof)));
  EXPECT_EQ(tx.GetPeginWitnessStackNum(index), 0);

  // AddPeginWitness
  ScriptWitness witness;
  for (size_t idx = 0; idx < exp_peg_vector.size(); ++idx) {
    EXPECT_NO_THROW(
        (witness = tx.AddPeginWitnessStack(index, exp_peg_vector[idx])));
  }
  std::vector<ByteData> test_peg_vector = witness.GetWitness();
  for (size_t idx = 0; idx < exp_peg_vector.size(); ++idx) {
    EXPECT_STREQ(test_peg_vector[idx].GetHex().c_str(),
                 exp_peg_vector[idx].GetHex().c_str());
  }
  std::vector<ByteData> tx_peg_vector = tx.GetTxIn(index).GetPeginWitness()
      .GetWitness();
  for (size_t idx = 0; idx < tx_peg_vector.size(); ++idx) {
    EXPECT_STREQ(test_peg_vector[idx].GetHex().c_str(),
                 tx_peg_vector[idx].GetHex().c_str());
  }
  EXPECT_EQ(tx.GetPeginWitnessStackNum(index), exp_peg_vector.size());

  // AddPeginWitness(160,256)
  EXPECT_THROW((witness = tx.AddPeginWitnessStack(index + 5, exp_data160)),
               CfdException);
  EXPECT_NO_THROW((witness = tx.AddPeginWitnessStack(index, exp_data160)));
  EXPECT_NO_THROW((witness = tx.AddPeginWitnessStack(index, exp_data256)));
  test_peg_vector = witness.GetWitness();
  EXPECT_STREQ(test_peg_vector[exp_peg_vector.size()].GetHex().c_str(),
               exp_data160.GetHex().c_str());
  EXPECT_STREQ(test_peg_vector[exp_peg_vector.size() + 1].GetHex().c_str(),
               exp_data256.GetHex().c_str());
  EXPECT_EQ(tx.GetPeginWitnessStackNum(index), exp_peg_vector.size() + 2);

  // SetPeginWitnessStack
  EXPECT_THROW(
      (witness = tx.SetPeginWitnessStack(index + 5, exp_peg_vector.size(),
                                         exp_data160)),
      CfdException);
  EXPECT_THROW(
      (witness = tx.SetPeginWitnessStack(index, exp_peg_vector.size() + 5,
                                         exp_data160)),
      CfdException);
  EXPECT_NO_THROW((witness = tx.SetPeginWitnessStack(index, 0, exp_data)));
  EXPECT_NO_THROW(
      (witness = tx.SetPeginWitnessStack(index, exp_peg_vector.size(),
                                         exp_data256)));
  EXPECT_NO_THROW(
      (witness = tx.SetPeginWitnessStack(index, exp_peg_vector.size() + 1,
                                         exp_data160)));
  test_peg_vector = witness.GetWitness();
  EXPECT_STREQ(test_peg_vector[0].GetHex().c_str(), exp_data.GetHex().c_str());
  EXPECT_STREQ(test_peg_vector[exp_peg_vector.size()].GetHex().c_str(),
               exp_data256.GetHex().c_str());
  EXPECT_STREQ(test_peg_vector[exp_peg_vector.size() + 1].GetHex().c_str(),
               exp_data160.GetHex().c_str());
  tx_peg_vector = tx.GetTxIn(index).GetPeginWitness().GetWitness();
  for (size_t idx = 0; idx < tx_peg_vector.size(); ++idx) {
    EXPECT_STREQ(test_peg_vector[idx].GetHex().c_str(),
                 tx_peg_vector[idx].GetHex().c_str());
  }

  // RemovePeginWitnessStackAll
  EXPECT_THROW((tx.RemovePeginWitnessStackAll(index + 5)), CfdException);
  EXPECT_NO_THROW((tx.RemovePeginWitnessStackAll(index)));
  EXPECT_EQ(tx.GetPeginWitnessStackNum(index), 0);
}

TEST(ConfidentialTransaction, ScriptWitnessTest) {
  ScriptWitness exp_witness_stack = GetExpectWitnessStack();
  const ByteData exp_data("1234567890");
  const ByteData160 exp_data160("1234567890123456789012345678901234567890");
  const ByteData256 exp_data256(
      "1234567890123456789012345678901234567890123456789012345678901234");
  const std::vector<ByteData>& exp_wit_vector = exp_witness_stack.GetWitness();

  ConfidentialTransaction tx(exp_tx_hex);
  uint32_t index = 0;
  EXPECT_NO_THROW(
      (index = tx.AddTxIn(exp_txid, exp_index, exp_sequence, exp_script)));
  EXPECT_NO_THROW(
      (tx.SetIssuance(index, exp_blinding_nonce, exp_asset_entropy,
                      exp_issuance_amount, exp_inflation_keys,
                      exp_issuance_amount_rangeproof,
                      exp_inflation_keys_rangeproof)));
  EXPECT_EQ(tx.GetScriptWitnessStackNum(index), 0);

  // AddScriptWitnessStack
  ScriptWitness witness;
  for (size_t idx = 0; idx < exp_wit_vector.size(); ++idx) {
    EXPECT_NO_THROW(
        (witness = tx.AddScriptWitnessStack(index, exp_wit_vector[idx])));
  }
  std::vector<ByteData> test_wit_vector = witness.GetWitness();
  for (size_t idx = 0; idx < exp_wit_vector.size(); ++idx) {
    EXPECT_STREQ(test_wit_vector[idx].GetHex().c_str(),
                 exp_wit_vector[idx].GetHex().c_str());
  }
  std::vector<ByteData> tx_wit_vector = tx.GetTxIn(index).GetScriptWitness()
      .GetWitness();
  for (size_t idx = 0; idx < tx_wit_vector.size(); ++idx) {
    EXPECT_STREQ(test_wit_vector[idx].GetHex().c_str(),
                 tx_wit_vector[idx].GetHex().c_str());
  }
  EXPECT_EQ(tx.GetScriptWitnessStackNum(index), exp_wit_vector.size());

  // AddScriptWitnessStack(160,256)
  EXPECT_THROW((witness = tx.AddScriptWitnessStack(index + 5, exp_data160)),
               CfdException);
  EXPECT_NO_THROW((witness = tx.AddScriptWitnessStack(index, exp_data160)));
  EXPECT_NO_THROW((witness = tx.AddScriptWitnessStack(index, exp_data256)));
  test_wit_vector = witness.GetWitness();
  EXPECT_STREQ(test_wit_vector[exp_wit_vector.size()].GetHex().c_str(),
               exp_data160.GetHex().c_str());
  EXPECT_STREQ(test_wit_vector[exp_wit_vector.size() + 1].GetHex().c_str(),
               exp_data256.GetHex().c_str());
  EXPECT_EQ(tx.GetScriptWitnessStackNum(index), exp_wit_vector.size() + 2);

  // SetScriptWitnessStack
  EXPECT_THROW(
      (witness = tx.SetScriptWitnessStack(index + 5, exp_wit_vector.size(),
                                          exp_data160)),
      CfdException);
  EXPECT_THROW(
      (witness = tx.SetScriptWitnessStack(index, exp_wit_vector.size() + 5,
                                          exp_data160)),
      CfdException);
  EXPECT_NO_THROW((witness = tx.SetScriptWitnessStack(index, 0, exp_data)));
  EXPECT_NO_THROW(
      (witness = tx.SetScriptWitnessStack(index, exp_wit_vector.size(),
                                          exp_data256)));
  EXPECT_NO_THROW(
      (witness = tx.SetScriptWitnessStack(index, exp_wit_vector.size() + 1,
                                          exp_data160)));
  test_wit_vector = witness.GetWitness();
  EXPECT_STREQ(test_wit_vector[0].GetHex().c_str(), exp_data.GetHex().c_str());
  EXPECT_STREQ(test_wit_vector[exp_wit_vector.size()].GetHex().c_str(),
               exp_data256.GetHex().c_str());
  EXPECT_STREQ(test_wit_vector[exp_wit_vector.size() + 1].GetHex().c_str(),
               exp_data160.GetHex().c_str());
  tx_wit_vector = tx.GetTxIn(index).GetScriptWitness().GetWitness();
  for (size_t idx = 0; idx < tx_wit_vector.size(); ++idx) {
    EXPECT_STREQ(test_wit_vector[idx].GetHex().c_str(),
                 tx_wit_vector[idx].GetHex().c_str());
  }

  // RemoveScriptWitnessStackAll
  EXPECT_THROW((tx.RemoveScriptWitnessStackAll(index + 5)), CfdException);
  EXPECT_NO_THROW((tx.RemoveScriptWitnessStackAll(index)));
  EXPECT_EQ(tx.GetScriptWitnessStackNum(index), 0);
}

TEST(ConfidentialTransaction, SetUnlockingScriptTest) {
  ConfidentialTransaction tx(exp_tx_hex);
  uint32_t index = 0;
  EXPECT_NO_THROW((index = tx.AddTxIn(exp_txid, exp_index, exp_sequence)));
  EXPECT_EQ(index, 1);

  // SetUnlockingScript
  EXPECT_THROW((tx.SetUnlockingScript(index + 5, exp_script)), CfdException);
  EXPECT_NO_THROW((tx.SetUnlockingScript(index, exp_script)));

  ConfidentialTxInReference txin_ref;
  EXPECT_NO_THROW((txin_ref = tx.GetTxIn(1)));
  EXPECT_STREQ(txin_ref.GetUnlockingScript().GetHex().c_str(),
               exp_script.GetHex().c_str());

  // SetUnlockingScript2
  const ByteData exp_data1("1234567890");
  const ByteData exp_data2("1234567890123456789012345678901234567890");
  std::vector<ByteData> exp_list;
  exp_list.push_back(exp_data1);
  exp_list.push_back(exp_data2);
  EXPECT_THROW((tx.SetUnlockingScript(index + 5, exp_list)), CfdException);
  EXPECT_NO_THROW((tx.SetUnlockingScript(index, exp_list)));

  EXPECT_NO_THROW((txin_ref = tx.GetTxIn(1)));
  EXPECT_STREQ(txin_ref.GetUnlockingScript().GetHex().c_str(),
               "051234567890141234567890123456789012345678901234567890");
}

TEST(ConfidentialTransaction, TxOutTest) {
  ConfidentialTransaction tx(exp_tx_empty_hex);
  uint32_t index = 0;
  EXPECT_NO_THROW((index = tx.AddTxIn(exp_txid, exp_index, exp_sequence)));

  // AddTxOut, GetTxOut, GetTxOutCount
  EXPECT_EQ(tx.GetTxOutCount(), 0);
  int64_t exp_satoshi = 12345678;

  Amount amt = Amount::CreateBySatoshiAmount(exp_satoshi);
  ConfidentialAssetId asset(exp_assetid);
  ConfidentialTxOutReference txout_ref;
  EXPECT_NO_THROW((index = tx.AddTxOut(amt, asset, exp_locking_script)));
  EXPECT_EQ(index, 0);
  EXPECT_EQ(tx.GetTxOutCount(), 1);

  EXPECT_THROW((txout_ref = tx.GetTxOut(index + 5)), CfdException);
  EXPECT_NO_THROW((txout_ref = tx.GetTxOut(index)));
  EXPECT_STREQ(
      txout_ref.GetAsset().GetHex().c_str(),
      "6f1a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3");
  EXPECT_STREQ(txout_ref.GetConfidentialValue().GetHex().c_str(),
               "010000000000bc614e");
  EXPECT_STREQ(txout_ref.GetLockingScript().GetHex().c_str(),
               exp_locking_script.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetNonce().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetSurjectionProof().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetRangeProof().GetHex().c_str(), "");

  // AddTxOut
  ConfidentialNonce nonce(
      "991a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3");
  ByteData surjection_proof("1234567890");
  ByteData range_proof("1234567890123456789012345678901234567890");
  EXPECT_NO_THROW(
      (index = tx.AddTxOut(amt, asset, exp_locking_script, nonce,
                           surjection_proof, range_proof)));
  EXPECT_EQ(index, 1);
  EXPECT_EQ(tx.GetTxOutCount(), 2);
  EXPECT_NO_THROW((txout_ref = tx.GetTxOut(index)));
  EXPECT_STREQ(
      txout_ref.GetAsset().GetHex().c_str(),
      "6f1a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3");
  EXPECT_STREQ(txout_ref.GetConfidentialValue().GetHex().c_str(),
               "010000000000bc614e");
  EXPECT_STREQ(txout_ref.GetLockingScript().GetHex().c_str(),
               exp_locking_script.GetHex().c_str());
  EXPECT_STREQ(
      txout_ref.GetNonce().GetHex().c_str(),
      "01991a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3");
  EXPECT_STREQ(txout_ref.GetSurjectionProof().GetHex().c_str(),
               surjection_proof.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetRangeProof().GetHex().c_str(),
               range_proof.GetHex().c_str());

  // GetTxOutList
  std::vector<ConfidentialTxOutReference> txout_list;
  EXPECT_NO_THROW((txout_list = tx.GetTxOutList()));
  EXPECT_EQ(txout_list.size(), 2);
  txout_ref = txout_list[0];
  EXPECT_STREQ(
      txout_ref.GetAsset().GetHex().c_str(),
      "6f1a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3");
  EXPECT_STREQ(txout_ref.GetConfidentialValue().GetHex().c_str(),
               "010000000000bc614e");
  EXPECT_STREQ(txout_ref.GetLockingScript().GetHex().c_str(),
               exp_locking_script.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetNonce().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetSurjectionProof().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetRangeProof().GetHex().c_str(), "");

  txout_ref = txout_list[1];
  EXPECT_STREQ(
      txout_ref.GetAsset().GetHex().c_str(),
      "6f1a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3");
  EXPECT_STREQ(txout_ref.GetConfidentialValue().GetHex().c_str(),
               "010000000000bc614e");
  EXPECT_STREQ(txout_ref.GetLockingScript().GetHex().c_str(),
               exp_locking_script.GetHex().c_str());
  EXPECT_STREQ(
      txout_ref.GetNonce().GetHex().c_str(),
      "01991a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3");
  EXPECT_STREQ(txout_ref.GetSurjectionProof().GetHex().c_str(),
               surjection_proof.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetRangeProof().GetHex().c_str(),
               range_proof.GetHex().c_str());

  // RemoveTxOut
  EXPECT_THROW((tx.RemoveTxOut(3)), CfdException);
  EXPECT_NO_THROW((tx.RemoveTxOut(0)));
  EXPECT_EQ(tx.GetTxOutCount(), 1);
}

TEST(ConfidentialTransaction, AddTxOutFeeTest) {
  ConfidentialTransaction tx(exp_tx_empty_hex);
  uint32_t index = 0;
  EXPECT_NO_THROW((index = tx.AddTxIn(exp_txid, exp_index, exp_sequence)));

  // AddTxOut, GetTxOut, GetTxOutCount
  EXPECT_EQ(tx.GetTxOutCount(), 0);
  int64_t exp_satoshi_fee = 12345;

  Amount amt = Amount::CreateBySatoshiAmount(exp_satoshi_fee);
  ConfidentialAssetId asset(exp_assetid);
  ConfidentialTxOutReference txout_ref;
  EXPECT_NO_THROW((index = tx.AddTxOutFee(amt, asset)));
  EXPECT_EQ(index, 0);
  EXPECT_EQ(tx.GetTxOutCount(), 1);

  EXPECT_THROW((txout_ref = tx.GetTxOut(index + 5)), CfdException);
  EXPECT_NO_THROW((txout_ref = tx.GetTxOut(index)));
  EXPECT_STREQ(
      txout_ref.GetAsset().GetHex().c_str(),
      "6f1a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3");
  EXPECT_STREQ(txout_ref.GetConfidentialValue().GetHex().c_str(),
               "010000000000003039");
  EXPECT_STREQ(txout_ref.GetLockingScript().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetNonce().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetSurjectionProof().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetRangeProof().GetHex().c_str(), "");
}

TEST(ConfidentialTransaction, SetTxOutCommitmentTest) {
  ConfidentialTransaction tx(exp_tx_empty_hex);
  uint32_t index = 0;
  EXPECT_NO_THROW((index = tx.AddTxIn(exp_txid, exp_index, exp_sequence)));

  // AddTxOut, GetTxOut, GetTxOutCount
  EXPECT_EQ(tx.GetTxOutCount(), 0);
  int64_t exp_satoshi = 12345678;

  Amount amt = Amount::CreateBySatoshiAmount(exp_satoshi);
  ConfidentialAssetId asset(exp_assetid);
  ConfidentialTxOutReference txout_ref;
  EXPECT_NO_THROW((index = tx.AddTxOut(amt, asset, exp_locking_script)));
  EXPECT_EQ(index, 0);
  EXPECT_EQ(tx.GetTxOutCount(), 1);
  EXPECT_NO_THROW((txout_ref = tx.GetTxOut(index)));

  // SetTxOutCommitment
  ConfidentialNonce nonce(
      "991a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3");
  ByteData surjection_proof("1234567890");
  ByteData range_proof("1234567890123456789012345678901234567890");
  EXPECT_NO_THROW(
      (tx.SetTxOutCommitment(index, asset, txout_ref.GetConfidentialValue(),
                             nonce, surjection_proof, range_proof)));
  EXPECT_NO_THROW((txout_ref = tx.GetTxOut(index)));
  EXPECT_STREQ(
      txout_ref.GetAsset().GetHex().c_str(),
      "6f1a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3");
  EXPECT_STREQ(txout_ref.GetConfidentialValue().GetHex().c_str(),
               "010000000000bc614e");
  EXPECT_STREQ(txout_ref.GetLockingScript().GetHex().c_str(),
               exp_locking_script.GetHex().c_str());
  EXPECT_STREQ(
      txout_ref.GetNonce().GetHex().c_str(),
      "01991a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3");
  EXPECT_STREQ(txout_ref.GetSurjectionProof().GetHex().c_str(),
               surjection_proof.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetRangeProof().GetHex().c_str(),
               range_proof.GetHex().c_str());
}

TEST(ConfidentialTransaction, BlindTxOutTest) {
  ConfidentialTransaction tx(
      "020000000001319bff5f4311e6255ecf4dd472650a6ef85fde7d11cd10d3e6ba5974174aeb560100000000ffffffff0201f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f0100000bd2cc1584c002deb65cc52301e1622f482a2f588b9800d2b8386ffabf74d6b2d73d17503a2f921976a9146a98a3f2935718df72518c00768ec67c589e0b2888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f0100000000004c4b40000000000000");
  double inputamount = 130000.0;
  std::string inputblinder =
      "fe3357df1f35df75412d9ad86ebd99e622e26019722f316027787a685e2cd71a";
  std::string inputasset =
      "6f1a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3";
  std::string inputassetblinder =
      "346dbdba35c19f6e3958a2c00881024503f6611d23d98d270b98ef9de3edc7a3";
  std::string pubkey_hex =
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16";
  Pubkey pubkey(pubkey_hex);

  std::vector<ConfidentialAssetId> asset_ids(1);
  std::vector<BlindFactor> abfs(1);
  std::vector<BlindFactor> vbfs(1);
  std::vector<Amount> values;
  asset_ids[0] = ConfidentialAssetId(inputasset);
  abfs[0] = BlindFactor(inputassetblinder);
  vbfs[0] = BlindFactor(inputblinder);
  Amount amount = Amount::CreateByCoinAmount(inputamount);
  values.push_back(amount);
  std::vector<Pubkey> pubkeys;
  pubkeys.push_back(pubkey);

  EXPECT_NO_THROW((tx.BlindTxOut(pubkeys, asset_ids, abfs, vbfs, values)));
  // 乱数が混ざるため、サイズだけチェック
  EXPECT_EQ(tx.GetHex().length(), 7662);
}

TEST(ConfidentialTransaction, SignatureHashTest) {
  ConfidentialTransaction tx(
      "020000000001319bff5f4311e6255ecf4dd472650a6ef85fde7d11cd10d3e6ba5974174aeb560100000000ffffffff0201f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f0100000bd2cc1584c002deb65cc52301e1622f482a2f588b9800d2b8386ffabf74d6b2d73d17503a2f921976a9146a98a3f2935718df72518c00768ec67c589e0b2888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f0100000000004c4b40000000000000");
  double inputamount = 130000.0;
  Amount amount = Amount::CreateByCoinAmount(inputamount);
  ByteData256 byte_data;
  SigHashType sig_hash_type(SigHashAlgorithm::kSigHashAll);
  Pubkey utxo_pubkey(
      "020ff7000e2754f34aeb894f1e4dc985e3f9742b194fac2350f963dfa219f177c4");
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_DUP);
  builder.AppendOperator(ScriptOperator::OP_HASH160);
  builder.AppendData(HashUtil::Hash160(utxo_pubkey));
  builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
  ByteData script_byte = builder.Build().GetData();

  EXPECT_NO_THROW(
      (byte_data = tx.GetElementsSignatureHash(0, script_byte, sig_hash_type,
                                               amount, false)));
  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "d0b8a3b596813756ca042fd510c4acac522378e8e3ac610fdc0301f6921aac34");
}

TEST(ConfidentialTransaction, SetAssetIssuanceTest) {
  ConfidentialTransaction tx_base(
      "0200000001017f3da365db9401a4d3facf68d2ccb6372bb714491987e5d035d2b474721078c601000000171600149a417c11cb67e1dc522997f07e1ff89e960d5ff1fdffffff020135e7a177b434ee0799be6dcffc945a1d892f2e0fdfc5975ba0f80d3bdbab9c84010000000002f9c1ec0017a914c9cbab5b0f3430e824b1961bf8e876be43d3fee0870135e7a177b434ee0799be6dcffc945a1d892f2e0fdfc5975ba0f80d3bdbab9c8401000000000000e07400000000000000000247304402207ab059e55e3e4337e88e1a6db00b7549110065eb5770880b1081dcdcdcf1c9a402207a3a0bc7d0d40661f54eff63c67838260a489984138d24eeee04b689f393bf2e012103753cff6c6123d25d99a3d02dc050a2c6b3ea40bcc04029c4330a4d30cb5390770000000000");
  ConfidentialTransaction expect_tx(
      "0200000001017f3da365db9401a4d3facf68d2ccb6372bb714491987e5d035d2b474721078c601000080171600149a417c11cb67e1dc522997f07e1ff89e960d5ff1fdffffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000002540be40001000000003b9aca00040135e7a177b434ee0799be6dcffc945a1d892f2e0fdfc5975ba0f80d3bdbab9c84010000000002f9c1ec0017a914c9cbab5b0f3430e824b1961bf8e876be43d3fee0870135e7a177b434ee0799be6dcffc945a1d892f2e0fdfc5975ba0f80d3bdbab9c8401000000000000e07400000107ec1ec7027d89071814d5ccd1f5ea4cee45e598287fc8f59acbb1d9129081dc0100000002540be400001976a914144f003aa8dd6408ba0e8ee91757cf1f1976315c88ac01aaf1579c847497d406605b4ef875a2b37164f4c5b9e5d2a23b2b2a16e132ec0501000000003b9aca00001976a914ae8cab151547d6f6e25b62b41200368dfdabe62b88ac0000000000000247304402207ab059e55e3e4337e88e1a6db00b7549110065eb5770880b1081dcdcdcf1c9a402207a3a0bc7d0d40661f54eff63c67838260a489984138d24eeee04b689f393bf2e012103753cff6c6123d25d99a3d02dc050a2c6b3ea40bcc04029c4330a4d30cb539077000000000000000000");

  // not blind
  ConfidentialTransaction tx(tx_base);
  Amount asset_amount = Amount::CreateByCoinAmount(100.0);
  Amount token_amount = Amount::CreateByCoinAmount(10.0);
  Script asset_script("76a914144f003aa8dd6408ba0e8ee91757cf1f1976315c88ac");
  Script token_script("76a914ae8cab151547d6f6e25b62b41200368dfdabe62b88ac");
  ConfidentialNonce asset_nonce;
  ConfidentialNonce token_nonce;
  ByteData256 contract_hash;
  bool is_blind = false;
  IssuanceParameter param;
  EXPECT_NO_THROW(
      (param = tx.SetAssetIssuance(0, asset_amount, asset_script, asset_nonce,
                                   token_amount, token_script, token_nonce,
                                   is_blind, contract_hash)));
  EXPECT_STREQ(tx.GetHex().c_str(), expect_tx.GetHex().c_str());
  EXPECT_STREQ(
      param.entropy.GetHex().c_str(),
      "0a002ed099bd2d52f4bb04d36ebc159c838f0557461d462127845b996e61cb70");
}

TEST(ConfidentialTransaction, RandomizeTxOutTest) {
  // out: value, fee
  ConfidentialTransaction tx(
      "0200000001017f3da365db9401a4d3facf68d2ccb6372bb714491987e5d035d2b474721078c601000000171600149a417c11cb67e1dc522997f07e1ff89e960d5ff1fdffffff020135e7a177b434ee0799be6dcffc945a1d892f2e0fdfc5975ba0f80d3bdbab9c84010000000002f9c1ec0017a914c9cbab5b0f3430e824b1961bf8e876be43d3fee0870135e7a177b434ee0799be6dcffc945a1d892f2e0fdfc5975ba0f80d3bdbab9c8401000000000000e07400000000000000000247304402207ab059e55e3e4337e88e1a6db00b7549110065eb5770880b1081dcdcdcf1c9a402207a3a0bc7d0d40661f54eff63c67838260a489984138d24eeee04b689f393bf2e012103753cff6c6123d25d99a3d02dc050a2c6b3ea40bcc04029c4330a4d30cb5390770000000000");

  EXPECT_NO_THROW((tx.RandomizeTxOut()));
}

TEST(ConfidentialTransaction, CalculateIssuanceValueTest) {
  Txid txid("d1efb621591f94f66a9c3161addd6d7db0ae82cc1674e3b098051793fb70028a");
  uint32_t vout = 1;
  ByteData256 contract_hash_empty;
  IssuanceParameter param;

  // not blind
  EXPECT_NO_THROW(
      (param = ConfidentialTransaction::CalculateIssuanceValue(
          txid, vout, false, contract_hash_empty)));
  EXPECT_STREQ(
      param.entropy.GetHex().c_str(),
      "18dde72422dba6e922b41ae3c23243e64d361a6e18c49b75a0b02e627b1dae0c");
  EXPECT_STREQ(
      param.asset.GetHex().c_str(),
      "598ae0bb5298b89e257b64bcbb05e4f70a2def1c1c74d929ef753021e0559e07");
  EXPECT_STREQ(
      param.token.GetHex().c_str(),
      "4dda0f2bc939213feae25a16dcade5f235ab28564d56dc4f7f69d977d441f993");

  // contract hash
  ByteData256 contract_hash(
      "fdf4d615b2b78b61c85ccd5129584dc1b7cbd6c75a1c799cc0738bc783dafd68");
  EXPECT_NO_THROW(
      (param = ConfidentialTransaction::CalculateIssuanceValue(txid, vout,
                                                               false,
                                                               contract_hash)));
  EXPECT_STREQ(
      param.entropy.GetHex().c_str(),
      "9ed3d5d8f571d5b6ad03b5d17cee4fec1de36b65f4eb7d84aad264ddf260c09c");
  EXPECT_STREQ(
      param.asset.GetHex().c_str(),
      "76ab84689c4b03e254c89188962d262d159d21b4f1ccdfaf061d79dd53ddf303");
  EXPECT_STREQ(
      param.token.GetHex().c_str(),
      "e9aab5dcff7203b1dd77d42b727058835eb0034b3fad91e6d2bb69c21d7a5879");

  // blind
  EXPECT_NO_THROW(
      (param = ConfidentialTransaction::CalculateIssuanceValue(
          txid, vout, true, contract_hash_empty)));
  EXPECT_STREQ(
      param.entropy.GetHex().c_str(),
      "18dde72422dba6e922b41ae3c23243e64d361a6e18c49b75a0b02e627b1dae0c");
  EXPECT_STREQ(
      param.asset.GetHex().c_str(),
      "598ae0bb5298b89e257b64bcbb05e4f70a2def1c1c74d929ef753021e0559e07");
  EXPECT_STREQ(
      param.token.GetHex().c_str(),
      "3b4a21657d88d5004008ccf00441270a20984228eb06289660b63b475b539610");
}

TEST(ConfidentialTransaction, UnblindTxOutTest) {
  using cfdcore::UnblindParameter;

  /** asset function **/
  // assert UnblindParam struct func
  auto CheckUnblindParams =
      [](UnblindParameter actual, UnblindParameter expect) {
        // check confidential asset id
        EXPECT_STREQ(
            actual.asset.GetHex().c_str(),
            expect.asset.GetHex().c_str());
        // check asset blind factor
        EXPECT_STREQ(
            actual.abf.GetHex().c_str(),
            expect.abf.GetHex().c_str());
        // check value blind factor
        EXPECT_STREQ(
            actual.vbf.GetHex().c_str(),
            expect.vbf.GetHex().c_str());
        // check confidential value
        EXPECT_EQ(
            actual.value.GetAmount().GetSatoshiValue(),
            expect.value.GetAmount().GetSatoshiValue());
        EXPECT_STREQ(
            actual.value.GetHex().c_str(),
            expect.value.GetHex().c_str());
      };

  // assert ConfidentialTxOut data func
  auto CheckTxOuts =
      [](ConfidentialTxOutReference actual, UnblindParameter unblind_params, ConfidentialTxOutReference prev_data) {
        // not change locking script
        EXPECT_STREQ(
            actual.GetLockingScript().GetHex().c_str(),
            prev_data.GetLockingScript().GetHex().c_str());
        // not change value
        EXPECT_EQ(
            actual.GetValue().GetSatoshiValue(),
            prev_data.GetValue().GetSatoshiValue());
        // change asset
        EXPECT_STRNE(
            actual.GetAsset().GetHex().c_str(),
            prev_data.GetAsset().GetHex().c_str());
        EXPECT_STREQ(
            actual.GetAsset().GetHex().c_str(),
            unblind_params.asset.GetHex().c_str());
        // change confidential_value
        EXPECT_STRNE(
            actual.GetConfidentialValue().GetHex().c_str(),
            prev_data.GetConfidentialValue().GetHex().c_str());
        EXPECT_STREQ(
            actual.GetConfidentialValue().GetHex().c_str(),
            unblind_params.value.GetHex().c_str());
        // empty nonce
        EXPECT_EQ(
            actual.GetNonce().GetData().GetDataSize(),
            0);
        // empty surjection proof
        EXPECT_EQ(
            actual.GetSurjectionProof().GetDataSize(),
            0);
        // empty range proof
        EXPECT_EQ(
            actual.GetRangeProof().GetDataSize(),
            0);
      };
  /** Prepare source data **/
  // from rpc sendtoaddress command "address" 33
  ConfidentialTransaction org_ctx(
      "020000000104a76c51c1a0ad26df3eae8e8391a9da3cecea24edabcda10436cd3e550cd2f9e2010000006a473044022037a85467fb53a0b579678d4427686772c440a72b1ca414a277c89541fdeec17e02204b83132cce2ea41eeac04fb9f75b8feda74baa46f240b05f441319cadeb1a8fc0121035bcdbee25133f192f51e13af9e60d571fb97cf1a4952225d9bba4c184edc69c7fdffffff37ae0d4fdb2e319449897e6defb3826632a5eaaab84ac5b4539979c4b5e042ea0100000017160014077042bf149434cda92751a2ca017eb35b1ae29cfdffffff08c67897576709ee329620a9d63f0e6f662ddaecceac73e5a8807f9c9fcb88430100000017160014a65e7f101ff5f4f4106603b884d2c631717f61d8fdffffff8daed986c59703a36742a38b9c379afa2489532a876da63e9cd1fe61577c0a74000000006a473044022054beb6150beb677cc2eff5325ac169384a378aa82ac9474cdc43f1c8510f0d790220536fa1e8230548fae4928f6d7a4dd6a35e10bbc069b07788c9c53499fd300d2d01210231ac57012170dfdbd4adcb737b1a795896b57e2cc004c5e98ee5721b78ad3940fdffffff030a151e78448b0efec64069c8d11ac9d494635c81c68be60dd8dc5d00b61e66937009f2c7d4ec124a14c9b6e4a2311b4081944d7c493da119117fff8118f09b5c20c703bc52778cf3328c1bccc647e890df68294bcd38632d39a10e53d0757453a6c1b81976a914027aa64642c68f9e3d2d06c3141484ef1704fa8c88ac0b8a04b307c5bb5d383137600d5815347f6fb3f712672ff9c104af1eed3f7b2c9909e02b1ef9d285f8bd1b310f30facc9b9b267f18692ebe675fba02b2eda9febd67025eb7264392705673c88a2dea01a2325354ebb60a5cf045af41351077bb0a0e4917a914df01567680d27699b7d84dafa2bdabb5ada034d5870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000b3740000dd0700000000000000000247304402204efc7d568f382eccba5a33c74e51a70ee694f1d6509bbaf115e20fc898ed262602207f4408d44f79f451fac416958b00998e073a1eee8bd2997ab6fb6b3c02a651470121028e9137d413e21d84b86deb7f455ea5693d2e37f34105d6a48dfbdef212001a0a00000002473044022005083890177505328661bb51e2871cc60356c2ef4af7edd14c9a38435ef39bbd02207e6cb720bba6acbfb7a0ced98cff1eafcb32f96c0e24d5861677cbf7570ca35b012102360a8ed10131a6e99a0342c5c62163ec78430293d21a76a3571553bf99530a7000000000008304000b13f3245f12994306c0732649e27622e0460517da75dae7bf3c3976bb7ab9cbed4719e56eb21b7fb65c2b938b61a6a53f368195b128c3178feec7ddaff3a9cc64e59fe0bfad6cb9506211c945fbba0be14a5457dab662094539b82d80ff2f50a492abaa7fe406810879833f2452651e0f6b51faaa5a0e507293330bfa16ea6283fd4d0b60230000000000000001c2b101c36161ea32674a76fc474e5a45d8bf234dc0dadaf96837b9b3117a63c06128b58861827accd9e5f4f64e61b1efdbc4b7757f7baa8d7072757e4bb65c6045cd70ff8b1ab4b9f1e82283dae8c61651351f56695a752f9f5bcc0ea785fdfce0d49f38c541912bcd55df51dc09cc161b35a0b04e0df400b122d4d4a393dbde8933ea7cea3c5be1caff45f3a760cd51315101d27456da3fb01acbf1af4a53a668ea7e5ebfe456ceef332b3878a21acd717a82557d2d353f39789893403987dadec79a934fd4d62418bcf5af3c9fb4250f9ae1456de1b110f25e9c713fc26470bd0acf2095799e3a73d91e4e187b30731d062ac917f6261df0c58e579a075019a8cb1e88f95fe509456510009ef5e0f9502ac426c264806f5bf1374ba826677b8b1b06fd00c060cf130bf1943a0a85d7b9993d937a1321aed730c13cc9a22316e57a526b0f5ec2e4f1355ef1d4820afa35d9d2c441fe128da31ca8f18b27c4e6fc5d73bf68165aaa4ad066aefee3cd342b85ec8b806433e58b49f300340b140bb042c63959f52a0b68155318f38065521c1564bbc80306fdbabd70c0805cebdd50e3f78ff5d55b53be8443bac0013ea25c0d1e5b9cf4edeaee946a266424c5ce45099b5f14ec0ec9ae9d1fafbdbdfcb608e3b3d6bc26ceb1e32d9535817f0ef1e90dbbd6013e94686fd846d50fc9b9312bd3016d81c0513c4c09078b3199f799dc1791f4e02e635de7295ed0e8bcf9971fa0cdb7067f71fe6226e6c5d6c9911fc5865a74a05d9f596c29e9ca2be83663f0ff1e41a5ec8ddc01c667026eb778c6b1f0d4f3d2dc0c937841238d8ded60a3f4a012a859b66d40bcd260acc6068bad56c8c3834ba4d1b4f778213d2d8365fa068b86613e3da1105123efc4b5ba934f532f5b6cb4af2e4828a1a560d3cd720eeef41f0fda6c466a6993c65ab9223cd3f0a09d99a6d7bac4974a586ea0bad4bc646c456e7df4ef84dda95943784cef2710653a9bdeacedbb7a541db754ea6a15ee9d38eac49a1c9e1ad1f38f4ebaa782da4b1e6fde7b66cd81ab60c002080dea754dabb296d4408e926a45f7f1301d551432d8c8e1294fdd307d9ee2a77e395e3684bae5a9b5afe76a389d67ee0913ef8832967955c0434fef85270411f5c60379512231c428bc03cdec09f0334659ebae151e2f7449f538b37c8c758fed826ab10da63a136938f12e8ad9c3cb76489c0610b8c1908820cc8dda284dda57e1e4c1e4f16c904aae0fc491019a273037d036ee0aa88cb43b4682fa8026933200ead8e0ad1792b2a9f2e177a58321f97ca0db36b6e1ce2661608b8d0bb654d43f676678ab2994436cac1f4c593abf0f11bc5dd737e2d645a6e92ecf7597b139268e5c565e24e7e0987358ae46900df03bc971b7a856181d551c149d6750459c56f1905799ef0552e0148418898839f5ed3167ec2fc1e0184514cd243c830e9092c6cb66a51f45d6a12b363adbc669b7aadf4d0b5cc2bf9922d6c1364dfdaca171fb6c3fd001fd1b053f42a24e9776a75daba64701a7248da6c7d4719c069364f86cb2f364b3f4e8fab3452545a24764bad1db29bc271bb8869c4dbf031f3786a12339ee562451c2b66d1af7ddbd7d65f6d06fafa06422be1312d144c1bc649e98fe665d0e5842cca596ea3a14a85d230da00e1f2880dfcd482535a617b4eb9d762d6771a90420bea9fbeb211e8794bbc77d353287a40c0b17ad86964a96318831fc815d92c5e6dd89968931f7487c86415cc1d600aa27bd164e3c4d0a15c01a7377d5a85ca3262f4462b945414bb9e4714f28fa6c8b0e57db2cf29b012a1730e976edb2f27ac24386bae63cd6022425fd8c2453aa6cd98e401ed8cdd6e86836d917c2bdd3e66b7c71c8a1628587b46c710df92fe74e16711179bc8eb19bae77cde2dc680fb2d862b74bba838621de9573c0b9875578441eb65e266b82db937e092e5260a42ac07659f7100aae03ee02977743a6249c685232851768a022fe95b7f35fa080d81f7de31a456d1a01d252b4e8860b48cfda15080616ce9f628c9ca670225102315ce92da545ddabce9943f257ff61f6ffc220840f1b29a64a8eada361386cdebc03d146f7682149e7bfcb3338430da40226714ff35a31aff60bdac47a0816806a1de48eeaaffbab88e82cc643d4ceb527f5c94bce1659bb56301460bb718f3ead9323345a7ecec1b8f0fd6297ef7d3850430fa8b90e75d45db87a265d3457fbefd6951c7d628496f06e75373c96f2eb97809b10c0143809cc28174b0a949f4dc8df6e6eb22896f26e5331e6ab66d7e0bc0347da39f0e7a3bd2c3369538bdea29a7d76461832dee3fe593bd598cb51a8b1966b135e3a84b8f4ec9a174b2be7cd0f6315d4ca03a958d2e88c1be4e19fc517111cd2a90c4fffc76583e6c361f5fabac6f0aac54cccaa02015e5cdb7f99b84b8026f5667c5f9b57a4f57cad899b7be8ce66b817a0483091378a8db14579cf1e9568ce2c4af3ed872193f449fe05bac79a7ea92743ffa72cf212f8da9679f733c89fee4b78dfe66a982c79cdd16e97b3a316f3191542a022a517f49566edb5bdbafe8a63fd844d5f6763e42e46bdc2c7de22705b8644253397c17480dc0c9484909ae99f3c5038ace18bddce9be9cae3b86312af4ec937a5e05e1a119a2dcc57391d291b25ffe3dff7da88451e5b9270ce7bac6086197a8a2796bf953b3b0fe70b1a53035ee560d302a9ab55f2926e7f888086367c9cf469d4b0a276525e567f73a7b55b48f0ddb36e1a7c1b97d2ee008e61c2bc635e6db9585b01dca600d81b044bb1af230c9ed6e658eb8c3c4b35e1d9773295ec57eec12ebf7da3135beb7e7de0ca086f254770ee0df3341271c6df96b10b3569fc479fbfe1cce62504612d38e30fc7b70fb22aab65ab178fbb095e04767a0198e3dcb6dd6aa04e538453d9e933e8c56bb16078ed85490963fb99ec7279b5d46618d2e596c5c057367d6ef3dfde0f6e61d9d0c9ec076c6ee1fe588463cb596921b5f130b278c1ba13ebec24cda89b4d8b25ac475c34de025b4a04a319367a5745a9963095a9f560e57b61c442a3b02c46302d2f8464966b4fdb28caa592da61695f292f76f69c3120ddd9308f6cc13c2008eee3ea874914cb1a8357949829fd8afd68ca1f854393d6aeb26bfc130d1e6c62d45b0ef5eb6700b7c0f5aa066ab985a825b65212affcc901278fe79f3b6cb45015f0010e92fb190758a64729a8b46f299564eb59a2ddb03057d97843723318f6ddf0f7e9254235dc49318dac7c028df6f680491ea1ab28a820a95d35f1937a9f035bb6cfb56050989900ef809fd55961d10832c2abd79e565d80131908a84d53f8a51752ed00abbb9ae41e6ffecc93fabc19373effa546cdf715c26456238f06651bdf4ffda9c0d77ada10354030480301f09ec383db5bca36deb002c482202e574e63cb5156d09bf511fae0a72125bb61d3efd2197f84e029558a3dd1cde325df7f639d4b030373807ca64fb49100ae21c632fca67ce4821132bd5c488517b5ef45a76013dd41d4449fd585bb128ee9eef39ceef57854e52a9cd61fd5122d8a249454e4f6cae75f37f616b20b5b340c789e5599541af4778d85efaa849e25b5224029179026245d5ced747e6871fa5a200898fedbae2954c452e267ab2a001b3ebd5920390e79687af5c012f53479c37a57897e578cf0e1fc3b4f038a84d72b3ca5363257a48919d74c606b1ed4361c5a1f7610ad70b5ee40f248a6c6822880e8ed4901b6ec0bca46aff4623273d256078701af941f4925df504961632c7e427c0dfd8607c5d1acc55c2f30ead6ea485512965f2a1d6015e6c4cf71453df81f70ced854eb0b23839223c5e18d1b63bbef7d79bc49a720e4fc2fe06e459d81340dc36f186c353295eb548838bfdd22876e34e2ea3170bb09104b77640e89dbd1048e6685df2d46bbc8ef682157d91f518d6ea083c649dbfeb23956164407b325424850ee2c0a98e6d2c3f19a1aeb4a5e6c38cf6792022ea6d5116671a1dee15006f2bbcb45b2f335e803c04d04fe089aae6c2151d30cd8e7d58304000ec0e7f42f42e6df0b144f11c0d5a3f6ad7cf84936e9d5a38fa266c3f7a742d4011f95f54553243fb35972ec66b650d781dad6ff672cbd8a935bd477b838595380ffe1586bf1bcee43e0ff18d252263250e952d39b0f215ebb69cf0c23a6b1a1d2b686c01c5d79fc5b486a88afbe466b4d4bc8e559b0b1f6432c98d8e0844cafecfd4d0b6023000000000000000111cb01acd74ab4034d001feb7cd326bb4f078d678ff1f7d281d3b1262864f97e6dbd42fcc90e63b1bfeacb96f2ee0b5889a2c1550467af8f940791eb2af806628252ff52a77cb2a48cc7b8ecfb0cf6db934e90d812bb4d51c73f84b32a7e9c481f89d56f24a2e7d36b2f6932f2ffc8eea9f9798f25f6f03e51729f4164171ce6475a9d0b9da3fa04922745ceaae12327bd7e40ff22f17d01dc4a6148674c4fcff4a3974fc48b8fb924f0545392d1b329301fba3a5e71fb541e8be0a96ad79bd2cd586bc43fecbc705e61240b58a21dbe0d2e0f0dab734ac0be7655e08917fa62fec78cda4cc83c50e8ae5089f94e14bf70f6f1698c23e914003f3633ef257cfe997327cce8bdf7f2adff2070785e651334e5a0ca97d5e8528e0b47e88570e152a18026c99658cc3350174bc83d887192fdf6221c938f25d09d64bddf98f4313c4f67909e9aeef61a633e2c708a1dc5f995882a780eb93f9db0bd97470b77fb61b0263abdc6232b654da092bbfe22f486b90a7c5898f83ec595a003a3ea66c4288cc6e529262d6226675a7009dd1bd762491a509225651c356b60ffdd1f36a6cc7c24ee719b941f02f2a88406e93d0d0b81c75ba33ce4821f7009c21274af21a5f61fd105b25cfa857df61b2cdd29ce0eeeec86faa52ead261dd3b1326d52d96945e8b15974d2c4be711813f7130234dafbb7715cc4dd8ed69d3c4ca62f0bf448bbf8a32e52df9334a094bfa9f577eab017de57bbbe028fc08014a2f3ee55d9df9cadff760dcab6d06257c814c031bb11c836a8363f261982a7ce73392f82fcb6bdd5968835f657831e7dd1b0252a2112a45c403bf2975bebabfaccc365eb09bb25abfc3b80797cb2058268b9899ba642570d17ce05b8d9a304eaeb4a61b6fec6dc189f54f3d337df46918a76bc7f1ce9846ede724eaef34d4f02b6da0a293aa3a60b306b7c937bc2fd11f58d08440287b0c7793649ecb23b69181af9912f83afb283af17f48f05c79fad79b2aafadb64309a29ee3d08521f5b08d075eca726e2731c6cf85209c9341ee65878b7f86d85503b96c115f8cd603dfebfd24d9d6fb1df2cd92a32bfbb5eb926c280f902cb5bff0ca683a64a5b215fc2f377995363f42080bf96d953153a640762f91a4e68fff1c62c382eba70301dea1823345c9b5e52c5e2488881a76f5aa29f30a24fbc720ef24e1811640e44d0e92fafffde3bb7c3c8c8e813569d89604afbd7e09bd99418dbe31457a33d528924fa51291b62be9e8bb4fea91578296d1ffda0eaf0549347010e64181271b52036613153b61b8e83ea1aeff860ecf4af953639ff008a92a8c2e15d846ac75da55c1732277273ba070235f40d60554181f17b17b05158260e62b0f3cb7a11fb92e20dea7eda89ded7a69b16a359cfe9b3f334d369def50b1700d250bf003cfe23af5a2ee44b7ec2109650c1d88b33edc4f9404cdec8916f84366b36a79e05b4083f201ac59e688dd1ba03e2ea48fd6a42f8ae524a48b6ebb4b4326c667ec75f79e88af078ca667caacc06af34ca42eacabf441dff6fd80a8d6daa89e184d80e9516df2544a539723c9ed18cbaecbc94557e3a31b6ca5b0ecd15d1839c0f193405f2a461e7a520f414d056864f0ff6591d6f0bac63746f9887b5cad36b208160fe008d4eae56384019f92de1ecc2ca53be8055c900ad94521440bd99646f365ef944b6caf92e2614454ae032cb52e59bdc4aff6710a978a4bb6c3ff4eaa478f6a40c96fdb26268cbb422b6ee7d6fda354de6ca7cde33456762a04db65389ff0c10f2852158b543abd9c26e0f1bd0ae04f7e40452f9b4d5d5aab0947856ba73202a5ac577b5a9a329299849b4304436289f271b8bb8f7da91f9c9d4d4fb2d707c3b0ccbf1820c4723ad5a6a1e4d79dbd62ab086ef409c3fc8b5e11bc7e8aa187b7d576d50fbfb755f1dbb8fa7658d52da16a8a7575747a841b52ad6d89c53bfc8afaf0f4d3041c774e05b40bbbaa4fccffa93054efa769d1566313c7f840a0ef9b91c45ac79f1b5e12c866157e4203f8860af2fcb26d2ff665d8e4e2baec6d7c05d5ba45cbcdb0c270b7e0b992e54ceeed41397a11d8478ced4f98ed161e335c4133372d1e4bcbcfa87fdb3fb0930cd99e4af6ac732ea164a328ee5445c374b59e9dfcd665399ed8d795b53dfca7059eb1364eac50d4a8e85ea72803069979843ebdb49436a3db93144b0438f0b15cf1d30b171a3352a6d3b2007fd7a4b97c62a20dd801944cd1e1e924a887fdb41fadee7a571a2d824f3c3925a8f32faa7308190c77b7da7516c81d2ba0302c4eb0763442b7873d85530080ec023aebc7191336c420db7b9c066eb6067f66fa2f6b03a510a1ccf301585aba7ba442b7f9be6182bf60db46a3e2ff380b350b7cf1432f530ce7d3503fd34195f74ee3292a6db28943d0362ee7de7f3bfc7103f074ef0bdb5c5741ed54ff27a11f1159fc2ec4334bad8050464df238403fb0b5d814f65fed6a6ed76bb11868abcf36509fafa05b04fbb80185a58022d87badafe4c09cc475566b4b883558f459c97652eb82510b07a1ad530342573d36722c35e3a3fecdb616a72942e1e889f7fbbed4c7f2fa30c1a1bdfb92fa55e047d7d51f89633f21fdd74315731ccf0c1ca647135cbea7db9a62f4b3cb43a92b1b8b03e910d2e709c9c8a0fe25041f72120a51a2c9ab4155c01685132a9cfb62718a483fdcfb87bfb705dd5a85b10c8bba2c4df81a63d10480812f42a2a2d57ef71c6b685f0faa79d08d01ffab71037f0276b5b966756532470d115d63e6bcca2e420b04f628017b022c95cb991663b85be23fa70014bea539bc02c033711fa3ac026813f233941917507b1bd2dad073668f92e8697834ac12fcf6da847535afa019726fbe5acfbb3df32f231322b11069a46d0e883d62ca1766d1f91063be7e2e55d2a875ff5a24bef810bf068edd93863bb21a03d478d8bf78ac902614aeb19a8be6eb82fff7db2588d93cbe55628b1abcfce379b9cebadd718f0cb96b72f859bc7e944777f182c0ad160d912b5e43cf3b7ae27b894a4b4f0c704ee9fbfb87e63b9d812a8277634e8e0960d0c736230d78d91d7268129562a5fc7674321833fc1085e826dec7bb6c7d98172302ea2abe016f0e38d75e0fb895f364378a5d8479879dba16d6248c6decf84e0ed58dcdc13c0b2c96fadd15cbc5bf92a6268bf1672b339581e90259accd515f66eb207ee962bab98179ea5d0438b40bbac52b248ef293d13beb22cdc081a1c7bbbbb4c0060e6ad1240ff46c1d43450839626365e768c3b8510e31c76a6166e023dad31077e9f6afea1dc9686454f25a60eb6cf7b999c51a005171ed8435588451de5f6ab831ede004f7e6be1d807cb45e45b82298764657ea17692c6198b27f5f93ece31297443dbed66bbe878fc7b2cecf11cfdab409c764e77015fb5bf8dc5add2986569e225f1890ef28c519e90f028e453b51a48d7896c0804c3297241d415bccd7e7cee0a859fc648635652e033311e59c70f08d588cb1fd1cd8cf0ed261d47d9cca08b777fe6e4d02ea586369a9f1e3f5dcfece64066eb3ce15f7c1e1fba956ed4aa3f9e9bec7e27f1dac19f4af425030a56ee318f7199959f26ab641de25ba563a2d1159528d4329ce84ce3bdff56306f7437f552e15a90072cd4b5f785fcca79b6b57e5adb7dfb5a957c8c9c42a44770336c0e6f57a584af3ecc0c08526ef33a044f14610decde7aa82741a764290f6cb9940152663aa118bd0fff7341b1e336823ccb6815f9404e3f4874c99e0d335d814516b8cf75a7931c5b344ab27366c08482b17b4374fbd4a61385143fbbec73845157ea9894472b0613f0892087fc7eb2cc92b3e47100ef3b2b404ad9dae0c447c53d7fa1907f2dca4c106ee66a4bd6a5136b1e303e8a50827b8a9a65c551a84bee01de37c30cb3e00073c641da19a3f405e94f22ff7ab713d9f3d94dd7a2831291db9b886d53ba7430ff863df094262ef8fe8cfae9e6dfc1aef29d7ba0ce49060c829b7f85ddb9138ef76b51df1bf51e1eddfc057895d113bc4cc98d9a964b22a2ca0000");
  std::vector<Privkey> blinding_keys;
  // TxOut[0]
  //    destination confidential address : "CTEutTrasoQiGBYbMANmRwLdM6Jmh25rnQE8g2fT2Dc2MnSf4qJrLGRg8SD3jdtQJo1dqB5jUmvfCkvo"
  //    blinding key: "c5b99c20f6a19e865baccea19addaa9e4fe4cb71686d785885acd12e4c067ea5"
  blinding_keys.push_back(
      Privkey(
          "c5b99c20f6a19e865baccea19addaa9e4fe4cb71686d785885acd12e4c067ea5"));
  // TxOut[1]
  //    change confidential address : "Azpvmq7pZ43m6uHDJt2YRH9ubHcZuHEC6p9NTS3KrVuz8KVf1HPJiHwA8rAJtTsdJ3DxQBH9XszFCTRL"
  //    blinding key: "e8c134da3a2489a24a76c0d0aee71b10dfa4ab6a1bf19a13e24ee6c66939d87f"
  blinding_keys.push_back(
      Privkey(
          "e8c134da3a2489a24a76c0d0aee71b10dfa4ab6a1bf19a13e24ee6c66939d87f"));

  // unblind single TxOut test
  {
    /** Prepare Condition **/
    ConfidentialTransaction ctx(org_ctx);
    uint32_t target_idx = 0;
    Privkey blinding_key(blinding_keys[target_idx]);

    /** Prepare Expect Value **/
    ConfidentialTransaction expect_tx(
        "020000000104a76c51c1a0ad26df3eae8e8391a9da3cecea24edabcda10436cd3e550cd2f9e2010000006a473044022037a85467fb53a0b579678d4427686772c440a72b1ca414a277c89541fdeec17e02204b83132cce2ea41eeac04fb9f75b8feda74baa46f240b05f441319cadeb1a8fc0121035bcdbee25133f192f51e13af9e60d571fb97cf1a4952225d9bba4c184edc69c7fdffffff37ae0d4fdb2e319449897e6defb3826632a5eaaab84ac5b4539979c4b5e042ea0100000017160014077042bf149434cda92751a2ca017eb35b1ae29cfdffffff08c67897576709ee329620a9d63f0e6f662ddaecceac73e5a8807f9c9fcb88430100000017160014a65e7f101ff5f4f4106603b884d2c631717f61d8fdffffff8daed986c59703a36742a38b9c379afa2489532a876da63e9cd1fe61577c0a74000000006a473044022054beb6150beb677cc2eff5325ac169384a378aa82ac9474cdc43f1c8510f0d790220536fa1e8230548fae4928f6d7a4dd6a35e10bbc069b07788c9c53499fd300d2d01210231ac57012170dfdbd4adcb737b1a795896b57e2cc004c5e98ee5721b78ad3940fdffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000c4b20100001976a914027aa64642c68f9e3d2d06c3141484ef1704fa8c88ac0b8a04b307c5bb5d383137600d5815347f6fb3f712672ff9c104af1eed3f7b2c9909e02b1ef9d285f8bd1b310f30facc9b9b267f18692ebe675fba02b2eda9febd67025eb7264392705673c88a2dea01a2325354ebb60a5cf045af41351077bb0a0e4917a914df01567680d27699b7d84dafa2bdabb5ada034d5870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000b3740000dd0700000000000000000247304402204efc7d568f382eccba5a33c74e51a70ee694f1d6509bbaf115e20fc898ed262602207f4408d44f79f451fac416958b00998e073a1eee8bd2997ab6fb6b3c02a651470121028e9137d413e21d84b86deb7f455ea5693d2e37f34105d6a48dfbdef212001a0a00000002473044022005083890177505328661bb51e2871cc60356c2ef4af7edd14c9a38435ef39bbd02207e6cb720bba6acbfb7a0ced98cff1eafcb32f96c0e24d5861677cbf7570ca35b012102360a8ed10131a6e99a0342c5c62163ec78430293d21a76a3571553bf99530a70000000000000008304000ec0e7f42f42e6df0b144f11c0d5a3f6ad7cf84936e9d5a38fa266c3f7a742d4011f95f54553243fb35972ec66b650d781dad6ff672cbd8a935bd477b838595380ffe1586bf1bcee43e0ff18d252263250e952d39b0f215ebb69cf0c23a6b1a1d2b686c01c5d79fc5b486a88afbe466b4d4bc8e559b0b1f6432c98d8e0844cafecfd4d0b6023000000000000000111cb01acd74ab4034d001feb7cd326bb4f078d678ff1f7d281d3b1262864f97e6dbd42fcc90e63b1bfeacb96f2ee0b5889a2c1550467af8f940791eb2af806628252ff52a77cb2a48cc7b8ecfb0cf6db934e90d812bb4d51c73f84b32a7e9c481f89d56f24a2e7d36b2f6932f2ffc8eea9f9798f25f6f03e51729f4164171ce6475a9d0b9da3fa04922745ceaae12327bd7e40ff22f17d01dc4a6148674c4fcff4a3974fc48b8fb924f0545392d1b329301fba3a5e71fb541e8be0a96ad79bd2cd586bc43fecbc705e61240b58a21dbe0d2e0f0dab734ac0be7655e08917fa62fec78cda4cc83c50e8ae5089f94e14bf70f6f1698c23e914003f3633ef257cfe997327cce8bdf7f2adff2070785e651334e5a0ca97d5e8528e0b47e88570e152a18026c99658cc3350174bc83d887192fdf6221c938f25d09d64bddf98f4313c4f67909e9aeef61a633e2c708a1dc5f995882a780eb93f9db0bd97470b77fb61b0263abdc6232b654da092bbfe22f486b90a7c5898f83ec595a003a3ea66c4288cc6e529262d6226675a7009dd1bd762491a509225651c356b60ffdd1f36a6cc7c24ee719b941f02f2a88406e93d0d0b81c75ba33ce4821f7009c21274af21a5f61fd105b25cfa857df61b2cdd29ce0eeeec86faa52ead261dd3b1326d52d96945e8b15974d2c4be711813f7130234dafbb7715cc4dd8ed69d3c4ca62f0bf448bbf8a32e52df9334a094bfa9f577eab017de57bbbe028fc08014a2f3ee55d9df9cadff760dcab6d06257c814c031bb11c836a8363f261982a7ce73392f82fcb6bdd5968835f657831e7dd1b0252a2112a45c403bf2975bebabfaccc365eb09bb25abfc3b80797cb2058268b9899ba642570d17ce05b8d9a304eaeb4a61b6fec6dc189f54f3d337df46918a76bc7f1ce9846ede724eaef34d4f02b6da0a293aa3a60b306b7c937bc2fd11f58d08440287b0c7793649ecb23b69181af9912f83afb283af17f48f05c79fad79b2aafadb64309a29ee3d08521f5b08d075eca726e2731c6cf85209c9341ee65878b7f86d85503b96c115f8cd603dfebfd24d9d6fb1df2cd92a32bfbb5eb926c280f902cb5bff0ca683a64a5b215fc2f377995363f42080bf96d953153a640762f91a4e68fff1c62c382eba70301dea1823345c9b5e52c5e2488881a76f5aa29f30a24fbc720ef24e1811640e44d0e92fafffde3bb7c3c8c8e813569d89604afbd7e09bd99418dbe31457a33d528924fa51291b62be9e8bb4fea91578296d1ffda0eaf0549347010e64181271b52036613153b61b8e83ea1aeff860ecf4af953639ff008a92a8c2e15d846ac75da55c1732277273ba070235f40d60554181f17b17b05158260e62b0f3cb7a11fb92e20dea7eda89ded7a69b16a359cfe9b3f334d369def50b1700d250bf003cfe23af5a2ee44b7ec2109650c1d88b33edc4f9404cdec8916f84366b36a79e05b4083f201ac59e688dd1ba03e2ea48fd6a42f8ae524a48b6ebb4b4326c667ec75f79e88af078ca667caacc06af34ca42eacabf441dff6fd80a8d6daa89e184d80e9516df2544a539723c9ed18cbaecbc94557e3a31b6ca5b0ecd15d1839c0f193405f2a461e7a520f414d056864f0ff6591d6f0bac63746f9887b5cad36b208160fe008d4eae56384019f92de1ecc2ca53be8055c900ad94521440bd99646f365ef944b6caf92e2614454ae032cb52e59bdc4aff6710a978a4bb6c3ff4eaa478f6a40c96fdb26268cbb422b6ee7d6fda354de6ca7cde33456762a04db65389ff0c10f2852158b543abd9c26e0f1bd0ae04f7e40452f9b4d5d5aab0947856ba73202a5ac577b5a9a329299849b4304436289f271b8bb8f7da91f9c9d4d4fb2d707c3b0ccbf1820c4723ad5a6a1e4d79dbd62ab086ef409c3fc8b5e11bc7e8aa187b7d576d50fbfb755f1dbb8fa7658d52da16a8a7575747a841b52ad6d89c53bfc8afaf0f4d3041c774e05b40bbbaa4fccffa93054efa769d1566313c7f840a0ef9b91c45ac79f1b5e12c866157e4203f8860af2fcb26d2ff665d8e4e2baec6d7c05d5ba45cbcdb0c270b7e0b992e54ceeed41397a11d8478ced4f98ed161e335c4133372d1e4bcbcfa87fdb3fb0930cd99e4af6ac732ea164a328ee5445c374b59e9dfcd665399ed8d795b53dfca7059eb1364eac50d4a8e85ea72803069979843ebdb49436a3db93144b0438f0b15cf1d30b171a3352a6d3b2007fd7a4b97c62a20dd801944cd1e1e924a887fdb41fadee7a571a2d824f3c3925a8f32faa7308190c77b7da7516c81d2ba0302c4eb0763442b7873d85530080ec023aebc7191336c420db7b9c066eb6067f66fa2f6b03a510a1ccf301585aba7ba442b7f9be6182bf60db46a3e2ff380b350b7cf1432f530ce7d3503fd34195f74ee3292a6db28943d0362ee7de7f3bfc7103f074ef0bdb5c5741ed54ff27a11f1159fc2ec4334bad8050464df238403fb0b5d814f65fed6a6ed76bb11868abcf36509fafa05b04fbb80185a58022d87badafe4c09cc475566b4b883558f459c97652eb82510b07a1ad530342573d36722c35e3a3fecdb616a72942e1e889f7fbbed4c7f2fa30c1a1bdfb92fa55e047d7d51f89633f21fdd74315731ccf0c1ca647135cbea7db9a62f4b3cb43a92b1b8b03e910d2e709c9c8a0fe25041f72120a51a2c9ab4155c01685132a9cfb62718a483fdcfb87bfb705dd5a85b10c8bba2c4df81a63d10480812f42a2a2d57ef71c6b685f0faa79d08d01ffab71037f0276b5b966756532470d115d63e6bcca2e420b04f628017b022c95cb991663b85be23fa70014bea539bc02c033711fa3ac026813f233941917507b1bd2dad073668f92e8697834ac12fcf6da847535afa019726fbe5acfbb3df32f231322b11069a46d0e883d62ca1766d1f91063be7e2e55d2a875ff5a24bef810bf068edd93863bb21a03d478d8bf78ac902614aeb19a8be6eb82fff7db2588d93cbe55628b1abcfce379b9cebadd718f0cb96b72f859bc7e944777f182c0ad160d912b5e43cf3b7ae27b894a4b4f0c704ee9fbfb87e63b9d812a8277634e8e0960d0c736230d78d91d7268129562a5fc7674321833fc1085e826dec7bb6c7d98172302ea2abe016f0e38d75e0fb895f364378a5d8479879dba16d6248c6decf84e0ed58dcdc13c0b2c96fadd15cbc5bf92a6268bf1672b339581e90259accd515f66eb207ee962bab98179ea5d0438b40bbac52b248ef293d13beb22cdc081a1c7bbbbb4c0060e6ad1240ff46c1d43450839626365e768c3b8510e31c76a6166e023dad31077e9f6afea1dc9686454f25a60eb6cf7b999c51a005171ed8435588451de5f6ab831ede004f7e6be1d807cb45e45b82298764657ea17692c6198b27f5f93ece31297443dbed66bbe878fc7b2cecf11cfdab409c764e77015fb5bf8dc5add2986569e225f1890ef28c519e90f028e453b51a48d7896c0804c3297241d415bccd7e7cee0a859fc648635652e033311e59c70f08d588cb1fd1cd8cf0ed261d47d9cca08b777fe6e4d02ea586369a9f1e3f5dcfece64066eb3ce15f7c1e1fba956ed4aa3f9e9bec7e27f1dac19f4af425030a56ee318f7199959f26ab641de25ba563a2d1159528d4329ce84ce3bdff56306f7437f552e15a90072cd4b5f785fcca79b6b57e5adb7dfb5a957c8c9c42a44770336c0e6f57a584af3ecc0c08526ef33a044f14610decde7aa82741a764290f6cb9940152663aa118bd0fff7341b1e336823ccb6815f9404e3f4874c99e0d335d814516b8cf75a7931c5b344ab27366c08482b17b4374fbd4a61385143fbbec73845157ea9894472b0613f0892087fc7eb2cc92b3e47100ef3b2b404ad9dae0c447c53d7fa1907f2dca4c106ee66a4bd6a5136b1e303e8a50827b8a9a65c551a84bee01de37c30cb3e00073c641da19a3f405e94f22ff7ab713d9f3d94dd7a2831291db9b886d53ba7430ff863df094262ef8fe8cfae9e6dfc1aef29d7ba0ce49060c829b7f85ddb9138ef76b51df1bf51e1eddfc057895d113bc4cc98d9a964b22a2ca0000");
    UnblindParameter expect_unblind_param = { ConfidentialAssetId(
        "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225"),
        BlindFactor(
            "c476cd1617367852d9b981f6cb0b3899d2c500cb95b978ebc89b89d8831e7606"),
        BlindFactor(
            "71507ff4c052c404d16d2c0f85e86a443fd58fa50d7b8fb87a202320f099b3d2"),
        ConfidentialValue(Amount::CreateByCoinAmount(33.00000000)) };

    /** Execute Test **/
    // store before unblind txouts
    std::vector<ConfidentialTxOutReference> befere_unblind_tx_outs = ctx
        .GetTxOutList();

    UnblindParameter actual_unblind_param;
    // unblind transaction
    EXPECT_NO_THROW(
        actual_unblind_param = ctx.UnblindTxOut(target_idx, blinding_key));
    // check hex data
    EXPECT_STREQ(ctx.GetHex().c_str(), expect_tx.GetHex().c_str());
    // check return value
    CheckUnblindParams(actual_unblind_param, expect_unblind_param);
    // check txout data
    std::vector<ConfidentialTxOutReference> actual_tx_outs = ctx.GetTxOutList();
    CheckTxOuts(actual_tx_outs[target_idx], actual_unblind_param,
                befere_unblind_tx_outs[target_idx]);
  }

  // unblind all TxOuts test
  {
    /** Prepare Condition **/
    ConfidentialTransaction ctx(org_ctx);

    /** Prepare Expect Value **/
    // from rpc blindrawtransaction "ctx" commnad
    ConfidentialTransaction expect_tx(
        "020000000104a76c51c1a0ad26df3eae8e8391a9da3cecea24edabcda10436cd3e550cd2f9e2010000006a473044022037a85467fb53a0b579678d4427686772c440a72b1ca414a277c89541fdeec17e02204b83132cce2ea41eeac04fb9f75b8feda74baa46f240b05f441319cadeb1a8fc0121035bcdbee25133f192f51e13af9e60d571fb97cf1a4952225d9bba4c184edc69c7fdffffff37ae0d4fdb2e319449897e6defb3826632a5eaaab84ac5b4539979c4b5e042ea0100000017160014077042bf149434cda92751a2ca017eb35b1ae29cfdffffff08c67897576709ee329620a9d63f0e6f662ddaecceac73e5a8807f9c9fcb88430100000017160014a65e7f101ff5f4f4106603b884d2c631717f61d8fdffffff8daed986c59703a36742a38b9c379afa2489532a876da63e9cd1fe61577c0a74000000006a473044022054beb6150beb677cc2eff5325ac169384a378aa82ac9474cdc43f1c8510f0d790220536fa1e8230548fae4928f6d7a4dd6a35e10bbc069b07788c9c53499fd300d2d01210231ac57012170dfdbd4adcb737b1a795896b57e2cc004c5e98ee5721b78ad3940fdffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000c4b20100001976a914027aa64642c68f9e3d2d06c3141484ef1704fa8c88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f3ba9c0017a914df01567680d27699b7d84dafa2bdabb5ada034d5870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000b3740000dd0700000000000000000247304402204efc7d568f382eccba5a33c74e51a70ee694f1d6509bbaf115e20fc898ed262602207f4408d44f79f451fac416958b00998e073a1eee8bd2997ab6fb6b3c02a651470121028e9137d413e21d84b86deb7f455ea5693d2e37f34105d6a48dfbdef212001a0a00000002473044022005083890177505328661bb51e2871cc60356c2ef4af7edd14c9a38435ef39bbd02207e6cb720bba6acbfb7a0ced98cff1eafcb32f96c0e24d5861677cbf7570ca35b012102360a8ed10131a6e99a0342c5c62163ec78430293d21a76a3571553bf99530a700000000000000000000000");
    std::vector<UnblindParameter> expect_unblind_params = { {
        ConfidentialAssetId(
            "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225"),
        BlindFactor(
            "c476cd1617367852d9b981f6cb0b3899d2c500cb95b978ebc89b89d8831e7606"),
        BlindFactor(
            "71507ff4c052c404d16d2c0f85e86a443fd58fa50d7b8fb87a202320f099b3d2"),
        ConfidentialValue(Amount::CreateByCoinAmount(33.00000000)) }, {
        ConfidentialAssetId(
            "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225"),
        BlindFactor(
            "44efd448c275d553455802567cfc6a77fd359d8ddd4849c01aba25248f81f275"),
        BlindFactor(
            "f1afebe5bede796aefa8042311b39651060213181b84d6fe5254d1af88ba9e02"),
        ConfidentialValue(Amount::CreateByCoinAmount(0.99859100)) } };

    /** Execute Test **/
    // store before unblind txouts
    std::vector<ConfidentialTxOutReference> befere_unblind_tx_outs = ctx
        .GetTxOutList();

    // unblind transaction
    std::vector<UnblindParameter> actual_unblind_params;
    EXPECT_NO_THROW(actual_unblind_params = ctx.UnblindTxOut(blinding_keys));
    // check hex data
    EXPECT_STREQ(ctx.GetHex().c_str(), expect_tx.GetHex().c_str());
    // check return values
    EXPECT_TRUE(actual_unblind_params.size() == expect_unblind_params.size());
    for (size_t i = 0; i < expect_unblind_params.size(); ++i) {
      CheckUnblindParams(actual_unblind_params[i], expect_unblind_params[i]);
    }
    // check txout data
    std::vector<ConfidentialTxOutReference> actual_tx_outs = ctx.GetTxOutList();
    size_t unblindparam_index = 0;
    for (size_t i = 0; i < actual_tx_outs.size(); ++i) {
      if (actual_tx_outs[i].GetLockingScript().IsEmpty()) {
        continue;
      }
      CheckTxOuts(actual_tx_outs[i],
                  actual_unblind_params[unblindparam_index++],
                  befere_unblind_tx_outs[i]);
    }
  }
}

#endif  // CFD_DISABLE_ELEMENTS
