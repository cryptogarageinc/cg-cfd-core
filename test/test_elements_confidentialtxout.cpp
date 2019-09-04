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
using cfdcore::ConfidentialTxOut;
using cfdcore::Amount;
using cfdcore::ConfidentialTxOutReference;

static const Script exp_script("0014fd1cd5452a43ca210ba7153d64227dc32acf6dbb");
static const ConfidentialAssetId exp_asset(
    "0a7f0c8d0a4e6fb92c63893345facbd99dc603dc1cd18c73e5700bd9a0babb1f0b");
static const ConfidentialValue exp_value(
    "09b6e7605917e27f35690dcae922f664c8a3b057e2c6249db6cd304096aa87a226");
static const ConfidentialNonce exp_nonce(
    "02c384a78ae89b9600a8d2b4ddb3090ba5dad224ff4b85e6868f2916ca64314ad9");
static const ByteData exp_surjection_proof(
    "0100017bb5ec655fa87e4cca4ed7bf37ae35d4e80d741cf1f86f8d0694f2b4e3ec9e2e72bea4cab89abddd262d016105b25b2b57ea3f304967a7b8093fc3da2f633708");
static const ByteData exp_range_proof(
    "602300000000000000018b000057b997ddb73af528b42ae583656ddeeb1bfa72ffee8eb0aec74ddf54d70c7bf6f7d2d8916a986b4c2fced512897d07a9ac79a7f17847adcb2153898b1199415117d2c7286413c97e6774fc4cd4c8ab56da30bb728670768d71242c763b00436e6b004ff98b79de797922c35a250fe471940eac9f1b63b316b34eac7c960d089551d8ef6d393d16f4eb325d7c6d4904a8f09a1ed78dbadfb2af4e9cf71c3c89ca42d45d50f2baa86c8921d91ab8f051c6844b8303f94aa6f1918181d0e072db0126fac6993ac0512f29b2ff2757a9819fb44a4978f21eeb6d1b55c8e57bbdc3290b7eca9f0f3653e3b2edcb76c08557ca48d418c92c716772c7723263532feddb16e1855b4c487f5ae546f1c5e375c3aed47a9104b9588e0880f91ecf51c0ce37e32367f265b904d195edf8d42f87a44f5cfa50f4c03df9621edbfc0e7d7ce06644d6eaac70f83904d65f60e8ff50536036b3063e4a65356acfd3e78e76755532c3e32d5c515ba1f3c7f504c1669b32479b1023730e1d4eefda59a1793eb7970d91ee98e7902caaa77fd50c56a10d5718588b1e434ecdc2334c0fecf4f53d55829c3058f17c209c3fb554e3dcc646b76b9ee4416168b240fd3ac15da6f49fca2a35c317489ab555f2868b07de03c873c0dc3525da0552e10afc11bc68b357f059017fea4c84fd83c7a07ab333ae0e262f479f5f48d53c4e84b961da7aeb5add83149cfca6914a4f755046c94836b23dbb0678d00cb2c48d15e424c275efb53845b1ad7968e569440773758e7f981a5c9f6831d6a52c115553db12df754c02e34b4f16db5ef362b1be0b94905442179677848d3ae0eb7ad5de47c28c48870dc08e1a3e4221977f3599319d1207de033025b571176eabaa20eea38db4070c3f09715afa2079765e35d079953b1228f6b781a18a92568c1ff608d135170b6ade9dd5282f0c21c40bb8240841ef1e6c54c920d9a50746c8bc161ee2a1693e2733966ba0bad17b34b10494683636fddeda80d984ce860af49ce96c49fdb69c779938115531abf4d361732787ac61e026f18c060fcb819adb62f16d1567e06a41662d633d2cdbfe211d68c70b1e51e27376b6472fbc67969ece59c0a2f7c39224f954730a384cf8fc6f2749a9c326978d881e955d6e0ab56e560a55b1702f765dbec1c6856c26d3c3c08c022f38cf2d3d92f9020dbb37966ce86d27d41c8f156600e928b6edf9450d4cbaa5f9b3a3fa8f8f492c8a4d0660e37b80a2ae7d4ecca955a1bc217f74b2776a18007c6d88630d8cb0f7f3c111663617f6b92ca272fdccbc4d90fa6f9b02b238db93b76ad1ffcf2920863c79de762a06e6ab538d491f2cca8fb4556b533b0584dbee0490c4adad9c00e0c8eb58874c8049db4b93404e47e8eed9719a8e4ecd5bffe16e853fe0d1e6c35ae99a91fd9febb4a3ca5b55206aa4e9f62fed1de1c550ccc871ddbb43e5aa60bb43487081b4e4be62cad18943deebef9370a6fdb98c3963688c6a887d6ebfed2ed774575e794526a4c5cec42ff98fc8abfa27775253662613f0389c70900e31bfb812dd458a71b53dfffcef0efba36627003cf6722362e717113c620764a1a361a9421e5ded53a9c6873319cca3763723aef0b7322eddba25673b48b8c3c25223ef8c11b408c2c9614082c85b68f987af065eb8a5fab99897c1c3a303c3d6aae5dd37cd6777f44e760e978632f0784e0b8bf5401c787ce66499888db906aef9cde617214f780d2a2ce193583aec36941b05dea17702c3562c027a99ee3b29cf0f5c74981fcf370c0c56548f626a08712e999a77dcbbf4bc06fdc390172e36f58867ec614815fac2d70b8bf4c3b1f29d100525381564b953b671f7084679f9a1196b8413f75c00b9f71a58c1d7541c3e08a215d61637d69063316e67df1c7fb263828635d1fbdee2d2a223950ad955f6ae6c690362f444e0c44f21627b15244fc3630313abb0d275f0f0014a86d16160345cfbbd430956adbc65dcb25c597d0ed33e30c749c78e630edfb72008729ac1ab8e6f09bc65dd8134d4f7762548b78255b3c64801fe49a392661a7a44c2cd507e243ba21b50ae9c5047789fd77df801c3def4ba8539d7daff99063e599920afc99b686848e35fb2092c8e502b3fd0c97a5d8e6aa3ebb49b20b64084a9c2b2b87c51fc75fa374530347b8aa856d93e9db98917f78c7b44718b64a0d6c5ad2615ab852912a691289d102285b3ea360d66d9e381c279a785a722895c24a2efb456724e2ba39cecdee11f79dac20917b9ebcd5284445ecc9c6ca288f7cef117f83a55541a520fa6468dcd1c48d2b84d1de60e25b292985635509fbb99296eae6655e47392b304d68f0a949e216601f04f12d61e89e8026f2bf03dfef1b47dad6471d106aa114938e6bc82318962ff5e8c5ed8e510ac313135fac1ad948b3c1ed1b898ff666f9c9840a8d39a11725dbfdde99c953c6a1cc9d60273fceeb93a538a0cb70456852d79d768507889c7431691e50fe3deb78697024561e873041bdfeacf527573a3486af3811140ba4ade4278d388f1b9498214cc10f8861cabd4ad24c74f6a469c552b297a126b7429e18982619a3a226bb530d58c6ed97a06aa0574594021f87cea4bfcad2577bb0f206a9871a408717d8ba3edaa7c93b2c609d771c8d9fab8ad637b1779d8742b127d7acd1dcb8610b3f4aa834882213e92b02cf8259653e46824c637c0963c4a6bc0a258b96c16004336ac11c5086e9f68995d81cf53b718824936f43aa179d47815afa73f875e545e6affd2b06d93b9b2be2a1a90adc51c4eba4faaa1c1682e435009d58d6565a18df92ad45178b71a53a7af0cc872cf6fc923bf63ca4360f1dd7dd1c9e28bebc4d412eea924945449210489798907e48222a079607b1fcdf0be09bf25d9dbba09e4b677f2b67afe18fc38b125dee82d0c3e7289f5e3c437fa5ffe5f5edfddab956be976c3493442961da351145ed70f0e96bb4efff14e4fee83aefd2bc9aee4b592f29be12dcdfd127b5522465686f5c667982410216b89404429fd57e2f04419110efb30e67a6bfb19ecf2e58a0024a717d22baf360c9a64e0689c245a2c0309d5aac3f88c7aa38e0eb77c23854b29c53aec38b004fd20c50c91becb9e094a1b5ccb5bf678304d326b4a14e3f0ba7165e2ce3773c7feb0a0e6c06ef5d4e21b57cdde81ff77afb50125cf4e29c8b18783790a4695d23b439a8591b2eaaa0a664f11c1f2d3231e6fd0da8292f3d77888717c91c298b5f7219c1380148a6390003423554c2a23e17275b2ec254a4dd4f08ffbf6488839be5d76e30545280f520f1a56a464ffb3eed9e5f949a0356dc2983d591e6027945c234ceed8ac40f0e7ab2757e9bf5b46fdae07e9fcc34bc57ce60d1afc3bfbd6aa75cef3fe3f9f55940ffaac02fb4e7daaf4bae694aaecbff2f3944c5117d08948e8cdc130215cc43ad99b244b7e335feecfa6f5ad8cfcfa3a1fae008fbf66d1304c2c962418306b5fb63fb41bd6543cbde9831b07deae90ec7aac53b79e21289382b338def494e949cbb8522f35d577ebafd5585d046584a8f200680be6a8410bb92630b1ff9d6e770a6e09dec6ba59a1a7ed21ed0520b8a99c65a45391b44bac1efac2f004ad5c395e64ca0f2fc808fe6441d5bef2e583600aa15b4e802b3fb2e548ea3b7bb8cb3980739905b04ed25cc01999504b1291c9aff12987ab00b8636ae13a69fb47abfdecf18b6cc881caf74dad934397c2715d49fd11ac451385c14f348fa7430fa13e2f7c5e0af9cb4883bf2c653811b28906ae33fbb21b721d3ba0d22f69aa2c209c8b0b2d19bd61dbf7ebfcc6ca9bdac1bdb6c17d16b05f59f4c5112ce7f2631b12c6945d541d1979de328ee5576e770a0f24ef5a95c62f650ca84d8e0ce33e6b15aca29ef6c407000beb846ff033dca353c2cce3832cca61196856effc5f939b034ae6e7c9e099f84b67ca904f018b4c8bc685098cfc9cb4630ceea66b42d21a4e9770f532a015876c810fddfe58dfc7515e494d5e7e772937d18992ae9aea3670dacba342aae96b08a7693c5da1645023");

TEST(ConfidentialTxOut, DefaultConstractor) {
  // default constructor
  ConfidentialTxOut txout;
  EXPECT_STREQ(txout.GetAsset().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetConfidentialValue().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetLockingScript().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetNonce().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetRangeProof().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetSurjectionProof().GetHex().c_str(), "");
  EXPECT_EQ(txout.GetValue().GetSatoshiValue(), 0);

  ConfidentialTxOutReference txout_ref(txout);
  EXPECT_STREQ(txout_ref.GetAsset().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetConfidentialValue().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetLockingScript().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetNonce().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetRangeProof().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetSurjectionProof().GetHex().c_str(), "");
  EXPECT_EQ(txout_ref.GetValue().GetSatoshiValue(), 0);
}

TEST(ConfidentialTxOut, Constractor1) {
  // Script, ConfidentialAssetId, ConfidentialValue
  ConfidentialTxOut txout(exp_script, exp_asset, exp_value);
  EXPECT_STREQ(txout.GetAsset().GetHex().c_str(), exp_asset.GetHex().c_str());
  EXPECT_STREQ(txout.GetConfidentialValue().GetHex().c_str(),
               exp_value.GetHex().c_str());
  EXPECT_STREQ(txout.GetLockingScript().GetHex().c_str(),
               exp_script.GetHex().c_str());
  EXPECT_STREQ(txout.GetNonce().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetRangeProof().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetSurjectionProof().GetHex().c_str(), "");
  EXPECT_EQ(txout.GetValue().GetSatoshiValue(), 0);

  ConfidentialTxOutReference txout_ref(txout);
  EXPECT_STREQ(txout_ref.GetAsset().GetHex().c_str(),
               exp_asset.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetConfidentialValue().GetHex().c_str(),
               exp_value.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetLockingScript().GetHex().c_str(),
               exp_script.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetNonce().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetRangeProof().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetSurjectionProof().GetHex().c_str(), "");
  EXPECT_EQ(txout_ref.GetValue().GetSatoshiValue(), 0);
}

TEST(ConfidentialTxOut, Constractor2) {
  // Script, ConfidentialAssetId, ConfidentialValue, ConfidentialNonce, ByteData, ByteData
  ConfidentialTxOut txout(exp_script, exp_asset, exp_value, exp_nonce,
                          exp_surjection_proof, exp_range_proof);
  EXPECT_STREQ(txout.GetAsset().GetHex().c_str(), exp_asset.GetHex().c_str());
  EXPECT_STREQ(txout.GetConfidentialValue().GetHex().c_str(),
               exp_value.GetHex().c_str());
  EXPECT_STREQ(txout.GetLockingScript().GetHex().c_str(),
               exp_script.GetHex().c_str());
  EXPECT_STREQ(txout.GetNonce().GetHex().c_str(), exp_nonce.GetHex().c_str());
  EXPECT_STREQ(txout.GetRangeProof().GetHex().c_str(),
               exp_range_proof.GetHex().c_str());
  EXPECT_STREQ(txout.GetSurjectionProof().GetHex().c_str(),
               exp_surjection_proof.GetHex().c_str());
  EXPECT_EQ(txout.GetValue().GetSatoshiValue(), 0);

  ConfidentialTxOutReference txout_ref(txout);
  EXPECT_STREQ(txout_ref.GetAsset().GetHex().c_str(),
               exp_asset.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetConfidentialValue().GetHex().c_str(),
               exp_value.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetLockingScript().GetHex().c_str(),
               exp_script.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetNonce().GetHex().c_str(),
               exp_nonce.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetRangeProof().GetHex().c_str(),
               exp_range_proof.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetSurjectionProof().GetHex().c_str(),
               exp_surjection_proof.GetHex().c_str());
  EXPECT_EQ(txout_ref.GetValue().GetSatoshiValue(), 0);
}

TEST(ConfidentialTxOut, Constractor3) {
  // ConfidentialAssetId, ConfidentialValue
  ConfidentialTxOut txout(exp_asset, exp_value);
  EXPECT_STREQ(txout.GetAsset().GetHex().c_str(), exp_asset.GetHex().c_str());
  EXPECT_STREQ(txout.GetConfidentialValue().GetHex().c_str(),
               exp_value.GetHex().c_str());
  EXPECT_STREQ(txout.GetLockingScript().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetNonce().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetRangeProof().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetSurjectionProof().GetHex().c_str(), "");
  EXPECT_EQ(txout.GetValue().GetSatoshiValue(), 0);

  ConfidentialTxOutReference txout_ref(txout);
  EXPECT_STREQ(txout_ref.GetAsset().GetHex().c_str(),
               exp_asset.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetConfidentialValue().GetHex().c_str(),
               exp_value.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetLockingScript().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetNonce().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetRangeProof().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetSurjectionProof().GetHex().c_str(), "");
  EXPECT_EQ(txout_ref.GetValue().GetSatoshiValue(), 0);
}

TEST(ConfidentialTxOut, Setter) {
  ConfidentialTxOut txout;

  EXPECT_STREQ(txout.GetAsset().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetConfidentialValue().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetLockingScript().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetNonce().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetRangeProof().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetSurjectionProof().GetHex().c_str(), "");
  EXPECT_EQ(txout.GetValue().GetSatoshiValue(), 0);

  txout.SetValue(Amount::CreateBySatoshiAmount(100000000));

  EXPECT_STREQ(txout.GetAsset().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetConfidentialValue().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetLockingScript().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetNonce().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetRangeProof().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetSurjectionProof().GetHex().c_str(), "");
  EXPECT_EQ(txout.GetValue().GetSatoshiValue(), 100000000);

  txout.SetCommitment(exp_asset, exp_value, exp_nonce, exp_surjection_proof,
                      exp_range_proof);

  EXPECT_STREQ(txout.GetAsset().GetHex().c_str(), exp_asset.GetHex().c_str());
  EXPECT_STREQ(txout.GetConfidentialValue().GetHex().c_str(),
               exp_value.GetHex().c_str());
  EXPECT_STREQ(txout.GetLockingScript().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetNonce().GetHex().c_str(), exp_nonce.GetHex().c_str());
  EXPECT_STREQ(txout.GetRangeProof().GetHex().c_str(),
               exp_range_proof.GetHex().c_str());
  EXPECT_STREQ(txout.GetSurjectionProof().GetHex().c_str(),
               exp_surjection_proof.GetHex().c_str());
  EXPECT_EQ(txout.GetValue().GetSatoshiValue(), 100000000);

  ConfidentialTxOutReference txout_ref(txout);
  EXPECT_STREQ(txout_ref.GetAsset().GetHex().c_str(),
               exp_asset.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetConfidentialValue().GetHex().c_str(),
               exp_value.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetLockingScript().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetNonce().GetHex().c_str(),
               exp_nonce.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetRangeProof().GetHex().c_str(),
               exp_range_proof.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetSurjectionProof().GetHex().c_str(),
               exp_surjection_proof.GetHex().c_str());
  EXPECT_EQ(txout_ref.GetValue().GetSatoshiValue(), 100000000);
}

#endif  // CFD_DISABLE_ELEMENTS
