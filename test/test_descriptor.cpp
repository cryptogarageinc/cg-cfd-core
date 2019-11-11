#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_transaction.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_descriptor.h"
#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_coin.h"
#include "cfdcore/cfdcore_key.h"

using cfd::core::Txid;
using cfd::core::ByteData;
using cfd::core::CfdException;
using cfd::core::Descriptor;
using cfd::core::DescriptorNode;
using cfd::core::DescriptorNodeType;
using cfd::core::DescriptorScriptType;
using cfd::core::DescriptorKeyType;
using cfd::core::Script;
using cfd::core::Address;
using cfd::core::AddressFormatData;
using cfd::core::Pubkey;

TEST(Descriptor, Parse_pk) {
  // cfd::core::CfdCoreHandle handle = nullptr;
  // cfd::core::Initialize(&handle);
  std::string descriptor = "pk(02a5613bd857b7048924264d1e70e08fb2a7e6527d32b7ab1bb993ac59964ff397)#rk5v7uqw";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetScript());
  EXPECT_NO_THROW(desc_str = desc.ToString());
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
    "02a5613bd857b7048924264d1e70e08fb2a7e6527d32b7ab1bb993ac59964ff397 OP_CHECKSIG");
}

TEST(Descriptor, Parse_pkh) {
  std::string descriptor = "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetScript());
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "OP_DUP OP_HASH160 06afd46bcdfd22ef94ac122aa11f241244a37ecc OP_EQUALVERIFY OP_CHECKSIG");
}

TEST(Descriptor, Parse_wpkh) {
  std::string descriptor = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetScript());
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "0 7dd65592d0ab2fe0d0257d571abf032cd9db93dc");
}

TEST(Descriptor, Parse_sh_wpkh) {
  std::string descriptor = "sh(wpkh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";
  std::vector<Script> script_list;

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetScript(&script_list));
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_FALSE(desc.IsComboScript());
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "OP_HASH160 cc6ffbc0bf31af759451068f90ba7a0272b6b332 OP_EQUAL");
  EXPECT_EQ(script_list.size(), 1);
  EXPECT_STREQ(script_list[0].ToString().c_str(),
      "0 7fda9cf020c16cacf529c87d8de89bfc70b8c9cb");
}

TEST(Descriptor, Parse_combo) {
  std::string descriptor = "combo(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";
  std::vector<Script> script_list;
  std::vector<Script> combo_list;

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetScript(&script_list));
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_NO_THROW(combo_list = desc.GetScriptCombo());
  EXPECT_TRUE(desc.IsComboScript());
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "0 751e76e8199196d454941c45d1b3a323f1433bd6");
  EXPECT_EQ(script_list.size(), 0);
  EXPECT_EQ(combo_list.size(), 4);
  if (combo_list.size() == 4) {
    EXPECT_STREQ(combo_list[0].ToString().c_str(),
        "0 751e76e8199196d454941c45d1b3a323f1433bd6");
    EXPECT_STREQ(combo_list[1].ToString().c_str(),
        "OP_HASH160 bcfeb728b584253d5f3f70bcb780e9ef218a68f4 OP_EQUAL");
    EXPECT_STREQ(combo_list[2].ToString().c_str(),
        "OP_DUP OP_HASH160 751e76e8199196d454941c45d1b3a323f1433bd6 OP_EQUALVERIFY OP_CHECKSIG");
    EXPECT_STREQ(combo_list[3].ToString().c_str(),
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 OP_CHECKSIG");
  }
}

TEST(Descriptor, Parse_sh_wsh) {
  std::string descriptor = "sh(wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)))";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";
  std::vector<Script> script_list;

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetScript(&script_list));
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "OP_HASH160 55e8d5e8ee4f3604aba23c71c2684fa0a56a3a12 OP_EQUAL");
  EXPECT_EQ(script_list.size(), 2);
  if (script_list.size() == 2) {
    EXPECT_STREQ(script_list[0].ToString().c_str(),
      "0 fc5acc302aab97f821f9a61e1cc572e7968a603551e95d4ba12b51df6581482f");
    EXPECT_STREQ(script_list[1].ToString().c_str(),
      "OP_DUP OP_HASH160 c42e7ef92fdb603af844d064faad95db9bcdfd3d OP_EQUALVERIFY OP_CHECKSIG");
  }
}

TEST(Descriptor, Parse_multi) {
  std::string descriptor = "multi(1,022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc)";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";
  std::vector<Script> script_list;

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetScript(&script_list));
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "1 022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4 025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc 2 OP_CHECKMULTISIG");
  EXPECT_EQ(script_list.size(), 1);
  EXPECT_STREQ(script_list[0].ToString().c_str(),
      "1 022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4 025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc 2 OP_CHECKMULTISIG");
}

TEST(Descriptor, Parse_sh_multi) {
  std::string descriptor = "sh(multi(2,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01,03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe))";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";
  std::vector<Script> script_list;

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetScript(&script_list));
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "OP_HASH160 a6a8b030a38762f4c1f5cbe387b61a3c5da5cd26 OP_EQUAL");
  EXPECT_EQ(script_list.size(), 1);
  if (script_list.size() == 1) {
    EXPECT_STREQ(script_list[0].ToString().c_str(),
        "2 022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01 03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe 2 OP_CHECKMULTISIG");
  }
}

TEST(Descriptor, Parse_sortedmulti) {
  std::string descriptor = "sh(sortedmulti(2,03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01))";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";
  std::vector<Script> script_list;

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetScript(&script_list));
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "OP_HASH160 a6a8b030a38762f4c1f5cbe387b61a3c5da5cd26 OP_EQUAL");
  EXPECT_EQ(script_list.size(), 1);
  if (script_list.size() == 1) {
    EXPECT_STREQ(script_list[0].ToString().c_str(),
      "2 022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01 03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe 2 OP_CHECKMULTISIG");
  }
}

TEST(Descriptor, Parse_wsh_multi) {
  std::string descriptor = "wsh(multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a))";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";
  std::vector<Script> script_list;

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetScript(&script_list));
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "0 773d709598b76c4e3b575c08aad40658963f9322affc0f8c28d1d9a68d0c944a");
  EXPECT_EQ(script_list.size(), 1);
  if (script_list.size() == 1) {
    EXPECT_STREQ(script_list[0].ToString().c_str(),
      "2 03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7 03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb 03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a 3 OP_CHECKMULTISIG");
  }
}

TEST(Descriptor, Parse_sh_wsh_multi) {
  std::string descriptor = "sh(wsh(multi(1,03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8,03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e)))";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";
  std::vector<Script> script_list;

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetScript(&script_list));
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "OP_HASH160 aec509e284f909f769bb7dda299a717c87cc97ac OP_EQUAL");
  EXPECT_EQ(script_list.size(), 2);
  if (script_list.size() == 2) {
    EXPECT_STREQ(script_list[0].ToString().c_str(),
      "0 ef8110fa7ddefb3e2d02b2c1b1480389b4bc93f606281570cfc20dba18066aee");
    EXPECT_STREQ(script_list[1].ToString().c_str(),
      "1 03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8 03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4 02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e 3 OP_CHECKMULTISIG");
  }
}

TEST(Descriptor, Parse_addr) {
  std::string descriptor = "addr(bc1qc7slrfxkknqcq2jevvvkdgvrt8080852dfjewde450xdlk4ugp7szw5tk9)";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetScript());
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "0 c7a1f1a4d6b4c1802a59631966a18359de779e8a6a65973735a3ccdfdabc407d");
}

TEST(Descriptor, Parse_raw) {
  std::string descriptor = "raw(6a4c4f54686973204f505f52455455524e207472616e73616374696f6e206f7574707574207761732063726561746564206279206d6f646966696564206372656174657261777472616e73616374696f6e2e)#zf2avljj";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetScript());
  EXPECT_NO_THROW(desc_str = desc.ToString());
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(), "OP_RETURN 54686973204f505f52455455524e207472616e73616374696f6e206f7574707574207761732063726561746564206279206d6f646966696564206372656174657261777472616e73616374696f6e2e");
}

TEST(Descriptor, Parse_pk_extkey) {
  std::string descriptor = "pk(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8)";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetScript());
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(), "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2 OP_CHECKSIG");
}

TEST(Descriptor, Parse_pkh_extkey) {
  // m/1'/2 -> m/1/2 : hardened is privkey only.
  std::string descriptor = "pkh(xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw/1/2)";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";

  try {
    desc = Descriptor::Parse(descriptor);
  } catch (const CfdException& except) {
    EXPECT_STREQ(except.what(), "");
  }
  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetScript());
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(), "OP_DUP OP_HASH160 f833c08f02389c451ae35ec797fccf7f396616bf OP_EQUALVERIFY OP_CHECKSIG");
}

TEST(Descriptor, Parse_pkh_extkey_derive) {
  std::string descriptor = "pkh([d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*)";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";
  Script gen_script;

  try {
    desc = Descriptor::Parse(descriptor);
  } catch (const CfdException& except) {
    EXPECT_STREQ(except.what(), "");
  }
  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_THROW(locking_script = desc.GetScript(), CfdException);
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_NO_THROW(locking_script = desc.GenerateScript("0"));
  EXPECT_NO_THROW(gen_script = desc.GenerateScript("0/44"));
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
    "OP_DUP OP_HASH160 2a05c214617c9b0434c92d0583200a85ef61818f OP_EQUALVERIFY OP_CHECKSIG");
  EXPECT_STREQ(gen_script.ToString().c_str(),
    "OP_DUP OP_HASH160 c463e6dedb2b780434e60fcee3f2d0a0fbcbbc90 OP_EQUALVERIFY OP_CHECKSIG");
}

TEST(Descriptor, Parse_wsh_extkey_derive) {
  std::string descriptor = "wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";
  Script gen_script;
  std::vector<Script> script_list;
  std::vector<Script> script_list2;

  try {
    desc = Descriptor::Parse(descriptor);
  } catch (const CfdException& except) {
    EXPECT_STREQ(except.what(), "");
  }
  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_THROW(locking_script = desc.GetScript(&script_list), CfdException);
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_NO_THROW(locking_script = desc.GenerateScript("0", &script_list));
  EXPECT_NO_THROW(gen_script = desc.GenerateScript("0/44", &script_list2));
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
    "0 64969d8cdca2aa0bb72cfe88427612878db98a5f07f9a7ec6ec87b85e9f9208b");
  EXPECT_STREQ(gen_script.ToString().c_str(),
    "0 2070830c75de894b00286a87cbbb201aaec3487b5891dbf657c0500e11efa27d");

  EXPECT_EQ(script_list.size(), 1);
  if (script_list.size() == 1) {
    EXPECT_STREQ(script_list[0].ToString().c_str(),
      "1 0205f8f73d8a553ad3287a506dbd53ed176cadeb200c8e4f7d68a001b1aed87106 02c04c4e03921809fcbef9a26da2d62b19b2b4eb383b3e6cfaaef6370e75144774 2 OP_CHECKMULTISIG");
  }

  EXPECT_EQ(script_list2.size(), 1);
  if (script_list2.size() == 1) {
    EXPECT_STREQ(script_list2[0].ToString().c_str(),
      "1 026e636c42ce086d19aae89eca84e95d568bad8a166b9e99b0e27041caab905f38 02bbd047b8f3dac46297e337fb91043fb7c211be89e6068f156e065ebe7fcca01c 2 OP_CHECKMULTISIG");
  }
}

TEST(Descriptor, GetNode_sh_wsh) {
  std::string descriptor = "sh(wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)))";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";
  std::vector<Script> script_list;
  DescriptorNode node;

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(node = desc.GetNode());
  EXPECT_STREQ(node.ToString(false).c_str(), descriptor.c_str());
}

#ifndef CFD_DISABLE_ELEMENTS
TEST(Descriptor, ParseElements_addr) {
  std::string descriptor = "addr(ert1qcc5c9wnzly8zj2dcsvxv83kupsu0uamx69u0y9lsmw7shuns2gqsflana4)";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";

  EXPECT_NO_THROW(desc = Descriptor::ParseElements(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetScript());
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "0 c62982ba62f90e2929b8830cc3c6dc0c38fe7766d178f217f0dbbd0bf2705201");
}
#endif  // CFD_DISABLE_ELEMENTS
