// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_elements_address.h
 *
 * @brief Elements対応したAddressクラス定義
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_ELEMENTS_ADDRESS_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_ELEMENTS_ADDRESS_H_
#ifndef CFD_DISABLE_ELEMENTS

#include <string>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_script.h"

namespace cfdcore {

/**
 * @brief ConfidentialKey(= Pubkey)の型定義
 * @see Pubkey
 */
using ConfidentialKey = Pubkey;

/**
 * @typedef ElementsNetType
 * @brief Elements Networkの定義
 */
enum ElementsNetType {
  kLiquidV1 = 0,       //!< Liquid mainnet(v1)
  kElementsRegtest,    //!< regtest
  kElementsNetTypeNum  //!< NETTYPE_NUM
};

/**
 * @struct ElementsNetParams
 * @brief ElementsNetType毎の各種パラメータ定義
 */
typedef struct {
  std::string name;              //!< name of Elements Network
  uint8_t p2pkh_addr_id;         //!< P2PKH address prefix
  uint8_t p2sh_addr_id;          //!< P2SH address prefix
  uint8_t confidential_addr_id;  //!< Confidential address prefix
  // (Elements doesn't implemented yet?)
  //  std::string bech32_hrp;  //!< bech32 human-readable part
} ElementsNetParams;

/**
 * @typedef ElementsAddressType
 * @brief ElementsのAddress種別の定義
 */
enum ElementsAddressType {
  kElementsP2shAddress = 1,  //!< Legacy address (Script Hash)
  kElementsP2pkhAddress,     //!< Legacy address (PublicKey Hash)
                             // (Elements doesn't support yet?)
  //  kP2wshAddress,  //!< segwit address (Script Hash)
  //  kP2wpkhAddress  //!< segwit address (PublicKey Hash)
  kUnknownElementsAddressType  //!< Unknown address type
};

/**
 * @class AbstractElementsAddress
 * @brief Elementsで使用するアドレスの基底クラス
 */
class CFD_CORE_EXPORT AbstractElementsAddress {
 public:
  /**
   * @brief コンストラクタ
   * @param[in] is_blinded  blindアドレスかどうか
   * @param[in] address     アドレス文字列
   */
  explicit AbstractElementsAddress(bool is_blinded, std::string address);

  /**
   * @brief コンストラクタ
   * @param[in] is_blinded  blindアドレスかどうか
   * @param[in] address     アドレス文字列
   * @param[in] type        ElementsNetType
   * @param[in] addr_type   アドレス種別
   * @param[in] hash        ハッシュデータ(P2PKH: PubkeyHash, P2SH: ScriptHash)
   */
  explicit AbstractElementsAddress(
      bool is_blinded, std::string address, ElementsNetType type,
      ElementsAddressType addr_type, const ByteData160& hash);

  /**
   * @brief デストラクタ
   */
  virtual ~AbstractElementsAddress() {
    // do nothing.
  }

  /**
   * @brief Blindアドレスかどうかを返却する.
   * @retval true Blindedアドレス
   * @retval false UnBlindedアドレス
   */
  bool IsBlinded() const { return is_blinded_; }

  /**
   * @brief アドレスのhex文字列を取得する.
   * @return アドレス文字列
   */
  std::string GetAddress() const { return address_; }

  /**
   * @brief AddressのElementsNetTypeを取得する.
   * @return ElementsNetType
   */
  virtual ElementsNetType GetNetType() const { return type_; }

  /**
   * @brief Address種別を取得する.
   * @return Elements Address種別
   */
  virtual ElementsAddressType GetAddressType() const { return addr_type_; }

  /**
   * @brief アドレスHashを取得する.
   * @return アドレスHashのByteDataインスタンス
   */
  virtual ByteData GetHash() const { return hash_; }

  /**
   * @brief 引数で指定されたアドレスがBlindされているアドレスであるかを判定する
   * @param address アドレス(base58)文字列
   * @retval true Blindされているアドレスの場合
   * @retval false Blindされていないアドレスの場合
   */
  static bool IsConfidentialAddress(std::string address);

 protected:
  /// Blindアドレスかどうか
  bool is_blinded_;

  /// アドレス文字列
  std::string address_;

  //! アドレスのElementsNetType
  ElementsNetType type_;

  //! Elements アドレス種別
  ElementsAddressType addr_type_;

  //! アドレスHash
  ByteData hash_;
};

/**
 * @class ElementsUnblindedAddress
 * @brief ElementsのUnblindedアドレスを表現するクラス
 */
class CFD_CORE_EXPORT ElementsUnblindedAddress
    : public AbstractElementsAddress {
 public:
  /**
   * @brief デフォルトコンストラクタ
   */
  ElementsUnblindedAddress();

  /**
   * @brief コンストラクタ(hex文字列からの復元)
   * @param[in] address_string   アドレス文字列
   */
  explicit ElementsUnblindedAddress(const std::string& address_string);

  /**
   * @brief コンストラクタ(P2PKH用)
   * @param[in] type      ElementsNetType
   * @param[in] pubkey    PublicKey
   */
  ElementsUnblindedAddress(ElementsNetType type, const Pubkey& pubkey);

  /**
   * @brief コンストラクタ(P2SH用)
   * @param[in] type          ElementsNetType
   * @param[in] redeem_script Redeem Script
   */
  ElementsUnblindedAddress(ElementsNetType type, const Script& redeem_script);

  /**
   * @brief コンストラクタ(P2PKH/P2SH Hash用。AddressType明示)
   * @param[in] type          ElementsNetType
   * @param[in] addr_type     アドレス種別
   * @param[in] hash          hashed Pubkey/Script
   */
  ElementsUnblindedAddress(
      ElementsNetType type, ElementsAddressType addr_type,
      const ByteData160& hash);

 private:
  /**
   * @brief Addressを算出する.
   */
  void CalculateAddress();

  /**
   * @brief Address(P2PKH/P2SH)の情報を算出する.
   * @param[in] prefix      Elements Address prefix(P2PKH or P2SH address prefix)
   * @param[in] hash_data   ハッシュデータ(P2PKH: PubkeyHash, P2SH: ScriptHash)
   */
  void CalculateAddress(const uint8_t prefix, const ByteData& hash_data);

  /* Elements Segwit Address Format(P2SH Wrapped Segwit)
   *
   * 例：GuxEjrPyiFqaM7vk4wLu2ct6c1RwMeg2AT
   * Decode Base58:278c1651b2a550855525caa9bf636821b97042517d
   *
   * "27" : Elements P2SH Prefix
   * "78c1651b2a550855525caa9bf636821b97042517d"
   *      : 下のwitness scriptのhash160
   * witness script(hex) = "0014a0f3b1624a9a7d79b93d36e53e6d1d3821d9fc48"
   *    "00" ：witness version
   *    "14" ：data長(P2WPKHは20byte/P2WSHは32byte)
   *    "a0f3b1624a9a7d79b93d36e53e6d1d3821d9fc48"
   *         ：witness program(PubkeyHash or ScriptHash)
   */
  /**
   * @brief 文字列をdecodeする.
   * @param[in] unblinded_address デコードするElementsアドレスのbase58文字列
   */
  void DecodeAddress(std::string unblinded_address);
};

/**
 * @class ElementsConfidentialAddress
 * @brief ElementsのConfidentialアドレスを表現するクラス
 */
class CFD_CORE_EXPORT ElementsConfidentialAddress
    : public AbstractElementsAddress {
 public:
  /**
   * @brief デフォルトコンストラクタ
   */
  ElementsConfidentialAddress();

  /**
   * @brief コンストラクタ(UnblindedAddressからConfidentialAddress生成)
   * @param unblinded_address UnblindedAddress インスタンス
   * @param confidential_key  ConfidentialKey インスタンス
   */
  ElementsConfidentialAddress(
      const ElementsUnblindedAddress& unblinded_address,
      const ConfidentialKey& confidential_key);

  /**
   * @brief コンストラクタ(ConfidentialAddress文字列からのデコード)
   * @param confidential_address confidential アドレス文字列
   */
  explicit ElementsConfidentialAddress(
      const std::string& confidential_address);

  /**
   * @brief UnblindedAddressを取得
   * @return ConfidentialAddressに紐づくUnblindedAddressインスタンス
   */
  ElementsUnblindedAddress GetUnblindedAddress() const {
    return unblinded_address_;
  }

  /**
   * @brief ConfidentialKeyを取得
   * @return ConfidentialAddressに紐づくConfidentialKeyインスタンス
   */
  ConfidentialKey GetConfidentialKey() const { return confidential_key_; }

 private:
  /**
   * @brief confidentialアドレス文字列からモデルのデコードを行う
   * @param[in] confidential_address confidentialアドレス文字列
   */
  void DecodeAddress(const std::string& confidential_address);

  /**
   * @brief unblinded_addressとconfidential_keyから、confidential_addressを計算する.
   * @details Elementsのネットワーク種別については、ublinded_addressと同種のネットワークで計算を行う.
   * @param unblinded_address UnblindedAddressインスタンス
   * @param confidential_key Blindに利用するConfidentialKeyインスタンス
   */
  void CalculateAddress(
      const ElementsUnblindedAddress& unblinded_address,
      const ConfidentialKey& confidential_key);

  /// Unblinded Address
  ElementsUnblindedAddress unblinded_address_;

  /// Confidential Key
  ConfidentialKey confidential_key_;
};

}  // namespace cfdcore

#endif  // CFD_DISABLE_ELEMENTS
#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_ELEMENTS_ADDRESS_H_
