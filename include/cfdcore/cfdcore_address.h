// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_address.h
 *
 * @brief Addressクラス定義
 *
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_ADDRESS_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_ADDRESS_H_

#include <string>
#include <vector>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_script.h"

/**
 * @brief cfdcore名前空間
 */
namespace cfdcore {

/**
 * @struct NetParams
 * @brief NetType毎の各種パラメータ定義
 */
typedef struct {
  std::string name;        //!< name of Bitcoin Network
  NetType type;            //!< network type
  uint8_t p2pkh_addr_id;   //!< First byte of a P2PKH address
  uint8_t p2sh_addr_id;    //!< First byte of a P2SH address
  std::string bech32_hrp;  //!< bech32 human-readable part
} NetParams;

/**
 * @typedef AddressType
 * @brief Address種別の定義
 */
enum AddressType {
  kP2shAddress = 1,   //!< Legacy address (Script Hash)
  kP2pkhAddress,      //!< Legacy address (PublicKey Hash)
  kP2wshAddress,      //!< Native segwit address (Script Hash)
  kP2wpkhAddress,     //!< Native segwit address (PublicKey Hash)
  kP2shP2wshAddress,  //!< P2sh wrapped address (Script Hash)
  kP2shP2wpkhAddress  //!< P2sh wrapped address (Pubkey Hash)
};

/**
 * @typedef WitnessVersion
 * @brief Witnessバージョンの定義
 */
enum WitnessVersion {
  kVersionNone = -1,  //!< Missing WitnessVersion
  kVersion0 = 0,      //!< version 0
  kVersion1,          //!< version 1 (for future use)
  kVersion2,          //!< version 2 (for future use)
  kVersion3,          //!< version 3 (for future use)
  kVersion4,          //!< version 4 (for future use)
  kVersion5,          //!< version 5 (for future use)
  kVersion6,          //!< version 6 (for future use)
  kVersion7,          //!< version 7 (for future use)
  kVersion8,          //!< version 8 (for future use)
  kVersion9,          //!< version 9 (for future use)
  kVersion10,         //!< version 10 (for future use)
  kVersion11,         //!< version 11 (for future use)
  kVersion12,         //!< version 12 (for future use)
  kVersion13,         //!< version 13 (for future use)
  kVersion14,         //!< version 14 (for future use)
  kVersion15,         //!< version 15 (for future use)
  kVersion16          //!< version 16 (for future use)
};

/**
 * @class Address
 * @brief ビットコインアドレスの生成クラス
 */
class CFD_CORE_EXPORT Address {
 public:
  /**
   * @brief デフォルトコンストラクタ
   */
  Address();

  /**
   * @brief コンストラクタ(hex文字列からの復元)
   * @param[in] address_string   アドレス文字列
   */
  explicit Address(const std::string& address_string);
  /**
   * @brief コンストラクタ(hex文字列からの復元)
   * @param[in] address_string      アドレス文字列
   * @param[in] network_parameters  network parameter list
   */
  explicit Address(
      const std::string& address_string,
      const std::vector<NetParams>& network_parameters);

  /**
   * @brief コンストラクタ(P2PKH用)
   * @param[in] type      NetType
   * @param[in] pubkey    PublicKey
   */
  Address(NetType type, const Pubkey& pubkey);
  /**
   * @brief コンストラクタ(P2PKH用)
   * @param[in] type      NetType
   * @param[in] pubkey    PublicKey
   * @param[in] prefix    p2pkh prefix
   */
  Address(NetType type, const Pubkey& pubkey, uint8_t prefix);
  /**
   * @brief コンストラクタ(P2PKH用)
   * @param[in] type      NetType
   * @param[in] pubkey    PublicKey
   * @param[in] network_parameter   network parameter
   */
  Address(
      NetType type, const Pubkey& pubkey, const NetParams& network_parameter);

  /**
   * @brief コンストラクタ(P2WPKH用)
   * @param[in] type        NetType
   * @param[in] witness_ver Witnessバージョン
   * @param[in] pubkey      PublicKey
   */
  Address(NetType type, WitnessVersion witness_ver, const Pubkey& pubkey);
  /**
   * @brief コンストラクタ(P2WPKH用)
   * @param[in] type        NetType
   * @param[in] witness_ver Witnessバージョン
   * @param[in] pubkey      PublicKey
   * @param[in] bech32_hrp  bech32 hrp
   */
  Address(
      NetType type, WitnessVersion witness_ver, const Pubkey& pubkey,
      const std::string& bech32_hrp);
  /**
   * @brief コンストラクタ(P2WPKH用)
   * @param[in] type        NetType
   * @param[in] witness_ver Witnessバージョン
   * @param[in] pubkey      PublicKey
   * @param[in] network_parameter   network parameter
   */
  Address(
      NetType type, WitnessVersion witness_ver, const Pubkey& pubkey,
      const NetParams& network_parameter);

  /**
   * @brief コンストラクタ(P2SH用)
   * @param[in] type          NetType
   * @param[in] redeem_script Redeem Script
   */
  Address(NetType type, const Script& redeem_script);
  /**
   * @brief コンストラクタ(P2SH用)
   * @param[in] type          NetType
   * @param[in] redeem_script Redeem Script
   * @param[in] prefix        p2sh prefix
   */
  Address(NetType type, const Script& redeem_script, uint8_t prefix);
  /**
   * @brief コンストラクタ(P2SH用)
   * @param[in] type          NetType
   * @param[in] redeem_script Redeem Script
   * @param[in] network_parameter   network parameter
   */
  Address(
      NetType type, const Script& redeem_script,
      const NetParams& network_parameter);

  /**
   * @brief コンストラクタ(P2WSH用)
   * @param[in] type          NetType
   * @param[in] witness_ver   Witnessバージョン
   * @param[in] redeem_script Redeem Script
   */
  Address(
      NetType type, WitnessVersion witness_ver, const Script& redeem_script);
  /**
   * @brief コンストラクタ(P2WSH用)
   * @param[in] type          NetType
   * @param[in] witness_ver   Witnessバージョン
   * @param[in] redeem_script Redeem Script
   * @param[in] bech32_hrp    bech32 hrp
   */
  Address(
      NetType type, WitnessVersion witness_ver, const Script& redeem_script,
      const std::string& bech32_hrp);
  /**
   * @brief コンストラクタ(P2WSH用)
   * @param[in] type          NetType
   * @param[in] witness_ver   Witnessバージョン
   * @param[in] redeem_script Redeem Script
   * @param[in] network_parameter   network parameter
   */
  Address(
      NetType type, WitnessVersion witness_ver, const Script& redeem_script,
      const NetParams& network_parameter);

  /**
   * @brief コンストラクタ(P2PKH/P2SH用。AddressType明示)
   * @param[in] type          NetType
   * @param[in] addr_type     種別
   * @param[in] hash          ハッシュ化済みの値
   */
  Address(NetType type, AddressType addr_type, const ByteData160& hash);
  /**
   * @brief コンストラクタ(P2PKH/P2SH用。AddressType明示)
   * @param[in] type          NetType
   * @param[in] addr_type     種別
   * @param[in] hash          ハッシュ化済みの値
   * @param[in] network_parameter   network parameter
   */
  Address(
      NetType type, AddressType addr_type, const ByteData160& hash,
      const NetParams& network_parameter);

  /**
   * @brief コンストラクタ(ハッシュ化済みの値用)
   * @param[in] type          NetType
   * @param[in] witness_ver   Witnessバージョン
   * @param[in] hash          ハッシュ化済みの値
   */
  Address(NetType type, WitnessVersion witness_ver, const ByteData& hash);
  /**
   * @brief コンストラクタ(ハッシュ化済みの値用)
   * @param[in] type          NetType
   * @param[in] witness_ver   Witnessバージョン
   * @param[in] hash          ハッシュ化済みの値
   * @param[in] network_parameter   network parameter
   */
  Address(
      NetType type, WitnessVersion witness_ver, const ByteData& hash,
      const NetParams& network_parameter);

  /**
   * @brief アドレスのhex文字列を取得する.
   * @return アドレス文字列
   */
  std::string GetAddress() const;

  /**
   * @brief AddressのNetTypeを取得する.
   * @return NetType
   */
  NetType GetNetType() const { return type_; }

  /**
   * @brief Address種別を取得する.
   * @return Address種別
   */
  AddressType GetAddressType() const { return addr_type_; }

  /**
   * @brief Witnessバージョンを取得する.
   * @return Witnessバージョン
   */
  WitnessVersion GetWitnessVersion() const { return witness_ver_; }

  /**
   * @brief アドレスHashを取得する.
   * @return アドレスHashのByteDataインスタンス
   */
  ByteData GetHash() const { return hash_; }

  /**
   * @brief PublicKeyを取得する.
   * @return Pubkeyオブジェクト
   */
  Pubkey GetPubkey() const { return pubkey_; }

  /**
   * @brief Redeem Scriptを取得する.
   * @return Scriptオブジェクト
   */
  Script GetScript() const { return redeem_script_; }

 private:
  /**
   * @brief P2SH Addressの情報を算出する.
   * @param[in] prefix      p2sh prefix
   */
  void CalculateP2SH(uint8_t prefix = 0);
  /**
   * @brief P2SH Addressの情報を算出する.
   * @param[in] hash_data   ハッシュ化済みRedeem script
   * @param[in] prefix      p2sh prefix
   */
  void CalculateP2SH(const ByteData160& hash_data, uint8_t prefix = 0);

  /**
   * @brief P2PKH Addressの情報を算出する.
   * @param[in] prefix      p2pkh prefix
   */
  void CalculateP2PKH(uint8_t prefix = 0);
  /**
   * @brief P2PKH Addressの情報を算出する.
   * @param[in] hash_data   ハッシュ化済みPubkey
   * @param[in] prefix      p2pkh prefix
   */
  void CalculateP2PKH(const ByteData160& hash_data, uint8_t prefix = 0);

  /**
   * @brief P2WSH Addressの情報を算出する.
   * @param[in] bech32_hrp    bech32 hrp
   */
  void CalculateP2WSH(const std::string& bech32_hrp = "");
  /**
   * @brief P2WSH Addressの情報を算出する.
   * @param[in] hash_data   ハッシュ化済みRedeemScript
   * @param[in] bech32_hrp  bech32 hrp
   */
  void CalculateP2WSH(
      const ByteData256& hash_data,  // script hash
      const std::string& bech32_hrp = "");

  /**
   * @brief P2WPKH Address算出()
   * @param[in] bech32_hrp    bech32 hrp
   */
  void CalculateP2WPKH(const std::string& bech32_hrp = "");
  /**
   * @brief P2WPKH Addressの情報を算出する.
   * @param[in] hash_data   ハッシュ化済みPubkey
   * @param[in] bech32_hrp  bech32 hrp
   */
  void CalculateP2WPKH(
      const ByteData160& hash_data,  // pubkey hash
      const std::string& bech32_hrp = "");

  /* Segwit Address Format
   *
   * 例：bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
   *
   *    "bc"or"tb"
   *        ：Human-readable part(bc=mainnet/tb=testnet)
   *    "1" ：Separator 1固定
   *    "v8f3t4"
   *        ：checksum
   *
   *    "qw508d6qejxtdg4y5r3zarvary0c5xw7k"をbase32Decode
   *    -> "0014751e76e8199196d454941c45d1b3a323f1433bd6"
   *    "00" ：witness version
   *    "14" ：data長(P2WPKHは20byte/P2WSHは32byte)
   *    "751e76e8199196d454941c45d1b3a323f1433bd6"
   *         ：witness program(PubkeyHash or ScriptHash)
   */
  /**
   * @brief Hex文字列をdecodeする.
   * @param[in] bs58                デコードするアドレスのbase58文字列
   * @param[in] network_parameters  network parameter list
   */
  void DecodeAddress(
      std::string bs58,  // LF
      const std::vector<NetParams>* network_parameters = nullptr);

  //! アドレスのNetType
  NetType type_;

  //! アドレス種別
  AddressType addr_type_;

  //! Witnessバージョン
  WitnessVersion witness_ver_;

  //! アドレス文字列
  std::string address_;

  //! アドレスHash
  ByteData hash_;

  //! PublicKey
  Pubkey pubkey_;

  //! Redeem Script
  Script redeem_script_;

  //! チェックサム
  uint8_t checksum_[4];
};
}  // namespace cfdcore

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_ADDRESS_H_
