// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_descriptor.h
 *
 * @brief Output Descriptor関連クラス定義
 *
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_DESCRIPTOR_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_DESCRIPTOR_H_

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_coin.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_key.h"

namespace cfd {
namespace core {

/**
 * @brief DescriptorNode の種別定義.
 */
enum DescriptorNodeType {
  kDescriptorTypeNull,    //!< null
  kDescriptorTypeScript,  //!< script
  kDescriptorTypeKey,     //!< key
  kDescriptorTypeNumber,  //!< number
};

/**
 * @brief DescriptorNode のScript種別定義.
 */
enum DescriptorScriptType {
  kDescriptorScriptNull,         //!< null
  kDescriptorScriptSh,           //!< script hash
  kDescriptorScriptWsh,          //!< segwit script hash
  kDescriptorScriptPk,           //!< pubkey
  kDescriptorScriptPkh,          //!< pubkey hash
  kDescriptorScriptWpkh,         //!< segwit pubkey hash
  kDescriptorScriptCombo,        //!< combo
  kDescriptorScriptMulti,        //!< multisig
  kDescriptorScriptSortedMulti,  //!< sorted multisig
  kDescriptorScriptAddr,         //!< address
  kDescriptorScriptRaw,          //!< raw script
};

/**
 * @brief DescriptorNode のKey種別定義.
 */
enum DescriptorKeyType {
  kDescriptorKeyNull,       //!< null
  kDescriptorKeyPublic,     //!< pubkey
  kDescriptorKeyBip32,      //!< bip32 extpubkey
  kDescriptorKeyBip32Priv,  //!< bip32 extprivkey
};

/**
 * @brief Descriptor用Node定義クラス
 */
class CFD_CORE_EXPORT DescriptorNode {
 public:
  /**
   * @brief parse output descriptor.
   * @param[in] output_descriptor   output descriptor
   * @param[in] network_parameters  network parameter
   * @return DescriptorNode object
   */
  static DescriptorNode Parse(
      const std::string& output_descriptor,
      const std::vector<AddressFormatData>& network_parameters);

  /**
   * @brief generate to checksum from descriptor.
   * @param[in] descriptor  output descriptor
   * @return checksum
   */
  static std::string GenerateChecksum(const std::string& descriptor);

  /**
   * @brief constructor.
   */
  DescriptorNode();
  /**
   * @brief constructor.
   * @param[in] network_parameters  network parameter
   */
  explicit DescriptorNode(
      const std::vector<AddressFormatData>& network_parameters);
  /**
   * @brief copy constructor.
   * @param[in] object    DescriptorNode object
   * @return DescriptorNode object
   */
  DescriptorNode& operator=(const DescriptorNode& object);

  /**
   * @brief generate script.
   * @param[in] array_argument  argument
   * @param[in] script_list     (redeem or locking) script list.
   * @return locking script
   */
  Script GenerateScript(
      std::vector<std::string>* array_argument,
      std::vector<Script>* script_list = nullptr) const;
  /**
   * @brief generate script all.
   * @param[in] array_argument  argument
   * @return locking script list
   */
  std::vector<Script> GenerateScriptAll(
      std::vector<std::string>* array_argument) const;

  /**
   * @brief argumentに必要な数を取得する。
   * @return argument number.
   */
  uint32_t GetNeedArgumentNum() const;

  /**
   * @brief collect output descriptor.
   * @param[in] append_checksum  append checksum
   * @return output descriptor
   */
  std::string ToString(bool append_checksum = true) const;

  /**
   * @brief DescriptorNodeの種別を取得する。
   * @return DescriptorNodeType
   */
  DescriptorNodeType GetNodeType() const { return node_type_; }
  /**
   * @brief DescriptorNodeのScript種別を取得する。
   * @return DescriptorScriptType
   */
  DescriptorScriptType GetScriptType() const { return script_type_; }

  /**
   * @brief check checksum.
   * @param[in] descriptor    check target descriptor.
   */
  void CheckChecksum(const std::string& descriptor);

 protected:
  /**
   * @brief get pubkey.
   * @param[in] array_argument  argument array.
   * @return pubkey
   */
  Pubkey GetPubkey(std::vector<std::string>* array_argument) const;

 private:
  std::string name_;                              //!< node name
  std::string value_;                             //!< node value
  std::string key_info_;                          //!< key information
  uint32_t number_ = 0;                           //!< number value
  std::vector<DescriptorNode> child_node_;        //!< child nodes
  std::string checksum_;                          //!< checksum
  uint32_t depth_ = 0;                            //!< depth
  uint32_t need_arg_num_ = 0;                     //!< need argument num
  DescriptorNodeType node_type_;                  //!< node type
  DescriptorScriptType script_type_;              //!< node script type
  DescriptorKeyType key_type_;                    //!< node key type
  std::vector<AddressFormatData> addr_prefixes_;  //!< address prefixes

  /**
   * @brief analyze child node.
   * @param[in] descriptor  output descriptor
   * @param[in] depth       node depth
   */
  void AnalyzeChild(const std::string& descriptor, uint32_t depth);
  /**
   * @brief analyze all node.
   * @param[in] parent_name  parent node name
   */
  void AnalyzeAll(const std::string& parent_name);
  /**
   * @brief analyze key node.
   */
  void AnalyzeKey();
};

/**
 * @brief Output Descriptor定義クラス
 */
class CFD_CORE_EXPORT Descriptor {
 public:
  /**
   * @brief parse output descriptor.
   * @param[in] output_descriptor   output descriptor
   * @param[in] network_parameters  network parameter
   * @return DescriptorNode object
   */
  static Descriptor Parse(
      const std::string& output_descriptor,
      const std::vector<AddressFormatData>* network_parameters = nullptr);

#ifndef CFD_DISABLE_ELEMENTS
  /**
   * @brief parse output descriptor on Elements.
   * @details supported an Elements `addr` descriptor.
   * @param[in] output_descriptor   output descriptor
   * @return DescriptorNode object
   */
  static Descriptor ParseElements(const std::string& output_descriptor);
#endif  // CFD_DISABLE_ELEMENTS

  /**
   * @brief constructor.
   */
  Descriptor();

  /**
   * @brief check combo script.
   * @retval true  combo script
   * @retval false other script
   */
  bool IsComboScript() const;
  /**
   * @brief argumentに必要な数を取得する。
   * @return argument number.
   */
  uint32_t GetNeedArgumentNum() const;

  /**
   * @brief get locking script.
   * @param[in] script_list     (redeem or locking) script list.
   * @return locking script
   */
  Script GetScript(std::vector<Script>* script_list = nullptr) const;

  /**
   * @brief generate locking script.
   * @param[in] argument        argument
   * @param[in] script_list     (redeem or locking) script list.
   * @return locking script
   */
  Script GenerateScript(
      const std::string& argument,
      std::vector<Script>* script_list = nullptr) const;
  /**
   * @brief generate locking script.
   * @param[in] array_argument  argument
   * @param[in] script_list     (redeem or locking) script list.
   * @return locking script
   */
  Script GenerateScript(
      const std::vector<std::string>& array_argument,
      std::vector<Script>* script_list = nullptr) const;

  /**
   * @brief generate combo script.
   * @return locking script list
   */
  std::vector<Script> GetScriptCombo() const;
  /**
   * @brief generate combo script.
   * @param[in] array_argument  argument
   * @return locking script list
   */
  std::vector<Script> GetScriptCombo(
      const std::vector<std::string>& array_argument) const;

  /**
   * @brief collect output descriptor.
   * @param[in] append_checksum  append checksum
   * @return output descriptor
   */
  std::string ToString(bool append_checksum = true) const;

  /**
   * @brief get descriptor node.
   * @return descriptor node
   */
  DescriptorNode GetNode() const;

 private:
  DescriptorNode root_node_;  //!< root node
};

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_DESCRIPTOR_H_
