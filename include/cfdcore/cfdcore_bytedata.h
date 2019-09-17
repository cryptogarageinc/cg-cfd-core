// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_bytedata.h
 *
 * @brief ByteData関連クラス定義
 */

#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_BYTEDATA_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_BYTEDATA_H_

#include <string>
#include <vector>
#include "cfdcore/cfdcore_common.h"

/**
 * @brief cfdcore名前空間
 */
namespace cfdcore {

/**
 * @class ByteData
 * @brief 可変サイズのByte配列データクラス
 */
class CFD_CORE_EXPORT ByteData {
 public:
  /**
   * @brief デフォルトコンストラクタ
   */
  ByteData();

  /**
   * @brief コンストラクタ
   * @param[in] vector  格納Byte配列
   */
  ByteData(const std::vector<uint8_t>& vector);  // NOLINT

  /**
   * @brief コンストラクタ
   * @param[in] hex  Byteデータ HEX文字列
   */
  ByteData(const std::string& hex);  // NOLINT

  /**
   * @brief HEX文字列を取得する.
   * @return HEX文字列
   */
  std::string GetHex() const;

  /**
   * @brief Byte配列を取得する.
   * @return Byte配列
   */
  std::vector<uint8_t> GetBytes() const;

  /**
   * @brief データサイズを取得する.
   * @return Byte配列サイズ
   */
  size_t GetDataSize() const;

  /**
   * @brief ByteData比較
   * @param bytedata 比較対象のオブジェクト
   * @retval true 一致した場合
   * @retval false 不一致の場合
   */
  bool Equals(const ByteData& bytedata) const;

 private:
  /**
   * @brief データ格納Byte配列
   */
  std::vector<uint8_t> data_;
};

/**
 * @class ByteData160
 * @brief サイズ固定(20byte)のByte配列データクラス
 */
class CFD_CORE_EXPORT ByteData160 {
 public:
  /**
   * @brief デフォルトコンストラクタ
   */
  ByteData160();

  /**
   * @brief コンストラクタ
   * @param[in] vector  20byteデータ格納Byte配列
   */
  ByteData160(const std::vector<uint8_t>& vector);  // NOLINT

  /**
   * @brief コンストラクタ
   * @param[in] hex  ByteデータHEX文字列
   */
  ByteData160(const std::string& hex);  // NOLINT

  /**
   * @brief HEX文字列を取得する.
   * @return HEX文字列
   */
  std::string GetHex() const;

  /**
   * @brief Byte配列を取得する.
   * @return Byte配列
   */
  std::vector<uint8_t> GetBytes() const;
  /**
   * @brief ByteData比較
   * @param bytedata 比較対象のオブジェクト
   * @retval true 一致した場合
   * @retval false 不一致の場合
   */
  bool Equals(const ByteData160& bytedata) const;

 private:
  /**
   * @brief 20byte固定データ格納Byte配列
   */
  std::vector<uint8_t> data_;
};

/**
 * @class ByteData256
 * @brief サイズ固定(32byte)のByte配列データクラス
 */
class CFD_CORE_EXPORT ByteData256 {
 public:
  /**
   * @brief デフォルトコンストラクタ
   */
  ByteData256();

  /**
   * @brief コンストラクタ
   * @param[in] vector  32byteデータ格納Byte配列
   */
  ByteData256(const std::vector<uint8_t>& vector);  // NOLINT

  /**
   * @brief コンストラクタ
   * @param[in] hex  ByteデータHEX文字列
   */
  ByteData256(const std::string& hex);  // NOLINT

  /**
   * @brief HEX文字列を取得する.
   * @return HEX文字列
   */
  std::string GetHex() const;

  /**
   * @brief Byte配列を取得する.
   * @return Byte配列
   */
  std::vector<uint8_t> GetBytes() const;
  /**
   * @brief ByteData比較
   * @param bytedata 比較対象のオブジェクト
   * @retval true 一致した場合
   * @retval false 不一致の場合
   */
  bool Equals(const ByteData256& bytedata) const;

 private:
  /**
   * @brief 32byte固定データ格納Byte配列
   */
  std::vector<uint8_t> data_;
};

}  // namespace cfdcore

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_BYTEDATA_H_
