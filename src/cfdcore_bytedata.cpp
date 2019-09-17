// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_bytedata.cpp
 *
 */
#include <string>
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore/cfdcore_util.h"

namespace cfdcore {

using logger::warn;

//////////////////////////////////
/// ByteData
//////////////////////////////////
ByteData::ByteData() : data_(0) {
  // do nothing
}

ByteData::ByteData(const std::vector<uint8_t>& vector) : data_(vector) {}

ByteData::ByteData(const std::string& hex)
    : data_(StringUtil::StringToByte(hex)) {}

std::string ByteData::GetHex() const {
  return StringUtil::ByteToString(data_);
}

std::vector<uint8_t> ByteData::GetBytes() const { return data_; }

size_t ByteData::GetDataSize() const { return data_.size(); }

bool ByteData::Equals(const ByteData& bytedata) const {
  if (data_ == bytedata.data_) {
    return true;
  }
  return false;
}

//////////////////////////////////
/// ByteData160
//////////////////////////////////
ByteData160::ByteData160() : data_(std::vector<uint8_t>(kByteData160Length)) {
  memset(data_.data(), 0, data_.size());
}

ByteData160::ByteData160(const std::vector<uint8_t>& vector)
    : data_(std::vector<uint8_t>(kByteData160Length)) {
  if (vector.size() != kByteData160Length) {
    warn(CFD_LOG_SOURCE, "ByteData160 size unmatch. size={}.", vector.size());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ByteData160 size unmatch.");
  }
  data_ = vector;
}

ByteData160::ByteData160(const std::string& hex)
    : data_(std::vector<uint8_t>(kByteData160Length)) {
  std::vector<uint8_t> vector = StringUtil::StringToByte(hex);
  if (vector.size() != kByteData160Length) {
    warn(CFD_LOG_SOURCE, "ByteData160 size unmatch. size={}.", vector.size());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ByteData160 size unmatch.");
  }
  data_ = vector;
}

std::string ByteData160::GetHex() const {
  return StringUtil::ByteToString(data_);
}

std::vector<uint8_t> ByteData160::GetBytes() const { return data_; }

bool ByteData160::Equals(const ByteData160& bytedata) const {
  if (data_ == bytedata.data_) {
    return true;
  }
  return false;
}

//////////////////////////////////
/// ByteData256
//////////////////////////////////
ByteData256::ByteData256() : data_(std::vector<uint8_t>(kByteData256Length)) {
  memset(data_.data(), 0, data_.size());
}

ByteData256::ByteData256(const std::vector<uint8_t>& vector)
    : data_(std::vector<uint8_t>(kByteData256Length)) {
  if (vector.size() != kByteData256Length) {
    warn(CFD_LOG_SOURCE, "ByteData256 size unmatch. size={}.", vector.size());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ByteData256 size unmatch.");
  }
  data_ = vector;
}

ByteData256::ByteData256(const std::string& hex)
    : data_(std::vector<uint8_t>(kByteData256Length)) {
  std::vector<uint8_t> vector = StringUtil::StringToByte(hex);
  if (vector.size() != kByteData256Length) {
    warn(CFD_LOG_SOURCE, "ByteData256 size unmatch. size={}.", vector.size());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ByteData256 size unmatch.");
  }
  data_ = vector;
}

std::string ByteData256::GetHex() const {
  return StringUtil::ByteToString(data_);
}

std::vector<uint8_t> ByteData256::GetBytes() const { return data_; }

bool ByteData256::Equals(const ByteData256& bytedata) const {
  if (data_ == bytedata.data_) {
    return true;
  }
  return false;
}

}  // namespace cfdcore
