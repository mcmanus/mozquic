/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "Logging.h"
#include "MozQuicInternal.h"
#include "NSSHelper.h"
#include "TransportExtension.h"
#include "assert.h"

namespace mozquic  {

enum TransportExtensionID {
  kInitialMaxStreamData = 0x0,
  kInitialMaxData       = 0x1,
  kInitialMaxStreamID   = 0x2,
  kIdleTimeout          = 0x3,
  kOmitConnectionID     = 0x4,
  kMaxPacketSize        = 0x5,
  kStatelessResetToken  = 0x6,
  kAckDelayExponent     = 0x7,
};

void
TransportExtension::Encode4ByteObject(unsigned char *output, uint16_t &_offset, uint16_t maxOutput,
                                   uint32_t object)
{
  assert(_offset + sizeof(object) <= maxOutput);
  if (_offset + sizeof(object) > maxOutput) {
    return;
  }
  object = htonl(object);
  memcpy(output + _offset, &object, sizeof(object));
  _offset += sizeof(object);
}

void
TransportExtension::Encode2ByteObject(unsigned char *output, uint16_t &_offset, uint16_t maxOutput,
                                      uint16_t object)
{
  assert(_offset + sizeof(object) <= maxOutput);
  if (_offset + sizeof(object) > maxOutput) {
    return;
  }
  object = htons(object);
  memcpy(output + _offset, &object, sizeof(object));
  _offset += sizeof(object);
}

void
TransportExtension::Encode1ByteObject(unsigned char *output, uint16_t &_offset, uint16_t maxOutput,
                                      uint8_t object)
{
  assert(_offset + sizeof(object) <= maxOutput);
  if (_offset + sizeof(object) > maxOutput) {
    return;
  }
  output[_offset] = object;
  _offset += sizeof(object);
}

void
TransportExtension::Encode16ByteObject(unsigned char *output, uint16_t &_offset, uint16_t maxOutput,
                                    unsigned char *object)
{
  assert(_offset + 16 <= maxOutput);
  if (_offset + 16 > maxOutput) {
    return;
  }
  memcpy(output + _offset, object, 16);
  _offset += 16;
}

void
TransportExtension::Encode2xLenx2Record(unsigned char *output, uint16_t &_offset, uint16_t maxOutput,
                                   uint16_t object1, uint16_t object2)
{
  Encode2ByteObject(output, _offset, maxOutput, object1);
  Encode2ByteObject(output, _offset, maxOutput, 2);
  Encode2ByteObject(output, _offset, maxOutput, object2);
}

void
TransportExtension::Encode2xLenx4Record(unsigned char *output, uint16_t &_offset, uint16_t maxOutput,
                                     uint16_t object1, uint32_t object2)
{
  Encode2ByteObject(output, _offset, maxOutput, object1);
  Encode2ByteObject(output, _offset, maxOutput, 4);
  Encode4ByteObject(output, _offset, maxOutput, object2);
}

void
TransportExtension::Decode4ByteObject(const unsigned char *input,
                                      uint16_t &_offset, uint16_t inputSize,
                                      uint32_t &_output)
{
  assert(sizeof(_output) == 4);
  assert(_offset + sizeof(_output) <= inputSize);
  uint32_t tmp32;
  memcpy(&tmp32, input + _offset, sizeof(_output));
  _output = ntohl(tmp32);
  _offset += sizeof(_output);
}

void
TransportExtension::Decode2ByteObject(const unsigned char *input,
                                      uint16_t &_offset, uint16_t inputSize,
                                      uint16_t &_output)
{
  assert(sizeof(_output) == 2);
  assert(_offset + sizeof(_output) <= inputSize);
  uint16_t tmp16;
  memcpy(&tmp16, input + _offset, sizeof(_output));
  _output = ntohs(tmp16);
  _offset += sizeof(_output);
}

void
TransportExtension::Decode1ByteObject(const unsigned char *input,
                                      uint16_t &_offset, uint16_t inputSize,
                                      uint8_t &_output)
{
  assert(sizeof(_output) == 1);
  assert(_offset + sizeof(_output) <= inputSize);
  _output = input[_offset];
  _offset += sizeof(_output);
}

void
TransportExtension::Decode16ByteObject(const unsigned char *input,
                                       uint16_t &_offset, uint16_t inputSize,
                                       unsigned char *_output)
{
  assert(_offset + 16 <= inputSize);
  memcpy(_output, input + _offset, 16);
  _offset += 16;
}

void
TransportExtension::EncodeClientTransportParameters(unsigned char *output, uint16_t &_offset, uint16_t maxOutput,
                                                    uint32_t negotiatedVersion,
                                                    uint32_t initialVersion,
                                                    uint32_t initialMaxStreamData,
                                                    __uint128_t initialMaxDataBytes,
                                                    uint32_t initialMaxStreamID,
                                                    uint16_t idleTimeout,
                                                    uint16_t maxPacket)
{
  assert(!(initialMaxDataBytes & 0x3ff));
  assert((initialMaxDataBytes >> 10) <= 0xffffffff);
  uint32_t initialMaxDataKB = initialMaxDataBytes >> 10;

  uint16_t maxPacketESize = 0;
  if (maxPacket > 1200 && maxPacket != kDefaultMaxPacketConfig) {
    maxPacketESize += 6;
  }
      
  Encode4ByteObject(output, _offset, maxOutput, negotiatedVersion);
  Encode4ByteObject(output, _offset, maxOutput, initialVersion);
  Encode2ByteObject(output, _offset, maxOutput, 30 + maxPacketESize); // size parameters

  Encode2xLenx4Record(output, _offset, maxOutput, kInitialMaxStreamData, initialMaxStreamData);
  Encode2xLenx4Record(output, _offset, maxOutput, kInitialMaxData, initialMaxDataKB);
  Encode2xLenx4Record(output, _offset, maxOutput, kInitialMaxStreamID, initialMaxStreamID);
  Encode2xLenx2Record(output, _offset, maxOutput, kIdleTimeout, idleTimeout);
  if (maxPacketESize) {
    Encode2xLenx2Record(output, _offset, maxOutput, kMaxPacketSize, maxPacket);
  }
}

#define TP_ENSURE_PARAM(x) \
  {if (x) { Log::sDoLog(Log::CONNECTION, 1, forLogging,     \
                        "Transport Parameter Duplicate\n"); \
            return MOZQUIC_ERR_GENERAL; }                   \
   x = true; }

uint32_t
TransportExtension::DecodeClientTransportParameters(unsigned char *input, uint16_t inputSize,
                                                    uint32_t &_negotiatedVersion,
                                                    uint32_t &_initialVersion,
                                                    uint32_t &_initialMaxStreamData,
                                                    uint32_t &_initialMaxDataKB,
                                                    uint32_t &_initialMaxStreamID,
                                                    uint16_t &_idleTimeout,
                                                    uint16_t &_maxPacket,
                                                    MozQuic *forLogging)
{
  if (inputSize < 10) { // the version fields and size of params
    return MOZQUIC_ERR_GENERAL;
  }
  uint16_t offset = 0;
  uint16_t paramSize;
  Decode4ByteObject(input, offset, inputSize, _negotiatedVersion);
  Decode4ByteObject(input, offset, inputSize, _initialVersion);
  Decode2ByteObject(input, offset, inputSize, paramSize);
  assert(offset == 10);
  if (paramSize < 30 || (offset + paramSize) > inputSize) {
    return MOZQUIC_ERR_GENERAL;
  }
  input = input + offset;
  offset = 0;
  inputSize = paramSize;
  bool maxStreamData = false, maxData = false, maxStreamID = false,
    idleTimeout = false, maxPacket = false;
  _maxPacket = kDefaultMaxPacketConfig;
  while (inputSize - offset >= 4) {
    // need to scan them all to make sure we err on stateless reset tokens
    uint16_t id, len;
    Decode2ByteObject(input, offset, inputSize, id);
    Decode2ByteObject(input, offset, inputSize, len);
    if (inputSize - offset < len) { return MOZQUIC_ERR_GENERAL; }
    switch (id) 
      {
      case kInitialMaxStreamData:
        if (len != 4) { return MOZQUIC_ERR_GENERAL; }
        Decode4ByteObject(input, offset, inputSize, _initialMaxStreamData);
        TP_ENSURE_PARAM(maxStreamData);
        break;
      case kInitialMaxData:
        if (len != 4) { return MOZQUIC_ERR_GENERAL; }
        Decode4ByteObject(input, offset, inputSize, _initialMaxDataKB);
        TP_ENSURE_PARAM(maxData);
        break;
      case kInitialMaxStreamID:
        if (len != 4) { return MOZQUIC_ERR_GENERAL; }
        Decode4ByteObject(input, offset, inputSize, _initialMaxStreamID);
        TP_ENSURE_PARAM(maxStreamID);
        break;
      case kIdleTimeout:
        if (len != 2) { return MOZQUIC_ERR_GENERAL; }
        Decode2ByteObject(input, offset, inputSize, _idleTimeout);
        TP_ENSURE_PARAM(idleTimeout);
        break;
      case kMaxPacketSize:
        if (len != 2) { return MOZQUIC_ERR_GENERAL; }
        Decode2ByteObject(input, offset, inputSize, _maxPacket);
        TP_ENSURE_PARAM(maxPacket);
        if (_maxPacket < 1200) {
          Log::sDoLog(Log::CONNECTION, 1, forLogging, 
                      "MaxPacketSize Recvd Too Small\n");
          return MOZQUIC_ERR_GENERAL;
        }
        break;
      case kStatelessResetToken:
        Log::sDoLog(Log::CONNECTION, 1, forLogging,
                    "Server Decoded Stateless Reset Token\n");
        return MOZQUIC_ERR_GENERAL;
      default:
        offset += len;
        break;
      }
  }

  return (maxStreamData && maxData && maxStreamID && idleTimeout) ? MOZQUIC_OK : MOZQUIC_ERR_GENERAL;
}
  
void
TransportExtension::EncodeServerTransportParameters(unsigned char *output, uint16_t &_offset, uint16_t maxOutput,
                                                    const uint32_t *versionList, uint16_t versionListSize,
                                                    uint32_t initialMaxStreamData,
                                                    __uint128_t initialMaxDataBytes,
                                                    uint32_t initialMaxStreamID,
                                                    uint16_t idleTimeout,
                                                    uint16_t maxPacket,
                                                    unsigned char *statelessResetToken /* 16 bytes */)
{
  assert(!(initialMaxDataBytes & 0x3ff));
  assert((initialMaxDataBytes >> 10) <= 0xffffffff);
  uint32_t initialMaxDataKB = initialMaxDataBytes >> 10;
  assert(versionListSize > 0);
  assert ((4 * versionListSize) <= 255);
  Encode1ByteObject(output, _offset, maxOutput, 4 * versionListSize);
  for (int i = 0; i < versionListSize; i++) {
    Encode4ByteObject(output, _offset, maxOutput, versionList[i]);
  }

  uint16_t maxPacketESize = 0;
  if (maxPacket > 1200 && maxPacket != kDefaultMaxPacketConfig) {
    maxPacketESize += 6;
  }
  Encode2ByteObject(output, _offset, maxOutput, 50 + maxPacketESize); // size of parameters
  Encode2xLenx4Record(output, _offset, maxOutput, kInitialMaxStreamData, initialMaxStreamData);
  Encode2xLenx4Record(output, _offset, maxOutput, kInitialMaxData, initialMaxDataKB);
  Encode2xLenx4Record(output, _offset, maxOutput, kInitialMaxStreamID, initialMaxStreamID);
  Encode2xLenx2Record(output, _offset, maxOutput, kIdleTimeout, idleTimeout);
  if (maxPacketESize) {
    Encode2xLenx2Record(output, _offset, maxOutput, kMaxPacketSize, maxPacket);
  }
  Encode2ByteObject(output, _offset, maxOutput, kStatelessResetToken);
  Encode2ByteObject(output, _offset, maxOutput, 16);
  Encode16ByteObject(output, _offset, maxOutput, statelessResetToken);
}

uint32_t
TransportExtension::DecodeServerTransportParameters(unsigned char *input, uint16_t inputSize,
                                                    uint32_t *versionList, uint16_t &_versionListSize,
                                                    uint32_t &_initialMaxStreamData,
                                                    uint32_t &_initialMaxDataKB,
                                                    uint32_t &_initialMaxStreamID,
                                                    uint16_t &_idleTimeout,
                                                    uint16_t &_maxPacket,
                                                    unsigned char *_statelessResetToken /* 16 bytes */,
                                                    MozQuic *forLogging)
{
  if (inputSize < 6) {
    return MOZQUIC_ERR_GENERAL;
  }
  uint8_t versionBytes;
  uint16_t offset = 0;
  Decode1ByteObject(input, offset, inputSize, versionBytes); // number of bytes in versionList
  if ((versionBytes < 4) || (versionBytes & 0x3)) { // invalid number of bytes
    return MOZQUIC_ERR_GENERAL;
  }
  if (_versionListSize < versionBytes / 4) { // no room for output
    return MOZQUIC_ERR_GENERAL;
  }
  _versionListSize = versionBytes / 4;
  if ((offset + versionBytes) > inputSize) {
    return MOZQUIC_ERR_GENERAL;
  }
  for (int i = 0; i < _versionListSize; i++) {
    uint32_t tmp32;
    Decode4ByteObject(input, offset, inputSize, tmp32);
    versionList[i] = tmp32;
  }
  uint16_t paramSize;
  Decode2ByteObject(input, offset, inputSize, paramSize); // bytes in transport parameters
  if (paramSize < 50) { // min size for all required
    return MOZQUIC_ERR_GENERAL;
  }
  if ((offset + paramSize) > inputSize) {
    return MOZQUIC_ERR_GENERAL;
  }
  
  input = input + offset;
  offset = 0;
  inputSize = paramSize;
  bool maxStreamData = false, maxData = false, maxStreamID = false, idleTimeout = false, maxPacket = false;
  bool statelessReset = false;
  _maxPacket = kDefaultMaxPacketConfig;

  do {
    if (inputSize - offset < 4) {
      return MOZQUIC_ERR_GENERAL;
    }
    uint16_t id, len;
    Decode2ByteObject(input, offset, inputSize, id);
    Decode2ByteObject(input, offset, inputSize, len);
    if (inputSize - offset < len) { return MOZQUIC_ERR_GENERAL; }
    switch (id) 
      {
      case kInitialMaxStreamData:
        if (len != 4) { return MOZQUIC_ERR_GENERAL; }
        Decode4ByteObject(input, offset, inputSize, _initialMaxStreamData);
        TP_ENSURE_PARAM(maxStreamData);
        break;
      case kInitialMaxData:
        if (len != 4) { return MOZQUIC_ERR_GENERAL; }
        Decode4ByteObject(input, offset, inputSize, _initialMaxDataKB);
        TP_ENSURE_PARAM(maxData);
        break;
      case kInitialMaxStreamID:
        if (len != 4) { return MOZQUIC_ERR_GENERAL; }
        Decode4ByteObject(input, offset, inputSize, _initialMaxStreamID);
        TP_ENSURE_PARAM(maxStreamID);
        break;
      case kIdleTimeout:
        if (len != 2) { return MOZQUIC_ERR_GENERAL; }
        Decode2ByteObject(input, offset, inputSize, _idleTimeout);
        TP_ENSURE_PARAM(idleTimeout);
        break;
      case kMaxPacketSize:
        if (len != 2) { return MOZQUIC_ERR_GENERAL; }
        Decode2ByteObject(input, offset, inputSize, _maxPacket);
        TP_ENSURE_PARAM(maxPacket);
        if (_maxPacket < 1200) {
          Log::sDoLog(Log::CONNECTION, 1, forLogging, 
                      "MaxPacketSize Recvd Too Small\n");
          return MOZQUIC_ERR_GENERAL;
        }
        break;
      case kStatelessResetToken:
        if (len != 16) { return MOZQUIC_ERR_GENERAL; }
        Decode16ByteObject(input, offset, inputSize, _statelessResetToken);
        TP_ENSURE_PARAM(statelessReset);
        break;
      default:
        offset += len;
        break;
      }
    if (maxStreamData && maxData && maxStreamID && idleTimeout && statelessReset) {
      return MOZQUIC_OK;
    }
  } while (1);
  
  return MOZQUIC_ERR_GENERAL;
}

#undef TP_ENSURE_PARAM

}



