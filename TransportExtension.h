/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

namespace mozquic  {

class MozQuic;

const uint16_t kDefaultMaxPacketConfig = 65527;
const uint8_t  kDefaultAckDelayExponent = 3;

class TransportExtension {
private:
  static void Encode1ByteObject(unsigned char *output, uint16_t &_offset, uint16_t maxOutput,
                                uint8_t object);
  static void Encode2ByteObject(unsigned char *output, uint16_t &_offset, uint16_t maxOutput,
                                uint16_t object);
  static void Encode4ByteObject(unsigned char *output, uint16_t &_offset, uint16_t maxOutput,
                                uint32_t object);
  static void Encode16ByteObject(unsigned char *output, uint16_t &_offset, uint16_t maxOutput,
                                unsigned char *object);
  static void Encode2xLenx1Record(unsigned char *output, uint16_t &_offset, uint16_t maxOutput,
                                  uint16_t object1, uint8_t object2);
  static void Encode2xLenx2Record(unsigned char *output, uint16_t &_offset, uint16_t maxOutput,
                               uint16_t object1, uint16_t object2);
  static void Encode2xLenx4Record(unsigned char *output, uint16_t &_offset, uint16_t maxOutput,
                               uint16_t object1, uint32_t object2);
  static void Decode1ByteObject(const unsigned char *input,
                                uint16_t &_offset, uint16_t inputSize,
                                uint8_t &_output);
  static void Decode2ByteObject(const unsigned char *input,
                                uint16_t &_offset, uint16_t inputSize,
                                uint16_t &_output);
  static void Decode4ByteObject(const unsigned char *input,
                                uint16_t &_offset, uint16_t inputSize,
                                uint32_t &_output);
  static void Decode16ByteObject(const unsigned char *input,
                                 uint16_t &_offset, uint16_t inputSize,
                                 unsigned char *_output);
public:
  static void EncodeClientTransportParameters(unsigned char *output, uint16_t &_offset, uint16_t maxOutput,
                                              uint32_t initialVersion,
                                              uint32_t initialMaxStreamData,
                                              uint32_t initialMaxDataBytes,
                                              uint32_t initialMaxStreamIDBidi,
                                              uint32_t initialMaxStreamIDUni,
                                              uint16_t idleTimeout,
                                              uint16_t maxPacket,
                                              uint8_t ackDelayExponent);
  static uint32_t DecodeClientTransportParameters(unsigned char *input, uint16_t inputSize,
                                                  uint32_t &_initialVersion,
                                                  uint32_t &_initialMaxStreamData,
                                                  uint32_t &_initialMaxDataBytes,
                                                  uint32_t &_initialMaxStreamIDBidi,
                                                  uint32_t &_initialMaxStreamIDUni,
                                                  uint16_t &_idleTimeout,
                                                  uint16_t &_maxPacket,
                                                  uint8_t  &_ackDelayExponent,
                                                  MozQuic *forLogging);
  
  static void EncodeServerTransportParameters(unsigned char *output, uint16_t &_offset, uint16_t maxOutput,
                                              uint32_t negotiatedVersion,
                                              const uint32_t *versionList, uint16_t versionListSize,
                                              uint32_t initialMaxStreamData,
                                              uint32_t initialMaxDataBytes,
                                              uint32_t initialMaxStreamIDBidi,
                                              uint32_t initialMaxStreamIUni,
                                              uint16_t idleTimeout,
                                              uint16_t maxPacket,
                                              uint8_t ackDelayExponent,
                                              unsigned char *statelessResetToken /* 16 bytes */);
  static uint32_t DecodeServerTransportParameters(unsigned char *input, uint16_t inputSize,
                                                  uint32_t &_negotiatedVersion,
                                                  uint32_t *versionList, uint16_t &_versionListSize,
                                                  uint32_t &_initialMaxStreamData,
                                                  uint32_t &_initialMaxDataBytes,
                                                  uint32_t &_initialMaxStreamIDBidi,
                                                  uint32_t &_initialMaxStreamIDUni,
                                                  uint16_t &_idleTimeout,
                                                  uint16_t &_maxPacket,
                                                  uint8_t  &_ackDelayExponent,
                                                  unsigned char *_statelessResetToken /* 16 bytes */,
                                                  bool     &_validStatelessResetToken,
                                                  MozQuic *forLogging);

private:
  TransportExtension(){}
  ~TransportExtension(){}
};

}

  
