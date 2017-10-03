/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

namespace mozquic  {

class MozQuic;
  
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
                                              uint32_t negotiatedVersion,
                                              uint32_t initialVersion,
                                              uint32_t initialMaxStreamData,
                                              __uint128_t initialMaxData,
                                              uint32_t initialMaxStreamID,
                                              uint16_t idleTimeout);
  static uint32_t DecodeClientTransportParameters(unsigned char *input, uint16_t inputSize,
                                                  uint32_t &_negotiatedVersion,
                                                  uint32_t &_initialVersion,
                                                  uint32_t &_initialMaxStreamData,
                                                  uint32_t &_initialMaxData,
                                                  uint32_t &_initialMaxStreamID,
                                                  uint16_t &_idleTimeout,
                                                  MozQuic *forLogging);
  
  static void EncodeServerTransportParameters(unsigned char *output, uint16_t &_offset, uint16_t maxOutput,
                                              const uint32_t *versionList, uint16_t versionListSize,
                                              uint32_t initialMaxStreamData,
                                              __uint128_t initialMaxData,
                                              uint32_t initialMaxStreamID,
                                              uint16_t idleTimeout,
                                              unsigned char *statelessResetToken /* 16 bytes */);
  static uint32_t DecodeServerTransportParameters(unsigned char *input, uint16_t inputSize,
                                                  uint32_t *versionList, uint16_t &_versionListSize,
                                                  uint32_t &_initialMaxStreamData,
                                                  uint32_t &_initialMaxData,
                                                  uint32_t &_initialMaxStreamID,
                                                  uint16_t &_idleTimeout,
                                                  unsigned char *_statelessResetToken /* 16 bytes */);

private:
  TransportExtension(){}
  ~TransportExtension(){}
};

}

  
