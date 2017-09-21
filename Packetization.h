/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

namespace mozquic  {

enum {
  kMaxMTU = 1472,
  kInitialMTU = 1200,
  kMozQuicMSS = 16384,
  kTagLen = 16,

  STREAM_FIN_BIT = 0x20,
};

enum LongHeaderType {
  PACKET_TYPE_VERSION_NEGOTIATION    = 1,
  PACKET_TYPE_CLIENT_INITIAL         = 2,
  PACKET_TYPE_SERVER_STATELESS_RETRY = 3,
  PACKET_TYPE_SERVER_CLEARTEXT       = 4,
  PACKET_TYPE_CLIENT_CLEARTEXT       = 5,
  PACKET_TYPE_0RTT_PROTECTED         = 6,
  PACKET_TYPE_1RTT_PROTECTED_KP0     = 7,
  PACKET_TYPE_1RTT_PROTECTED_KP1     = 8,
  PACKET_TYPE_PUBLIC_RESET           = 9,
};

class LongHeaderData
{
public:
  LongHeaderData(unsigned char *, uint32_t);
  enum LongHeaderType mType;
  uint64_t mConnectionID;
  uint64_t mPacketNumber;
  uint32_t mVersion;
};

class ShortHeaderData
{
private:
  static uint64_t DecodePacketNumber(unsigned char *pkt, int pnSize, uint64_t next);

public:
  ShortHeaderData(unsigned char *, uint32_t, uint64_t, uint64_t);
  uint32_t mHeaderSize;
  uint64_t mConnectionID;
  uint64_t mPacketNumber;
};

enum FrameType {
  FRAME_TYPE_PADDING           = 0x0,
  FRAME_TYPE_RST_STREAM        = 0x1,
  FRAME_TYPE_CLOSE             = 0x2,
  // 3 was goaway
  FRAME_TYPE_MAX_DATA          = 0x4,
  FRAME_TYPE_MAX_STREAM_DATA   = 0x5,
  FRAME_TYPE_MAX_STREAM_ID     = 0x6,
  FRAME_TYPE_PING              = 0x7,
  FRAME_TYPE_BLOCKED           = 0x8,
  FRAME_TYPE_STREAM_BLOCKED    = 0x9,
  FRAME_TYPE_STREAM_ID_BLOCKED  = 0xA,
  FRAME_TYPE_NEW_CONNECTION_ID = 0xB,
  FRAME_TYPE_STOP_SENDING      = 0xC,
  // ACK                       = 0xa0 - 0xbf
  FRAME_MASK_ACK               = 0xe0,
  FRAME_TYPE_ACK               = 0xa0, // 101. ....
  // STREAM                    = 0xc0 - 0xff
  FRAME_MASK_STREAM            = 0xc0,
  FRAME_TYPE_STREAM            = 0xc0, // 11.. ....
};

class MozQuic;

class FrameHeaderData
{
public:
  FrameHeaderData(const unsigned char *, uint32_t, MozQuic *, bool);
  FrameType mType;
  uint32_t  mValid;
  uint32_t  mFrameLen;
  union {
    struct {
      bool mFinBit;
      uint16_t mDataLen;
      uint32_t mStreamID;
      uint64_t mOffset;
    } mStream;
    struct {
      uint8_t mAckBlockLengthLen;
      uint8_t mNumBlocks;
      uint8_t mNumTS;
      uint64_t mLargestAcked;
      uint16_t mAckDelay;
    } mAck;
    struct {
      uint32_t mErrorCode;
      uint32_t mStreamID;
      uint64_t mFinalOffset;
    } mRstStream;
    struct {
      uint32_t mErrorCode;
      uint32_t mStreamID;
    } mStopSending;
    struct {
      uint32_t mErrorCode;
    } mClose;
    struct {
      uint32_t mClientStreamID;
      uint32_t mServerStreamID;
    } mGoaway;
    struct {
      uint64_t mMaximumData;
    } mMaxData;
    struct {
      uint32_t mStreamID;
      uint64_t mMaximumStreamData;
    } mMaxStreamData;
    struct {
      uint32_t mMaximumStreamID;
    } mMaxStreamID;
    struct {
      uint32_t mStreamID;
    } mStreamBlocked;
    struct {
      uint16_t mSequence;
      uint64_t mConnectionID;
    } mNewConnectionID;
  } u;
};

enum FrameTypeLengths {
  FRAME_TYPE_PADDING_LENGTH           = 1,
  FRAME_TYPE_RST_STREAM_LENGTH        = 17,
  FRAME_TYPE_CLOSE_LENGTH             = 7,
  FRAME_TYPE_MAX_DATA_LENGTH          = 9,
  FRAME_TYPE_MAX_STREAM_DATA_LENGTH   = 13,
  FRAME_TYPE_MAX_STREAM_ID_LENGTH     = 5,
  FRAME_TYPE_PING_LENGTH              = 1,
  FRAME_TYPE_BLOCKED_LENGTH           = 1,
  FRAME_TYPE_STREAM_BLOCKED_LENGTH    = 5,
  FRAME_TYPE_STREAM_ID_BLOCKED_LENGTH  = 1,
  FRAME_TYPE_NEW_CONNECTION_ID_LENGTH = 11,
  FRAME_TYPE_STOP_SENDING_LENGTH      = 9,
};

}

  
