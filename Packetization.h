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

  STREAM_FIN_BIT = 0x01,
  STREAM_LEN_BIT = 0x02,
  STREAM_OFF_BIT = 0x04,
};

enum LongHeaderType {
  PACKET_TYPE_INITIAL                = 0x7F,
  PACKET_TYPE_RETRY                  = 0x7E,
  PACKET_TYPE_HANDSHAKE              = 0x7D,
  PACKET_TYPE_0RTT_PROTECTED         = 0x7C,
};

enum ShortHeaderType {
  SHORT_1 = 0x00,
  SHORT_2 = 0x01,
  SHORT_4 = 0x02,
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

class MozQuic;

class ShortHeaderData
{
private:
  static uint64_t DecodePacketNumber(unsigned char *pkt, int pnSize, uint64_t next);

public:
  ShortHeaderData(MozQuic *logging, unsigned char *, uint32_t, uint64_t, bool, uint64_t);
  uint32_t mHeaderSize;
  uint64_t mConnectionID;
  uint64_t mPacketNumber;
};

enum FrameType {
  FRAME_TYPE_PADDING           = 0x00,
  FRAME_TYPE_RST_STREAM        = 0x01,
  FRAME_TYPE_CONN_CLOSE        = 0x02,
  FRAME_TYPE_APPLICATION_CLOSE = 0x03,
  FRAME_TYPE_MAX_DATA          = 0x04,
  FRAME_TYPE_MAX_STREAM_DATA   = 0x05,
  FRAME_TYPE_MAX_STREAM_ID     = 0x06,
  FRAME_TYPE_PING              = 0x07,
  FRAME_TYPE_BLOCKED           = 0x08,
  FRAME_TYPE_STREAM_BLOCKED    = 0x09,
  FRAME_TYPE_STREAM_ID_BLOCKED  = 0x0A,
  FRAME_TYPE_NEW_CONNECTION_ID = 0x0B,
  FRAME_TYPE_STOP_SENDING      = 0x0C,
  FRAME_TYPE_ACK               = 0x0D,
  FRAME_TYPE_PATH_CHALLENGE    = 0x0E,
  FRAME_TYPE_PATH_RESPONSE     = 0x0F,

  // STREAM                    = 0x10 to 0x17
  FRAME_MASK_STREAM            = 0xf8,
  FRAME_TYPE_STREAM            = 0x10, // 0001 0...
};

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
      uint32_t mDataLen;
      uint32_t mStreamID;
      uint64_t mOffset;
    } mStream;
    struct {
      uint64_t mLargestAcked;
      uint64_t mAckDelay;
      uint64_t mAckBlocks; // includes block 0 with implicit gap0
    } mAck;
    struct {
      uint32_t mStreamID;
      uint16_t mErrorCode;
      uint64_t mFinalOffset;
    } mRstStream;
    struct {
      uint32_t mStreamID;
      uint16_t mErrorCode;
    } mStopSending;
    struct {
      uint16_t mErrorCode;
    } mConnClose;
    struct {
      uint16_t mErrorCode;
    } mApplicationClose;
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
      uint64_t mOffset;
    } mStreamBlocked;
    struct {
      uint64_t mSequence;
      uint64_t mConnectionID;
      uint8_t  mToken[16];
     } mNewConnectionID;
    struct {
      uint64_t mOffset;
    } mBlocked;
    struct {
      uint32_t mStreamID;
    } mStreamIDBlocked;
  } u;

};

enum FrameTypeLengths {
  FRAME_TYPE_PADDING_LENGTH           = 1,
  FRAME_TYPE_PING_LENGTH              = 1,
};

}

  
