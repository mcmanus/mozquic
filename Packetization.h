/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <assert.h>

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
  PACKET_TYPE_ERR                    = 0xFF
};

enum operationType {
  kEncrypt0,
  kDecrypt0,
//  kEncrypt1,
//  kDecrypt1,
  kEncryptHandshake,
  kDecryptHandshake,
  kEncrypt0RTT,
  kDecrypt0RTT,
};

class CID
{
public:
CID() : mNull(true) { mText[0] = '-'; mText[1] = 0;}
  void Parse(uint8_t cil, const unsigned char *cidptr);
  void Randomize();
  char *Text();

  operator uint64_t() const{
    assert(0);
    return 0;
  }
  
  operator bool() const {
    return !Null();
  }

  bool operator !() const {
    return Null();
  }

  bool operator ==(const CID &b) const {
    return (mLen == b.mLen) && !memcmp(mID, b.mID, mLen);
  }

  bool operator !=(const CID &b) const {
    return !((mLen == b.mLen) && !memcmp(mID, b.mID, mLen));
  }

  size_t Hash() const;
  uint32_t Len() const { return mLen; }
  const unsigned char *Data() const { return &mID[0]; }

  static uint32_t FormatLongHeader(const CID &destCID, const CID &srcCID, bool omitLocal,
                                   unsigned char *output, uint32_t avail, uint32_t &used);
private:
  bool Null() const { return mNull; }
  void BuildText();

  unsigned char mID[18];
  uint32_t mLen;
  bool         mNull;
  char mText[37]; // todo make this lazy allocated for logging
};

class MozQuic;

class LongHeaderData
{
public:
  LongHeaderData(MozQuic *, unsigned char *, uint32_t, uint64_t next);
  enum LongHeaderType mType;
  CID mDestCID;
  CID mSourceCID;
  uint32_t mPayloadLen;
  uint64_t mPacketNumber;
  uint32_t mVersion;
  uint32_t mHeaderSize;

private:
  uint64_t DecodePacketNumber(unsigned char *pkt, uint64_t next, uint32_t pktSize,
                              size_t &outPNSize);
};

class ShortHeaderData
{
public:
  ShortHeaderData(MozQuic *logging, unsigned char *, uint32_t, uint64_t, bool,
                  CID &defaultCID);

  static uint64_t DecodePacketNumber(MozQuic *, enum operationType mode,
                                     unsigned char *pkt, uint64_t next, uint32_t pktSize,
                                     size_t &outPNSize);

  static uint64_t DecodePlaintextPacketNumber(unsigned char *pkt,
                                              uint64_t next, uint32_t pktSize,
                                              size_t &outPNSize);

  uint32_t mHeaderSize;
  CID mDestCID;
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
      uint8_t  mToken[16];
     } mNewConnectionID;
    struct {
      uint64_t mOffset;
    } mBlocked;
    struct {
      uint32_t mStreamID;
    } mStreamIDBlocked;
    struct {
      uint64_t mData;
    } mPathChallenge;
    struct {
      uint64_t mData;
    } mPathResponse;
  } u;

  CID  mForNewConnectionID;
};

enum FrameTypeLengths {
  FRAME_TYPE_PADDING_LENGTH           = 1,
  FRAME_TYPE_PING_LENGTH              = 1,
  FRAME_TYPE_PATH_CHALLENGE_LENGTH    = 9,
  FRAME_TYPE_PATH_RESPONSE_LENGTH     = 9
};

}

  
