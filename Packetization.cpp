/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "Logging.h"
#include "MozQuic.h"
#include "MozQuicInternal.h"
#include "Packetization.h"
#include "Streams.h"

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

namespace mozquic  {

uint32_t
MozQuic::CreateShortPacketHeader(unsigned char *pkt, uint32_t pktSize,
                                 uint32_t &used)
{
  used = 0;
  // dtls hack
  return MOZQUIC_OK;
}

uint32_t
MozQuic::DecodeVarint(const unsigned char *ptr, uint32_t avail, uint64_t &result, uint32_t &used) 
{
  used = 0;
  if (avail < 1) {
    return MOZQUIC_ERR_GENERAL;
  }

  if ((ptr[0] & 0xC0) == 0x00) {
    result = ptr[0] & ~0xC0;
    used = 1;
    
  } else if ((ptr[0] & 0xC0) == 0x40) {
    if (avail < 2) {
      return MOZQUIC_ERR_GENERAL;
    }
    uint16_t tmp16;
    memcpy(&tmp16, ptr, sizeof(tmp16));
    ((unsigned char *)&tmp16)[0] &= ~0xC0;
    result = ntohs(tmp16);
    used = 2;
    
  } else if ((ptr[0] & 0xC0) == 0x80) {
    if (avail < 4) {
      return MOZQUIC_ERR_GENERAL;
    }
    uint32_t tmp32;
    memcpy(&tmp32, ptr, sizeof(tmp32));
    ((unsigned char *)&tmp32)[0] &= ~0xC0;
    result = ntohl(tmp32);
    used = 4;

  } else {
    assert ((ptr[0] & 0xC0) == 0xC0);
    if (avail < 8) {
      return MOZQUIC_ERR_GENERAL;
    }
    uint64_t tmp64;
    memcpy(&tmp64, ptr, sizeof(tmp64));
    ((unsigned char *)&tmp64)[0] &= ~0xC0;
    result = PR_ntohll(tmp64);
    used = 8;
  }
  return MOZQUIC_OK;
}

uint32_t
MozQuic::DecodeVarintMax32(const unsigned char *ptr, uint32_t avail, uint32_t &result, uint32_t &used)
{
  uint64_t tmp64;
  uint32_t rv = DecodeVarint(ptr, avail, tmp64, used);
  if (rv != MOZQUIC_OK) {
    return rv;
  }
  if (tmp64 & ~0xffffffffULL) {
    return MOZQUIC_ERR_GENERAL;
  }
  result = tmp64;
  return MOZQUIC_OK;
}
  
void
MozQuic::EncodeVarintAs1(uint64_t input, unsigned char *dest)
{
  assert (input < (1 << 6));
  dest[0] = (uint8_t) input;
}

void
MozQuic::EncodeVarintAs2(uint64_t input, unsigned char *dest)
{
  assert (input < (1 << 14));
  uint16_t tmp16 = (uint16_t) input;
  tmp16 = htons(tmp16);
  memcpy(dest, &tmp16, sizeof(tmp16));
  dest[0] |= 0x40;
}

void
MozQuic::EncodeVarintAs4(uint64_t input, unsigned char *dest)
{
  assert (input < (1 << 30));
  uint32_t tmp32 = (uint32_t) input;
  tmp32 = htonl(tmp32);
  memcpy(dest, &tmp32, sizeof(tmp32));
  dest[0] |= 0x80;
}

void
MozQuic::EncodeVarintAs8(uint64_t input, unsigned char *dest)
{
  assert (input < (1ULL << 62));
  input = PR_htonll(input);
  memcpy(dest, &input, sizeof(input));
  dest[0] |= 0xC0;
}

uint32_t
MozQuic::EncodeVarint(uint64_t input, unsigned char *dest, uint32_t avail, uint32_t &used)
{
  used = 0;
  if (input < (1 << 6)) {
    if (avail < 1) {
      return MOZQUIC_ERR_GENERAL;
    }
    used = 1;
    EncodeVarintAs1(input, dest);
  } else if (input < (1 << 14)) {
    if (avail < 2) {
      return MOZQUIC_ERR_GENERAL;
    }
    used = 2;
    EncodeVarintAs2(input, dest);
  } else if (input < (1 << 30)) {
    if (avail < 4) {
      return MOZQUIC_ERR_GENERAL;
    }
    used = 4;
    EncodeVarintAs4(input, dest);
  } else if (input < (1ULL << 62)) {
    if (avail < 8) {
      return MOZQUIC_ERR_GENERAL;
    }
    used = 8;
    EncodeVarintAs8(input, dest);
  } else {
    // out of range
    return MOZQUIC_ERR_GENERAL;
  }

  return MOZQUIC_OK;
}

FrameHeaderData::FrameHeaderData(const unsigned char *pkt, uint32_t pktSize,
                                 MozQuic *session, bool fromCleartext)
{
  uint32_t used;
  uint16_t tmp16;
  memset(&u, 0, sizeof (u));
  mValid = MOZQUIC_ERR_GENERAL;

  unsigned char type = pkt[0];
  const unsigned char *framePtr = pkt + 1;
  const unsigned char *endOfPkt = pkt + pktSize;

  if ((type & FRAME_MASK_STREAM) == FRAME_TYPE_STREAM) {
    mType = FRAME_TYPE_STREAM;
    u.mStream.mFinBit = (type & STREAM_FIN_BIT);

    if (MozQuic::DecodeVarintMax32(framePtr, endOfPkt - framePtr, u.mStream.mStreamID, used) != MOZQUIC_OK) {
      session->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "parse err");
      return;
    }
    framePtr += used;
    
    if (type & STREAM_OFF_BIT) {
      if (MozQuic::DecodeVarint(framePtr, endOfPkt - framePtr, u.mStream.mOffset, used) != MOZQUIC_OK) {
        session->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "parse err");
        return;
      }
      framePtr += used;
    } else {
      u.mStream.mOffset = 0;
    }

    if (type & STREAM_LEN_BIT) {
      if (MozQuic::DecodeVarintMax32(framePtr, endOfPkt - framePtr, u.mStream.mDataLen, used) != MOZQUIC_OK) {
        session->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "parse err");
        return;
      }
      framePtr += used;
    } else {
      u.mStream.mDataLen = (endOfPkt - framePtr);
      Log::sDoLog(Log::CONNECTION, 5, session,
                  "stream %d implicit len %d\n", u.mStream.mStreamID, u.mStream.mDataLen);
    }

    if ((framePtr - pkt) + u.mStream.mDataLen > pktSize) {
      if (!fromCleartext) {
        session->Shutdown(FRAME_FORMAT_ERROR, "stream frame header short");
      }
      session->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "stream frame data short");
      return;
    }

    mValid = MOZQUIC_OK;
    mFrameLen = framePtr - pkt;
    return;
  } else {
    switch(type) {

    case FRAME_TYPE_PADDING:
      mType = FRAME_TYPE_PADDING;
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_PADDING_LENGTH;
      return;

    case FRAME_TYPE_RST_STREAM:
      mType = FRAME_TYPE_RST_STREAM;

      if (MozQuic::DecodeVarintMax32(framePtr, endOfPkt - framePtr, u.mRstStream.mStreamID, used) != MOZQUIC_OK) {
        session->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "parse err");
        return;
      }
      framePtr += used;

      if ((endOfPkt - framePtr) < 2) {
        session->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "parse err");
        return;
      }
      memcpy(&u.mRstStream.mErrorCode, framePtr, 2);
      u.mRstStream.mErrorCode = ntohs(u.mRstStream.mErrorCode);
      framePtr += 2;

      if (MozQuic::DecodeVarint(framePtr, endOfPkt - framePtr, u.mRstStream.mFinalOffset, used) != MOZQUIC_OK) {
        session->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "parse err");
        return;
      }
      framePtr += used;

      mValid = MOZQUIC_OK;
      mFrameLen = framePtr - pkt;
      return;

    case FRAME_TYPE_CONN_CLOSE:
    case FRAME_TYPE_APPLICATION_CLOSE:
      mType = (FrameType) type;

      if ((endOfPkt - framePtr) < 2) {
        session->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "parse err");
        return;
      }
      memcpy(&tmp16, framePtr, 2);
      tmp16 = ntohs(tmp16);
      if (mType == FRAME_TYPE_CONN_CLOSE) {
        u.mConnClose.mErrorCode = tmp16;
      } else {
        u.mApplicationClose.mErrorCode = tmp16;
      }
      framePtr += 2;

      {
        uint32_t len;
        if (MozQuic::DecodeVarintMax32(framePtr, endOfPkt - framePtr, len, used) != MOZQUIC_OK) {
          session->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "parse err");
          return;
        }
        framePtr += used;

        if (len) {
          if ((endOfPkt - framePtr) < len) {
            session->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "parse err");
            return;
          }
          // Log error!
          char reason[2048];
          if (len < 2048) {
            memcpy(reason, framePtr, len);
            reason[len] = '\0';
            Log::sDoLog(Log::CONNECTION, 4, session,
                        "Close conn code %X reason: %s\n", tmp16, reason);
          }
          framePtr += len;
        }
      }
      mValid = MOZQUIC_OK;
      mFrameLen = framePtr - pkt;
      return;

    case FRAME_TYPE_MAX_DATA:
      mType = FRAME_TYPE_MAX_DATA;

      if (MozQuic::DecodeVarint(framePtr, endOfPkt - framePtr, u.mMaxData.mMaximumData, used) != MOZQUIC_OK) {
        session->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "parse err");
        return;
      }
      framePtr += used;
        
      mValid = MOZQUIC_OK;
      mFrameLen = framePtr - pkt;
      return;

    case FRAME_TYPE_MAX_STREAM_DATA:
      mType = FRAME_TYPE_MAX_STREAM_DATA;

      if (MozQuic::DecodeVarintMax32(framePtr, endOfPkt - framePtr, u.mMaxStreamData.mStreamID, used) != MOZQUIC_OK) {
        session->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "parse err");
        return;
      }
      framePtr += used;

      if (MozQuic::DecodeVarint(framePtr, endOfPkt - framePtr, u.mMaxStreamData.mMaximumStreamData, used) != MOZQUIC_OK) {
        session->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "parse err");
        return;
      }
      framePtr += used;

      mValid = MOZQUIC_OK;
      mFrameLen = framePtr - pkt;
      return;

    case FRAME_TYPE_MAX_STREAM_ID:
      mType = FRAME_TYPE_MAX_STREAM_ID;
      if (MozQuic::DecodeVarintMax32(framePtr, endOfPkt - framePtr, u.mMaxStreamID.mMaximumStreamID, used) != MOZQUIC_OK) {
        session->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "parse err");
        return;
      }
      framePtr += used;
      mValid = MOZQUIC_OK;
      mFrameLen = framePtr - pkt;
      return;

    case FRAME_TYPE_PING:
      if (pktSize < FRAME_TYPE_PING_LENGTH) {
        session->RaiseError(MOZQUIC_ERR_GENERAL,
                            (char *) "PING frame length expected");
        return;
      }
      mType = FRAME_TYPE_PING;
      u.mPing.mDataLen = framePtr[0];
      if (pktSize < FRAME_TYPE_PING_LENGTH + u.mPing.mDataLen) {
        session->RaiseError(MOZQUIC_ERR_GENERAL,
                            (char *) "PING frame length expected");
        return;
      }
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_PING_LENGTH;
      return;

    case FRAME_TYPE_PONG:
      if (pktSize < FRAME_TYPE_PONG_LENGTH) {
        session->RaiseError(MOZQUIC_ERR_GENERAL,
                            (char *) "PONG frame length expected");
        return;
      }
      mType = FRAME_TYPE_PONG;
      u.mPong.mDataLen = framePtr[0];
      if (pktSize < FRAME_TYPE_PONG_LENGTH + u.mPong.mDataLen) {
        session->RaiseError(MOZQUIC_ERR_GENERAL,
                            (char *) "PONG frame length expected");
        return;
      }
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_PONG_LENGTH;
      return;

    case FRAME_TYPE_BLOCKED:
      mType = FRAME_TYPE_BLOCKED;
      if (MozQuic::DecodeVarint(framePtr, endOfPkt - framePtr, u.mBlocked.mOffset, used) != MOZQUIC_OK) {
        session->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "parse err");
        return;
      }
      framePtr += used;

      mValid = MOZQUIC_OK;
      mFrameLen = framePtr - pkt;
      return;

    case FRAME_TYPE_STREAM_BLOCKED:
      mType = FRAME_TYPE_STREAM_BLOCKED;

      if (MozQuic::DecodeVarintMax32(framePtr, endOfPkt - framePtr, u.mStreamBlocked.mStreamID, used) != MOZQUIC_OK) {
        session->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "parse err");
        return;
      }
      framePtr += used;

      if (MozQuic::DecodeVarint(framePtr, endOfPkt - framePtr, u.mStreamBlocked.mOffset, used) != MOZQUIC_OK) {
        session->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "parse err");
        return;
      }
      framePtr += used;
      mFrameLen = framePtr - pkt;
      mValid = MOZQUIC_OK;

      return;

    case FRAME_TYPE_STREAM_ID_BLOCKED:
      mType = FRAME_TYPE_STREAM_ID_BLOCKED;
      if (MozQuic::DecodeVarintMax32(framePtr, endOfPkt - framePtr, u.mStreamIDBlocked.mStreamID, used) != MOZQUIC_OK) {
        session->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "parse err");
        return;
      }
      framePtr += used;

      mValid = MOZQUIC_OK;
      mFrameLen = framePtr - pkt;
      return;

    case FRAME_TYPE_NEW_CONNECTION_ID:
      mType = FRAME_TYPE_NEW_CONNECTION_ID;
      if (MozQuic::DecodeVarint(framePtr, endOfPkt - framePtr, u.mNewConnectionID.mSequence, used) != MOZQUIC_OK) {
        session->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "parse err");
        return;
      }
      framePtr += used;

      if ((endOfPkt - framePtr) < 24) {
        session->RaiseError(MOZQUIC_ERR_GENERAL,
                            (char *) "NEW_CONNECTION_ID frame length expected");
        return;
      }

      memcpy(&u.mNewConnectionID.mConnectionID, framePtr, 8);
      u.mNewConnectionID.mConnectionID = PR_ntohll(u.mNewConnectionID.mConnectionID);
      framePtr += 8;
      memcpy(u.mNewConnectionID.mToken, framePtr, 16);
      framePtr += 16;
             
      mValid = MOZQUIC_OK;
      mFrameLen = framePtr - pkt;
      return;

    case FRAME_TYPE_STOP_SENDING:
      mType = FRAME_TYPE_STOP_SENDING;
      if (MozQuic::DecodeVarintMax32(framePtr, endOfPkt - framePtr, u.mStopSending.mStreamID, used) != MOZQUIC_OK) {
        session->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "parse err");
        return;
      }
      framePtr += used;

      if ((endOfPkt - framePtr) < 2) {
        session->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "parse error");
        return;
      }

      memcpy(&u.mStopSending.mErrorCode, framePtr, 2);
      u.mStopSending.mErrorCode = ntohs(u.mStopSending.mErrorCode);
      framePtr += 2;
      
      mValid = MOZQUIC_OK;
      mFrameLen = framePtr - pkt;
      return;
      
    case FRAME_TYPE_ACK:
      mType = FRAME_TYPE_ACK;
      u.mAck.mLargestAcked = 0;
      uint32_t used;
      if (MozQuic::DecodeVarint(framePtr, (pkt + pktSize) - framePtr,
                                u.mAck.mLargestAcked, used) != MOZQUIC_OK) {
        session->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "ack frame header short");
        return;
      }
      framePtr += used;
      if (MozQuic::DecodeVarint(framePtr, (pkt + pktSize) - framePtr,
                                u.mAck.mAckDelay, used) != MOZQUIC_OK) {
        session->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "ack frame header short");
        return;
      }
      framePtr += used;
      if (MozQuic::DecodeVarint(framePtr, (pkt + pktSize) - framePtr,
                                u.mAck.mAckBlocks, used) != MOZQUIC_OK) {
        session->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "ack frame header short");
        return;
      }
      framePtr += used;
      u.mAck.mAckBlocks++;

      mValid = MOZQUIC_OK;
      mFrameLen = framePtr - pkt;
      return;

    default:
      return;
    }
  }
  mValid = MOZQUIC_OK;
}

ShortHeaderData::ShortHeaderData(MozQuic *logging,
                                 unsigned char *pkt, uint32_t pktSize,
                                 uint64_t nextPN, bool allowOmitCID,
                                 uint64_t defaultCID)
{
  mHeaderSize = 0;
  mConnectionID = 0;
  mPacketNumber = 0xffffffff;
  if (pktSize < 11) {
    Log::sDoLog(Log::CONNECTION, 1, logging,
                "DTLS HEADER NOT AT LEAST 11\n");
    return;
  }

  // pkt[0] is type.. application is 23 handshake is 22
  // pkt[1] pkt[2] is version.. 254.253 for dtls 1.2. 254.255 is 1.3?
  // pkt[3] pkt[4] is epoch (3 for quic generated data)
  // pkt[5] [6] [7] [8] [9] [10] 48 bits is seq no (pkt no)

  mPacketNumber = 0;
  memcpy(((unsigned char *)(&mPacketNumber)) + 2, pkt + 5, 6);
  mPacketNumber = PR_ntohll(mPacketNumber);
}

}
