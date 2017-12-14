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
  // need to decide if we want 2 or 4 byte packet numbers. 1 is pretty much
  // always too short as it doesn't allow a useful window
  // if (nextNumber - lowestUnacked) > 16000 then use 4.
  uint8_t pnSizeType = SHORT_2;
  if (!mStreamState->mUnAckedPackets.empty() &&
      ((mNextTransmitPacketNumber - mStreamState->mUnAckedPackets.front()->mPacketNumber) > 16000)) {
    pnSizeType = SHORT_4; // 4 bytes
  }

  // section 5.2 of transport short form header:
  // (0, mPeerOmitCID, k=0) | type [2 or 3]
  pkt[0] = ((mPeerOmitCID) ? 0x40 : 0x00) | pnSizeType;
  used = 1;

  if (!mPeerOmitCID) {
    uint64_t tmp64 = PR_htonll(mConnectionID);
    memcpy(pkt + used, &tmp64, 8);
    used += 8;
  }

  if (pnSizeType == 0x1e) { // 2 bytes
    uint16_t tmp16 = htons(mNextTransmitPacketNumber & 0xffff);
    memcpy(pkt + used, &tmp16, 2);
    used += 2;
  } else {
    assert(pnSizeType == 0x1d);
    uint32_t tmp32 = htonl(mNextTransmitPacketNumber & 0xffffffff);
    memcpy(pkt + used, &tmp32, 4);
    used += 4;
  }

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
  memset(&u, 0, sizeof (u));
  mValid = MOZQUIC_ERR_GENERAL;

  unsigned char type = pkt[0];
  const unsigned char *framePtr = pkt + 1;

  if ((type & FRAME_MASK_STREAM) == FRAME_TYPE_STREAM) {
    mType = FRAME_TYPE_STREAM;

    u.mStream.mFinBit = (type & STREAM_FIN_BIT);

    uint8_t ssBit = (type & 0x18) >> 3;
    uint8_t ooBit = (type & 0x06) >> 1;
    uint8_t dBit = (type & 0x01);

    uint32_t lenLen = dBit ? 2 : 0;
    uint32_t offsetLen = 0;
    assert(!(ooBit & 0xFC));
    if (ooBit == 0) {
      offsetLen = 0;
    } else if (ooBit == 1) {
      offsetLen = 2;
    } else if (ooBit == 2) {
      offsetLen = 4;
    } else if (ooBit == 3) {
      offsetLen = 8;
    }

    assert(!(ssBit & 0xFC));
    uint32_t idLen = ssBit + 1;

    uint32_t bytesNeeded = 1 + lenLen + idLen + offsetLen;
    if (bytesNeeded > pktSize) {
      if (!fromCleartext) {
        session->Shutdown(FRAME_FORMAT_ERROR, "stream frame header short");
      }
      session->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "stream frame header short");
      return;
    }

    memcpy(((char *)&u.mStream.mStreamID) + (4 - idLen), framePtr, idLen);
    framePtr += idLen;
    u.mStream.mStreamID = ntohl(u.mStream.mStreamID);

    memcpy(((char *)&u.mStream.mOffset) + (8 - offsetLen), framePtr, offsetLen);
    framePtr += offsetLen;
    u.mStream.mOffset = PR_ntohll(u.mStream.mOffset);
    if (dBit) {
      memcpy (&u.mStream.mDataLen, framePtr, 2);
      framePtr += 2;
      u.mStream.mDataLen = ntohs(u.mStream.mDataLen);
    } else {
      u.mStream.mDataLen = pktSize - bytesNeeded;
    }

    // todo log frame len
    if (bytesNeeded + u.mStream.mDataLen > pktSize) {
      if (!fromCleartext) {
        session->Shutdown(FRAME_FORMAT_ERROR, "stream frame header short2");
      }
      session->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "stream frame data short");
      return;
    }

    mValid = MOZQUIC_OK;
    mFrameLen = bytesNeeded;
    return;
  } else {
    switch(type) {

    case FRAME_TYPE_PADDING:
      mType = FRAME_TYPE_PADDING;
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_PADDING_LENGTH;
      return;

    case FRAME_TYPE_RST_STREAM:
      if (pktSize < FRAME_TYPE_RST_STREAM_LENGTH) {
        if (!fromCleartext) {
          session->Shutdown(FRAME_FORMAT_ERROR, "RST_STREAM frame length expected");
        }
        session->RaiseError(MOZQUIC_ERR_GENERAL,
                   (char *) "RST_STREAM frame length expected");
        return;
      }

      mType = FRAME_TYPE_RST_STREAM;

      memcpy(&u.mRstStream.mStreamID, framePtr, 4);
      u.mRstStream.mStreamID = ntohl(u.mRstStream.mStreamID);
      framePtr += 4;
      memcpy(&u.mRstStream.mErrorCode, framePtr, 2);
      u.mRstStream.mErrorCode = ntohs(u.mRstStream.mErrorCode);
      framePtr += 2;
      memcpy(&u.mRstStream.mFinalOffset, framePtr, 8);
      u.mRstStream.mFinalOffset = PR_ntohll(u.mRstStream.mFinalOffset);
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_RST_STREAM_LENGTH;
      return;

    case FRAME_TYPE_CONN_CLOSE:
      if (pktSize < FRAME_TYPE_CONN_CLOSE_LENGTH) {
        session->RaiseError(MOZQUIC_ERR_GENERAL,
                            "CONN_CLOSE frame length expected");
        return;
      }

      mType = FRAME_TYPE_CONN_CLOSE;

      memcpy(&u.mConnClose.mErrorCode, framePtr, 2);
      u.mConnClose.mErrorCode = ntohs(u.mConnClose.mErrorCode);
      framePtr += 2;
      {
        uint16_t len;
        memcpy(&len, framePtr, 2);
        len = ntohs(len);
        framePtr += 2;
        if (len) {
          if (pktSize < ((uint32_t)FRAME_TYPE_CONN_CLOSE_LENGTH + len)) {
            session->RaiseError(MOZQUIC_ERR_GENERAL,
                                (char *) "CONNECTION_CLOSE frame length expected");
            return;
          }
          // Log error!
          char reason[2048];
          if (len < 2048) {
            memcpy(reason, framePtr, len);
            reason[len] = '\0';
            Log::sDoLog(Log::CONNECTION, 4, session,
                        "Close conn code %X reason: %s\n",
                        u.mConnClose.mErrorCode, reason);
          }
        }
        mValid = MOZQUIC_OK;
        mFrameLen = FRAME_TYPE_CONN_CLOSE_LENGTH + len;
      }
      return;

    case FRAME_TYPE_APPLICATION_CLOSE:
      if (pktSize < FRAME_TYPE_APPLICATION_CLOSE_LENGTH) {
        session->RaiseError(MOZQUIC_ERR_GENERAL,
                            "APPLICATION_CLOSE frame length expected");
        return;
      }

      mType = FRAME_TYPE_APPLICATION_CLOSE;

      memcpy(&u.mApplicationClose.mErrorCode, framePtr, 2);
      u.mApplicationClose.mErrorCode = ntohs(u.mApplicationClose.mErrorCode);
      framePtr += 2;
      {
        uint16_t len;
        memcpy(&len, framePtr, 2);
        len = ntohs(len);
        framePtr += 2;
        if (len) {
          if (pktSize < ((uint32_t)FRAME_TYPE_APPLICATION_CLOSE_LENGTH + len)) {
            session->RaiseError(MOZQUIC_ERR_GENERAL,
                                (char *) "APPLICATION_CLOSE frame length expected");
            return;
          }
          // Log error!
          char reason[2048];
          if (len < 2048) {
            memcpy(reason, framePtr, len);
            reason[len] = '\0';
            Log::sDoLog(Log::CONNECTION, 4, session,
                        "Application close code %X reason: %s\n",
                        u.mApplicationClose.mErrorCode, reason);
          }
        }
        mValid = MOZQUIC_OK;
        mFrameLen = FRAME_TYPE_APPLICATION_CLOSE_LENGTH + len;
      }
      return;

    case FRAME_TYPE_MAX_DATA:
      if (pktSize < FRAME_TYPE_MAX_DATA_LENGTH) {
        session->RaiseError(MOZQUIC_ERR_GENERAL,
                   (char *) "MAX_DATA frame length expected");
        return;
      }

      mType = FRAME_TYPE_MAX_DATA;

      memcpy(&u.mMaxData.mMaximumData, framePtr, 8);
      u.mMaxData.mMaximumData = PR_ntohll(u.mMaxData.mMaximumData);
      mValid = MOZQUIC_OK;
      mFrameLen =  FRAME_TYPE_MAX_DATA_LENGTH;
      return;

    case FRAME_TYPE_MAX_STREAM_DATA:
      if (pktSize < FRAME_TYPE_MAX_STREAM_DATA_LENGTH) {
        session->RaiseError(MOZQUIC_ERR_GENERAL,
                   (char *) "MAX_STREAM_DATA frame length expected");
        return;
      }

      mType = FRAME_TYPE_MAX_STREAM_DATA;

      memcpy(&u.mMaxStreamData.mStreamID, framePtr, 4);
      u.mMaxStreamData.mStreamID = ntohl(u.mMaxStreamData.mStreamID);
      framePtr += 4;
      memcpy(&u.mMaxStreamData.mMaximumStreamData, framePtr, 8);
      u.mMaxStreamData.mMaximumStreamData =
        PR_ntohll(u.mMaxStreamData.mMaximumStreamData);
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_MAX_STREAM_DATA_LENGTH;
      return;

    case FRAME_TYPE_MAX_STREAM_ID:
      if (pktSize < FRAME_TYPE_MAX_STREAM_ID_LENGTH) {
        session->RaiseError(MOZQUIC_ERR_GENERAL,
                   (char *) "MAX_STREAM_ID frame length expected");
        return;
      }

      mType = FRAME_TYPE_MAX_STREAM_ID;

      memcpy(&u.mMaxStreamID.mMaximumStreamID, framePtr, 4);
      u.mMaxStreamID.mMaximumStreamID =
        ntohl(u.mMaxStreamID.mMaximumStreamID);
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_MAX_STREAM_ID_LENGTH;
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
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_BLOCKED_LENGTH;
      return;

    case FRAME_TYPE_STREAM_BLOCKED:
      if (pktSize < FRAME_TYPE_STREAM_BLOCKED_LENGTH) {
        session->RaiseError(MOZQUIC_ERR_GENERAL,
                   (char *) "STREAM_BLOCKED frame length expected");
        return;
      }

      mType = FRAME_TYPE_STREAM_BLOCKED;

      memcpy(&u.mStreamBlocked.mStreamID, framePtr, 4);
      u.mStreamBlocked.mStreamID = ntohl(u.mStreamBlocked.mStreamID);
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_STREAM_BLOCKED_LENGTH;
      return;

    case FRAME_TYPE_STREAM_ID_BLOCKED:
      mType = FRAME_TYPE_STREAM_ID_BLOCKED;
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_STREAM_ID_BLOCKED_LENGTH;
      return;

    case FRAME_TYPE_NEW_CONNECTION_ID:
      if (pktSize < FRAME_TYPE_NEW_CONNECTION_ID_LENGTH) {
        session->RaiseError(MOZQUIC_ERR_GENERAL,
                   (char *) "NEW_CONNECTION_ID frame length expected");
        return;
      }

      mType = FRAME_TYPE_NEW_CONNECTION_ID;

      memcpy(&u.mNewConnectionID.mSequence, framePtr, 2);
      u.mNewConnectionID.mSequence = ntohs(u.mNewConnectionID.mSequence);
      framePtr += 2;
      memcpy(&u.mNewConnectionID.mConnectionID, framePtr, 8);
      u.mNewConnectionID.mConnectionID =
        PR_ntohll(u.mNewConnectionID.mConnectionID);
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_NEW_CONNECTION_ID_LENGTH;
      return;

    case FRAME_TYPE_STOP_SENDING:
      if (pktSize < FRAME_TYPE_STOP_SENDING_LENGTH) {
        session->RaiseError(MOZQUIC_ERR_GENERAL,
                   (char *) "STOP SENDING frame length expected");
        return;
      }

      mType = FRAME_TYPE_STOP_SENDING;

      memcpy(&u.mStopSending.mStreamID, framePtr, 4);
      u.mStopSending.mStreamID = ntohl(u.mStopSending.mStreamID);
      framePtr += 4;
      memcpy(&u.mStopSending.mErrorCode, framePtr, 2);
      u.mStopSending.mErrorCode = ntohs(u.mStopSending.mErrorCode);
      
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_STOP_SENDING_LENGTH;
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

LongHeaderData::LongHeaderData(unsigned char *pkt, uint32_t pktSize)
{
  // these fields are all version independent - though the interpretation
  // of type is not.
  assert(pktSize >= 17);
  assert(pkt[0] & 0x80);
  mType = static_cast<enum LongHeaderType>(pkt[0] & ~0x80);
  memcpy(&mConnectionID, pkt + 1, 8);
  mConnectionID = PR_ntohll(mConnectionID);
  memcpy(&mVersion, pkt + 9, 4);
  mVersion = ntohl(mVersion);
  memcpy(&mPacketNumber, pkt + 13, 4);
  mPacketNumber = ntohl(mPacketNumber);
}

uint64_t
ShortHeaderData::DecodePacketNumber(unsigned char *pkt, int pnSize, uint64_t next)
{
  // pkt should point to a variable (as defined by pnSize) amount of data
  // in network byte order
  uint64_t candidate1, candidate2;
  if (pnSize == 1) {
    candidate1 = (next & ~0xFFUL) | pkt[0];
    candidate2 = candidate1 + 0x100UL;
  } else if (pnSize == 2) {
    uint16_t tmp16;
    memcpy(&tmp16, pkt, 2);
    tmp16 = ntohs(tmp16);
    candidate1 = (next & ~0xFFFFUL) | tmp16;
    candidate2 = candidate1 + 0x10000UL;
  } else {
    assert (pnSize == 4);
    uint32_t tmp32;
    memcpy(&tmp32, pkt, 4);
    tmp32 = ntohl(tmp32);
    candidate1 = (next & ~0xFFFFFFFFUL) | tmp32;
    candidate2 = candidate1 + 0x100000000UL;
  }

  uint64_t distance1 = (next >= candidate1) ? (next - candidate1) : (candidate1 - next);
  uint64_t distance2 = (next >= candidate2) ? (next - candidate2) : (candidate2 - next);
  uint64_t rv = (distance1 < distance2) ? candidate1 : candidate2;
  return rv;
}

ShortHeaderData::ShortHeaderData(unsigned char *pkt, uint32_t pktSize,
                                 uint64_t nextPN, uint64_t defaultCID)
{
  mHeaderSize = 0xffffffff;
  mConnectionID = 0;
  mPacketNumber = 0;
  assert(pktSize >= 1);
  assert(!(pkt[0] & 0x80));
  uint32_t pnSize = pkt[0] & 0x1f;
  if (pnSize == SHORT_1) {
    pnSize = 1;
  } else if (pnSize == SHORT_2) {
    pnSize = 2;
  } else if (pnSize == SHORT_4) {
    pnSize = 4;
  } else {
    return;
  }

  uint32_t used;
  if (((pkt[0] & 0x40)) || (pktSize < (9 + pnSize))) {
    // missing connection id. without the truncate transport option this cannot happen
    used = 1;
    mConnectionID = defaultCID;
  } else {
    memcpy(&mConnectionID, pkt + 1, 8);
    mConnectionID = PR_ntohll(mConnectionID);
    used = 9;
  }

  mHeaderSize = used + pnSize;
  mPacketNumber = DecodePacketNumber(pkt + used, pnSize, nextPN);
}

}
