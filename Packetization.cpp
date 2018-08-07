/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "Logging.h"
#include "MozQuic.h"
#include "MozQuicInternal.h"
#include "NSSHelper.h"
#include "Packetization.h"
#include "Streams.h"

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

namespace mozquic  {

uint32_t
MozQuic::CreateShortPacketHeader(unsigned char *pkt, uint32_t pktSize,
                                 uint32_t &used, unsigned char **pnPtrOut)
{
  // need to decide if we want 2 or 4 byte packet numbers. 1 is pretty much
  // always too short as it doesn't allow a useful window
  // if (nextNumber - lowestUnacked) > 8000 then use 4.
  size_t pnSize = 2;
  uint32_t needed = 3 + mPeerCID.Len();
  if (!mStreamState->mUnAckedPackets.empty() &&
      ((mNextTransmitPacketNumber - mStreamState->mUnAckedPackets.front()->mPacketNumber) > 8000)) {
    pnSize = 4;
    needed += 2;
  }

  if (needed > pktSize) {
    return MOZQUIC_ERR_GENERAL;
  }

  // section 4.2 of transport short form header:
  // 0k11 0rrr .. k=0 r=0
  pkt[0] = 0x30;
  used = 1;
  memcpy (pkt + used, mPeerCID.Data(), mPeerCID.Len());
  used += mPeerCID.Len();
  *pnPtrOut = pkt + used;

  if (pnSize == 2) { // 2 bytes
    uint16_t tmp16 = htons(mNextTransmitPacketNumber & 0x3fff);
    memcpy(pkt + used, &tmp16, 2);
    pkt[used] |= 0x80; // 2 byte marker
    used += 2;
  } else {
    assert(pnSize == 4);
    uint32_t tmp32 = htonl(mNextTransmitPacketNumber & 0x3fffffff);
    memcpy(pkt + used, &tmp32, 4);
    pkt[used] |= 0xC0; // 4 byte marker
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

uint32_t
MozQuic::Create0RTTLongPacketHeader(unsigned char *pkt, uint32_t pktSize,
                                    uint32_t &used, unsigned char **payloadLenPtr,
                                    unsigned char **pnPtr)
{
  unsigned char *framePtr = pkt;
  if (pktSize < 5) {
    return MOZQUIC_ERR_GENERAL;
  }
  framePtr[0] = 0x80 | PACKET_TYPE_0RTT_PROTECTED;
  framePtr++;

  uint32_t tmp32 = htonl(mVersion);
  memcpy(framePtr, &tmp32, 4);
  framePtr += 4;

  uint32_t rv = CID::FormatLongHeader(mPeerCID, mLocalCID, mLocalOmitCID, framePtr,
                                      (pkt + pktSize) - framePtr, used);
  if (rv != MOZQUIC_OK) {
    return rv;
  }
  framePtr += used;

  if (((pkt + pktSize) - framePtr) < 6) {
    return MOZQUIC_ERR_GENERAL;
  }

  // This is the pointer to the payloadLen varint that
  // the caller will need to fill in (we don't yet know the
  // payload len). always make it 2 bytes to accomodate the
  // full possible range.
  *payloadLenPtr = framePtr;
  (*payloadLenPtr)[0] = 0x40;
  (*payloadLenPtr)[1] = 0x00;  
  framePtr += 2;

  size_t pnLen;
  *pnPtr = framePtr;
  EncodePN(mNextTransmitPacketNumber, framePtr, pnLen);
  framePtr += pnLen;

  used = framePtr - pkt;
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
      mType = FRAME_TYPE_PING;
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_PING_LENGTH;
      return;

    case FRAME_TYPE_PATH_CHALLENGE:
      if (fromCleartext) {
        session->Shutdown(FRAME_FORMAT_ERROR, "Frame Type not allowed");
        return;
      }

      if (pktSize < FRAME_TYPE_PATH_CHALLENGE_LENGTH) {
        session->RaiseError(MOZQUIC_ERR_GENERAL,
                            (char *) "challenge length expected");
        return;
      }

      memcpy(&u.mPathChallenge.mData, framePtr, sizeof(u.mPathChallenge.mData));
      mType = FRAME_TYPE_PATH_CHALLENGE;
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_PATH_CHALLENGE_LENGTH;
      break;

    case FRAME_TYPE_PATH_RESPONSE:
      if (fromCleartext) {
        session->Shutdown(FRAME_FORMAT_ERROR, "Frame Type not allowed");
        return;
      }

      if (pktSize < FRAME_TYPE_PATH_RESPONSE_LENGTH) {
        session->RaiseError(MOZQUIC_ERR_GENERAL,
                            (char *) "response length expected");
        return;
      }

      memcpy(&u.mPathResponse.mData, framePtr, sizeof(u.mPathResponse.mData));
      mType = FRAME_TYPE_PATH_RESPONSE;
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_PATH_RESPONSE_LENGTH;
      break;

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
    {
      mType = FRAME_TYPE_NEW_CONNECTION_ID;
      if (MozQuic::DecodeVarint(framePtr, endOfPkt - framePtr, u.mNewConnectionID.mSequence, used) != MOZQUIC_OK) {
        session->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "parse err");
        return;
      }
      framePtr += used;

      if ((endOfPkt - framePtr) < 1) {
        session->RaiseError(MOZQUIC_ERR_GENERAL,
                            (char *) "NEW_CONNECTION_ID too short");
        return;
      }

      // 1 byte cidLen
      uint8_t cidLen = *framePtr;
      framePtr += 1;

      // range check this in 4-18 range then -3
      if ((cidLen < 4) || (cidLen > 18)) {
        session->RaiseError(MOZQUIC_ERR_GENERAL,
                            (char *) "NEW_CONNECTION_ID CID len out of range");
        return;
      }

      if ((endOfPkt - framePtr) < cidLen) {
        session->RaiseError(MOZQUIC_ERR_GENERAL,
                            (char *) "NEW_CONNECTION_ID too short cid");
        return;
      }

      cidLen -= 3;
      mForNewConnectionID.Parse(cidLen - 3, framePtr);
      framePtr += cidLen;
      
      // if sending to peercid.len()==0 then recpt of this is an err

      // 16 of token
      if ((endOfPkt - framePtr) < 16) {
        session->RaiseError(MOZQUIC_ERR_GENERAL,
                            (char *) "NEW_CONNECTION_ID frame length expected token");
        return;
      }

      memcpy(u.mNewConnectionID.mToken, framePtr, 16);
      framePtr += 16;
             
      mValid = MOZQUIC_OK;
      mFrameLen = framePtr - pkt;
      return;
    }
    
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

LongHeaderData::LongHeaderData(MozQuic *mq, unsigned char *pkt, uint32_t pktSize, uint64_t nextPN)
{
  assert(pkt[0] & 0x80);
  mType = PACKET_TYPE_ERR; // signal parse error
  mVersion = 0;
  mHeaderSize = 0;

  // these fields are all version independent - though the interpretation
  // of type is not.

  do {
    if (pktSize < 6) break;
    memcpy(&mVersion, pkt + 1, 4);
    mVersion = ntohl(mVersion);
    uint8_t dcil = (pkt[5] & 0xf0) >> 4;
    uint8_t scil = (pkt[5] & 0x0f);
    uint32_t offset = 6;

    if (pktSize < offset + dcil) break;
    mDestCID.Parse(dcil, pkt + offset);
    offset += mDestCID.Len();

    if (pktSize < offset + scil) break;
    mSourceCID.Parse(scil, pkt + offset);
    offset += mSourceCID.Len();

    if (mVersion) {
      uint32_t used;

      // payload Length
      if (MozQuic::DecodeVarintMax32(pkt + offset,
                                     pktSize - offset, mPayloadLen, used) != MOZQUIC_OK) {
        break;
      }
      offset += used;

      // Packet Number
      size_t pnLen;
      enum LongHeaderType pktType = static_cast<enum LongHeaderType>(pkt[0] & ~0x80);
      if (mq) {
        mPacketNumber = ShortHeaderData::DecodePacketNumber(mq,
                                                            pktType == PACKET_TYPE_0RTT_PROTECTED ? kDecrypt0RTT : kDecryptHandshake,
                                                            pkt + offset, nextPN,
                                                            pktSize - offset, pnLen);
      } else if (pktType == PACKET_TYPE_INITIAL) {
        mPacketNumber = DecodePacketNumber(pkt + offset, nextPN,
                                           pktSize - offset, pnLen);
      } else {
        mPacketNumber = 0;
        pnLen = 1;
      }
      offset += pnLen;
    }
        
    mHeaderSize = offset;

    // Assigning the type makes it OK
    mType = static_cast<enum LongHeaderType>(pkt[0] & ~0x80);
  } while (0);
}

void
MozQuic::EncryptPNInPlace(enum operationType mode, unsigned char *pn,
                          const unsigned char *cipherTextToSample,
                          uint32_t cipherLen)
{
  return mNSSHelper->EncryptPNInPlace(mode, pn, cipherTextToSample, cipherLen);
}

void
MozQuic::DecryptPNInPlace(enum operationType mode, unsigned char *pn,
                          const unsigned char *cipherTextToSample,
                          uint32_t cipherLen)
{
  if (mode == kDecrypt0RTT && mEarlyDataState != EARLY_DATA_ACCEPTED) {
    return;
  }
  return mNSSHelper->DecryptPNInPlace(mode, pn, cipherTextToSample, cipherLen);
}

uint64_t
LongHeaderData::DecodePacketNumber(unsigned char *pkt, uint64_t next, uint32_t pktSize,
                                   size_t &outPNSize)
{
  outPNSize = 0;
  if (pktSize < 4) {
    return 0;
  }

  NSSHelper::staticDecryptPNInPlace(pkt,
                                    mDestCID,
                                    pkt + 4, pktSize - 4);
  return ShortHeaderData::DecodePlaintextPacketNumber(pkt, next, pktSize, outPNSize);
}

uint64_t
ShortHeaderData::DecodePacketNumber(MozQuic *mq, enum operationType mode,
                                    unsigned char *pkt, uint64_t next, uint32_t pktSize,
                                    size_t &outPNSize)
{
  assert(mq);
  outPNSize = 0;
  if (pktSize < 4) {
    return 0;
  }

  mq->DecryptPNInPlace(mode, pkt, pkt + 4, pktSize - 4);
  return DecodePlaintextPacketNumber(pkt, next, pktSize, outPNSize);
}

uint64_t
ShortHeaderData::DecodePlaintextPacketNumber(unsigned char *pkt,
                                             uint64_t next, uint32_t pktSize,
                                             size_t &outPNSize)
{
  outPNSize = 0;

  uint64_t candidate1, candidate2;
  if ((*pkt & 0x80) == 0) {
    outPNSize = 1;
    candidate1 = (next & ~0xFFUL) | (*pkt & ~0x80);
    candidate2 = candidate1 + 0x100UL;
  } else if ((*pkt & 0xC0) == 0x80) {
    if (pktSize < 2) {
      return 0;
    }
    outPNSize = 2;
    uint16_t tmp16;
    memcpy((unsigned char *)&tmp16, pkt, 2);
    ((unsigned char *)&tmp16)[0] &= ~0xC0;
    tmp16 = ntohs(tmp16);
    candidate1 = (next & ~0xFFFFUL) | tmp16;
    candidate2 = candidate1 + 0x10000UL;
  } else {
    assert((*pkt & 0xC0) == 0xC0);
    if (pktSize < 4) {
      return 0;
    }
    outPNSize = 4;
    uint32_t tmp32;
    memcpy((unsigned char *)&tmp32, pkt, 4);
    ((unsigned char *)&tmp32)[0] &= ~0xC0;
    tmp32 = ntohl(tmp32);
    candidate1 = (next & ~0xFFFFFFFFUL) | tmp32;
    candidate2 = candidate1 + 0x100000000UL;
  }
  uint64_t distance1 = (next >= candidate1) ? (next - candidate1) : (candidate1 - next);
  uint64_t distance2 = (next >= candidate2) ? (next - candidate2) : (candidate2 - next);
  uint64_t rv = (distance1 < distance2) ? candidate1 : candidate2;
  return rv;
}

// must be even and <= 18
static const uint32_t localCIDSize = 10; // 4 ought to be plenty. but stress test

ShortHeaderData::ShortHeaderData(MozQuic *mq,
                                 unsigned char *pkt, uint32_t pktSize,
                                 uint64_t nextPN, bool allowOmitCID,
                                 CID &defaultCID)
{
  // note that StatlessReset.cpp also hand rolls a special short packet header

  mHeaderSize = 0xffffffff;
  mPacketNumber = 0;
  assert(pktSize >= 1);
  if ((pkt[0] & 0xB8) != 0x30) {
    Log::sDoLog(Log::CONNECTION, 1, mq, "short header failed const bits\n");
    return;
  }

  uint32_t used = 1;

  if (allowOmitCID) {
    mDestCID = defaultCID;
  } else {
    // parse.. to do so we need to know how long the cid is supposed to be
    if (pktSize < used + localCIDSize) {
      return;
    }
    assert(localCIDSize >= 4);
    mDestCID.Parse(localCIDSize - 3, pkt + used);
    used += mDestCID.Len();
  }

  if (!nextPN) {
    mPacketNumber = 0;
  } else {
    size_t pnSize;
    mPacketNumber = DecodePacketNumber(mq, kDecrypt0, pkt + used, nextPN, pktSize - used, pnSize);
    used += pnSize;
  }

  mHeaderSize = used;
}

void
CID::Randomize()
{
  assert(!(localCIDSize & 1));
  assert(localCIDSize <= 18);
  for (unsigned int i=0; i < (localCIDSize / 2); i++) {
    uint16_t rd = random() & 0xffff;
    memcpy(mID + (i * 2), &rd, 2);
  }
  mLen = localCIDSize;
  mNull = false;
  BuildText();
}

void
CID::BuildText()
{
  assert(!mNull);
  if (!mLen) {
    mText[0] = '-';
    mText[1] = 0;
    return;
  }
  mText[mLen * 2] = 0;
  auto o = &mText[0];
  for (uint32_t i = 0; i < mLen; i++ ) {
    sprintf(o, "%02x", mID[i]);
    o += 2;
  }
}

void
CID::Parse(uint8_t cil, const unsigned char *p)
{
  mLen = 0;
  if (cil) {
    mLen = cil + 3;
    memcpy(mID, p, mLen);
  }
  mNull = false;
  BuildText();
}

uint32_t
CID::FormatLongHeader(const CID &destCID, const CID &srcCID, bool omitLocal,
                      unsigned char *output, uint32_t avail, uint32_t &used)
{
  uint8_t dcil = destCID.Len() ? (destCID.Len() - 3) : 0;
  uint8_t scil;
  if (omitLocal) {
    scil = 0;
    used = destCID.Len() + 1;
  } else {
    scil = srcCID.Len() ? (srcCID.Len() - 3) : 0;
    used = destCID.Len() + srcCID.Len() + 1;
  }

  if (avail < used) {
    used = 0;
    return MOZQUIC_ERR_GENERAL;
  }
  memcpy(output + 1, destCID.Data(), destCID.Len());
  if (!omitLocal) {
    memcpy(output + 1 + destCID.Len(), srcCID.Data(), srcCID.Len());
  }

  output[0] = (dcil << 4) | scil;
  return MOZQUIC_OK;
}

char *CID::Text()
{
  return &(mText[0]);
}

size_t
CID::Hash() const
{
  size_t rv = 0;
  int offset = 0;
  int len = mLen;
  while (len > 0) {
    size_t t = ~0;
    memcpy(&t, mID + offset, len < (int)sizeof (size_t) ? len : sizeof(size_t));
    rv ^= t;
    len -= sizeof(size_t);
    offset += sizeof(size_t);
  }
  return rv;
}

}
