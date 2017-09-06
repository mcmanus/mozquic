/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "MozQuic.h"
#include "MozQuicInternal.h"
#include "Streams.h"

#include "assert.h"
#include "stdlib.h"
#include "unistd.h"

namespace mozquic  {

uint32_t
StreamState::StartNewStream(MozQuicStreamPair **outStream, const void *data,
                            uint32_t amount, bool fin)
{
  *outStream = new MozQuicStreamPair(mNextStreamId, mMozQuic, this,
                                     mPeerMaxStreamData, mLocalMaxStreamData);
  mStreams.insert( { mNextStreamId, *outStream } );
  mNextStreamId += 2;
  if ( amount || fin) {
    return (*outStream)->Write((const unsigned char *)data, amount, fin);
  }
  return MOZQUIC_OK;
}

uint32_t
StreamState::FindStream(uint32_t streamID, std::unique_ptr<ReliableData> &d)
{
  // Open a new stream and implicitly open all streams with ID smaller than
  // streamID that are not already opened.
  while (streamID >= mNextRecvStreamId) {
    fprintf(stderr, "Add new stream %d\n", mNextRecvStreamId);
    MozQuicStreamPair *stream = new MozQuicStreamPair(mNextRecvStreamId,
                                                      mMozQuic, this,
                                                      mPeerMaxStreamData, mLocalMaxStreamData);
    mStreams.insert( { mNextRecvStreamId, stream } );
    mNextRecvStreamId += 2;
  }

  auto i = mStreams.find(streamID);
  if (i == mStreams.end()) {
    fprintf(stderr, "Stream %d already closed.\n", streamID);
    // this stream is already closed and deleted. Discharge frame.
    d.reset();
    return MOZQUIC_ERR_ALREADY_FINISHED;
  }
  (*i).second->Supply(d);
  if (!(*i).second->Empty() && mMozQuic->mConnEventCB) {
    mMozQuic->mConnEventCB(mMozQuic->mClosure, MOZQUIC_EVENT_NEW_STREAM_DATA, (*i).second);
  }
  return MOZQUIC_OK;
}

void
StreamState::DeleteStream(uint32_t streamID)
{
  fprintf(stderr, "Delete stream %lu\n", streamID);
  mStreams.erase(streamID);
}

uint32_t
StreamState::HandleStreamFrame(FrameHeaderData *result, bool fromCleartext,
                               const unsigned char *pkt, const unsigned char *endpkt,
                               uint32_t &_ptr)
{
  fprintf(stderr,"recv stream %d len=%d offset=%d fin=%d\n",
          result->u.mStream.mStreamID,
          result->u.mStream.mDataLen,
          result->u.mStream.mOffset,
          result->u.mStream.mFinBit);

  if (!result->u.mStream.mStreamID && result->u.mStream.mFinBit) {
    // todo need to respond with a connection error PROTOCOL_VIOLATION 12.2
    mMozQuic->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "fin not allowed on stream 0\n");
    return MOZQUIC_ERR_GENERAL;
  }

  // todo, ultimately the stream chunk could hold references to
  // the packet buffer and _ptr into it for zero copy

  // parser checked for this, but jic
  assert(pkt + _ptr + result->u.mStream.mDataLen <= endpkt);
  std::unique_ptr<ReliableData>
    tmp(new ReliableData(result->u.mStream.mStreamID,
                               result->u.mStream.mOffset,
                               pkt + _ptr,
                               result->u.mStream.mDataLen,
                               result->u.mStream.mFinBit));
  if (!result->u.mStream.mStreamID) {
    mStream0->Supply(tmp);
  } else {
    if (fromCleartext) {
      mMozQuic->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "cleartext non 0 stream id\n");
      return MOZQUIC_ERR_GENERAL;
    }
    uint32_t rv = FindStream(result->u.mStream.mStreamID, tmp);
    if (rv != MOZQUIC_OK) {
      return rv;
    }
  }
  _ptr += result->u.mStream.mDataLen;
  return MOZQUIC_OK;
}

uint32_t
StreamState::HandleMaxStreamDataFrame(FrameHeaderData *result, bool fromCleartext,
                                      const unsigned char *pkt, const unsigned char *endpkt,
                                      uint32_t &_ptr)
{
  if (fromCleartext) {
    mMozQuic->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "max stream data frames not allowed in cleartext\n");
    return MOZQUIC_ERR_GENERAL;
  }

  uint32_t streamID = result->u.mMaxStreamData.mStreamID;
  auto i = mStreams.find(streamID);
  if (i == mStreams.end()) {
    fprintf(stderr, "cannot find streamid %d for max stream data frame. pehaps closed.\n",
            streamID);
    return MOZQUIC_OK;
  }

  fprintf(stderr,"recvd max stream data id=%X offset=%ld current limit=%ld\n",
          streamID,
          result->u.mMaxStreamData.mMaximumStreamData,
          i->second->mOut.mFlowControlLimit);
  if (i->second->mOut.mFlowControlLimit < result->u.mMaxStreamData.mMaximumStreamData) {
    i->second->mOut.mFlowControlLimit = result->u.mMaxStreamData.mMaximumStreamData;
  }
  return MOZQUIC_OK;
}

uint32_t
StreamState::HandleStreamBlockedFrame(FrameHeaderData *result, bool fromCleartext,
                                      const unsigned char *pkt, const unsigned char *endpkt,
                                      uint32_t &_ptr)
{
  if (fromCleartext) {
    mMozQuic->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "stream blocked frames not allowed in cleartext\n");
    return MOZQUIC_ERR_GENERAL;
  }

  uint32_t streamID = result->u.mStreamBlocked.mStreamID;
  fprintf(stderr,"recvd stream blocked id=%X\n", streamID);
  return MOZQUIC_OK;
}

uint32_t
StreamState::ScrubUnWritten(uint32_t streamID)
{
  auto iter = mConnUnWritten.begin();
  while (iter != mConnUnWritten.end()) {
    auto chunk = (*iter).get();
    if (chunk->mStreamID == streamID && chunk->mType != ReliableData::kStreamRst) {
      iter = mConnUnWritten.erase(iter);
      fprintf(stderr,"scrubbing chunk %p of unwritten id %d\n",
              chunk, streamID);
    } else {
      iter++;
    }
  }

  auto iter2 = mUnAckedData.begin();
  while (iter2 != mUnAckedData.end()) {
    auto chunk = (*iter2).get();
    if (chunk->mStreamID == streamID && chunk->mType != ReliableData::kStreamRst) {
      iter2 = mUnAckedData.erase(iter2);
      fprintf(stderr,"scrubbing chunk %p of unacked id %d\n",
              chunk, streamID);
    } else {
      iter2++;
    }
  }
  return MOZQUIC_OK;
}

uint32_t
StreamState::FlowControlPromotionForStream(MozQuicStreamOut *out)
{
  for (auto iBuffer = out->mStreamUnWritten.begin();
       iBuffer != out->mStreamUnWritten.end(); ) {
    // todo whitelist 0len

    if ((*iBuffer)->mLen) {
      if ((*iBuffer)->mOffset >= out->mFlowControlLimit) {
        iBuffer++;
        if (!out->mBlocked) {
          fprintf(stderr,"Stream %d BLOCKED flow control\n",
                  (*iBuffer)->mStreamID);
          out->mBlocked = true;
          std::unique_ptr<ReliableData> tmp(new ReliableData((*iBuffer)->mStreamID, 0, nullptr, 0, 0));
          tmp->MakeStreamBlocked();
          return ConnectionWrite(tmp);
        }
        continue;
      }
      if ((*iBuffer)->mOffset + (*iBuffer)->mLen > out->mFlowControlLimit) {
        // need to split it!

        uint64_t room = out->mFlowControlLimit - (*iBuffer)->mOffset;

        std::unique_ptr<ReliableData>
          tmp(new ReliableData((*iBuffer)->mStreamID,
                                     (*iBuffer)->mOffset + room,
                                     (*iBuffer)->mData.get() + room,
                                     (*iBuffer)->mLen - room,
                                     (*iBuffer)->mFin));
        (*iBuffer)->mLen = room;
        (*iBuffer)->mFin = false;
        fprintf(stderr,"FlowControlPromotionForStream splitting chunk into "
                "%ld.%d and %ld.%d\n",
                (*iBuffer)->mOffset, (*iBuffer)->mLen,
                tmp->mOffset, tmp->mLen);
        auto iterReg = iBuffer++;
        out->mStreamUnWritten.insert(iBuffer, std::move(tmp));
        iBuffer = iterReg;
      }
    }
    
    assert((*iBuffer)->mOffset + (*iBuffer)->mLen <= out->mFlowControlLimit);
    out->mBlocked = false;
    fprintf(stderr,"promoting chunk stream %d %ld.%d [limit=%ld]\n",
            (*iBuffer)->mStreamID, (*iBuffer)->mOffset, (*iBuffer)->mLen,
            out->mFlowControlLimit);
    assert((*iBuffer)->mOffset + (*iBuffer)->mLen <= out->mFlowControlLimit);
    std::unique_ptr<ReliableData> x(std::move(*iBuffer));
    mConnUnWritten.push_back(std::move(x));
    iBuffer = out->mStreamUnWritten.erase(iBuffer);
  }
  return MOZQUIC_OK;
}

// This fx() identifies buffers in streampair.out.mStreamUnWritten and
// promotoes them to the connection scoped mConnUnWritten according to
// flow control rules
uint32_t
StreamState::FlowControlPromotion()
{
  if (mStream0) {
    FlowControlPromotionForStream(&mStream0->mOut);
  }
  for (auto iStreamPair = mStreams.begin(); iStreamPair != mStreams.end(); iStreamPair++) {
    FlowControlPromotionForStream(&iStreamPair->second->mOut);
  }
  return MOZQUIC_OK;
}

static uint8_t varSize(uint64_t input)
{
  // returns 0->3 depending on magnitude of input
  return (input < 0x100) ? 0 : (input < 0x10000) ? 1 : (input < 0x100000000UL) ? 2 : 3;
}

uint32_t
StreamState::CreateStreamFrames(unsigned char *&framePtr, const unsigned char *endpkt, bool justZero)
{
  auto iter = mConnUnWritten.begin();
  while (iter != mConnUnWritten.end()) {
    if (justZero && (*iter)->mStreamID) {
      iter++;
      continue;
    }
    if ((*iter)->mType == ReliableData::kStreamRst) {
      if (CreateStreamRstFrame(framePtr, endpkt, (*iter).get()) != MOZQUIC_OK) {
        break;
      }
    } else if ((*iter)->mType == ReliableData::kMaxStreamData) {
      if (CreateMaxStreamDataFrame(framePtr, endpkt, (*iter).get()) != MOZQUIC_OK) {
        break;
      }
    } else if ((*iter)->mType == ReliableData::kStreamBlocked) {
      if (CreateStreamBlockedFrame(framePtr, endpkt, (*iter).get()) != MOZQUIC_OK) {
        break;
      }
    } else {
      assert ((*iter)->mType == ReliableData::kStream);

      uint32_t room = endpkt - framePtr;
      if (room < 1) {
        break; // this is only for type, we will do a second check later.
      }

      // 11fssood -> 11000001 -> 0xC1. Fill in fin, offset-len and id-len below dynamically
      auto typeBytePtr = framePtr;
      framePtr[0] = 0xc1;

      // Determine streamId size without varSize becuase we use 24 bit value
      uint32_t tmp32 = (*iter)->mStreamID;
      tmp32 = htonl(tmp32);
      uint8_t idLen = 4;
      for (int i=0; (i < 3) && (((uint8_t*)(&tmp32))[i] == 0); i++) {
        idLen--;
      }

      // determine offset size
      uint64_t offsetValue = PR_htonll((*iter)->mOffset);
      uint8_t offsetSizeType = varSize((*iter)->mOffset);
      uint8_t offsetLen;
      if (offsetSizeType == 0) {
        // 0, 16, 32, 64 instead of usual 8, 16, 32, 64
        if ((*iter)->mOffset) {
          offsetSizeType = 1;
          offsetLen = 2;
        } else {
          offsetLen = 0;
        }
      } else {
        offsetLen = 1 << offsetSizeType;
      }

      // 1(type) + idLen + offsetLen + 2(len) + 1(data)
      if (room < (4 + idLen + offsetLen)) {
        break;
      }

      // adjust the frame type:
      framePtr[0] |= (idLen - 1) << 3;
      assert(!(offsetSizeType & ~0x3));
      framePtr[0] |= (offsetSizeType << 1);
      framePtr++;

      // Set streamId
      memcpy(framePtr, ((uint8_t*)(&tmp32)) + (4 - idLen), idLen);
      framePtr += idLen;

      // Set offset
      if (offsetLen) {
        memcpy(framePtr, ((uint8_t*)(&offsetValue)) + (8 - offsetLen), offsetLen);
        framePtr += offsetLen;
      }

      room -= (3 + idLen + offsetLen); //  1(type) + idLen + offsetLen + 2(len)
      if (room < (*iter)->mLen) {
        // we need to split this chunk. its too big
        // todo iterate on them all instead of doing this n^2
        // as there is a copy involved
        std::unique_ptr<ReliableData>
          tmp(new ReliableData((*iter)->mStreamID,
                                     (*iter)->mOffset + room,
                                     (*iter)->mData.get() + room,
                                     (*iter)->mLen - room,
                                     (*iter)->mFin));
        (*iter)->mLen = room;
        (*iter)->mFin = false;
        auto iterReg = iter++;
        mConnUnWritten.insert(iter, std::move(tmp));
        iter = iterReg;
      }
      assert(room >= (*iter)->mLen);

      // set the len and fin bits after any potential split
      uint16_t tmp16 = (*iter)->mLen;
      tmp16 = htons(tmp16);
      memcpy(framePtr, &tmp16, 2);
      framePtr += 2;

      if ((*iter)->mFin) {
        *typeBytePtr = *typeBytePtr | STREAM_FIN_BIT;
      }

      memcpy(framePtr, (*iter)->mData.get(), (*iter)->mLen);
      fprintf(stderr,"writing a stream %d frame %d @ offset %d [fin=%d] in packet %lX\n",
              (*iter)->mStreamID, (*iter)->mLen, (*iter)->mOffset, (*iter)->mFin,
              mMozQuic->mNextTransmitPacketNumber);
      framePtr += (*iter)->mLen;
    }

    (*iter)->mPacketNumber = mMozQuic->mNextTransmitPacketNumber;
    (*iter)->mTransmitTime = MozQuic::Timestamp();
    if ((mMozQuic->GetConnectionState() == CLIENT_STATE_CONNECTED) ||
        (mMozQuic->GetConnectionState() == SERVER_STATE_CONNECTED) ||
        (mMozQuic->GetConnectionState() == CLIENT_STATE_0RTT)) {
      (*iter)->mTransmitKeyPhase = keyPhase1Rtt;
    } else {
      (*iter)->mTransmitKeyPhase = keyPhaseUnprotected;
    }
    (*iter)->mRetransmitted = false;

    // move it to the unacked list
    std::unique_ptr<ReliableData> x(std::move(*iter));
    mUnAckedData.push_back(std::move(x));
    iter = mConnUnWritten.erase(iter);
  }
  return MOZQUIC_OK;
}

uint32_t
StreamState::Flush(bool forceAck)
{
  if (!mMozQuic->DecodedOK()) {
    mMozQuic->FlushStream0(forceAck);
  }

  FlowControlPromotion();
  if (mConnUnWritten.empty() && !forceAck) {
    return MOZQUIC_OK;
  }

  unsigned char plainPkt[kMaxMTU];
  uint32_t headerLen;
  uint32_t mtu = mMozQuic->mMTU;
  assert(mtu <= kMaxMTU);

  mMozQuic->CreateShortPacketHeader(plainPkt, mtu - kTagLen, headerLen);

  unsigned char *framePtr = plainPkt + headerLen;
  const unsigned char *endpkt = plainPkt + mtu - kTagLen; // reserve 16 for aead tag
  CreateStreamFrames(framePtr, endpkt, false);
  
  uint32_t rv = mMozQuic->ProtectedTransmit(plainPkt, headerLen,
                                            plainPkt + headerLen, framePtr - (plainPkt + headerLen),
                                            mtu - headerLen - kTagLen, true);
  if (rv != MOZQUIC_OK) {
    return rv;
  }

  if (!mConnUnWritten.empty()) {
    return Flush(false);
  }
  return MOZQUIC_OK;
}

uint32_t
StreamState::ConnectionWrite(std::unique_ptr<ReliableData> &p)
{
  // this data gets queued to unwritten and framed and
  // transmitted after prioritization by flush()
  assert (mMozQuic->GetConnectionState() != STATE_UNINITIALIZED);
  
  mConnUnWritten.push_back(std::move(p));

  return MOZQUIC_OK;
}

uint32_t
StreamState::GetIncrement()
{
  if (mLocalMaxStreamData < 1024 * 1024) {
    return mLocalMaxStreamData;
  }
  return 1024 * 1024; // todo
}

uint32_t
StreamState::IssueStreamCredit(uint32_t streamID, uint64_t newMax)
{
  if ((mMozQuic->GetConnectionState() != CLIENT_STATE_CONNECTED) &&
      (mMozQuic->GetConnectionState() != SERVER_STATE_CONNECTED)) {
    return MOZQUIC_ERR_GENERAL;
  }
          
  fprintf(stderr,"Issue a stream credit id=%d maxoffset=%ld\n", streamID, newMax);

  std::unique_ptr<ReliableData> tmp(new ReliableData(streamID, 0, nullptr, 0, 0));
  tmp->MakeMaxStreamData(newMax);
  return ConnectionWrite(tmp);
}

uint32_t
StreamState::RetransmitTimer()
{
  if (mUnAckedData.empty()) {
    return MOZQUIC_OK;
  }

  // this is a crude stand in for reliability until we get a real loss
  // recovery system built
  uint64_t now = MozQuic::Timestamp();
  uint64_t discardEpoch = now - kForgetUnAckedThresh;

  for (auto i = mUnAckedData.begin(); i != mUnAckedData.end(); ) {
    // just a linear backoff for now
    uint64_t retransEpoch = now - (kRetransmitThresh * (*i)->mTransmitCount);
    if ((*i)->mTransmitTime > retransEpoch) {
      break;
    }
    if (((*i)->mTransmitTime <= discardEpoch) && (*i)->mRetransmitted) {
      // this is only on packets that we are keeping around for timestamp purposes
      fprintf(stderr,"old unacked packet forgotten %lX\n",
              (*i)->mPacketNumber);
      assert(!(*i)->mData);
      i = mUnAckedData.erase(i);
    } else if (!(*i)->mRetransmitted) {
      assert((*i)->mData);
      fprintf(stderr,"data associated with packet %lX retransmitted\n",
              (*i)->mPacketNumber);
      (*i)->mRetransmitted = true;

      // move the data pointer from iter to tmp
      std::unique_ptr<ReliableData> tmp(new ReliableData(*(*i)));
      assert(!(*i)->mData);
      assert(tmp->mData);

      // its ok to bypass the per out stream flow control window on rexmit
      ConnectionWrite(tmp);
      i++;
    } else {
      i++;
    }
  }

  return MOZQUIC_OK;
}

uint32_t
StreamState::CreateStreamRstFrame(unsigned char *&framePtr, const unsigned char *endpkt,
                                  ReliableData *chunk)
{
  fprintf(stderr,"generating stream reset %d\n", chunk->mOffset);
  assert(chunk->mType == ReliableData::kStreamRst);
  assert(chunk->mStreamID);
  assert(!chunk->mLen);
  uint32_t room = endpkt - framePtr;
  if (room < 17) {
    return MOZQUIC_ERR_GENERAL;
  }
  framePtr[0] = FRAME_TYPE_RST_STREAM;
  uint32_t tmp32 = htonl(chunk->mStreamID);
  memcpy(framePtr + 1, &tmp32, 4);
  tmp32 = htonl(chunk->mRstCode);
  memcpy(framePtr + 5, &tmp32, 4);
  uint64_t tmp64 = PR_htonll(chunk->mOffset);
  memcpy(framePtr + 9, &tmp64, 8);
  framePtr += 17;
  return MOZQUIC_OK;
}

uint32_t
StreamState::CreateMaxStreamDataFrame(unsigned char *&framePtr, const unsigned char *endpkt,
                                      ReliableData *chunk)
{
  fprintf(stderr,"generating max stream data id=%d val=%ld\n",
          chunk->mStreamID, chunk->mStreamCreditValue);
  assert(chunk->mType == ReliableData::kMaxStreamData);
  assert(chunk->mStreamCreditValue);
  assert(!chunk->mLen);

  uint32_t room = endpkt - framePtr;
  if (room < 13) {
    return MOZQUIC_ERR_GENERAL;
  }
  framePtr[0] = FRAME_TYPE_MAX_STREAM_DATA;
  uint32_t tmp32 = htonl(chunk->mStreamID);
  memcpy(framePtr + 1, &tmp32, 4);
  uint64_t tmp64 = PR_htonll(chunk->mStreamCreditValue);
  memcpy(framePtr + 5, &tmp64, 8);
  framePtr += 13;
  return MOZQUIC_OK;
}

uint32_t
StreamState::CreateStreamBlockedFrame(unsigned char *&framePtr, const unsigned char *endpkt,
                                      ReliableData *chunk)
{
  fprintf(stderr,"generating stream blocked id=%d\n", chunk->mStreamID);
  assert(chunk->mType == ReliableData::kStreamBlocked);
  assert(!chunk->mLen);

  uint32_t room = endpkt - framePtr;
  if (room < 5) {
    return MOZQUIC_ERR_GENERAL;
  }
  framePtr[0] = FRAME_TYPE_STREAM_BLOCKED;
  uint32_t tmp32 = htonl(chunk->mStreamID);
  memcpy(framePtr + 1, &tmp32, 4);
  framePtr += 5;
  return MOZQUIC_OK;
}

StreamState::StreamState(MozQuic *q)
  : mMozQuic(q)
  , mNextStreamId(1)
  , mNextRecvStreamId(1)
  , mPeerMaxStreamData(kMaxStreamDataDefault)
  , mLocalMaxStreamData(5000) // todo config
  , mPeerMaxData(kMaxDataDefault)
  , mPeerMaxStreamID(kMaxStreamIDDefault)
{
}

}

