/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "Logging.h"
#include "MozQuic.h"
#include "MozQuicInternal.h"
#include "Streams.h"

#include "assert.h"
#include "stdlib.h"
#include "unistd.h"

namespace mozquic  {

#define StreamLog1(...) Log::sDoLog(Log::STREAM, 1, mMozQuic, __VA_ARGS__);
#define StreamLog2(...) Log::sDoLog(Log::STREAM, 2, mMozQuic, __VA_ARGS__);
#define StreamLog3(...) Log::sDoLog(Log::STREAM, 3, mMozQuic, __VA_ARGS__);
#define StreamLog4(...) Log::sDoLog(Log::STREAM, 4, mMozQuic, __VA_ARGS__);
#define StreamLog5(...) Log::sDoLog(Log::STREAM, 5, mMozQuic, __VA_ARGS__);
#define StreamLog6(...) Log::sDoLog(Log::STREAM, 6, mMozQuic, __VA_ARGS__);
#define StreamLog7(...) Log::sDoLog(Log::STREAM, 7, mMozQuic, __VA_ARGS__);
#define StreamLog8(...) Log::sDoLog(Log::STREAM, 8, mMozQuic, __VA_ARGS__);
#define StreamLog9(...) Log::sDoLog(Log::STREAM, 9, mMozQuic, __VA_ARGS__);
#define StreamLog10(...) Log::sDoLog(Log::STREAM, 10, mMozQuic, __VA_ARGS__);

uint32_t
StreamState::StartNewStream(StreamPair **outStream, const void *data,
                            uint32_t amount, bool fin)
{
  if (mNextStreamID > mPeerMaxStreamID) {
    if (!mMaxStreamIDBlocked) {
      mMaxStreamIDBlocked = true;
      StreamLog3("new stream BLOCKED on stream id flow control %d\n",
                 mPeerMaxStreamID);
      std::unique_ptr<ReliableData> tmp(new ReliableData(0, 0, nullptr, 0, 0));
      tmp->MakeStreamIDBlocked();
      ConnectionWrite(tmp);
    }
    return MOZQUIC_ERR_IO;
  }

  std::shared_ptr<StreamPair> tmp(new StreamPair(mNextStreamID, mMozQuic, this,
                                                 mPeerMaxStreamData, mLocalMaxStreamData));
  mStreams.insert( { mNextStreamID, tmp } );
  *outStream = tmp.get();

  mNextStreamID += 2;
  if ( amount || fin) {
    return (*outStream)->Write((const unsigned char *)data, amount, fin);
  }
  return MOZQUIC_OK;
}

uint32_t
StreamState::FindStream(uint32_t streamID, std::unique_ptr<ReliableData> &d)
{
  // is this a stream that should be initiated by the peer?
  if (((streamID & 1) && !mMozQuic->mIsClient) || // odd and you're the server
      (!(streamID & 1) && mMozQuic->mIsClient)) { // even and you're the client

    // Open a new stream and implicitly open all streams with ID smaller than
    // streamID that are not already opened.
    if (streamID > mLocalMaxStreamID) {
      mMozQuic->Shutdown(STREAM_ID_ERROR, "recv stream id too high\n");
      mMozQuic->RaiseError(MOZQUIC_ERR_IO, "need stream id %d but peer only allowed %d\n",
                           streamID, mLocalMaxStreamID);
      return MOZQUIC_ERR_IO;
    }

    bool addedStream = false;
    while (streamID >= mNextRecvStreamIDUsed) {
      StreamLog5("Add new stream %d\n", mNextRecvStreamIDUsed);
      addedStream = true;
      std::shared_ptr<StreamPair> tmp(new StreamPair(mNextRecvStreamIDUsed,
                                                     mMozQuic, this,
                                                     mPeerMaxStreamData, mLocalMaxStreamData));
      mStreams.insert( { mNextRecvStreamIDUsed, tmp } );
      mNextRecvStreamIDUsed += 2;
    }

    if (addedStream && !mMozQuic->mBackPressure) {
      if (mNextRecvStreamIDUsed >= mLocalMaxStreamID ||
          (mLocalMaxStreamID - mNextRecvStreamIDUsed < 512)) {
        mLocalMaxStreamID += 1024;
        StreamLog5("Increasing Peer's Max StreamID to %d\n", mLocalMaxStreamID);
        std::unique_ptr<ReliableData> tmp(new ReliableData(0, 0, nullptr, 0, 0));
        tmp->MakeMaxStreamID(mLocalMaxStreamID);
        ConnectionWrite(tmp);
      }
    }
  } else { // stream should have been intiated by this end
    if (streamID >= mNextStreamID) {
      assert(mStreams.find(streamID) == mStreams.end());
      mMozQuic->Shutdown(STREAM_STATE_ERROR, "recvd frame on stream this peer should have started");
      mMozQuic->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "recvd frame on stream this peer should have started");
      return MOZQUIC_ERR_GENERAL;
    }
  }
  
  auto i = mStreams.find(streamID);
  if (i == mStreams.end()) {
    StreamLog4("Stream %d already closed.\n", streamID);
    // this stream is already closed and deleted. Discharge frame.
    d.reset();
    return MOZQUIC_ERR_ALREADY_FINISHED;
  }
  std::shared_ptr<StreamPair> deleteProtector((*i).second);
  (*i).second->Supply(d);

  while (!(*i).second->Empty() && !(*i).second->mIn.Done() && mMozQuic->mConnEventCB) {
    uint64_t offset = (*i).second->mIn.mOffset;
    mMozQuic->mConnEventCB(mMozQuic->mClosure, MOZQUIC_EVENT_NEW_STREAM_DATA, (*i).second.get());
    if (offset == (*i).second->mIn.mOffset) {
      break;
    }
  }
  return MOZQUIC_OK;
}

bool
StreamState::MaybeDeleteStream(uint32_t streamID)
{
  auto i = mStreams.find(streamID);
  if (i == mStreams.end()) {
    return false;
  }
  if ((*i).second->Done()) {
    StreamLog5("Delete stream %lu\n", streamID);
    mStreams.erase(i);
    return true;
  }
  return false;
}

uint32_t
StreamState::HandleStreamFrame(FrameHeaderData *result, bool fromCleartext,
                               const unsigned char *pkt, const unsigned char *endpkt,
                               uint32_t &_ptr)
{
  StreamLog5("recv stream %d len=%d offset=%d fin=%d\n",
             result->u.mStream.mStreamID,
             result->u.mStream.mDataLen,
             result->u.mStream.mOffset,
             result->u.mStream.mFinBit);

  if (!result->u.mStream.mStreamID && result->u.mStream.mFinBit) {
    if (!fromCleartext) {
      mMozQuic->Shutdown(PROTOCOL_VIOLATION, "fin not allowed on stream 0\n");
    }
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
    StreamLog4("cannot find streamid %d for max stream data frame. pehaps closed.\n",
               streamID);
    return MOZQUIC_OK;
  }

  StreamLog5("recvd max stream data id=%X offset=%ld current limit=%ld\n",
             streamID,
             result->u.mMaxStreamData.mMaximumStreamData,
             i->second->mOut.mFlowControlLimit);
  if (i->second->mOut.mFlowControlLimit < result->u.mMaxStreamData.mMaximumStreamData) {
    i->second->mOut.mFlowControlLimit = result->u.mMaxStreamData.mMaximumStreamData;
  }
  return MOZQUIC_OK;
}

uint32_t
StreamState::HandleMaxDataFrame(FrameHeaderData *result, bool fromCleartext,
                                const unsigned char *pkt, const unsigned char *endpkt,
                                uint32_t &_ptr)
{
  if (fromCleartext) {
    mMozQuic->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "max data frames not allowed in cleartext\n");
    return MOZQUIC_ERR_GENERAL;
  }

  uint64_t curLimitKB = mPeerMaxData >> 10;
  StreamLog5("recvd max data current %ldKB new %ldKB\n",
             curLimitKB, result->u.mMaxData.mMaximumData);
  if (result->u.mMaxData.mMaximumData > curLimitKB) {
    mPeerMaxData = ((__uint128_t) result->u.mMaxData.mMaximumData) << 10;
  }
  return MOZQUIC_OK;
}

uint32_t
StreamState::HandleMaxStreamIDFrame(FrameHeaderData *result, bool fromCleartext,
                                    const unsigned char *pkt, const unsigned char *endpkt,
                                    uint32_t &_ptr)
{
  if (fromCleartext) {
    mMozQuic->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "max stream id frames not allowed in cleartext\n");
    return MOZQUIC_ERR_GENERAL;
  }

  StreamLog5("recvd max stream id current %d new %d\n",
             mPeerMaxStreamID, result->u.mMaxStreamID.mMaximumStreamID);
  if (result->u.mMaxStreamID.mMaximumStreamID > mPeerMaxStreamID) {
    mPeerMaxStreamID = result->u.mMaxStreamID.mMaximumStreamID;
    mMaxStreamIDBlocked = false;
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
  StreamLog2("recvd stream blocked id=%X\n", streamID);
  return MOZQUIC_OK;
}

uint32_t
StreamState::HandleBlockedFrame(FrameHeaderData *result, bool fromCleartext,
                                const unsigned char *pkt, const unsigned char *endpkt,
                                uint32_t &_ptr)
{
  if (fromCleartext) {
    mMozQuic->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "blocked frames not allowed in cleartext\n");
    return MOZQUIC_ERR_GENERAL;
  }

  StreamLog2("recvd connection blocked\n");
  return MOZQUIC_OK;
}

uint32_t
StreamState::HandleStreamIDBlockedFrame(FrameHeaderData *result, bool fromCleartext,
                                        const unsigned char *pkt, const unsigned char *endpkt,
                                        uint32_t &_ptr)
{
  if (fromCleartext) {
    mMozQuic->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "streamidneeded frames not allowed in cleartext\n");
    return MOZQUIC_ERR_GENERAL;
  }

  StreamLog2("recvd streamidneeded\n");
  return MOZQUIC_OK;
}

uint32_t
StreamState::HandleResetStreamFrame(FrameHeaderData *result, bool fromCleartext,
                                    const unsigned char *pkt, const unsigned char *endpkt,
                                    uint32_t &_ptr)
{
  if (fromCleartext) {
    mMozQuic->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "rst_stream frames not allowed in cleartext\n");
    return MOZQUIC_ERR_GENERAL;
  }
  StreamLog5("recvd rst_stream id=%X err=%X, offset=%ld\n",
             result->u.mRstStream.mStreamID, result->u.mRstStream.mErrorCode,
             result->u.mRstStream.mFinalOffset);

  if (!result->u.mRstStream.mStreamID) {
    mMozQuic->Shutdown(PROTOCOL_VIOLATION, "rst_stream frames not allowed on stream 0\n");
    mMozQuic->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "rst_stream frames not allowed on stream 0\n");
    return MOZQUIC_ERR_GENERAL;
  }

  auto i = mStreams.find(result->u.mRstStream.mStreamID);
  if (i == mStreams.end()) {
    StreamLog4("StreamState::HandleResetStreamFrame %d not found.\n",
               result->u.mRstStream.mStreamID);
    return MOZQUIC_ERR_GENERAL;
  }
  StreamPair *sp = (*i).second.get();
  sp->mIn.HandleResetStream(result->u.mRstStream.mFinalOffset);
  return MOZQUIC_OK;
}

uint32_t
StreamIn::HandleResetStream(uint64_t finalOffset)
{
  if (mFinalOffset && (mFinalOffset != finalOffset)) {
    StreamLog1("stream %d recvd rst with finoffset of %ld expected %ld\n",
               mStreamID, finalOffset, mFinalOffset);
    mMozQuic->Shutdown(FINAL_OFFSET_ERROR, "offset too large");
    return MOZQUIC_ERR_IO;
  }

  mFinalOffset = finalOffset;
  mFinRecvd = true;
  mRstRecvd = true;
  mOffset = mFinalOffset;
  return ScrubUnRead();
}

uint32_t
StreamState::HandleStopSendingFrame(FrameHeaderData *result, bool fromCleartext,
                                    const unsigned char *pkt, const unsigned char *endpkt,
                                    uint32_t &_ptr)
{
  if (fromCleartext) {
    mMozQuic->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "stop_sending frames not allowed in cleartext\n");
    return MOZQUIC_ERR_GENERAL;
  }

  StreamLog4("recvd stop sending %ld %lx\n",
             result->u.mStopSending.mStreamID, result->u.mStopSending.mErrorCode);
  RstStream(result->u.mStopSending.mStreamID, result->u.mStopSending.mErrorCode);
  return MOZQUIC_OK;
}

uint32_t
StreamState::RstStream(uint32_t streamID, uint32_t code)
{
  auto i = mStreams.find(streamID);
  if (i == mStreams.end()) {
    StreamLog4("StreamState::RstStream %d not found.\n", streamID);
    return MOZQUIC_ERR_GENERAL;
  }
  return (*i).second->RstStream(code);
}

uint32_t
StreamState::ScrubUnWritten(uint32_t streamID)
{
  auto iter = mConnUnWritten.begin();
  while (iter != mConnUnWritten.end()) {
    auto chunk = (*iter).get();
    if (chunk->mStreamID == streamID && chunk->mType != ReliableData::kRstStream) {
      iter = mConnUnWritten.erase(iter);
      StreamLog6("scrubbing chunk %p of unwritten id %d\n",
                 chunk, streamID);
    } else {
      iter++;
    }
  }

  auto iter2 = mUnAckedData.begin();
  while (iter2 != mUnAckedData.end()) {
    auto chunk = (*iter2).get();
    if (chunk->mStreamID == streamID && chunk->mType != ReliableData::kRstStream) {
      iter2 = mUnAckedData.erase(iter2);
      StreamLog6("scrubbing chunk %p of unacked id %d\n",
                 chunk, streamID);
    } else {
      iter2++;
    }
  }
  return MOZQUIC_OK;
}

uint64_t
StreamState::CalculateConnectionCharge(ReliableData *data, StreamOut *out)
{
  uint64_t newConnectionCharge = 0;
  if (data->mStreamID &&
      (data->mOffset + data->mLen > out->mOffsetChargedToConnFlowControl)) {
    newConnectionCharge = data->mOffset + data->mLen - out->mOffsetChargedToConnFlowControl;
  }
  return newConnectionCharge;
}

uint32_t
StreamState::FlowControlPromotionForStreamPair(StreamPair *sp)
{
  StreamOut *out = &sp->mOut;

  for (auto iBuffer = out->mStreamUnWritten.begin();
       iBuffer != out->mStreamUnWritten.end(); ) {

    uint64_t newConnectionCharge = 0;
    if ((*iBuffer)->mLen) {

      newConnectionCharge = CalculateConnectionCharge((*iBuffer).get(), out);

      if (newConnectionCharge) {
      
        if (mMaxDataSent >= mPeerMaxData) {
          if (!mMaxDataBlocked) {
            mMaxDataBlocked = true;
            StreamLog2("BLOCKED by connection window 1\n");
            std::unique_ptr<ReliableData> tmp(new ReliableData(0, 0, nullptr, 0, 0));
            tmp->MakeBlocked();
            ConnectionWrite(tmp);
          }
          iBuffer++;
          continue;
        }
      
        if (mMaxDataSent + newConnectionCharge > mPeerMaxData) {
          // split buffer
          uint64_t minCharge = 1; // for hypothetical 1 byte frame
          if ((*iBuffer)->mOffset + 1 > out->mOffsetChargedToConnFlowControl) {
            minCharge = (*iBuffer)->mOffset + 1 - out->mOffsetChargedToConnFlowControl;
          }
          if (mMaxDataSent + minCharge > mPeerMaxData) {
            if (!mMaxDataBlocked) {
              mMaxDataBlocked = true;
              StreamLog2("BLOCKED by connection window 2\n");
              std::unique_ptr<ReliableData> tmp(new ReliableData(0, 0, nullptr, 0, 0));
              tmp->MakeBlocked();
              ConnectionWrite(tmp);
            }
            iBuffer++;
            continue;
          }
          uint64_t maxCharge = mPeerMaxData - mMaxDataSent;
          uint64_t room = maxCharge - minCharge + 1;
          assert (room < (*iBuffer)->mLen);

          std::unique_ptr<ReliableData>
            tmp(new ReliableData((*iBuffer)->mStreamID,
                                 (*iBuffer)->mOffset + room,
                                 (*iBuffer)->mData.get() + room,
                                 (*iBuffer)->mLen - room,
                                 (*iBuffer)->mFin));
          (*iBuffer)->mLen = room;
          (*iBuffer)->mFin = false;
          StreamLog7("FlowControlPromotionForStreamPair ConnWindow splitting chunk into "
                     "%ld.%d and %ld.%d\n",
                     (*iBuffer)->mOffset, (*iBuffer)->mLen,
                     tmp->mOffset, tmp->mLen);
          auto iterReg = iBuffer++;
          out->mStreamUnWritten.insert(iBuffer, std::move(tmp));
          iBuffer = iterReg;

          newConnectionCharge = CalculateConnectionCharge((*iBuffer).get(), out);
        }
      }
            
      if ((*iBuffer)->mOffset >= out->mFlowControlLimit) {
        if (!out->mBlocked) {
          StreamLog2("Stream %d BLOCKED flow control\n", (*iBuffer)->mStreamID);
          out->mBlocked = true;
          std::unique_ptr<ReliableData> tmp(new ReliableData((*iBuffer)->mStreamID, 0, nullptr, 0, 0));
          tmp->MakeStreamBlocked();
          ConnectionWrite(tmp);
        }
        iBuffer++;
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
        StreamLog7("FlowControlPromotionForStreamPair StreamWindow splitting chunk into "
                   "%ld.%d and %ld.%d\n",
                   (*iBuffer)->mOffset, (*iBuffer)->mLen,
                   tmp->mOffset, tmp->mLen);
        auto iterReg = iBuffer++;
        out->mStreamUnWritten.insert(iBuffer, std::move(tmp));
        iBuffer = iterReg;
        newConnectionCharge = CalculateConnectionCharge((*iBuffer).get(), out);
      }
    }
  
    assert((*iBuffer)->mOffset + (*iBuffer)->mLen <= out->mFlowControlLimit);
    out->mOffsetChargedToConnFlowControl += newConnectionCharge;
    mMaxDataSent += newConnectionCharge;
    assert(mMaxDataSent <= mPeerMaxData);

    if ((*iBuffer)->mLen) {
      out->mBlocked = false;
      if (((*iBuffer)->mStreamID)) {
        mMaxDataBlocked = false;
      }
    }
    uint64_t pmd = mPeerMaxData; // will trunc, but just for logging
    uint64_t mds = mMaxDataSent; // will trunc, but just for logging
    StreamLog6("promoting chunk stream %d %ld.%d [stream limit=%ld] [conn limit %llu of %lld]\n",
               (*iBuffer)->mStreamID, (*iBuffer)->mOffset, (*iBuffer)->mLen,
               out->mFlowControlLimit, mds, pmd);
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
  // todo something better than polling
  if (mStream0) {
    FlowControlPromotionForStreamPair(mStream0.get());
  }
  for (auto iStreamPair = mStreams.begin(); iStreamPair != mStreams.end(); iStreamPair++) {
    FlowControlPromotionForStreamPair(iStreamPair->second.get());
    if (MaybeDeleteStream(iStreamPair->second->mStreamID)) {
      return FlowControlPromotion(); // vector needs to be restarted
    }
  }
  return MOZQUIC_OK;
}

void
StreamState::MaybeIssueFlowControlCredit()
{
  // todo something better than polling
  ConnectionReadBytes(0);
  if (mStream0) {
    mStream0->mIn.MaybeIssueFlowControlCredit();
  }
  for (auto iStreamPair = mStreams.begin(); iStreamPair != mStreams.end(); iStreamPair++) {
    iStreamPair->second->mIn.MaybeIssueFlowControlCredit();
  }
  if (mNextRecvStreamIDUsed >= mLocalMaxStreamID ||
      (mLocalMaxStreamID - mNextRecvStreamIDUsed < 512)) {
    mLocalMaxStreamID += 1024;
    StreamLog5("Increasing Peer's Max StreamID to %d\n", mLocalMaxStreamID);
    std::unique_ptr<ReliableData> tmp(new ReliableData(0, 0, nullptr, 0, 0));
    tmp->MakeMaxStreamID(mLocalMaxStreamID);
    ConnectionWrite(tmp);
  }
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
    if (justZero && (((*iter)->mType != ReliableData::kStream)|| (*iter)->mStreamID)) {
      iter++;
      continue;
    }
    if ((*iter)->mType == ReliableData::kRstStream) {
      if (CreateRstStreamFrame(framePtr, endpkt, (*iter).get()) != MOZQUIC_OK) {
        break;
      }
    } else if ((*iter)->mType == ReliableData::kMaxStreamData) {
      if (CreateMaxStreamDataFrame(framePtr, endpkt, (*iter).get()) != MOZQUIC_OK) {
        // this one sometimes fails and we should just delete the info and move on
        // as the stream no longer needs flow control
        iter = mConnUnWritten.erase(iter);
        continue;
      }
    } else if ((*iter)->mType == ReliableData::kStopSending) {
      if (CreateStopSendingFrame(framePtr, endpkt, (*iter).get()) != MOZQUIC_OK) {
        break;
      }
    } else if ((*iter)->mType == ReliableData::kMaxData) {
      if (CreateMaxDataFrame(framePtr, endpkt, (*iter).get()) != MOZQUIC_OK) {
        break;
      }
    } else if ((*iter)->mType == ReliableData::kMaxStreamID) {
      if (CreateMaxStreamIDFrame(framePtr, endpkt, (*iter).get()) != MOZQUIC_OK) {
        break;
      }
    } else if ((*iter)->mType == ReliableData::kStreamBlocked) {
      if (CreateStreamBlockedFrame(framePtr, endpkt, (*iter).get()) != MOZQUIC_OK) {
        break;
      }
    } else if ((*iter)->mType == ReliableData::kBlocked) {
      if (CreateBlockedFrame(framePtr, endpkt, (*iter).get()) != MOZQUIC_OK) {
        break;
      }
    } else if ((*iter)->mType == ReliableData::kStreamIDBlocked) {
      if (CreateStreamIDBlockedFrame(framePtr, endpkt, (*iter).get()) != MOZQUIC_OK) {
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

      // Determine streamID size without varSize becuase we use 24 bit value
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

      // Set streamID
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
      StreamLog5("writing a stream %d frame %d @ offset %d [fin=%d] in packet %lX\n",
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
  return 4 * 1024 * 1024; // todo
}

uint32_t
StreamState::IssueStreamCredit(uint32_t streamID, uint64_t newMax)
{
  if ((mMozQuic->GetConnectionState() != CLIENT_STATE_CONNECTED) &&
      (mMozQuic->GetConnectionState() != SERVER_STATE_CONNECTED)) {
    return MOZQUIC_ERR_GENERAL;
  }
  if (mMozQuic->mBackPressure) {
    return MOZQUIC_ERR_GENERAL;
  }

  StreamLog5("Issue a stream credit id=%d maxoffset=%ld\n", streamID, newMax);

  std::unique_ptr<ReliableData> tmp(new ReliableData(streamID, 0, nullptr, 0, 0));
  tmp->MakeMaxStreamData(newMax);
  return ConnectionWrite(tmp);
}

uint32_t
StreamState::ConnectionReadBytes(uint64_t amt)
{
  if ((mMozQuic->GetConnectionState() != CLIENT_STATE_CONNECTED) &&
      (mMozQuic->GetConnectionState() != SERVER_STATE_CONNECTED)) {
    return MOZQUIC_ERR_GENERAL;
  }

  if (mLocalMaxDataUsed + amt > mLocalMaxData) {
    StreamLog1("Peer violated connection flow control\n");
    mMozQuic->Shutdown(FLOW_CONTROL_ERROR,
                       "peer violated connection flow control\n");
    return MOZQUIC_ERR_IO;
  }
  mLocalMaxDataUsed += amt;

  // todo - credit scheme should be based on how much is queued here.
  // todo - autotuning
  uint64_t available = mLocalMaxData - mLocalMaxDataUsed;

  if (mMozQuic->mBackPressure || (available > 4 * 1024 * 1024)) {
    return MOZQUIC_OK;
  }

  mLocalMaxData += 8 * 1024 * 1024;
  mLocalMaxData -= mLocalMaxData & 0x3ff;
  uint64_t lmd = mLocalMaxData;
  StreamLog5("Issue a connection credit newmax %ld\n", lmd);

  std::unique_ptr<ReliableData> tmp(new ReliableData(0, 0, nullptr, 0, 0));
  assert(!(mLocalMaxData & 0x3ff));
  tmp->MakeMaxData(mLocalMaxData >> 10);
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
      StreamLog7("old unacked packet forgotten %lX\n",
                 (*i)->mPacketNumber);
      assert(!(*i)->mData);
      i = mUnAckedData.erase(i);
    } else if (!(*i)->mRetransmitted) {
      assert((*i)->mData);
      StreamLog4("data associated with packet %lX retransmitted\n",
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
StreamState::CreateRstStreamFrame(unsigned char *&framePtr, const unsigned char *endpkt,
                                  ReliableData *chunk)
{
  StreamLog3("generating stream reset %d id=%ld pkt=%ld\n",
             chunk->mOffset, chunk->mStreamID,
             mMozQuic->mNextTransmitPacketNumber);
  assert(chunk->mType == ReliableData::kRstStream);
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
  StreamLog5("generating max stream data id=%d val=%ld into pkt=%lx\n",
             chunk->mStreamID, chunk->mStreamCreditValue,
             mMozQuic->mNextTransmitPacketNumber);
  assert(chunk->mType == ReliableData::kMaxStreamData);
  assert(chunk->mStreamCreditValue);
  assert(!chunk->mLen);

  if (chunk->mStreamID) {
    auto i = mStreams.find(chunk->mStreamID);
    if (i == mStreams.end() ||
        (*i).second->mIn.mFinRecvd ||
        (*i).second->mIn.mRstRecvd) {
      return MOZQUIC_ERR_GENERAL;
    }
  }

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
StreamState::CreateMaxStreamIDFrame(unsigned char *&framePtr, const unsigned char *endpkt,
                                    ReliableData *chunk)
{
  StreamLog5("generating max stream id=%d into pkt=%lx\n",
             chunk->mMaxStreamID,
             mMozQuic->mNextTransmitPacketNumber);
  assert(chunk->mType == ReliableData::kMaxStreamID);
  assert(chunk->mMaxStreamID);
  assert(!chunk->mLen);

  uint32_t room = endpkt - framePtr;
  if (room < 5) {
    return MOZQUIC_ERR_GENERAL;
  }
  framePtr[0] = FRAME_TYPE_MAX_STREAM_ID;
  uint32_t tmp32 = htonl(chunk->mMaxStreamID);
  memcpy(framePtr + 1, &tmp32, 4);
  framePtr += 5;
  return MOZQUIC_OK;
}

uint32_t
StreamState::CreateStopSendingFrame(unsigned char *&framePtr, const unsigned char *endpkt,
                                    ReliableData *chunk)
{
  StreamLog5("generating stop sending code stream %d %x\n",
             chunk->mStreamID, chunk->mStopSendingCode);
  assert(chunk->mType == ReliableData::kStopSending);
  assert(chunk->mStreamID);
  assert(!chunk->mLen);

  uint32_t room = endpkt - framePtr;
  if (room < 9) {
    return MOZQUIC_ERR_GENERAL;
  }
  framePtr[0] = FRAME_TYPE_STOP_SENDING;
  uint32_t tmp32 = htonl(chunk->mStreamID);
  memcpy(framePtr + 1, &tmp32, 4);
  tmp32 = htonl(chunk->mStopSendingCode);
  memcpy(framePtr + 5, &tmp32, 4);
  framePtr += 9;
  return MOZQUIC_OK;
}

uint32_t
StreamState::CreateMaxDataFrame(unsigned char *&framePtr, const unsigned char *endpkt,
                                ReliableData *chunk)
{
  StreamLog5("generating max data val=%ld (KB) into pkt=%lx\n",
             chunk->mConnectionCreditKB,
             mMozQuic->mNextTransmitPacketNumber);
  assert(chunk->mType == ReliableData::kMaxData);
  assert(chunk->mConnectionCreditKB);
  assert(!chunk->mLen);
  assert(!chunk->mStreamID);

  uint32_t room = endpkt - framePtr;
  if (room < 9) {
    return MOZQUIC_ERR_GENERAL;
  }
  framePtr[0] = FRAME_TYPE_MAX_DATA;
  uint64_t tmp64 = PR_htonll(chunk->mConnectionCreditKB);
  memcpy(framePtr + 1, &tmp64, 8);
  framePtr += 9;
  return MOZQUIC_OK;
}

uint32_t
StreamState::CreateStreamBlockedFrame(unsigned char *&framePtr, const unsigned char *endpkt,
                                      ReliableData *chunk)
{
  StreamLog2("generating stream blocked id=%d into pkt=%lx\n",
             chunk->mStreamID,
             mMozQuic->mNextTransmitPacketNumber);
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

uint32_t
StreamState::CreateBlockedFrame(unsigned char *&framePtr, const unsigned char *endpkt,
                                ReliableData *chunk)
{
  StreamLog2("generating blocked into pkt=%lx\n",
             mMozQuic->mNextTransmitPacketNumber);
  assert(chunk->mType == ReliableData::kBlocked);
  assert(!chunk->mLen);

  uint32_t room = endpkt - framePtr;
  if (room < 1) {
    return MOZQUIC_ERR_GENERAL;
  }
  framePtr[0] = FRAME_TYPE_BLOCKED;
  framePtr += 1;
  return MOZQUIC_OK;
}

uint32_t
StreamState::CreateStreamIDBlockedFrame(unsigned char *&framePtr, const unsigned char *endpkt,
                                        ReliableData *chunk)
{
  StreamLog2("generating streamID needed into pkt=%lx\n",
             mMozQuic->mNextTransmitPacketNumber);
  assert(chunk->mType == ReliableData::kStreamIDBlocked);
  assert(!chunk->mLen);

  uint32_t room = endpkt - framePtr;
  if (room < 1) {
    return MOZQUIC_ERR_GENERAL;
  }
  framePtr[0] = FRAME_TYPE_STREAM_ID_BLOCKED;
  framePtr += 1;
  return MOZQUIC_OK;
}

StreamState::StreamState(MozQuic *q, uint64_t initialStreamWindow,
                         uint64_t initialConnectionWindowKB)
  : mMozQuic(q)
  , mNextStreamID(1)
  , mPeerMaxStreamData(kMaxStreamDataDefault)
  , mLocalMaxStreamData(initialStreamWindow)
  , mPeerMaxData(kMaxDataDefault)
  , mMaxDataSent(0)
  , mMaxDataBlocked(false)
  , mLocalMaxData(((__uint128_t)initialConnectionWindowKB) << 10)
  , mLocalMaxDataUsed(0)
  , mPeerMaxStreamID(kMaxStreamIDDefault)
  , mLocalMaxStreamID(kMaxStreamIDDefault) // todo config
  , mMaxStreamIDBlocked(false)
  , mNextRecvStreamIDUsed(1)
{
}

StreamPair::StreamPair(uint32_t id, MozQuic *m,
                       FlowController *flowController,
                       uint64_t peerMaxStreamData, uint64_t localMaxStreamData)
  : mStreamID(id)
  , mOut(m, id, flowController, peerMaxStreamData)
  , mIn(m, id, flowController, localMaxStreamData)
  , mMozQuic(m)
{
}

bool
StreamPair::Done()
{
  return mOut.Done() && mIn.Done();
}

int
StreamPair::StopSending(uint32_t code)
{
  std::unique_ptr<ReliableData> tmp(new ReliableData(mStreamID, 0, nullptr, 0, 0));
  tmp->MakeStopSending(code);
  return mOut.ConnectionWrite(tmp);
}

uint32_t
StreamPair::Supply(std::unique_ptr<ReliableData> &p) {
  assert(p->mType != ReliableData::kRstStream);
  return mIn.Supply(p);
}

uint32_t
StreamPair::Write(const unsigned char *data, uint32_t len, bool fin)
{
  if (!mMozQuic->IsOpen()) {
    return MOZQUIC_ERR_IO;
  }
  return mOut.Write(data, len, fin);
}

StreamIn::StreamIn(MozQuic *m, uint32_t id,
                   FlowController *flowcontroller, uint64_t localMaxStreamData)
  : mMozQuic(m)
  , mStreamID(id)
  , mOffset(0)
  , mFinalOffset(0)
  , mLocalMaxStreamData(localMaxStreamData)
  , mNextStreamDataExpected(0)
  , mFlowController(flowcontroller)
  , mFinRecvd(false)
  , mRstRecvd(false)
  , mEndGivenToApp(false)
{
}

StreamIn::~StreamIn()
{
}

uint32_t
StreamPair::ResetInbound()
{
  // this is used in a very peculiar circumstance after HRR on stream 0 only
  assert(mStreamID == 0);
  return mIn.ResetInbound();
}

uint32_t
StreamIn::ResetInbound()
{
  assert(Empty());
  mOffset = 0;
  mFinalOffset = 0;
  mFinRecvd = false;
  mRstRecvd = false;
  mEndGivenToApp = false;
  return MOZQUIC_OK;
}

// returning amt = 0 is not a fin or an error on its own
uint32_t
StreamIn::Read(unsigned char *buffer, uint32_t avail, uint32_t &amt, bool &fin)
{
  amt = 0;
  fin = false;
  if (mFinRecvd && mFinalOffset == mOffset) {
    fin = true;
    mEndGivenToApp = true;
    return mRstRecvd ? MOZQUIC_ERR_IO : MOZQUIC_OK;
  }
  if (Empty()) {
    return MOZQUIC_OK;
  }

  auto i = mAvailable.begin();
  if ((*i)->mOffset > mOffset) {
    assert (mRstRecvd);
    mEndGivenToApp = true;
    return MOZQUIC_ERR_IO;
  }

  uint64_t skip = mOffset - (*i)->mOffset;
  const unsigned char *src = (*i)->mData.get() + skip;
  assert((*i)->mLen > skip);
  uint64_t copyLen = (*i)->mLen - skip;
  if (copyLen > avail) {
    copyLen = avail;
  }
  memcpy (buffer, src, copyLen);
  amt = copyLen;
  mOffset += copyLen;
  if (mFinRecvd && mFinalOffset == mOffset) {
    fin = true;
    mEndGivenToApp = true;
  }
  assert(mOffset <= (*i)->mOffset + (*i)->mLen);
  if (mOffset == (*i)->mOffset + (*i)->mLen) {
    // we dont need this buffer anymore
    mAvailable.erase(i);
  }
  return MOZQUIC_OK;
}

void
StreamIn::MaybeIssueFlowControlCredit()
{
  
  uint64_t available = mLocalMaxStreamData - mNextStreamDataExpected;
  uint32_t increment = mFlowController->GetIncrement();

  if (mNextStreamDataExpected > mLocalMaxStreamData) {
    assert(!mStreamID);
    available = 0;
    increment = mNextStreamDataExpected - mLocalMaxStreamData + 1000000;
  }
        
  StreamLog7("peer has %ld stream flow control credits available on stream %d\n",
             available, mStreamID);
  if (mFinRecvd || mRstRecvd) {
    return; // does not need more
  }

  if ((available < 32 * 1024) ||
      (available < (increment / 2))) {
    if (mLocalMaxStreamData > (0xffffffffffffffffULL - increment)) {
      return;
    }
    mLocalMaxStreamData += increment;

    if (mFlowController->IssueStreamCredit(mStreamID, mLocalMaxStreamData) != MOZQUIC_OK) {
      mLocalMaxStreamData -= increment;
    }
  }
}

uint32_t
StreamIn::Supply(std::unique_ptr<ReliableData> &d)
{
  // new frame segment goes into a linked list ordered by seqno
  // any overlapping data is dropped

  if (mRstRecvd) {
    d.reset(); // drop it
    return MOZQUIC_OK;
  }

  assert(d->mType != ReliableData::kRstStream);

  if (d->mFin) {
    if (!mFinRecvd) {
      mFinRecvd = true;
      mFinalOffset = d->mOffset + d->mLen;
    } else {
      if (mFinalOffset != d->mOffset + d->mLen) {
        StreamLog1("stream %d recvd fin with offset of %ld.%ld expected %ld\n",
                   mStreamID, d->mOffset, d->mLen, mFinalOffset);
        mMozQuic->Shutdown(FINAL_OFFSET_ERROR, "offset too large");
        return MOZQUIC_ERR_IO;
      }
    }
  }

  if (mFinalOffset && (d->mOffset + d->mLen > mFinalOffset)) {
    StreamLog1("stream %d has finoffset of %ld and new packet %ld.%ld\n",
               mStreamID, mFinalOffset, d->mOffset, d->mLen);
    mMozQuic->Shutdown(FINAL_OFFSET_ERROR, "offset too large");
    return MOZQUIC_ERR_IO;
  }
  
  uint64_t endData = d->mOffset + d->mLen;
  if (endData <= mOffset) {
    // this is 100% old data. we can drop it
    d.reset();
    return MOZQUIC_OK;
  }

  if (endData > mNextStreamDataExpected) {
    if (mStreamID) {
      mFlowController->ConnectionReadBytes(endData - mNextStreamDataExpected);
    }

    mNextStreamDataExpected = endData;
    // todo - credit scheme should be based on how much is queued here.
    // todo - autotuning
    if (mStreamID && (mNextStreamDataExpected > mLocalMaxStreamData)) {
      mMozQuic->Shutdown(FLOW_CONTROL_ERROR, "stream flow control error");
      StreamLog1("stream flow control recvd too much data\n");
      return MOZQUIC_ERR_IO;
    }
    MaybeIssueFlowControlCredit();
  }

  // if the list is empty, add it to the list!
  if (mAvailable.empty()) {
    mAvailable.push_front(std::move(d));
    return MOZQUIC_OK;
  }

  // note these are reverse iterators so iter++ moves to the left (earlier seqno)
  // and insert puts new node to the right (later seqno)
  auto i = mAvailable.rbegin();
  auto end = mAvailable.rend();

  while (i != end) {
    // we don't need empty chunks
    if (!d->mLen) {
      // todo log
      std::unique_ptr<ReliableData> x(std::move(d));
      return MOZQUIC_OK;
    }

    // check for dup
    // if i offset && len == d offset && len drop it
    if ((d->mOffset == (*i)->mOffset) && (d->mLen == (*i)->mLen)) {
      // todo log
      // this is a dup. ignore it.
      std::unique_ptr<ReliableData> x(std::move(d));
      return MOZQUIC_OK;
    }

    // check for full append to the right (later seq [d is after i])
    // if i offset + len <= d.offset then append after
    if (((*i)->mOffset + (*i)->mLen) <= d->mOffset) {
      mAvailable.insert(i.base(), std::move(d));
      return MOZQUIC_OK;
    }

    // check for full location to the left (earlier seq [d is before i])
    // if d offset + len <= i.offset then iter left and rpt
    if ((d->mOffset + d->mLen) <= (*i)->mOffset){
      i++;
      continue;
    }

    // d overlaps with i. Form a new chunk with any portion that
    // exists to the right and append that (if it exists), and then
    // adjust the current chunk to only cover data to the left (not
    // any overlap) and iter to the left.
    if ((d->mOffset + d->mLen) > ((*i)->mOffset + (*i)->mLen)) {
      // we need a new chunk
      uint64_t skip = (*i)->mOffset + (*i)->mLen - d->mOffset;
      std::unique_ptr<ReliableData>
        newChunk(new ReliableData(d->mStreamID,
                                  (*i)->mOffset + (*i)->mLen,
                                  d->mData.get() + skip,
                                  d->mLen - skip, false));
      d->mLen = skip;

      // todo log
      // append it to the right
      mAvailable.insert(i.base(), std::move(newChunk));
      // dont continue or return, still need to deal with remainder
    }

    if ((*i)->mOffset <= d->mOffset) {
      // there is no more data to the left. drop it.
      // todo log
      std::unique_ptr<ReliableData> x(std::move(d));
      return MOZQUIC_OK;
    }

    // adjust data to be non overlapping
    d->mLen = (*i)->mOffset - d->mOffset;
    // todo log
    i++;
  }

  mAvailable.push_front(std::move(d));
  return MOZQUIC_OK;
}

bool
StreamIn::Empty()
{
  if (mRstRecvd) {
    return false;
  }

  if (mFinRecvd && mFinalOffset == mOffset) {
    return false;
  }
  if (mAvailable.empty()) {
    return true;
  }

  auto i = mAvailable.begin();
  if ((*i)->mOffset > mOffset) {
    return true;
  }

  return false;
}

StreamOut::StreamOut(MozQuic *m, uint32_t id, FlowController *fc,
                     uint64_t flowControlLimit)
  : mWriter(fc)
  , mStreamID(id)
  , mOffset(0)
  , mFlowControlLimit(flowControlLimit)
  , mOffsetChargedToConnFlowControl(0)
  , mFin(false)
  , mRst(false)
  , mBlocked(false)
{
}

StreamOut::~StreamOut()
{
}

uint32_t
StreamOut::StreamWrite(std::unique_ptr<ReliableData> &p)
{
  mStreamUnWritten.push_back(std::move(p));

  return MOZQUIC_OK;
}


uint32_t
StreamOut::Write(const unsigned char *data, uint32_t len, bool fin)
{
  if (mRst) {
    return MOZQUIC_ERR_IO;
  }

  if (mFin) {
    return MOZQUIC_ERR_ALREADY_FINISHED;
  }

  std::unique_ptr<ReliableData> tmp(new ReliableData(mStreamID, mOffset, data, len, fin));
  mOffset += len;
  mFin = fin;
  return StreamWrite(tmp);
}

int
StreamOut::EndStream()
{
  if (mFin) {
    return MOZQUIC_ERR_ALREADY_FINISHED;
  }
  mFin = true;

  std::unique_ptr<ReliableData> tmp(new ReliableData(mStreamID, mOffset, nullptr, 0, true));
  return StreamWrite(tmp);
}

int
StreamOut::RstStream(uint32_t code)
{
  if (mFin) {
    return MOZQUIC_ERR_ALREADY_FINISHED;
  }
  mFin = true;
  mRst = true;

  // empty local queue before sending rst
  ScrubUnWritten();
    
  std::unique_ptr<ReliableData> tmp(new ReliableData(mStreamID, mOffset, nullptr, 0, 0));
  tmp->MakeRstStream(code);
  return mWriter->ConnectionWrite(tmp);
}

ReliableData::ReliableData(uint32_t id, uint64_t offset,
                           const unsigned char *data, uint32_t len,
                           bool fin)
  : mType(kStream)
  , mData(new unsigned char[len])
  , mLen(len)
  , mStreamID(id)
  , mOffset(offset)
  , mFin(fin)
  , mRstCode(0)
  , mStreamCreditValue(0)
  , mConnectionCreditKB(0)
  , mTransmitTime(0)
  , mTransmitCount(1)
  , mRetransmitted(false)
  , mTransmitKeyPhase(keyPhaseUnknown)
{
  if ((0xfffffffffffffffe - offset) < len) {
    // todo should not silently truncate like this
    len = 0xfffffffffffffffe - offset;
  }

  memcpy((void *)mData.get(), data, len);
}

ReliableData::ReliableData(ReliableData &orig)
  : mType(orig.mType)
  , mLen(orig.mLen)
  , mStreamID(orig.mStreamID)
  , mOffset(orig.mOffset)
  , mFin(orig.mFin)
  , mRstCode(orig.mRstCode)
  , mStreamCreditValue(orig.mStreamCreditValue)
  , mConnectionCreditKB(orig.mConnectionCreditKB)
  , mTransmitTime(0)
  , mTransmitCount(orig.mTransmitCount + 1)
  , mRetransmitted(false)
  , mTransmitKeyPhase(keyPhaseUnknown)
{
  mData = std::move(orig.mData);
}

ReliableData::~ReliableData()
{
}

} // namespace

