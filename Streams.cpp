/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "Logging.h"
#include "MozQuic.h"
#include "MozQuicInternal.h"
#include "Sender.h"
#include "Streams.h"

#include "assert.h"
#include "stdlib.h"
#include "unistd.h"

#include <algorithm>

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
StreamState::StartNewStream(StreamPair **outStream, StreamType streamType,
                            bool no_replay, const void *data, uint32_t amount,
                            bool fin)
{
  if ((mMozQuic->GetConnectionState() != CLIENT_STATE_CONNECTED) &&
      (mMozQuic->GetConnectionState() != CLIENT_STATE_0RTT) &&
      (mMozQuic->GetConnectionState() != SERVER_STATE_CONNECTED)) {
    return MOZQUIC_ERR_IO;
  }

  if (mNextStreamID[streamType] > mPeerMaxStreamID[streamType]) {
    if (!mMaxStreamIDBlocked[streamType]) {
      mMaxStreamIDBlocked[streamType] = true;
      StreamLog3("new stream BLOCKED on stream id flow control %d\n",
                 mPeerMaxStreamID[streamType]);
      std::unique_ptr<ReliableData> tmp(new ReliableData(0, 0, nullptr, 0, 0));
      tmp->MakeStreamIDBlocked(mPeerMaxStreamID[streamType]);
      ConnectionWrite(tmp);
    }
    return MOZQUIC_ERR_IO;
  }

  std::shared_ptr<StreamPair> tmp(new StreamPair(mNextStreamID[streamType], mMozQuic, this,
                                                 mPeerMaxStreamData, mLocalMaxStreamData, no_replay));
  mStreams.insert( { mNextStreamID[streamType], tmp } );
  *outStream = tmp.get();

  mNextStreamID[streamType] += 4;

  if ( amount || fin) {
    return (*outStream)->Write((const unsigned char *)data, amount, fin);
  }
  return MOZQUIC_OK;
}

bool
StreamState::IsAllAcked()
{
  return (!AnyUnackedPackets()) && mConnUnWritten.empty();
}

uint32_t
StreamState::MakeSureStreamCreated(uint32_t streamID)
{
  StreamType streamType = GetStreamType(streamID);

  // is this a stream that should be initiated by the peer?
  if (IsPeerStream(streamID)) {
    // Open a new stream and implicitly open all streams with ID smaller than
    // streamID that are not already opened, but only open uni=orbidirectional
    // streams depending on the stream type.
    if (streamID > mLocalMaxStreamID[streamType]) {
      mMozQuic->Shutdown(STREAM_ID_ERROR, "recv stream id too high\n");
      mMozQuic->RaiseError(MOZQUIC_ERR_IO, "need stream id %d but peer only allowed %d\n",
                           streamID, mLocalMaxStreamID[streamType]);
      return MOZQUIC_ERR_IO;
    }

    bool addedStream = false;
    while (streamID >= mNextRecvStreamIDUsed[streamType]) {
      StreamLog5("Add new %s stream %d\n",
                 (streamType == BIDI_STREAM) ? "bidi" : "uni",
                 mNextRecvStreamIDUsed[streamType]);
      addedStream = true;
      std::shared_ptr<StreamPair> tmp(new StreamPair(mNextRecvStreamIDUsed[streamType],
                                                     mMozQuic, this,
                                                     mPeerMaxStreamData, mLocalMaxStreamData,
                                                     false));
      mStreams.insert( { mNextRecvStreamIDUsed[streamType], tmp } );
      mNextRecvStreamIDUsed[streamType] += 4;
    }

    if (addedStream && !mMozQuic->mBackPressure) {
      if (mNextRecvStreamIDUsed[streamType] >= mLocalMaxStreamID[streamType] ||
          (mLocalMaxStreamID[streamType] - mNextRecvStreamIDUsed[streamType] < 512)) {
        mLocalMaxStreamID[streamType] += 1024;
        StreamLog5("Increasing Peer's Max StreamID to %d\n", mLocalMaxStreamID[streamType]);
        std::unique_ptr<ReliableData> tmp(new ReliableData(0, 0, nullptr, 0, 0));
        tmp->MakeMaxStreamID(mLocalMaxStreamID[streamType]);
        ConnectionWrite(tmp);
      }
    }
  } else { // stream should have been intiated by this end
    if (streamID >= mNextStreamID[streamType]) {
      assert(mStreams.find(streamID) == mStreams.end());
      mMozQuic->Shutdown(STREAM_STATE_ERROR, "recvd frame on stream this peer should have started");
      mMozQuic->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "recvd frame on stream this peer should have started");
      return MOZQUIC_ERR_GENERAL;
    }
  }
  
  return MOZQUIC_OK;
}

uint32_t
StreamState::FindStream(uint32_t streamID, std::unique_ptr<ReliableData> &d)
{
  assert(IsBidiStream(streamID) || IsPeerStream(streamID));

  uint32_t rv = MakeSureStreamCreated(streamID);

  if (rv != MOZQUIC_OK) {
    return rv;
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

  while (!(*i).second->Empty() && !(*i).second->mIn->Done() && mMozQuic->mConnEventCB) {
    uint64_t offset = (*i).second->mIn->mOffset;
    mMozQuic->mConnEventCB(mMozQuic->mClosure, MOZQUIC_EVENT_NEW_STREAM_DATA, (*i).second.get());
    if (offset == (*i).second->mIn->mOffset) {
      break;
    }
  }
  return MOZQUIC_OK;
}

void
StreamState::DeleteDoneStreams()
{
  auto i = mStreams.begin();
  while (i != mStreams.end()) {
    if ((*i).second->Done()) {
      StreamLog5("Delete stream %lu\n", (*i).second->mStreamID);
      i = mStreams.erase(i);
    } else {
      i++;
    }
  }
}

bool
StreamState::MaybeDeleteStream(uint32_t streamID)
{
  if (mMozQuic->GetConnectionState() == CLIENT_STATE_0RTT) {
    // Do not delete streams during 0RTT, maybe we need to restart them.
    return false;
  }
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
  StreamLog5("recv stream %lu len=%lu offset=%lu fin=%d\n",
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

  if (IsSendOnlyStream(result->u.mStream.mStreamID)) {
    mMozQuic->Shutdown(PROTOCOL_VIOLATION, "received data on a local uni-stream.\n");
    mMozQuic->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "received data on a local uni-stream.\n");
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
  uint32_t rv = MOZQUIC_OK;
  if (!result->u.mStream.mStreamID) {
    mStream0->Supply(tmp);
  } else {
    if (fromCleartext) {
      mMozQuic->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "cleartext non 0 stream id\n");
      return MOZQUIC_ERR_GENERAL;
    }
    rv = FindStream(result->u.mStream.mStreamID, tmp);
  }
  _ptr += result->u.mStream.mDataLen;
  return rv;
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

  if (IsRecvOnlyStream(result->u.mMaxStreamData.mStreamID)) {
    mMozQuic->Shutdown(PROTOCOL_VIOLATION, "received maxstreamdata on a recv only stream.\n");
    mMozQuic->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "received maxstreamdata on a recv only stream.\n");
    return MOZQUIC_ERR_GENERAL;
  }

  if (IsSendOnlyStream(result->u.mMaxStreamData.mStreamID) &&
      result->u.mMaxStreamData.mStreamID >= mNextStreamID[1]) {
    mMozQuic->Shutdown(PROTOCOL_VIOLATION, "received maxstreamdata on unopened sendonly stream.\n");
    mMozQuic->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "received maxstreamdata on unopened sendonly stream.\n");
    return MOZQUIC_ERR_GENERAL;
  }

  uint32_t rv = MakeSureStreamCreated(streamID);

  if (rv != MOZQUIC_OK) {
    return rv;
  }

  auto i = mStreams.find(streamID);
  if (i == mStreams.end()) {
    StreamLog4("cannot find streamid %d for max stream data frame. pehaps closed.\n",
               streamID);
    return MOZQUIC_OK;
  }

  StreamLog5("recvd max stream data id=%X offset=%ld current limit=%ld\n",
             streamID,
             result->u.mMaxStreamData.mMaximumStreamData,
             i->second->mOut->mFlowControlLimit);
  if (i->second->mOut->mFlowControlLimit < result->u.mMaxStreamData.mMaximumStreamData) {
    i->second->mOut->mFlowControlLimit = result->u.mMaxStreamData.mMaximumStreamData;
    if (i->second->mOut->mBlocked) {
      StreamLog5("stream %X has blocked, unblocke it.\n", streamID);
      // The stream was blocked on the flow control, unblocked it and continue
      // writing if there are data to write.
      i->second->mOut->mBlocked = false;
      if (!i->second->mOut->mStreamUnWritten.empty()) {
        i->second->mOut->mWriter->SignalReadyToWrite(i->second->mOut.get());
      }
    }
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

  StreamLog5("recvd max data current %ld new %ld\n",
             mPeerMaxData, result->u.mMaxData.mMaximumData);
  if (result->u.mMaxData.mMaximumData > mPeerMaxData) {
    mPeerMaxData = result->u.mMaxData.mMaximumData;
    if (mMaxDataBlocked) {
      StreamLog5("conn was blocked by the flow control. Check if there were "
                 "streams that wants to write new data.\n");
      mMaxDataBlocked = false;
      FlowControlPromotion();
    }
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

  StreamType streamType = GetStreamType(result->u.mMaxStreamID.mMaximumStreamID);
  StreamLog5("recvd max %s stream id current %d new %d\n",
             (streamType == BIDI_STREAM) ? "bidi" : "uni",
             mPeerMaxStreamID[streamType],
             result->u.mMaxStreamID.mMaximumStreamID);

  if (!IsLocalStream(result->u.mMaxStreamID.mMaximumStreamID)) {
    mMozQuic->Shutdown(FRAME_ERROR_MASK | FRAME_TYPE_MAX_STREAM_ID, "remote max stream id\n");
    mMozQuic->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "remote max stream id\n");
    return MOZQUIC_ERR_GENERAL;
  }
  
  if (result->u.mMaxStreamID.mMaximumStreamID > mPeerMaxStreamID[streamType]) {
    mPeerMaxStreamID[streamType] = result->u.mMaxStreamID.mMaximumStreamID;
    mMaxStreamIDBlocked[streamType] = false;
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

  if (IsSendOnlyStream(result->u.mStreamBlocked.mStreamID)) {
    mMozQuic->Shutdown(PROTOCOL_VIOLATION, "received streamblocked on a local uni-stream.\n");
    mMozQuic->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "received streamblocked on a local uni-stream.\n");
    return MOZQUIC_ERR_GENERAL;
  }

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
    mMozQuic->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "streamidblocked frames not allowed in cleartext\n");
    return MOZQUIC_ERR_GENERAL;
  }

  StreamLog2("recvd streamidblocked\n");
  return MOZQUIC_OK;
}

uint32_t
StreamState::HandleResetStreamFrame(FrameHeaderData *result, bool fromCleartext,
                                    const unsigned char *pkt, const unsigned char *endpkt,
                                    uint32_t &)
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

  if (IsSendOnlyStream(result->u.mRstStream.mStreamID)) {
    mMozQuic->Shutdown(PROTOCOL_VIOLATION, "rst_stream frames not allowed on send only stream\n");
    mMozQuic->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "rst_stream not allowed on send only stream\n");
    return MOZQUIC_ERR_GENERAL;
  }

  uint32_t rv = MakeSureStreamCreated(result->u.mRstStream.mStreamID);

  if (rv != MOZQUIC_OK) {
    return rv;
  }

  auto i = mStreams.find(result->u.mRstStream.mStreamID);
  if (i == mStreams.end()) {
    StreamLog4("StreamState::HandleResetStreamFrame %d not found.\n",
               result->u.mRstStream.mStreamID);
    return MOZQUIC_ERR_GENERAL;
  }
  StreamPair *sp = (*i).second.get();
  sp->mIn->HandleResetStream(result->u.mRstStream.mFinalOffset);
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
                                    uint32_t &)
{
  if (fromCleartext) {
    mMozQuic->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "stop_sending frames not allowed in cleartext\n");
    return MOZQUIC_ERR_GENERAL;
  }

  if (IsRecvOnlyStream(result->u.mStopSending.mStreamID)) {
    mMozQuic->Shutdown(PROTOCOL_VIOLATION, "received stopSending on wrong uni-stream.\n");
    mMozQuic->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "received stopSending on wrong uni-stream.\n");
    return MOZQUIC_ERR_GENERAL;
  }

  StreamLog4("recvd stop sending %ld %lx\n",
             result->u.mStopSending.mStreamID, result->u.mStopSending.mErrorCode);
  RstStream(result->u.mStopSending.mStreamID, result->u.mStopSending.mErrorCode);
  return MOZQUIC_OK;
}

uint32_t
StreamState::GeneratePathResponse(uint64_t data)
{
  std::unique_ptr<ReliableData> tmp(new ReliableData(0, 0, nullptr, 0, 0));
  tmp->MakePathResponse(data);
  ConnectionWrite(tmp);
  return MOZQUIC_OK;
}

uint32_t
StreamState::RstStream(uint32_t streamID, uint16_t code)
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
  bool foundDataPkt = false; // this is just for testing that we do not write on uni-stream from a peer.
  for (auto iter = mConnUnWritten.begin(); iter != mConnUnWritten.end();) {
    auto chunk = (*iter).get();
    if (chunk->mStreamID == streamID && chunk->mType != ReliableData::kRstStream) {
      iter = mConnUnWritten.erase(iter);
      StreamLog6("scrubbing chunk %p of unwritten id %d\n",
                 chunk, streamID);
      foundDataPkt = true;
    } else {
      iter++;
    }
  }

  for (auto packetIter = mUnAckedPackets.begin(); packetIter != mUnAckedPackets.end(); packetIter++) {
    for (auto frameIter = (*packetIter)->mFrameList.begin();
         frameIter != (*packetIter)->mFrameList.end(); ) {
      if ((*frameIter)->mStreamID == streamID &&
          (*frameIter)->mType != ReliableData::kRstStream) {
        frameIter = (*packetIter)->mFrameList.erase(frameIter);
        StreamLog5("scrubbing frame of unacked id %d\n", streamID);
        foundDataPkt = true;
      } else {
        frameIter++;
      }
    }
  }

  if (IsRecvOnlyStream(streamID)) {
    assert(!foundDataPkt);
  }
  mStreamsReadyToWrite.remove(streamID);

  return MOZQUIC_OK;
}

void
StreamState::Reset0RTTData()
{
  // We will go through the mUnAckedPackets data first then through the
  // mConnUnWritten data.
  // We also start with the oldest sent(easier to delete data without
  // a revert-iterator to iterator conversion).

  auto iter1 = mUnAckedPackets.begin();
  while (iter1 != mUnAckedPackets.end()) {
    auto iter2 = (*iter1).get()->mFrameList.begin();
    while (iter2 != (*iter1).get()->mFrameList.end()) {
      if ((*iter2)->mType == ReliableData::kStream && (*iter2)->mStreamID) {
        auto i = mStreams.find((*iter2)->mStreamID);
        assert (i != mStreams.end());

        mMozQuic->mSendState->Dismissed0RTTPackets((*iter2)->mLen);
        std::unique_ptr<ReliableData> x(std::move((*iter2)));
        iter2 = (*iter1).get()->mFrameList.erase(iter2);

        if ((*i).second->mOut->mStreamUnWritten.empty()) {
          (*i).second->mOut->mStreamUnWritten.push_front(std::move(x));
        } else {
          auto data = (*i).second->mOut->mStreamUnWritten.rbegin();
          while ((data != (*i).second->mOut->mStreamUnWritten.rend()) &&
                 (*data)->mOffset > x->mOffset) {
            data++;
          }
          // A bit of a strange conversion from reverse-iterator to normal one.
          (*i).second->mOut->mStreamUnWritten.insert(data.base(), std::move(x));
        }

        (*i).second->mOut->mOffsetChargedToConnFlowControl = 0;
        (*i).second->mOut->mBlocked = false;
      } else {
        iter2++;
      }
    }
    if ((*iter1).get()->mFrameList.empty()) {
      iter1 = mUnAckedPackets.erase(iter1);
    } else {
      iter1++;
    }
  }

  auto iter3 = mConnUnWritten.begin();
  while (iter3 != mConnUnWritten.end()) {
    if ((*iter3)->mType == ReliableData::kStream && (*iter3)->mStreamID) {
      auto i = mStreams.find((*iter3)->mStreamID);
      assert (i != mStreams.end());

      std::unique_ptr<ReliableData> x(std::move(*iter3));
      iter3 = mConnUnWritten.erase(iter3);

      if ((*i).second->mOut->mStreamUnWritten.empty()) {
        (*i).second->mOut->mStreamUnWritten.push_front(std::move(x));
      } else {
        auto data = (*i).second->mOut->mStreamUnWritten.rbegin();
        while ((data != (*i).second->mOut->mStreamUnWritten.rend()) &&
               (*data)->mOffset > x->mOffset) {
          data++;
        }
        // A bit of a strange conversion from reverse-iterator to normal one.
        (*i).second->mOut->mStreamUnWritten.insert(data.base(), std::move(x));
      }

      (*i).second->mOut->mOffsetChargedToConnFlowControl = 0;
      (*i).second->mOut->mBlocked = false;
    } else {
      iter3++;
    }
  }

  mStreamsReadyToWrite.clear();

  // Delete "no_replay" streams and renumber the rest.
  for (int type = 0; type < 2; type++) {
    uint32_t nextStreamID = !type ? 4 : 2;
    for (uint32_t streamID = nextStreamID; streamID < mNextStreamID[type]; streamID += 4) {
      auto streamPair = mStreams[streamID];
      assert(streamPair->mStreamID == streamID);
      if (streamPair->mNoReplay) {
        // raise error.
        if (mMozQuic->mClosure) {
          mMozQuic->mConnEventCB(mMozQuic->mClosure, MOZQUIC_EVENT_STREAM_NO_REPLAY_ERROR, streamPair.get());
        }
        mStreams.erase(streamID);
      } else {
        if (nextStreamID != streamID) {
          streamPair->ChangeStreamID(nextStreamID);
          mStreams.insert( { nextStreamID, streamPair } );
          mStreams.erase(streamID);
        }
        mStreamsReadyToWrite.push_back(nextStreamID);
        nextStreamID += 4;
      }
    }
    mNextStreamID[type] = nextStreamID;
  }
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
StreamState::FlowControlPromotionForStreamPair(StreamOut *out)
{
  for (auto iBuffer = out->mStreamUnWritten.begin();
       iBuffer != out->mStreamUnWritten.end(); ) {

    uint64_t newConnectionCharge = 0;
    if ((*iBuffer)->mLen) {

      newConnectionCharge = CalculateConnectionCharge((*iBuffer).get(), out);

      if (newConnectionCharge) {
      
        if (mMaxDataSent >= mPeerMaxData) {
          if (!mMaxDataBlocked) {
            mMaxDataBlocked = true;
            StreamLog2("BLOCKED by connection window id=%lX (sent %d peer limit %d)\n",
                       (*iBuffer)->mStreamID, mMaxDataSent, mPeerMaxData);
            std::unique_ptr<ReliableData> tmp(new ReliableData(0, 0, nullptr, 0, 0));
            tmp->MakeBlocked(mPeerMaxData);
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
              tmp->MakeBlocked(mPeerMaxData);
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
          tmp->MakeStreamBlocked(out->mFlowControlLimit);
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

// This fx() is called when the connection flow control is unblocked.
// It goes through the list of the streams that are waiting to write data
// and promotes mStreamUnWritten buffers to the connection scoped
// mConnUnWritten.
uint32_t
StreamState::FlowControlPromotion()
{
  while (!mStreamsReadyToWrite.empty()) {
    auto streamID = mStreamsReadyToWrite.front();
    if (!streamID) {
      FlowControlPromotionForStreamPair(mStream0.get()->mOut.get());
      if (mStream0->mOut->mStreamUnWritten.empty()) {
        mStreamsReadyToWrite.pop_front();
      }
    } else {
      assert(IsBidiStream(streamID) || IsLocalStream(streamID)); // We cannot write to a peer's uni stream.
      auto streamPair = mStreams[streamID];
      FlowControlPromotionForStreamPair(streamPair.get()->mOut.get());

      if (MaybeDeleteStream(streamPair->mStreamID) ||
          streamPair->mOut->mBlocked || streamPair->mOut->mStreamUnWritten.empty()) {
        mStreamsReadyToWrite.pop_front();
      }
    }
    if (mMaxDataBlocked) {
      return MOZQUIC_OK;
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
    mStream0->mIn->MaybeIssueFlowControlCredit();
  }
  for (auto iStreamPair = mStreams.begin(); iStreamPair != mStreams.end(); iStreamPair++) {
    if (IsBidiStream(iStreamPair->second->mStreamID) ||
        IsPeerStream(iStreamPair->second->mStreamID)) {
      iStreamPair->second->mIn->MaybeIssueFlowControlCredit();
    }
  }
  for (int i = 0 ; i < 2; i++) {
    if (mNextRecvStreamIDUsed[i] >= mLocalMaxStreamID[i] ||
        (mLocalMaxStreamID[i] - mNextRecvStreamIDUsed[i] < 512)) {
      mLocalMaxStreamID[i] += 1024;
      StreamLog5("Increasing Peer's Max StreamID to %d\n", mLocalMaxStreamID[i]);
      std::unique_ptr<ReliableData> tmp(new ReliableData(0, 0, nullptr, 0, 0));
      tmp->MakeMaxStreamID(mLocalMaxStreamID[i]);
      ConnectionWrite(tmp);
    }
  }
}

uint32_t
StreamState::CreateFrames(unsigned char *&aFramePtr, const unsigned char *endpkt, bool justZero,
                          TransmittedPacket *transmittedPacket)
{
  auto iter = mConnUnWritten.begin();
  while (iter != mConnUnWritten.end()) {
    unsigned char *framePtr = aFramePtr;
    if (framePtr == endpkt) {
      break;
    }
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
      bool toRemove = false;
      if (CreateStreamIDBlockedFrame(framePtr, endpkt, (*iter).get(), toRemove) != MOZQUIC_OK) {
        if (toRemove) {
          iter = mConnUnWritten.erase(iter);
          continue;
        }
        break;
      }
    } else if ((*iter)->mType == ReliableData::kPathResponse) {
      if ((*iter)->mCloned) {
        // don't retransmit path response
        iter = mConnUnWritten.erase(iter);
        continue;
      }
      if (CreatePathResponseFrame(framePtr, endpkt, (*iter).get()) != MOZQUIC_OK) {
        break;
      }
    } else {
      assert ((*iter)->mType == ReliableData::kStream);

      uint32_t used = 0;
      auto typeBytePtr = framePtr; // used to fill in fin bit later
      framePtr[0] = FRAME_TYPE_STREAM | STREAM_LEN_BIT;
      if ((*iter)->mOffset) {
        framePtr[0] |= STREAM_OFF_BIT;
      }
      framePtr++;
      if (MozQuic::EncodeVarint((*iter)->mStreamID, framePtr, (endpkt - framePtr), used) != MOZQUIC_OK) {
        return MOZQUIC_ERR_GENERAL;
      }
      framePtr += used;
      if ((*iter)->mOffset) {
        if (MozQuic::EncodeVarint((*iter)->mOffset, framePtr, (endpkt - framePtr), used) != MOZQUIC_OK) {
          return MOZQUIC_ERR_GENERAL;
        }
        framePtr += used;
      }

      // calc assumes 2 byte length encoding
      uint32_t room = (endpkt - framePtr) - 2;
            
      if (room < ((*iter)->mLen)) {
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
        tmp->mFromRTO = (*iter)->mFromRTO;
        auto iterReg = iter++;
        mConnUnWritten.insert(iter, std::move(tmp));
        iter = iterReg;
      }
      assert(room >= (*iter)->mLen);
      assert((*iter)->mLen <= (1 << 14)); // check 2 byte assumption

      // set the len and fin bit after any potential frame split
      if (MozQuic::EncodeVarint((*iter)->mLen, framePtr, (endpkt - framePtr), used) != MOZQUIC_OK) {
        return MOZQUIC_ERR_GENERAL;
      }
      assert(used <= 2);
      framePtr += used;

      if ((*iter)->mFin) {
        *typeBytePtr = *typeBytePtr | STREAM_FIN_BIT;
      }

      memcpy(framePtr, (*iter)->mData.get(), (*iter)->mLen);
      StreamLog5("writing a stream %d frame %d @ offset %d [fin=%d] in packet %lX\n",
                 (*iter)->mStreamID, (*iter)->mLen, (*iter)->mOffset, (*iter)->mFin,
                 mMozQuic->mNextTransmitPacketNumber);
      framePtr += (*iter)->mLen;
    }

    if ((mMozQuic->GetConnectionState() == CLIENT_STATE_CONNECTED) ||
        (mMozQuic->GetConnectionState() == SERVER_STATE_CONNECTED) ||
        (mMozQuic->GetConnectionState() == CLIENT_STATE_0RTT)) {
      (*iter)->mTransmitKeyPhase = keyPhase1Rtt;
    } else {
      (*iter)->mTransmitKeyPhase = keyPhaseUnprotected;
    }
    if ((*iter)->mFromRTO) {
      transmittedPacket->mFromRTO = true;
    }
    if ((*iter)->mQueueOnTransmit) {
      transmittedPacket->mQueueOnTransmit = true;
    }

    // move it to the unacked list
    transmittedPacket->mFrameList.push_back(std::move(*iter));
    iter = mConnUnWritten.erase(iter);
    aFramePtr = framePtr;
  }
  return MOZQUIC_OK;
}

uint32_t
StreamState::FlushOnce(bool forceAck, bool forceFrame, bool &outWritten)
{
  outWritten = false;

  if (mMozQuic->GetConnectionState() != SERVER_STATE_CONNECTED) {
    mMozQuic->FlushStream0(forceAck);
  }

  if (mConnUnWritten.empty() && !forceAck) {
    return MOZQUIC_OK;
  }

  unsigned char plainPkt[kMaxMTU];
  uint32_t headerLen;
  uint32_t mtu = mMozQuic->mMTU;
  assert(mtu <= kMaxMTU);

  unsigned char *payloadLenPtr = nullptr;
  unsigned char *pnPtr = nullptr;
  if (mMozQuic->GetConnectionState() == CLIENT_STATE_0RTT) {
    mMozQuic->Create0RTTLongPacketHeader(plainPkt, mtu - kTagLen, headerLen,
                                         &payloadLenPtr, &pnPtr);
  } else if ((mMozQuic->GetConnectionState() != SERVER_STATE_CONNECTED) &&
             (mMozQuic->GetConnectionState() != SERVER_STATE_0RTT) &&
             (mMozQuic->GetConnectionState() != CLIENT_STATE_CONNECTED)) {
    // if 0RTT data gets rejected, wait for the connected state to send data.
    return MOZQUIC_OK;
  } else {
    mMozQuic->CreateShortPacketHeader(plainPkt, mtu - kTagLen, headerLen, &pnPtr);
  }

  unsigned char *framePtr = plainPkt + headerLen;
  const unsigned char *endpkt = plainPkt + mtu - kTagLen; // reserve 16 for aead tag
  std::unique_ptr<TransmittedPacket> packet(new TransmittedPacket(mMozQuic->mNextTransmitPacketNumber));

  bool makeFrames = false;
  if (!mConnUnWritten.empty()) {

    makeFrames = forceFrame;

    if (!makeFrames) {
      // this is the normal congestion control test.. make a frame if there is cwnd room and
      // nothing is buffered in sender right now
      makeFrames = mMozQuic->mSendState->EmptyQueue() &&
        mMozQuic->mSendState->CanSendNow(kInitialMTU,
                                         (mMozQuic->GetConnectionState() == CLIENT_STATE_0RTT) ||
                                         (mMozQuic->GetConnectionState() == SERVER_STATE_0RTT));
    }
    
    // if that didn't work but the first bit of data is probe data (to be unblocked) ignore
    // congestion control limits and do it right now
    if (!makeFrames) {
      auto iter = mConnUnWritten.begin();
      makeFrames = (*iter)->mSendUnblocked;
    }
  }

  if (makeFrames) {
    CreateFrames(framePtr, endpkt, false, packet.get());
  } else if (!forceAck) {
    return MOZQUIC_OK;
  }

  if (payloadLenPtr) {
    uint16_t payloadLen = (framePtr - (plainPkt + headerLen)) + 16;
    if (payloadLen > 16383) {
      return MOZQUIC_ERR_GENERAL;
    }
    // make it a 2 byte varint
    payloadLenPtr[0] = 0x40 | (payloadLen & 0xff00);
    payloadLenPtr[1] = payloadLen & 0xff;
  }
    
  uint32_t bytesOut = 0;
  bool bareAck = framePtr == (plainPkt + headerLen);
  uint32_t rv = mMozQuic->ProtectedTransmit(plainPkt, headerLen, pnPtr,
                                            plainPkt + headerLen, framePtr - (plainPkt + headerLen),
                                            mtu - headerLen - kTagLen, !payloadLenPtr, !bareAck,
                                            packet->mQueueOnTransmit, 0, &bytesOut);
  if (rv != MOZQUIC_OK) {
    return rv;
  }
  assert(!payloadLenPtr || (bytesOut == headerLen + (framePtr - (plainPkt + headerLen)) + 16));

  outWritten = true;
  if (!bareAck && bytesOut) {
    packet->mTransmitTime = MozQuic::Timestamp();
    packet->mPacketLen = bytesOut;
    mUnAckedPackets.push_back(std::move(packet));
  }

  return MOZQUIC_OK;
}

uint32_t
StreamState::Flush(bool forceAck)
{
  bool didWrite;

  uint32_t rv = FlushOnce(forceAck, false, didWrite);

  if (rv != MOZQUIC_OK) {
    return rv;
  }

  return didWrite ? Flush(false) : MOZQUIC_OK;
}

void
StreamState::TrackPacket(uint64_t packetNumber, uint32_t packetSize)
{
  std::unique_ptr<TransmittedPacket> packet(new TransmittedPacket(packetNumber));
  packet->mTransmitTime = MozQuic::Timestamp();
  packet->mPacketLen = packetSize;
  mUnAckedPackets.push_back(std::move(packet));
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
StreamState::ConnectionWriteNow(std::unique_ptr<ReliableData> &p)
{
  // this data gets queued to front of unwritten and framed and
  // transmitted after prioritization by flush()
  assert (mMozQuic->GetConnectionState() != STATE_UNINITIALIZED);

  p->mSendUnblocked = true;
  p->mQueueOnTransmit = true; // this is the post cc queue
  mConnUnWritten.push_front(std::move(p));
  Flush(false);
  return MOZQUIC_OK;
}

void
StreamState::SignalReadyToWrite(StreamOut *out)
{
  FlowControlPromotionForStreamPair(out);
  if (mMaxDataBlocked && !out->mBlocked &&
      !out->mStreamUnWritten.empty()) {
    // This stream still has data to write but it is blocked by the connection
    // flow control.
    if (std::find(mStreamsReadyToWrite.begin(), mStreamsReadyToWrite.end(), out->mStreamID) == mStreamsReadyToWrite.end()) {
      mStreamsReadyToWrite.push_back(out->mStreamID);
    }
  }
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
  uint64_t lmd = mLocalMaxData;
  StreamLog5("Issue a connection credit newmax %ld\n", lmd);

  std::unique_ptr<ReliableData> tmp(new ReliableData(0, 0, nullptr, 0, 0));
  tmp->MakeMaxData(mLocalMaxData);
  return ConnectionWrite(tmp);
}

bool
StreamState::AnyUnackedPackets()
{
  if (mUnAckedPackets.empty()) {
    return false;
  }
  for (auto pkt = mUnAckedPackets.begin();
       pkt != mUnAckedPackets.end();
       pkt++) {

    if (!(*pkt)->mFrameList.empty()) {
      return true;
    }
  }
  
  return false;
}

uint32_t
StreamState::RetransmitOldestUnackedData(bool fromRTO)
// loss timers use this if there is no new data
{
  for (auto packetIter = mUnAckedPackets.begin();
       packetIter != mUnAckedPackets.end();
       packetIter++) {

    if ((*packetIter)->mFrameList.empty()) {
      continue;
    }

    for (auto frameIter = (*packetIter)->mFrameList.begin();
         frameIter != (*packetIter)->mFrameList.end(); frameIter++) {
      StreamLog4("data associated with packet %lX retransmitted type %d %s not yet lost\n",
                 (*packetIter)->mPacketNumber, (*frameIter)->mType,
                 fromRTO ? "RTO-timer" : "TLP-timer");
      // move the data pointer from iter to tmp
      std::unique_ptr<ReliableData> tmp(new ReliableData(*(*frameIter)));
      assert(!(*frameIter)->mData);
      assert(tmp->mData);

      // its ok to bypass the per out stream flow control window on rexmit
      tmp->mFromRTO = fromRTO;
      ConnectionWriteNow(tmp);
    }

    (*packetIter)->mFrameList.clear();
    // we do not erase the packet because it is not lost
    // we do not report it lost because that is done when an ack for the rto
    // probe is received.
    return MOZQUIC_OK;
  }
  return MOZQUIC_ERR_GENERAL;
}

uint32_t
StreamState::ReportLossLessThan(uint64_t packetNumber)
{
  bool firstTime = true;
  for (auto packetIter = mUnAckedPackets.begin();
         (packetIter != mUnAckedPackets.end()) &&
         ((*packetIter)->mPacketNumber < packetNumber);
       packetIter = mUnAckedPackets.erase(packetIter)) {

    if (firstTime) {
      StreamLog4("ReportLossLessThan Packet Number %lX\n", packetNumber);
      firstTime = false;
    }

    mMozQuic->mSendState->ReportLoss((*packetIter)->mPacketNumber,
                                     (*packetIter)->mPacketLen);

    if ((*packetIter)->mFrameList.empty()) {
      continue;
    }
    uint32_t ctr = 0;
    for (auto frameIter = (*packetIter)->mFrameList.begin();
         frameIter != (*packetIter)->mFrameList.end(); frameIter++) {
      StreamLog4("data frame %u with packet %lX retransmitted type %d declared lost\n",
                 ctr++, (*packetIter)->mPacketNumber, (*frameIter)->mType);
      // move the data pointer from iter to tmp
      std::unique_ptr<ReliableData> tmp(new ReliableData(*(*frameIter)));
      assert(!(*frameIter)->mData);
      assert(tmp->mData);
      tmp->mFromRTO = false;
      // its ok to bypass the per out stream flow control window on rexmit
      ConnectionWrite(tmp);
    }
    (*packetIter)->mFrameList.clear();
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
  assert(IsBidiStream(chunk->mStreamID) || IsLocalStream(chunk->mStreamID) || !chunk->mOffset); // offset on a peer's uni stream must be 0.
  uint32_t used;
  framePtr[0] = FRAME_TYPE_RST_STREAM;
  framePtr++;
  if (MozQuic::EncodeVarint(chunk->mStreamID, framePtr, (endpkt - framePtr), used) != MOZQUIC_OK) {
    return MOZQUIC_ERR_GENERAL;
  }
  framePtr += used;
  if ((endpkt - framePtr) < 2) {
    return MOZQUIC_ERR_GENERAL;
  }
  uint tmp16 = htons(chunk->mRstCode);
  memcpy(framePtr, &tmp16, 2);
  framePtr += 2;
  if (MozQuic::EncodeVarint(chunk->mOffset, framePtr, (endpkt - framePtr), used) != MOZQUIC_OK) {
    return MOZQUIC_ERR_GENERAL;
  }
  framePtr += used;
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
  assert(IsBidiStream(chunk->mStreamID) || IsPeerStream(chunk->mStreamID)); // we should not send maxdata on a local uni stream.

  if (chunk->mStreamID) {
    auto i = mStreams.find(chunk->mStreamID);
    if (i == mStreams.end() ||
        (*i).second->mIn->mFinRecvd ||
        (*i).second->mIn->mRstRecvd ||
        (*i).second->mIn->mLocalMaxStreamData > chunk->mStreamCreditValue) {
      StreamLog5("not generating max stream data id=%d\n", chunk->mStreamID);
      return MOZQUIC_ERR_GENERAL;
    }
  }

  framePtr[0] = FRAME_TYPE_MAX_STREAM_DATA;
  framePtr++;

  uint32_t used;
  if (MozQuic::EncodeVarint(chunk->mStreamID, framePtr, (endpkt - framePtr), used) != MOZQUIC_OK) {
    return MOZQUIC_ERR_GENERAL;
  }
  framePtr += used;

  if (MozQuic::EncodeVarint(chunk->mStreamCreditValue, framePtr, (endpkt - framePtr), used) != MOZQUIC_OK) {
    return MOZQUIC_ERR_GENERAL;
  }
  framePtr += used;

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

  uint32_t used;
  framePtr[0] = FRAME_TYPE_MAX_STREAM_ID;
  framePtr++;
  if (MozQuic::EncodeVarint(chunk->mMaxStreamID, framePtr, (endpkt - framePtr), used) != MOZQUIC_OK) {
    return MOZQUIC_ERR_GENERAL;
  }
  framePtr += used;
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
  assert(IsBidiStream(chunk->mStreamID) || IsPeerStream(chunk->mStreamID)); // we should not send stopsending on a local uni stream.

  uint32_t used;
  framePtr[0] = FRAME_TYPE_STOP_SENDING;
  framePtr++;

  if (MozQuic::EncodeVarint(chunk->mStreamID, framePtr, (endpkt - framePtr), used) != MOZQUIC_OK) {
    return MOZQUIC_ERR_GENERAL;
  }
  framePtr += used;

  if ((endpkt - framePtr) < 2) {
    return MOZQUIC_ERR_GENERAL;
  }
  uint16_t tmp16 = htons(chunk->mStopSendingCode);
  memcpy(framePtr, &tmp16, 2);
  framePtr += 2;
  return MOZQUIC_OK;
}

uint32_t
StreamState::CreateMaxDataFrame(unsigned char *&framePtr, const unsigned char *endpkt,
                                ReliableData *chunk)
{
  StreamLog5("generating max data val=%ld into pkt=%lx\n",
             chunk->mConnectionCredit,
             mMozQuic->mNextTransmitPacketNumber);
  assert(chunk->mType == ReliableData::kMaxData);
  assert(chunk->mConnectionCredit);
  assert(!chunk->mLen);
  assert(!chunk->mStreamID);

  uint32_t used;
  framePtr[0] = FRAME_TYPE_MAX_DATA;
  framePtr++;
  if (MozQuic::EncodeVarint(chunk->mConnectionCredit, framePtr, (endpkt - framePtr), used) != MOZQUIC_OK) {
    StreamLog5("not generating max data val=%ld last sent val=%ld\n",
               chunk->mConnectionCredit, mLocalMaxData);
    return MOZQUIC_ERR_GENERAL;
  }
  framePtr += used;
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
  assert(IsBidiStream(chunk->mStreamID) || IsLocalStream(chunk->mStreamID)); // we should not send streamblocked on a peer's uni stream.

  uint32_t used;
  framePtr[0] = FRAME_TYPE_STREAM_BLOCKED;
  framePtr++;
  if (MozQuic::EncodeVarint(chunk->mStreamID, framePtr, (endpkt - framePtr), used) != MOZQUIC_OK) {
    return MOZQUIC_ERR_GENERAL;
  }
  framePtr += used;
  if (MozQuic::EncodeVarint(chunk->mOffset, framePtr, (endpkt - framePtr), used) != MOZQUIC_OK) {
    return MOZQUIC_ERR_GENERAL;
  }
  framePtr += used;
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

  uint32_t used;
  framePtr[0] = FRAME_TYPE_BLOCKED;
  framePtr++;
  if (MozQuic::EncodeVarint(chunk->mOffset, framePtr, (endpkt - framePtr), used) != MOZQUIC_OK) {
    return MOZQUIC_ERR_GENERAL;
  }
  framePtr += used;
  return MOZQUIC_OK;
}

uint32_t
StreamState::CreatePathResponseFrame(unsigned char *&framePtr, const unsigned char *endpkt,
                                ReliableData *chunk)
{
  StreamLog5("create path response %lx\n", chunk->mPathData);
  assert(chunk->mType == ReliableData::kPathResponse);
  assert(!chunk->mLen);

  framePtr[0] = FRAME_TYPE_PATH_RESPONSE;
  assert(FRAME_TYPE_PATH_RESPONSE_LENGTH == sizeof (chunk->mPathData) + 1);
  memcpy(framePtr + 1, &(chunk->mPathData), sizeof (chunk->mPathData));
  framePtr += FRAME_TYPE_PATH_RESPONSE_LENGTH;
  return MOZQUIC_OK;
}
        
uint32_t
StreamState::CreateStreamIDBlockedFrame(unsigned char *&framePtr, const unsigned char *endpkt,
                                        ReliableData *chunk, bool &toRemove)
{
  StreamLog2("generating streamID blocked into pkt=%lx\n",
             mMozQuic->mNextTransmitPacketNumber);
  assert(chunk->mType == ReliableData::kStreamIDBlocked);
  assert(!chunk->mLen);

  if (chunk->mMaxStreamID < mPeerMaxStreamID[GetStreamType(chunk->mMaxStreamID)]) {
    toRemove = true;
    return MOZQUIC_ERR_GENERAL;
  }

  uint32_t used;
  framePtr[0] = FRAME_TYPE_STREAM_ID_BLOCKED;
  framePtr++;

  if (MozQuic::EncodeVarint(chunk->mMaxStreamID, framePtr, (endpkt - framePtr), used) != MOZQUIC_OK) {
    return MOZQUIC_ERR_GENERAL;
  }
  framePtr += used;

  return MOZQUIC_OK;
}

StreamState::StreamState(MozQuic *q, uint64_t initialStreamWindow,
                         uint64_t initialConnectionWindow)
  : mMozQuic(q)
  , mPeerMaxStreamData(kMaxStreamDataDefault)
  , mLocalMaxStreamData(initialStreamWindow)
  , mPeerMaxData(kMaxDataDefault)
  , mMaxDataSent(0)
  , mMaxDataBlocked(false)
  , mLocalMaxData(initialConnectionWindow)
  , mLocalMaxDataUsed(0)
{
  mNextStreamID[0] = 1;
  mNextStreamID[1] = 1;
  mMaxStreamIDBlocked[0] = false;
  mMaxStreamIDBlocked[1] = false;
  mNextRecvStreamIDUsed[0] = 1;
  mNextRecvStreamIDUsed[1] = 1;
  mPeerMaxStreamID[0] = 0;
  mPeerMaxStreamID[1] = 0;
  mLocalMaxStreamID[0] = 0;
  mLocalMaxStreamID[1] = 0;
}

StreamPair::StreamPair(uint32_t id, MozQuic *m,
                       FlowController *flowController,
                       uint64_t peerMaxStreamData, uint64_t localMaxStreamData,
                       bool no_replay)
  : mStreamID(id)
  , mNoReplay(no_replay)
  , mMozQuic(m)
{
  if (IsBidiStream() || IsLocalStream()) {
    mOut.reset(new StreamOut(m, id, flowController, peerMaxStreamData));
  }

  if (IsBidiStream() || IsPeerStream()) {
    mIn.reset(new StreamIn(m, id, flowController, localMaxStreamData));
  }
}

bool
StreamPair::Done()
{
  if (IsBidiStream()) {
    return mOut->Done() && mIn->Done();
  } else if (IsLocalStream()) {
    return mOut->Done();
  } else {
    return mIn->Done();
  }
}

int
StreamPair::StopSending(uint16_t code)
{
  assert(IsBidiStream() || IsPeerStream());
  std::unique_ptr<ReliableData> tmp(new ReliableData(mStreamID, 0, nullptr, 0, 0));
  tmp->MakeStopSending(code);
  return mIn->ConnectionWrite(tmp);
}

uint32_t
StreamPair::Supply(std::unique_ptr<ReliableData> &p) {
  assert(IsBidiStream() || IsPeerStream());
  assert(p->mType != ReliableData::kRstStream);
  return mIn->Supply(p);
}

uint32_t
StreamPair::Write(const unsigned char *data, uint32_t len, bool fin)
{
  if (!mMozQuic->IsOpen()) {
    return MOZQUIC_ERR_IO;
  }
  if (!mOut) {
    assert(IsRecvOnlyStream());
    return MOZQUIC_ERR_IO;
  }
  return mOut->Write(data, len, fin);
}

uint32_t
StreamPair::Read(unsigned char *buffer, uint32_t avail, uint32_t &amt, bool &fin)
{
  if (!mIn) {
    assert(IsSendOnlyStream());
    return MOZQUIC_ERR_IO;
  }
  return mIn->Read(buffer, avail, amt, fin);
}

bool
StreamPair::Empty()
{
  if (!mIn) {
    assert(IsSendOnlyStream());
    return true;
  }

  return mIn->Empty();
}

int
StreamPair::RstStream(uint16_t code)
{
  if (mOut) {
    return mOut->RstStream(code);
  }

  std::unique_ptr<ReliableData> tmp(new ReliableData(mStreamID, 0, nullptr, 0, 0));
  tmp->MakeRstStream(code);
  return mIn->ConnectionWrite(tmp);
}

int
StreamPair::EndStream()
{
  if (!mOut) {
    assert(IsRecvOnlyStream());
    return MOZQUIC_ERR_IO;
  }
  return mOut->EndStream();
}

uint32_t
StreamPair::NewFlowControlLimit(uint64_t limit) {
  if (!mOut) {
    assert(IsRecvOnlyStream());
    return MOZQUIC_ERR_IO;
  }
  mOut->NewFlowControlLimit(limit);
  return MOZQUIC_OK;
}

void
StreamPair::ChangeStreamID(uint32_t newStreamID)
{
  assert (mOut); // must be a local stream. This is only called on the client after 0rtt data is rejected.
  mStreamID = newStreamID;
  mOut->ChangeStreamID(newStreamID);
  if (mIn) {
    mIn->ChangeStreamID(newStreamID);
  }
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
  return mIn->ResetInbound();
}

uint32_t
StreamIn::ResetInbound()
{
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
  bool signalReadyToWrite = (mStreamUnWritten.empty() && !mBlocked) ? true : false;

  mStreamUnWritten.push_back(std::move(p));

  if (signalReadyToWrite) {
    mWriter->SignalReadyToWrite(this);
  }

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
StreamOut::RstStream(uint16_t code)
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

void
StreamOut::ChangeStreamID(uint32_t newStreamID)
{
  mStreamID = newStreamID;
  for(auto i = mStreamUnWritten.begin(); i != mStreamUnWritten.end(); i++) {
    (*i)->mStreamID = newStreamID;
  }
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
  , mFromRTO(false)
  , mSendUnblocked(false)
  , mQueueOnTransmit(false)
  , mRstCode(0)
  , mStreamCreditValue(0)
  , mConnectionCredit(0)
  , mTransmitKeyPhase(keyPhaseUnknown)
  , mCloned(false)
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
  , mFromRTO(false)
  , mSendUnblocked(false)
  , mQueueOnTransmit(false)
  , mRstCode(orig.mRstCode)
  , mStopSendingCode (orig.mStopSendingCode)
  , mStreamCreditValue(orig.mStreamCreditValue)
  , mConnectionCredit(orig.mConnectionCredit)
  , mMaxStreamID(orig.mMaxStreamID)
  , mPathData(orig.mPathData)
  , mTransmitKeyPhase(keyPhaseUnknown)
  , mCloned(true)
{
  mData = std::move(orig.mData);
}

ReliableData::~ReliableData()
{
}

} // namespace

