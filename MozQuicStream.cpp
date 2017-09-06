/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "MozQuic.h"
#include "MozQuicInternal.h"
#include "MozQuicStream.h"

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

namespace mozquic {

MozQuicStreamPair::MozQuicStreamPair(uint32_t id, MozQuic *m,
                                     FlowController *flowController,
                                     uint64_t peerMaxStreamData, uint64_t localMaxStreamData)
  : mStreamID(id)
  , mOut(id, flowController, peerMaxStreamData)
  , mIn(id, flowController, localMaxStreamData)
  , mMozQuic(m)
{
}

MozQuicStreamPair::~MozQuicStreamPair()
{
}

bool
MozQuicStreamPair::Done()
{
  return mOut.Done() && mIn.Done();
}

uint32_t
MozQuicStreamPair::Supply(std::unique_ptr<ReliableData> &p) {
  if (p->mType == ReliableData::kStreamRst) {
    if (!mOut.Done() && !mIn.Done()) {
      RstStream(MozQuic::ERROR_NO_ERROR);
    }
    mOut.mPeerRst = true;
    mOut.ScrubUnWritten(p->mStreamID);
  }
  return mIn.Supply(p);
}

uint32_t
MozQuicStreamPair::Write(const unsigned char *data, uint32_t len, bool fin)
{
  if (!mMozQuic->IsOpen()) {
    return MOZQUIC_ERR_IO;
  }
  return mOut.Write(data, len, fin);
}

MozQuicStreamIn::MozQuicStreamIn(uint32_t id,
                                 FlowController *flowcontroller, uint64_t localMaxStreamData)
  : mStreamID(id)
  , mOffset(0)
  , mFinOffset(0)
  , mLocalMaxStreamData(localMaxStreamData)
  , mNextStreamDataExpected(0)
  , mFlowController(flowcontroller)
  , mFinRecvd(false)
  , mRstRecvd(false)
  , mEndGivenToApp(false)
{
}

MozQuicStreamIn::~MozQuicStreamIn()
{
}

uint32_t
MozQuicStreamPair::ResetInbound()
{
  // this is used in a very peculiar circumstance after HRR on stream 0 only
  assert(mStreamID == 0);
  return mIn.ResetInbound();
}

uint32_t
MozQuicStreamIn::ResetInbound()
{
  assert(Empty());
  mOffset = 0;
  mFinOffset = 0;
  mFinRecvd = false;
  mRstRecvd = false;
  mEndGivenToApp = false;
  return MOZQUIC_OK;
}

// returning amt = 0 is not a fin or an error on its own
uint32_t
MozQuicStreamIn::Read(unsigned char *buffer, uint32_t avail, uint32_t &amt, bool &fin)
{
  amt = 0;
  fin = false;
  if (mFinRecvd && mFinOffset == mOffset) {
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
  if (mFinRecvd && mFinOffset == mOffset) {
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

uint32_t
MozQuicStreamIn::Supply(std::unique_ptr<ReliableData> &d)
{
  // new frame segment goes into a linked list ordered by seqno
  // any overlapping data is dropped

  if (mRstRecvd) {
    d.reset(); // drop it
    return MOZQUIC_OK;
  }

  if (d->mType == ReliableData::kStreamRst && !mFinRecvd) {
    mFinRecvd = true;
    mRstRecvd = true;
    assert(d->mLen == 0);
    mFinOffset = d->mOffset;
  }

  if (d->mFin && !mFinRecvd) {
    mFinRecvd = true;
    mFinOffset = d->mOffset + d->mLen;
  }

  uint64_t endData = d->mOffset + d->mLen;
  if (endData <= mOffset) {
    // this is 100% old data. we can drop it
    d.reset();
    return MOZQUIC_OK;
  }
  
  if (endData > mNextStreamDataExpected) {
    mNextStreamDataExpected = endData;
    // todo - credit scheme should be based on how much is queued here.
    // todo - autotuning
    uint64_t available = mLocalMaxStreamData - endData;
    uint32_t increment = mFlowController->GetIncrement();
    fprintf(stderr,"peer has %ld flow control credits available on stream %d\n",
            available, mStreamID);

    if ((available < 32 * 1024) ||
        (available < (increment / 2))) {
      if (mLocalMaxStreamData > (0xffffffffffffffffULL - increment)) {
        return MOZQUIC_ERR_IO;
      }
      mLocalMaxStreamData += increment;
      if (mFlowController->IssueStreamCredit(mStreamID, mLocalMaxStreamData) != MOZQUIC_OK) {
        mLocalMaxStreamData -= increment;
      }
    }
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
MozQuicStreamIn::Empty()
{
  if (mRstRecvd) {
    return false;
  }

  if (mFinRecvd && mFinOffset == mOffset) {
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

MozQuicStreamOut::MozQuicStreamOut(uint32_t id, FlowController *fc,
                                   uint64_t flowControlLimit)
  : mWriter(fc)
  , mStreamID(id)
  , mOffset(0)
  , mFlowControlLimit(flowControlLimit)
  , mFin(false)
  , mPeerRst(false)
{
}

MozQuicStreamOut::~MozQuicStreamOut()
{
}

uint32_t
MozQuicStreamOut::StreamWrite(std::unique_ptr<ReliableData> &p)
{
  mStreamUnWritten.push_back(std::move(p));

  return MOZQUIC_OK;
}


uint32_t
MozQuicStreamOut::Write(const unsigned char *data, uint32_t len, bool fin)
{
  if (mPeerRst) {
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
MozQuicStreamOut::EndStream()
{
  if (mFin) {
    return MOZQUIC_ERR_ALREADY_FINISHED;
  }
  mFin = true;

  std::unique_ptr<ReliableData> tmp(new ReliableData(mStreamID, mOffset, nullptr, 0, true));
  return StreamWrite(tmp);
}

int
MozQuicStreamOut::RstStream(uint32_t code)
{
  if (mFin) {
    return MOZQUIC_ERR_ALREADY_FINISHED;
  }
  mFin = true;

  // empty local queue before sending rst
  mStreamUnWritten.clear();
  std::unique_ptr<ReliableData> tmp(new ReliableData(mStreamID, mOffset, nullptr, 0, 0));
  tmp->MakeStreamRst(code);
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
