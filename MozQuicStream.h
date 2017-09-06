/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <list>
#include <stdint.h>
#include <unistd.h>
#include <memory>

namespace mozquic {

class ReliableData
{
public:
  ReliableData(uint32_t id, uint64_t offset, const unsigned char *data,
               uint32_t len, bool fin);

  // This form of ctor steals the data pointer. used for retransmit
  ReliableData(ReliableData &);
  ~ReliableData();

  void MakeStreamRst(uint32_t code) { mType = kStreamRst; mRstCode = code;}
  void MakeMaxStreamData(uint64_t offset) { mType = kMaxStreamData; mStreamCreditValue = offset;}
  void MakeStreamBlocked() { mType = kStreamBlocked; }

  enum 
  {
    kStream, kStreamRst, kMaxStreamData, kStreamBlocked,
  } mType;
  
  std::unique_ptr<const unsigned char []>mData;
  uint32_t mLen;
  uint32_t mStreamID;
  uint64_t mOffset;
  bool     mFin;

  uint32_t mRstCode; // for kStreamRst

  uint64_t mStreamCreditValue; // forkMaxStreamData
  
  // when unacked these are set
  uint64_t mPacketNumber;
  uint64_t mTransmitTime; // todo.. hmm if this gets queued for any cc/fc reason (same for ack)
  uint16_t mTransmitCount;
  bool     mRetransmitted; // no data after retransmitted
  enum keyPhase mTransmitKeyPhase;
};

class FlowController
{
public:
  // the caller owns the unique_ptr if it returns 0
  virtual uint32_t ConnectionWrite(std::unique_ptr<ReliableData> &p) = 0;
  virtual uint32_t ScrubUnWritten(uint32_t id) = 0;
  virtual uint32_t GetIncrement() = 0;
  virtual uint32_t IssueStreamCredit(uint32_t streamID, uint64_t newMax) = 0;
};

class MozQuicStreamOut
{
  friend class StreamState;
public:
  MozQuicStreamOut(uint32_t id, FlowController *f, uint64_t limit);
  ~MozQuicStreamOut();
  uint32_t Write(const unsigned char *data, uint32_t len, bool fin);
  int EndStream();
  int RstStream(uint32_t code);
  bool Done() { return mFin || mPeerRst; }
  uint32_t ScrubUnWritten(uint32_t id) { return mWriter->ScrubUnWritten(id); }
  void NewFlowControlLimit(uint64_t limit) {
    mFlowControlLimit = limit;
  }

private:
  uint32_t StreamWrite(std::unique_ptr<ReliableData> &p);
  
  FlowController *mWriter;
  std::list<std::unique_ptr<ReliableData>> mStreamUnWritten;
  uint32_t mStreamID;
  uint64_t mOffset;
  uint64_t mFlowControlLimit;
  bool mFin;
  bool mBlocked;
public:
  bool mPeerRst;
};

class MozQuicStreamIn
{
public:
  MozQuicStreamIn(uint32_t id, FlowController *flowController, uint64_t localMSD);
  ~MozQuicStreamIn();
  uint32_t Read(unsigned char *buffer, uint32_t avail, uint32_t &amt, bool &fin);
  uint32_t Supply(std::unique_ptr<ReliableData> &p);
  bool     Empty();

  bool Done() {
    return mEndGivenToApp;
  }
  uint32_t ResetInbound();

private:
  uint32_t mStreamID;
  uint64_t mOffset;
  uint64_t mFinOffset;

  uint64_t mLocalMaxStreamData; // highest flow control we have sent to peer
  uint64_t mNextStreamDataExpected;

  FlowController *mFlowController;

  bool     mFinRecvd;
  bool     mRstRecvd;
  bool     mEndGivenToApp;

  std::list<std::unique_ptr<ReliableData>> mAvailable;
};

class MozQuic;

class MozQuicStreamPair
{
public:
  MozQuicStreamPair(uint32_t id, MozQuic *, FlowController *,
                    uint64_t peerMSD, uint64_t localMSD);
  ~MozQuicStreamPair();

  // Supply places data on the input (i.e. read()) queue
  uint32_t Supply(std::unique_ptr<ReliableData> &p);

  // todo it would be nice to have a zero copy interface
  uint32_t Read(unsigned char *buffer, uint32_t avail, uint32_t &amt, bool &fin) {
    return mIn.Read(buffer, avail, amt, fin);
  }

  bool Empty() {
    return mIn.Empty();
  }

  uint32_t ResetInbound();

  void NewFlowControlLimit(uint64_t limit) {
    mOut.NewFlowControlLimit(limit);
  }

  uint32_t Write(const unsigned char *data, uint32_t len, bool fin);

  int EndStream() {
    return mOut.EndStream();
  }

  int RstStream(uint32_t code) {
    return mOut.RstStream(code);
  }

  bool Done(); // All data and fin bit given to an application and all data are transmitted and acked.
               // todo(or stream has been reseted)
               // the stream can be removed from the stream list.

  uint32_t mStreamID;
  MozQuicStreamOut mOut;
  MozQuicStreamIn  mIn;
  MozQuic *mMozQuic;
};

} //namespace
