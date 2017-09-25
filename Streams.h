/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <map>

namespace mozquic  {

enum  {
  kMaxStreamIDDefault   = 1024,
  kMaxStreamDataDefault = 10 * 1024 * 1024,
  kMaxDataDefault       = 50 * 1024 * 1024,
  kRetransmitThresh     = 500,
  kForgetUnAckedThresh  = 4000, // ms
};

class StreamAck
{
public:
  StreamAck(uint64_t num, uint64_t rtime, enum keyPhase kp)
    : mPacketNumber(num)
    , mExtra(0)
    , mPhase (kp)
    , mTimestampTransmitted(false)
  {
    mReceiveTime.push_front(rtime);
  }

  // num=10, mExtra=3 means we are acking 10, 9, 8, 7
  // and ReceiveTime applies to 10
  uint64_t mPacketNumber; // being ACKd
  uint64_t mExtra;
  std::list<uint64_t> mReceiveTime;
  enum keyPhase mPhase;
  bool mTimestampTransmitted;

  // pair.first is packet number of transmitted ack
  // pair.second is transmission time
  std::vector<std::pair<uint64_t, uint64_t>> mTransmits;

  bool Transmitted() { return !mTransmits.empty(); }
};

class FlowController
{
public:
  // the caller owns the unique_ptr if it returns 0
  virtual uint32_t ConnectionWrite(std::unique_ptr<ReliableData> &p) = 0;
  virtual uint32_t ScrubUnWritten(uint32_t id) = 0;
  virtual uint32_t GetIncrement() = 0;
  virtual uint32_t IssueStreamCredit(uint32_t streamID, uint64_t newMax) = 0;
  virtual uint32_t ConnectionReadBytes(uint64_t amt) = 0;
};

class StreamOut
{
  friend class StreamState;
public:
  StreamOut(MozQuic *m, uint32_t id, FlowController *f, uint64_t limit);
  ~StreamOut();
  uint32_t Write(const unsigned char *data, uint32_t len, bool fin);
  int EndStream();
  int RstStream(uint32_t code);
  bool Done() { return mFin && mStreamUnWritten.empty(); }
  uint32_t ScrubUnWritten() { mStreamUnWritten.clear(); return mWriter->ScrubUnWritten(mStreamID); }
  void NewFlowControlLimit(uint64_t limit) {
    mFlowControlLimit = limit;
  }
  uint32_t ConnectionWrite(std::unique_ptr<ReliableData> &p) {
    return mWriter->ConnectionWrite(p);
  }

private:
  uint32_t StreamWrite(std::unique_ptr<ReliableData> &p);
  
  FlowController *mWriter;
  std::list<std::unique_ptr<ReliableData>> mStreamUnWritten;
  uint32_t mStreamID;
  uint64_t mOffset;
  uint64_t mFlowControlLimit;
  uint64_t mOffsetChargedToConnFlowControl;

  bool mFin;
  bool mRst;
  bool mBlocked; // blocked on stream based flow control
};

class StreamState : public FlowController
{
  friend class MozQuic;
public:
  StreamState(MozQuic *, uint64_t initialStreamWindow,
                         uint64_t initialConnectionWindow);

  // FlowController Methods
  uint32_t ConnectionWrite(std::unique_ptr<ReliableData> &p) override;
  uint32_t ScrubUnWritten(uint32_t id) override;
  uint32_t GetIncrement() override;
  uint32_t IssueStreamCredit(uint32_t streamID, uint64_t newMax) override;
  uint32_t ConnectionReadBytes(uint64_t amt) override;
  
  uint32_t StartNewStream(StreamPair **outStream, const void *data, uint32_t amount, bool fin);
  uint32_t FindStream(uint32_t streamID, std::unique_ptr<ReliableData> &d);
  uint32_t RetransmitTimer();
  bool     MaybeDeleteStream(uint32_t streamID);
  uint32_t RstStream(uint32_t streamID, uint32_t code);

  uint32_t Flush(bool forceAck);
  uint32_t HandleStreamFrame(FrameHeaderData *result, bool fromCleartext,
                             const unsigned char *pkt, const unsigned char *endpkt,
                             uint32_t &_ptr);
  uint32_t HandleResetStreamFrame(FrameHeaderData *result, bool fromCleartext,
                                  const unsigned char *pkt, const unsigned char *endpkt,
                                  uint32_t &_ptr);
  uint32_t HandleMaxStreamDataFrame(FrameHeaderData *result, bool fromCleartext,
                                    const unsigned char *pkt, const unsigned char *endpkt,
                                    uint32_t &_ptr);
  uint32_t HandleMaxDataFrame(FrameHeaderData *result, bool fromCleartext,
                              const unsigned char *pkt, const unsigned char *endpkt,
                              uint32_t &_ptr);
  uint32_t HandleMaxStreamIDFrame(FrameHeaderData *result, bool fromCleartext,
                              const unsigned char *pkt, const unsigned char *endpkt,
                              uint32_t &_ptr);
  uint32_t HandleStreamBlockedFrame(FrameHeaderData *result, bool fromCleartext,
                                    const unsigned char *pkt, const unsigned char *endpkt,
                                    uint32_t &_ptr);
  uint32_t HandleBlockedFrame(FrameHeaderData *result, bool fromCleartext,
                              const unsigned char *pkt, const unsigned char *endpkt,
                              uint32_t &_ptr);
  uint32_t HandleStreamIDBlockedFrame(FrameHeaderData *result, bool fromCleartext,
                                      const unsigned char *pkt, const unsigned char *endpkt,
                                      uint32_t &_ptr);
  uint32_t HandleStopSendingFrame(FrameHeaderData *result, bool fromCleartext,
                                  const unsigned char *pkt, const unsigned char *endpkt,
                                  uint32_t &_ptr);
  uint32_t CreateStreamFrames(unsigned char *&framePtr, const unsigned char *endpkt,
                              bool justZero);
  uint32_t CreateRstStreamFrame(unsigned char *&framePtr, const unsigned char *endpkt,
                                ReliableData *chunk);
  uint32_t CreateStopSendingFrame(unsigned char *&framePtr, const unsigned char *endpkt,
                                  ReliableData *chunk);
  uint32_t CreateMaxStreamDataFrame(unsigned char *&framePtr, const unsigned char *endpkt,
                                    ReliableData *chunk);
  uint32_t CreateMaxDataFrame(unsigned char *&framePtr, const unsigned char *endpkt,
                              ReliableData *chunk);
  uint32_t CreateMaxStreamIDFrame(unsigned char *&framePtr, const unsigned char *endpkt,
                                  ReliableData *chunk);
  uint32_t CreateStreamBlockedFrame(unsigned char *&framePtr, const unsigned char *endpkt,
                                    ReliableData *chunk);
  uint32_t CreateBlockedFrame(unsigned char *&framePtr, const unsigned char *endpkt,
                              ReliableData *chunk);
  uint32_t CreateStreamIDBlockedFrame(unsigned char *&framePtr, const unsigned char *endpkt,
                                      ReliableData *chunk);

  void InitIDs(uint32_t next, uint32_t nextR) { mNextStreamID = next; mNextRecvStreamIDUsed = nextR; }
  void MaybeIssueFlowControlCredit();

private:
  uint32_t FlowControlPromotion();
  uint32_t FlowControlPromotionForStreamPair(StreamPair *);
  uint64_t CalculateConnectionCharge(ReliableData *data, StreamOut *out);
  
  MozQuic *mMozQuic;
  uint32_t mNextStreamID;

private: // these still need friend mozquic
  uint32_t mPeerMaxStreamData;  // max offset we can send from transport params on new stream
  uint32_t mLocalMaxStreamData; // max offset peer can send on new stream

  // I'm sorry if you cannot compile __uint128_t - a c++ class can surely fix it
  __uint128_t mPeerMaxData; // conn limit set by other side
  __uint128_t mMaxDataSent; // sending bytes charged againts mPeerMaxData
  bool        mMaxDataBlocked; // blocked from sending by connectionFlowControl

  __uint128_t mLocalMaxData; // conn credit announced to peer
  __uint128_t mLocalMaxDataUsed; // conn credit consumed by peer

  uint32_t mPeerMaxStreamID;  // id limit set by peer
  uint32_t mLocalMaxStreamID; // id limit sent to peer
  bool     mMaxStreamIDBlocked; // blocked from creating by streamID limits
  uint32_t mNextRecvStreamIDUsed; //  id consumed by peer

  std::unique_ptr<StreamPair> mStream0;

  // when issue #48 is resolved, this can become an unordered map
  std::map<uint32_t, std::shared_ptr<StreamPair>> mStreams;

  // retransmit happens off of mUnAckedData by
  // duplicating it and placing it in mConnUnWritten. The
  // dup'd entry is marked retransmitted so it doesn't repeat that. After a
  // certain amount of time the retransmitted packet is just forgotten (as
  // it won't be retransmitted again - that happens to the dup'd
  // incarnation)
  // mUnackedData is sorted by the packet number it was sent in.
  std::list<std::unique_ptr<ReliableData>> mConnUnWritten;
  std::list<std::unique_ptr<ReliableData>> mUnAckedData;

  // macklist is the current state of all unacked acks - maybe written out,
  // maybe not. ordered with the highest packet ack'd at front.Each time
  // the whole set needs to be written out. each entry in acklist contains
  // a vector of pairs (transmitTime, transmitID) representing each time it
  // is written. Upon receipt of an ack we need to find transmitID and
  // remove the entry from the acklist. TODO index by transmitID, but for
  // now iterate from rear (oldest data being acknowledged).
  //
  // acks ordered {1,2,5,6,7} as 7/2, 2/1 (biggest at head)
  std::list<StreamAck>                    mAckList;
};

class ReliableData
{
public:
  ReliableData(uint32_t id, uint64_t offset, const unsigned char *data,
               uint32_t len, bool fin);

  // This form of ctor steals the data pointer. used for retransmit
  ReliableData(ReliableData &);
  ~ReliableData();

  void MakeRstStream(uint32_t code) { mType = kRstStream; mRstCode = code;}
  void MakeStopSending(uint32_t code) { mType = kStopSending; mStopSendingCode = code;}
  void MakeMaxStreamData(uint64_t offset) { mType = kMaxStreamData; mStreamCreditValue = offset;}
  void MakeMaxData(uint64_t kb) { mType = kMaxData; mConnectionCreditKB = kb;}
  void MakeMaxStreamID(uint32_t maxID) {mType = kMaxStreamID; mMaxStreamID = maxID; }
  void MakeStreamBlocked() { mType = kStreamBlocked; }
  void MakeBlocked() { mType = kBlocked; }
  void MakeStreamIDBlocked() { mType = kStreamIDBlocked; }

  enum 
  {
    kStream, kRstStream, kMaxStreamData, kStreamBlocked, kMaxData, kBlocked,
    kStreamIDBlocked, kMaxStreamID, kStopSending
  } mType;
  
  std::unique_ptr<const unsigned char []>mData;
  uint32_t mLen;
  uint32_t mStreamID;
  uint64_t mOffset;
  bool     mFin;

  uint32_t mRstCode; // for kRstStream
  uint32_t mStopSendingCode;
  uint64_t mStreamCreditValue; // for kMaxStreamData
  uint64_t mConnectionCreditKB; // for kMaxData 
  uint32_t mMaxStreamID; // for kMaxStreamID
  
  // when unacked these are set
  uint64_t mPacketNumber;
  uint64_t mTransmitTime; // todo.. hmm if this gets queued for any cc/fc reason (same for ack)
  uint16_t mTransmitCount;
  bool     mRetransmitted; // no data after retransmitted
  enum keyPhase mTransmitKeyPhase;
};

class StreamIn
{
  friend class StreamState;
public:
  StreamIn(MozQuic *m, uint32_t id, FlowController *flowController, uint64_t localMSD);
  ~StreamIn();
  uint32_t Read(unsigned char *buffer, uint32_t avail, uint32_t &amt, bool &fin);
  uint32_t Supply(std::unique_ptr<ReliableData> &p);
  void MaybeIssueFlowControlCredit();
  bool     Empty();

  bool Done() {
    return mEndGivenToApp;
  }
  uint32_t ResetInbound(); // reset as in start over for hrr, not stream reset
  uint32_t HandleResetStream(uint64_t finalOffset);
  uint32_t ScrubUnRead() { mAvailable.clear(); return MOZQUIC_OK; }

private:
  MozQuic *mMozQuic;
  uint32_t mStreamID;
  uint64_t mOffset;
  uint64_t mFinalOffset;

  uint64_t mLocalMaxStreamData; // highest flow control we have sent to peer
  uint64_t mNextStreamDataExpected;

  FlowController *mFlowController;

  bool     mFinRecvd;
  bool     mRstRecvd;
  bool     mEndGivenToApp;

  std::list<std::unique_ptr<ReliableData>> mAvailable;
};

class StreamPair
{
public:
  StreamPair(uint32_t id, MozQuic *, FlowController *,
                    uint64_t peerMSD, uint64_t localMSD);
  ~StreamPair() {};

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

  int StopSending(uint32_t code);
  
  bool Done(); // All data and fin bit given to an application and all data are transmitted and acked.
               // todo(or stream has been reseted)
               // the stream can be removed from the stream list.

  uint32_t mStreamID;
  StreamOut mOut;
  StreamIn  mIn;
  MozQuic *mMozQuic;
};

}

  
