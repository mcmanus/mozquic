/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <map>

namespace mozquic  {

enum  {
  kMaxStreamIDServerDefaultBidi   = 1024 + 1,
  kMaxStreamIDServerDefaultUni    = 1024 + 3,
  kMaxStreamIDClientDefaultBidi   = 1024 + 4,
  kMaxStreamIDClientDefaultUni    = 1024 + 2,
  kMaxStreamDataDefault           = 10 * 1024 * 1024,
  kMaxDataDefault                 = 50 * 1024 * 1024,
};

enum StreamType{
  BIDI_STREAM = 0,
  UNI_STREAM = 1
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

class StreamOut;
class TransmittedPacket;

class FlowController
{
public:
  // the caller owns the unique_ptr if it returns 0
  virtual uint32_t ConnectionWrite(std::unique_ptr<ReliableData> &p) = 0;
  virtual uint32_t ScrubUnWritten(uint32_t id) = 0;
  virtual void Reset0RTTData() = 0;
  virtual uint32_t GetIncrement() = 0;
  virtual uint32_t IssueStreamCredit(uint32_t streamID, uint64_t newMax) = 0;
  virtual uint32_t ConnectionReadBytes(uint64_t amt) = 0;
  virtual void     SignalReadyToWrite(StreamOut *streamOut) = 0;
};

class StreamOut
{
  friend class StreamState;
public:
  StreamOut(MozQuic *m, uint32_t id, FlowController *f, uint64_t limit);
  ~StreamOut();
  uint32_t Write(const unsigned char *data, uint32_t len, bool fin);
  int EndStream();
  int RstStream(uint16_t code);
  bool Done() { return mFin && mStreamUnWritten.empty(); }
  uint32_t ScrubUnWritten() { mStreamUnWritten.clear(); return mWriter->ScrubUnWritten(mStreamID); }
  void NewFlowControlLimit(uint64_t limit) {
    mFlowControlLimit = limit;
  }
  uint32_t ConnectionWrite(std::unique_ptr<ReliableData> &p) {
    return mWriter->ConnectionWrite(p);
  }

  void ChangeStreamID(uint32_t newStreamID);

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
  virtual ~StreamState() {}

  // FlowController Methods
  uint32_t ConnectionWrite(std::unique_ptr<ReliableData> &p) override;
  uint32_t ConnectionWriteNow(std::unique_ptr<ReliableData> &p);
  uint32_t ScrubUnWritten(uint32_t id) override;
  void Reset0RTTData() override;
  uint32_t GetIncrement() override;
  uint32_t IssueStreamCredit(uint32_t streamID, uint64_t newMax) override;
  uint32_t ConnectionReadBytes(uint64_t amt) override;
  void     SignalReadyToWrite(StreamOut *out) override;
  
  uint32_t StartNewStream(StreamPair **outStream, StreamType streamType, bool no_replay, const void *data, uint32_t amount, bool fin);
  uint32_t MakeSureStreamCreated(uint32_t streamID);
  uint32_t FindStream(uint32_t streamID, std::unique_ptr<ReliableData> &d);
  uint32_t RetransmitOldestUnackedData(bool fromRTO);
  uint32_t ReportLossLessThan(uint64_t packetNumber);
  bool     AnyUnackedPackets();
  void     DeleteDoneStreams();
  bool     MaybeDeleteStream(uint32_t streamID);
  uint32_t RstStream(uint32_t streamID, uint16_t code);

  uint32_t FlushOnce(bool forceAck, bool forceFrame, bool &outDidWrite);
  uint32_t Flush(bool forceAck);
  void     TrackPacket(uint64_t packetNumber, uint32_t packetSize);
  uint32_t GeneratePathResponse(uint64_t data);
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
  uint32_t CreateFrames(unsigned char *&framePtr, const unsigned char *endpkt,
                        bool justZero, TransmittedPacket *);
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
  uint32_t CreatePathResponseFrame(unsigned char *&framePtr, const unsigned char *endpkt,
                                   ReliableData *chunk);
  uint32_t CreateStreamIDBlockedFrame(unsigned char *&framePtr, const unsigned char *endpkt,
                                      ReliableData *chunk, bool &toRemove);

  void InitIDs(uint32_t nextBidi, uint32_t nextUni, uint32_t nextRBidi, uint32_t nextRUni,
               uint32_t maxStreamIDBidi, uint32_t maxStreamIDUni) {
    mNextStreamID[0] = nextBidi;
    mNextStreamID[1] = nextUni;
    mNextRecvStreamIDUsed[0] = nextRBidi;
    mNextRecvStreamIDUsed[1] = nextRUni;
    mLocalMaxStreamID[0] = maxStreamIDBidi;
    mLocalMaxStreamID[1] = maxStreamIDUni;
  }
  void MaybeIssueFlowControlCredit();
  bool IsAllAcked();

private:
  uint32_t FlowControlPromotion();
  uint32_t FlowControlPromotionForStreamPair(StreamOut *);
  uint64_t CalculateConnectionCharge(ReliableData *data, StreamOut *out);

  StreamType GetStreamType(uint32_t streamID) { return (streamID & 0x2) ? UNI_STREAM : BIDI_STREAM; }
  bool IsBidiStream(uint32_t streamID) { return (streamID & 0x2) ? false : true; }
  bool IsUniStream(uint32_t streamID) { return (streamID & 0x2) ? true : false; }
  bool IsLocalStream(uint32_t streamID) { return (!(streamID & 1) && mMozQuic->mIsClient) || // even and you're the client
                                         ((streamID & 1) && !mMozQuic->mIsClient); } // odd and you're the server
  bool IsPeerStream(uint32_t streamID) {return (!(streamID & 1) && !mMozQuic->mIsClient) ||  // even and you're the server
                                        ((streamID & 1) && mMozQuic->mIsClient); }    // odd and you're the client
  bool IsSendOnlyStream(uint32_t streamID) { return IsUniStream(streamID) && IsLocalStream(streamID); }
  bool IsRecvOnlyStream(uint32_t streamID) { return IsUniStream(streamID) && IsPeerStream(streamID); }

  MozQuic *mMozQuic;
  uint32_t mNextStreamID[2]; // [0]->bidirectional [1]->unidirectional

private: // these still need friend mozquic
  uint32_t mPeerMaxStreamData;  // max offset we can send from transport params on new stream
  uint32_t mLocalMaxStreamData; // max offset peer can send on new stream

  uint64_t mPeerMaxData; // conn limit set by other
  uint64_t mMaxDataSent; // sending bytes charged againts mPeerMaxData
  bool        mMaxDataBlocked; // blocked from sending by connectionFlowControl

  uint64_t mLocalMaxData; // conn credit announced to peer
  uint64_t mLocalMaxDataUsed; // conn credit consumed by peer

  uint32_t mPeerMaxStreamID[2];  // id limit set by peer [0]->bidirectional [1]->unidirectional
  uint32_t mLocalMaxStreamID[2]; // id limit sent to peer [0]->bidirectional [1]->unidirectional
  bool     mMaxStreamIDBlocked[2]; // blocked from creating by streamID limits [0]->bidirectional [1]->unidirectional
  uint32_t mNextRecvStreamIDUsed[2]; //  id consumed by peer [0]->bidirectional [1]->unidirectional

  std::unique_ptr<StreamPair> mStream0;

  // when issue #48 is resolved, this can become an unordered map
  std::map<uint32_t, std::shared_ptr<StreamPair>> mStreams;

  // This is a list of streams that are ready to write data but are blocked by
  // the connection flow control.
  std::list<uint32_t> mStreamsReadyToWrite;

  // retransmit happens off of the FrameList in mUnAckedPackets
  // duplicating it and placing it in mConnUnWritten.
  // mUnackedPackets is sorted by the packet number it was sent in.
  std::list<std::unique_ptr<ReliableData>> mConnUnWritten;
  std::list<std::unique_ptr<TransmittedPacket>> mUnAckedPackets;

  // macklist is the current state of all unacked acks - maybe written out,
  // maybe not. ordered with the highest packet ack'd at front. Each time
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
  // this more or less corresponds to a reliable frame
public:
  ReliableData(uint32_t id, uint64_t offset, const unsigned char *data,
               uint32_t len, bool fin);

  // This form of ctor steals the data pointer. used for retransmit
  ReliableData(ReliableData &);
  ~ReliableData();

  void MakeRstStream(uint16_t code) { mType = kRstStream; mRstCode = code;}
  void MakeStopSending(uint16_t code) { mType = kStopSending; mStopSendingCode = code;}
  void MakeMaxStreamData(uint64_t offset) { mType = kMaxStreamData; mStreamCreditValue = offset;}
  void MakeMaxData(uint64_t bytes) { mType = kMaxData; mConnectionCredit = bytes;}
  void MakeMaxStreamID(uint32_t maxID) {mType = kMaxStreamID; mMaxStreamID = maxID; }
  void MakeStreamBlocked(uint64_t offset) { mType = kStreamBlocked; mOffset = offset;}
  void MakeBlocked(uint64_t offset) { mType = kBlocked; mOffset = offset;}
  void MakeStreamIDBlocked(uint32_t maxID) { mType = kStreamIDBlocked; mMaxStreamID = maxID; }
  void MakePathResponse(uint64_t data) { mType = kPathResponse; mPathData = data; }

  enum 
  {
    kStream, kRstStream, kMaxStreamData, kStreamBlocked, kMaxData, kBlocked,
    kStreamIDBlocked, kMaxStreamID, kStopSending, kPathResponse
  } mType;
  
  std::unique_ptr<const unsigned char []>mData;
  uint32_t mLen;
  uint32_t mStreamID;
  uint64_t mOffset;
  bool     mFin;
  bool     mFromRTO;
  bool     mSendUnblocked;
  bool     mQueueOnTransmit;

  uint16_t mRstCode; // for kRstStream
  uint16_t mStopSendingCode;
  uint64_t mStreamCreditValue; // for kMaxStreamData
  uint64_t mConnectionCredit; // for kMaxData 
  uint32_t mMaxStreamID; // for kMaxStreamID and kStreamIDBlocked
  uint64_t mPathData; // pathResponse
  
  // when unacked these are set
  enum keyPhase mTransmitKeyPhase;
  bool mCloned; // i.e. retransmit
};

class TransmittedPacket
{
public:
  TransmittedPacket(uint64_t packetNumber)
    : mPacketNumber(packetNumber), mPacketLen(0), mTransmitTime(0)
    , mFromRTO(false), mQueueOnTransmit(false)
  {
  }

  uint64_t mPacketNumber;
  uint32_t mPacketLen;
  uint64_t mTransmitTime;
  bool     mFromRTO;
  bool     mQueueOnTransmit;
  std::list<std::unique_ptr<ReliableData>> mFrameList;
private:
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
  uint32_t ConnectionWrite(std::unique_ptr<ReliableData> &p) {
    return mFlowController->ConnectionWrite(p);
  }

  void ChangeStreamID(uint32_t newStreamID) { mStreamID = newStreamID; }

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
             uint64_t peerMSD, uint64_t localMSD, bool no_replay);
  ~StreamPair() {};

  // Supply places data on the input (i.e. read()) queue
  uint32_t Supply(std::unique_ptr<ReliableData> &p);

  // todo it would be nice to have a zero copy interface
  uint32_t Read(unsigned char *buffer, uint32_t avail, uint32_t &amt, bool &fin);

  bool Empty();

  uint32_t ResetInbound();

  uint32_t NewFlowControlLimit(uint64_t limit);

  uint32_t Write(const unsigned char *data, uint32_t len, bool fin);

  int EndStream();

  int RstStream(uint16_t code);

  int StopSending(uint16_t code);

  void ChangeStreamID(uint32_t newStreamID);
  
  bool Done(); // All data and fin bit given to an application and all data are transmitted and acked.
               // todo(or stream has been reseted)
               // the stream can be removed from the stream list.

  bool IsBidiStream() { return (mStreamID & 0x2) ? false : true; }
  bool IsUniStream() { return (mStreamID & 0x2) ? true : false; }
  bool IsLocalStream() { return (!(mStreamID & 1) && mMozQuic->mIsClient) || // even and you're the client
                                ((mStreamID & 1) && !mMozQuic->mIsClient); } // odd and you're the server
  bool IsPeerStream() {return (!(mStreamID & 1) && !mMozQuic->mIsClient) ||  // even and you're the server
                              ((mStreamID & 1) && mMozQuic->mIsClient); }    // odd and you're the client
  bool IsSendOnlyStream() { return IsUniStream() && IsLocalStream(); }
  bool IsRecvOnlyStream() { return IsUniStream() && IsPeerStream(); }

  uint32_t mStreamID;
  bool mNoReplay;
  std::unique_ptr<StreamOut> mOut;
  std::unique_ptr<StreamIn>  mIn;
  MozQuic *mMozQuic;
};

}

  
