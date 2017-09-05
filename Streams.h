/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

namespace mozquic  {

enum  {
  kMaxStreamIDDefault   = 0xffffffff,
  kMaxStreamDataDefault = 0xffffffff,
  kMaxDataDefault       = 0xffffffff,
  kRetransmitThresh     = 500,
  kForgetUnAckedThresh  = 4000, // ms
};

class MozQuicStreamAck
{
public:
  MozQuicStreamAck(uint64_t num, uint64_t rtime, enum keyPhase kp)
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

class StreamState : public MozQuicWriter
{
  friend class MozQuic;
public:
  StreamState(MozQuic *);
  uint32_t ConnectionWrite(std::unique_ptr<MozQuicStreamChunk> &p) override;

  uint32_t StartNewStream(MozQuicStreamPair **outStream, const void *data, uint32_t amount, bool fin);
  uint32_t FindStream(uint32_t streamID, std::unique_ptr<MozQuicStreamChunk> &d);
  uint32_t RetransmitTimer();
  void DeleteStream(uint32_t streamID);
  uint32_t Flush(bool forceAck);
  uint32_t ScrubUnWritten(uint32_t id) override;
  uint32_t HandleStreamFrame(FrameHeaderData *result, bool fromCleartext,
                             const unsigned char *pkt, const unsigned char *endpkt,
                             uint32_t &_ptr);
  uint32_t CreateStreamFrames(unsigned char *&framePtr, const unsigned char *endpkt,
                              bool justZero);

  void InitIDs(uint32_t next, uint32_t nextR) { mNextStreamId = next; mNextRecvStreamId = nextR; }

private:
  uint32_t FlowControlPromotion();
  uint32_t FlowControlPromotionForStream(MozQuicStreamOut *out);

  MozQuic *mMozQuic;
  uint32_t mNextStreamId;
  uint32_t mNextRecvStreamId;

private: // these still need friend mozquic
  uint32_t mPeerMaxStreamData;
  uint32_t mPeerMaxData;
  uint32_t mPeerMaxStreamID;

  std::unique_ptr<MozQuicStreamPair> mStream0;
  std::unordered_map<uint32_t, MozQuicStreamPair *> mStreams;

  // retransmit happens off of mUnAckedData by
  // duplicating it and placing it in mConnUnWritten. The
  // dup'd entry is marked retransmitted so it doesn't repeat that. After a
  // certain amount of time the retransmitted packet is just forgotten (as
  // it won't be retransmitted again - that happens to the dup'd
  // incarnation)
  // mUnackedData is sorted by the packet number it was sent in.
  std::list<std::unique_ptr<MozQuicStreamChunk>> mConnUnWritten;
  std::list<std::unique_ptr<MozQuicStreamChunk>> mUnAckedData;

  // macklist is the current state of all unacked acks - maybe written out,
  // maybe not. ordered with the highest packet ack'd at front.Each time
  // the whole set needs to be written out. each entry in acklist contains
  // a vector of pairs (transmitTime, transmitID) representing each time it
  // is written. Upon receipt of an ack we need to find transmitID and
  // remove the entry from the acklist. TODO index by transmitID, but for
  // now iterate from rear (oldest data being acknowledged).
  //
  // acks ordered {1,2,5,6,7} as 7/2, 2/1 (biggest at head)
  std::list<MozQuicStreamAck>                    mAckList;
};

}

  
