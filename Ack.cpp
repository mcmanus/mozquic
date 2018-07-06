/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "Logging.h"
#include "MozQuic.h"
#include "MozQuicInternal.h"
#include "Sender.h"
#include "Streams.h"
#include "TransportExtension.h"

#include <array>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

namespace mozquic  {

static const uint32_t kReorderingThreshold = 3;

// a request to acknowledge a packetnumber
void
MozQuic::AckScoreboard(uint64_t packetNumber, enum keyPhase kp)
{
  if (mStreamState->mAckList.empty()) {
    mStreamState->mAckList.emplace_front(packetNumber, Timestamp(), kp);
    return;
  }
  auto iter = mStreamState->mAckList.begin();
  for (; iter != mStreamState->mAckList.end(); ++iter) {
    if ((iter->mPhase == kp) &&
        ((iter->mPacketNumber + 1) == packetNumber)) {
      // the common case is to just adjust this counter
      // in the first element.. but you can't do that if it has
      // already been transmitted. (that needs a new node)
      if (iter->Transmitted()) {
        break;
      }
      iter->mPacketNumber++;
      iter->mExtra++;
      iter->mReceiveTime.push_front(Timestamp());
      return;
    }
    if (iter->mPacketNumber >= packetNumber &&
        packetNumber >= (iter->mPacketNumber - iter->mExtra)) {
      return; // dup
    }
    if (iter->mPacketNumber < packetNumber) {
      break;
    }
  }
  mStreamState->mAckList.emplace(iter, packetNumber, Timestamp(), kp);
}

int
MozQuic::MaybeSendAck(bool delAckOK)
{
  if (mStreamState->mAckList.empty()) {
    return MOZQUIC_OK;
  }

  // if we aren't in connected we will only piggyback
  if (mConnectionState != CLIENT_STATE_CONNECTED &&
      mConnectionState != SERVER_STATE_CONNECTED) {
    return MOZQUIC_OK;
  }

  if (delAckOK &&
      mDelAckTimer->Armed() && !mDelAckTimer->Expired()) {
    AckLog5("bare ack delayed due to existing delAckTimer\n");
    return MOZQUIC_OK;
  }

  if (delAckOK && !mDelAckTimer->Armed()) {
    uint64_t timerVal = mSendState->SmoothedRTT() >> 2;
    // todo min and max filters
    // todo consider how 1/4 addition to measured rtt loop impacts srtt based things
    AckLog5("bare ack arm and delay delAckTimer %d\n", timerVal);
    mDelAckTimer->Arm(timerVal);
    return MOZQUIC_OK;
  }

  if (mDelAckTimer->Armed()) {
    assert(mDelAckTimer->Expired());
    AckLog5("bare ack timer expired\n");
    mDelAckTimer->Cancel();
  }
  
  for (auto iter = mStreamState->mAckList.begin();
       iter != mStreamState->mAckList.end(); ++iter) {
    if (iter->Transmitted()) {
      continue;
    }
    AckLog7("Trigger Ack based on %lX (extra %d) kp=%d\n",
            iter->mPacketNumber, iter->mExtra, iter->mPhase);
    mStreamState->Flush(true);
    break;
  }
  return MOZQUIC_OK;
}

// To clarify.. an ack frame for 15,14,13,11,10,8,2,1
// ackblockcount=3, largest=15, 1stAckBlock= 2 // 15,14,13
// #1 gap=0, additional ack block=1 // 11,10
// #2 gap=0, additional ack block=0 // 8
// #3 gap=4, additional ack block=1 // 2, 1

uint32_t
MozQuic::AckPiggyBack(unsigned char *pkt, uint64_t packetNumberOfAck, uint32_t avail, keyPhase kp,
                      bool bareAck, uint32_t &used)
{
  used = 0;

  // build as many ack frames as will fit
  uint64_t lowAcked = 0;
  bool newFrame = true;
  uint32_t outputSize = 0;
  unsigned char *ackBlockLocation = NULL;
  uint32_t ackBlockCounter = 0;
  uint32_t offsetRollbackExtra = 0;
  uint32_t offsetCheckpoint = 0;

  for (auto iter = mStreamState->mAckList.begin(); iter != mStreamState->mAckList.end(); iter++) {
    // list ordered as 7/2, 2/1.. (ack 7,6,5.. 2,1 but not 4,3 or 0) i.e. highest num first
    if ((kp <= keyPhaseUnprotected) && (iter->mPhase >= keyPhase0Rtt)) {
      AckLog7("skip ack generation of %lX wrong kp need %d the phase is %d\n",
              iter->mPacketNumber, iter->mPhase, kp);
      break;
    }

    if (newFrame) {
      newFrame = false;
      assert(!used);
      if (avail < 5) {
        return MOZQUIC_OK;
      }
      
      pkt[0] = FRAME_TYPE_ACK;
      used = 1;
      avail -= 1;

      if (EncodeVarint(iter->mPacketNumber, pkt + used, avail, outputSize) != MOZQUIC_OK) {
        AckLog7("Cannot create new ack frame due to lack of space in packet\n");
        used = 0;
        return MOZQUIC_OK; // ok to return as we haven't written any of the frame
      }
      used += outputSize;
      avail -= outputSize;

      assert(iter->mReceiveTime.size());
      uint64_t delay64 =  0;
      if (!bareAck) {
        delay64 = Timestamp() - *(iter->mReceiveTime.begin());
        delay64 *= 1000; // wire encoding is microseconds
        if (kp != keyPhaseUnprotected) {
          delay64 /= (1ULL << mLocalAckDelayExponent);
        } else {
          delay64 /= (1ULL << kDefaultAckDelayExponent);
        }
      }

      if (EncodeVarint(delay64, pkt + used, avail, outputSize) != MOZQUIC_OK) {
        AckLog7("Cannot create new ack frame due to lack of space in packet\n");
        used = 0;
        return MOZQUIC_OK; // ok to return as we haven't written any of the frame
      }
      used += outputSize;
      avail -= outputSize;

      // we will fill in ackBlockLength at the end, until then reserve 2 bytes for it
      if (avail < 2) {
        AckLog7("Cannot create new ack frame due to lack of space in packet\n");
        used = 0;
        return MOZQUIC_OK; // ok to return as we haven't written any of the frame
      }
      ackBlockLocation = pkt + used;
      used += 2;
      avail -= 2;

      offsetRollbackExtra = used;
      if (EncodeVarint(iter->mExtra, pkt + used, avail, outputSize) != MOZQUIC_OK) {
        used = 0;
        return MOZQUIC_OK; // ok to return as we haven't written any of the frame
      }
      used += outputSize;
      avail -= outputSize;

      lowAcked = iter->mPacketNumber - iter->mExtra;
      offsetCheckpoint = used;
    } else {
      assert(lowAcked > iter->mPacketNumber);

      if ((lowAcked - iter->mPacketNumber) == 1) {
        if (avail < 7) {
          // this expands the last entry by an unknown amount
          // and we don't have a checkpoint to pop back to when running out of
          // room - so just don't start this operation if the worst case cannot
          // be accommodated.
          break;
        }
        // crud. There is no gap here which is not allowed by the packet format.
        // so we need to logically coalesce the last list entry with this one
        assert(offsetRollbackExtra);
        assert(used > offsetRollbackExtra);
        avail += (used - offsetRollbackExtra);
        used = offsetRollbackExtra;
        uint64_t lastExtra;
        uint32_t lenExtra;
        DecodeVarint(pkt + offsetRollbackExtra, avail, lastExtra, lenExtra);
        uint64_t newExtra = lastExtra + 1 + iter->mExtra;
        lowAcked -= 1 + iter->mExtra;
        assert (lowAcked == iter->mPacketNumber - iter->mExtra);
        if (EncodeVarint(newExtra, pkt + used, avail, outputSize) != MOZQUIC_OK) {
          used = offsetCheckpoint;
          break;
        }
        used += outputSize;
        avail -= outputSize;
        offsetCheckpoint = used;
      } else {
        uint64_t gap = lowAcked - iter->mPacketNumber - 2;

        if (EncodeVarint(gap, pkt + used, avail, outputSize) != MOZQUIC_OK) {
          used = offsetCheckpoint;
          break;
        }
        used += outputSize;
        avail -= outputSize;

        offsetRollbackExtra = used;
        if (EncodeVarint(iter->mExtra, pkt + used, avail, outputSize) != MOZQUIC_OK) {
          used = offsetCheckpoint;
          break;
        }
        used += outputSize;
        avail -= outputSize;

        lowAcked -= iter->mExtra + gap + 2;
        assert (lowAcked == iter->mPacketNumber - iter->mExtra);
        ackBlockCounter++;
        offsetCheckpoint = used;
      }
    }

    AckLog6("created ack of %lX (%d extra) into pn=%lX @ block %d [%d prev transmits]\n",
            iter->mPacketNumber, iter->mExtra, packetNumberOfAck, ackBlockCounter, iter->mTransmits.size());
    iter->mTransmits.push_back(std::pair<uint64_t, uint64_t>(packetNumberOfAck, Timestamp()));
  }
  
  if (ackBlockLocation) {
    // this does not impact used or avail as we are just filling in a hole that
    // has already been accounted for
    EncodeVarintAs2(ackBlockCounter, ackBlockLocation);
  }
  return MOZQUIC_OK;
}

void
MozQuic::Acknowledge(uint64_t packetNumber, keyPhase kp)
{
  assert(mIsChild || mIsClient);

  if (packetNumber >= mNextRecvPacketNumber) {
    mNextRecvPacketNumber = packetNumber + 1;
  }

  AckLog6("%p REQUEST TO GEN ACK FOR %lX kp=%d\n", this, packetNumber, kp);

  AckScoreboard(packetNumber, kp);
}

void
MozQuic::ProcessAck(FrameHeaderData *ackMetaInfo, const unsigned char *framePtr,
                    const unsigned char *endOfPacket, bool fromCleartext,
                    uint32_t &outUsedByAckFrame)
{
  // frameptr points to the beginning of the ackblock section
  assert (ackMetaInfo->mType == FRAME_TYPE_ACK);
  assert (ackMetaInfo->u.mAck.mAckBlocks <= 4096);

  const unsigned char *originalFramePtr = framePtr;
  outUsedByAckFrame = 0;

  uint16_t numRanges = 0;
  std::array<std::pair<uint64_t, uint64_t>, 4096> ackStack;

  uint64_t largestAcked = ackMetaInfo->u.mAck.mLargestAcked;
  for (uint32_t idx = 0; idx < ackMetaInfo->u.mAck.mAckBlocks; idx++) {
    if (largestAcked == 0ULL - 1) {
      RaiseError(MOZQUIC_ERR_GENERAL, (char *) "invalid ack encoding");
      return;
    }

    uint32_t amtParsed;
    if (idx != 0) { // mind the gap
      uint64_t gap;
      if (DecodeVarint(framePtr, endOfPacket - framePtr, gap, amtParsed) != MOZQUIC_OK) {
        RaiseError(MOZQUIC_ERR_GENERAL, (char *) "ack frame header short");
        return;
      }
      framePtr += amtParsed;
      if (largestAcked < (gap + 1)) {
        RaiseError(MOZQUIC_ERR_GENERAL, (char *) "invalid ack encoding");
        return;
      } 
      largestAcked -= gap + 1;
    }
    uint64_t extra = 0;

    if (DecodeVarint(framePtr, endOfPacket - framePtr, extra, amtParsed) != MOZQUIC_OK) {
      RaiseError(MOZQUIC_ERR_GENERAL, (char *) "ack frame header short");
      return;
    }
    framePtr += amtParsed;

    AckLog5("ACK RECVD (%s) FOR %lX -> %lX\n",
            fromCleartext ? "cleartext" : "protected",
            largestAcked - extra, largestAcked);

    // form a stack here so we can process them starting at the
    // lowest packet number, which is how mStreamState->mUnAckedPackets is ordered and
    // do it all in one pass
    if (numRanges >= 4096) {
      RaiseError(MOZQUIC_ERR_GENERAL, (char *) "ack frame too long to handle");
      return;
    }
    ackStack[numRanges++] =
      std::pair<uint64_t, uint64_t>(largestAcked - extra, extra + 1);

    if (largestAcked < (extra)) {
      RaiseError(MOZQUIC_ERR_GENERAL, (char *) "invalid ack encoding");
      return;
    } 
    largestAcked -= extra + 1;
  }

  outUsedByAckFrame = framePtr - originalFramePtr;
  bool maybeDoEarlyRetransmit = false;
  uint64_t reportLossLessThan = 0;

  auto dataIter = mStreamState->mUnAckedPackets.cbegin();
  for (auto iters = numRanges; iters > 0; --iters) {
    uint64_t haveAckFor = ackStack[iters - 1].first;
    uint64_t haveAckForEnd = haveAckFor + ackStack[iters - 1].second;

    if (mPMTUD1PacketNumber &&
        (mPMTUD1PacketNumber >= haveAckFor) &&
        (mPMTUD1PacketNumber < haveAckForEnd)) {
      CompletePMTUD1();
    }

    for (; haveAckFor < haveAckForEnd; haveAckFor++) {

      // skip over stuff that is too low
      for (; (dataIter != mStreamState->mUnAckedPackets.cend()) && ((*dataIter)->mPacketNumber < haveAckFor); dataIter++);

      if ((dataIter == mStreamState->mUnAckedPackets.cend()) || ((*dataIter)->mPacketNumber > haveAckFor)) {
        AckLog9("haveAckFor %lX did not find matching unacked data\n", haveAckFor)
      } else {
        assert ((*dataIter)->mPacketNumber == haveAckFor);

        if ((haveAckFor == mHighestTransmittedAckable) && haveAckFor) {
          maybeDoEarlyRetransmit = true;
        }
        AckLog5("haveAckFor %lX found unacked data. packet size %d fromrto=%d\n", haveAckFor,
                (*dataIter)->mPacketLen, (*dataIter)->mFromRTO);
        
        if ((*dataIter)->mFromRTO) {
          reportLossLessThan = std::max(reportLossLessThan, (*dataIter)->mPacketNumber);
        }
        if (ackMetaInfo->u.mAck.mLargestAcked == haveAckFor) {
          uint64_t xmit = (*dataIter)->mTransmitTime;
          mSendState->RTTSample(xmit,
                                ackMetaInfo->u.mAck.mAckDelay *
                                (1ULL << (fromCleartext ? kDefaultAckDelayExponent : mPeerAckDelayExponent)) /
                                1000ULL);
        }
        mSendState->Ack((*dataIter)->mPacketNumber, (*dataIter)->mPacketLen);
        dataIter = mStreamState->mUnAckedPackets.erase(dataIter);
      }
    }
    // fast retransmit.. may be a nop
    reportLossLessThan = std::max(reportLossLessThan, haveAckForEnd - kReorderingThreshold);
  }

  if (maybeDoEarlyRetransmit && !mStreamState->mUnAckedPackets.empty()) {
    // this means we processed an ack for the highest unacked packet
    // but some things still are not acked. That means early retransmit.
    // todo this should really have a delay
    reportLossLessThan = std::max(reportLossLessThan, mHighestTransmittedAckable);
  }
  if (reportLossLessThan) {
    mStreamState->ReportLossLessThan(reportLossLessThan);
  }

  // obv unacked lists should be combined (data, other frames, acks)
  for (auto iters = numRanges; iters > 0; --iters) {
    uint64_t haveAckFor = ackStack[iters - 1].first;
    uint64_t haveAckForEnd = haveAckFor + ackStack[iters - 1].second;
    for (; haveAckFor < haveAckForEnd; haveAckFor++) {
      bool foundHaveAckFor = false;
      for (auto acklistIter = mStreamState->mAckList.cbegin(); acklistIter != mStreamState->mAckList.cend(); ) {
        bool foundAckFor = false;
        for (auto vectorIter = acklistIter->mTransmits.cbegin();
             vectorIter != acklistIter->mTransmits.cend(); vectorIter++ ) {
          if ((*vectorIter).first == haveAckFor) {
            AckLog5("haveAckFor %lX found unacked ack of %lX (+%d) transmitted %d times\n",
                    haveAckFor, acklistIter->mPacketNumber, acklistIter->mExtra,
                    acklistIter->mTransmits.size());
            foundAckFor = true;
            break; // vector iteration
            // need to keep looking at the rest of mStreamState->mAckList. Todo this is terribly wasteful.
          }
        } // vector iteration
        if (!foundAckFor) {
          acklistIter++;
        } else {
          acklistIter = mStreamState->mAckList.erase(acklistIter);
          foundHaveAckFor = true;
        }
      } // macklist iteration
      if (!foundHaveAckFor) {
        AckLog9("haveAckFor %lX did not find matching unacked ack\n", haveAckFor)
      }
    } // haveackfor iteration
  } //ranges iteration

  // cong control limits are better now
  mSendState->Flush();
}

uint32_t
MozQuic::HandleAckFrame(FrameHeaderData *result, bool fromCleartext,
                        const unsigned char *pkt, const unsigned char *endpkt,
                        uint32_t &_ptr)
{
  if (fromCleartext && (mConnectionState == SERVER_STATE_LISTEN)) {
    // acks are not allowed processing client_initial
    RaiseError(MOZQUIC_ERR_GENERAL, (char *) "acks are not allowed in client initial\n");
    return MOZQUIC_ERR_GENERAL;
  }

  // pkt + _ptr now points at ack blocks
  uint32_t used;
  ProcessAck(result, pkt + _ptr, endpkt, fromCleartext, used);
  _ptr += used;
  return MOZQUIC_OK;
}

}
