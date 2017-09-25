/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "Logging.h"
#include "MozQuic.h"
#include "MozQuicInternal.h"
#include "Streams.h"
#include "ufloat16.h"

#include <array>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

namespace mozquic  {

static uint8_t varSize(uint64_t input)
{
  // returns 0->3 depending on magnitude of input
  return (input < 0x100) ? 0 : (input < 0x10000) ? 1 : (input < 0x100000000UL) ? 2 : 3;
}

// a request to acknowledge a packetnumber
void
MozQuic::AckScoreboard(uint64_t packetNumber, enum keyPhase kp)
{
  // todo out of order packets should be coalesced
  if (mStreamState->mAckList.empty()) {
    mStreamState->mAckList.emplace_front(packetNumber, Timestamp(), kp);
    return;
  }
  // todo coalesce also in case where two ranges can be combined

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
MozQuic::MaybeSendAck()
{
  if (mStreamState->mAckList.empty()) {
    return MOZQUIC_OK;
  }

  // if we aren't in connected we will only piggyback
  if (mConnectionState != CLIENT_STATE_CONNECTED &&
      mConnectionState != SERVER_STATE_CONNECTED) {
    return MOZQUIC_OK;
  }
  // todo for doing some kind of delack

  auto iter = mStreamState->mAckList.begin();
  for (; iter != mStreamState->mAckList.end(); ++iter) {
    if (iter->Transmitted()) {
      continue;
    }
    AckLog6("Trigger Ack based on %lX (extra %d) kp=%d\n",
            iter->mPacketNumber, iter->mExtra, iter->mPhase);
    mStreamState->Flush(true);
    break;
  }
  return MOZQUIC_OK;
}

// To clarify.. an ack frame for 15,14,13,11,10,8,2,1
// numblocks=3
// largest=15, first ack block length = 2 // 15, 14, 13
// ack block 1 = {1, 2} // 11, 10
// ack block 2 = {1, 1} // 8
// ack block 3 = {5, 2} / 2, 1

uint32_t
MozQuic::AckPiggyBack(unsigned char *pkt, uint64_t pktNumOfAck, uint32_t avail, keyPhase kp, uint32_t &used)
{
  used = 0;

  // build as many ack frames as will fit
  // always 16bit run length
  bool newFrame = true;
  uint8_t *numBlocks = nullptr;
  uint8_t *numTS = nullptr;
  uint64_t largestAcked;
  uint64_t lowAcked;
  for (auto iter = mStreamState->mAckList.begin(); iter != mStreamState->mAckList.end(); ) {
    // list  ordered as 7/2, 2/1.. (with gap @4 @3)
    // i.e. highest num first
    if ((kp <= keyPhaseUnprotected) && iter->mPhase >= keyPhase0Rtt) {
      AckLog6("skip ack generation of %lX wrong kp need %d\n", iter->mPacketNumber, kp);
      ++iter;
      continue;
    }

    largestAcked = iter->mPacketNumber;
    if (newFrame) {
      uint32_t need = 7;
      uint8_t pnSizeType = varSize(largestAcked);
      need += 1 << pnSizeType;
      if (avail < need) {
        AckLog6("Cannot create new ack frame due to lack of space in packet %d of %d\n",
                avail, need);
        return MOZQUIC_OK; // ok to return as we haven't written any of the frame
      }

      newFrame = false;

      // ack with numblocks, 16/32 bit largest and 16 bit run
      pkt[0] = 0xb0 | (pnSizeType << 2) | 0x01;
      used += 1;
      numBlocks = pkt + used;
      *numBlocks = 0;
      used += 1;
      numTS = pkt + used;
      *numTS = 0;
      used += 1;
      if (pnSizeType == 0) {
        pkt[used] = largestAcked & 0xff;
        used += 1;
      } else if (pnSizeType == 1) {
        uint16_t packet16 = largestAcked & 0xffff;
        packet16 = htons(packet16);
        memcpy(pkt + used, &packet16, 2);
        used += 2;
      } else if (pnSizeType == 2) {
        uint32_t packet32 = largestAcked & 0xffffffff;
        packet32 = htonl(packet32);
        memcpy(pkt + used, &packet32, 4);
        used += 4;
      } else {
        assert (pnSizeType == 3);
        uint32_t packet64 = largestAcked;
        packet64 = PR_htonll(packet64);
        memcpy(pkt + used, &packet64, 8);
        used += 8;
      }

      // timestamp is microseconds (10^-6) as 16 bit fixed point #
      assert(iter->mReceiveTime.size());
      uint64_t delay64 = (Timestamp() - *(iter->mReceiveTime.begin())) * 1000;
      uint16_t delay = htons(ufloat16_encode(delay64));
      memcpy(pkt + used, &delay, 2);
      used += 2;
      uint16_t extra = htons(iter->mExtra);
      memcpy(pkt + used, &extra, 2); // first ack block len
      used += 2;
      lowAcked = iter->mPacketNumber - iter->mExtra;
      pkt += used;
      avail -= used;
    } else {
      assert(lowAcked > iter->mPacketNumber);
      if (avail < 3) {
        AckLog6("Cannot create new ack frame due to lack of space in packet %d of %d\n",
                avail, 3);
        break; // do not return as we have a partially written frame
      }
      uint64_t gap = lowAcked - iter->mPacketNumber - 1;

      while (gap > 255) {
        if (avail < 3) {
          break;
        }
        *numBlocks = *numBlocks + 1;
        AckLog9("gap %d is an empty 255 gap\n", *numBlocks);
        pkt[0] = 255; // empty block
        pkt[1] = 0;
        pkt[2] = 0;
        lowAcked -= 255;
        pkt += 3;
        used += 3;
        avail -= 3;
        gap -= 255;
      }
      if (avail < 3) {
        break;
      }
      assert(gap <= 255);
      *numBlocks = *numBlocks + 1;
      pkt[0] = gap;
      uint16_t ackBlockLen = htons(iter->mExtra + 1);
      memcpy(pkt + 1, &ackBlockLen, 2);
      lowAcked -= (gap + iter->mExtra + 1);
      pkt += 3;
      used += 3;
      avail -= 3;
    }

    AckLog6("created ack of %lX (%d extra) into pn=%lX @ block %d [%d prev transmits]\n",
            iter->mPacketNumber, iter->mExtra, pktNumOfAck, *numBlocks, iter->mTransmits.size());

    iter->mTransmits.push_back(std::pair<uint64_t, uint64_t>(pktNumOfAck, Timestamp()));
    ++iter;
    if (*numBlocks == 0xff) {
      break;
    }
  }

  return MOZQUIC_OK;
}

void
MozQuic::Acknowledge(uint64_t packetNum, keyPhase kp)
{
  assert(mIsChild || mIsClient);

  if (packetNum >= mNextRecvPacketNumber) {
    mNextRecvPacketNumber = packetNum + 1;
  }

  AckLog6("%p REQUEST TO GEN ACK FOR %lX kp=%d\n", this, packetNum, kp);

  AckScoreboard(packetNum, kp);
}

void
MozQuic::ProcessAck(FrameHeaderData *ackMetaInfo, const unsigned char *framePtr, bool fromCleartext)
{
  // frameptr points to the beginning of the ackblock section
  // we have already runtime tested that there is enough data there
  // to read the ackblocks and the tsblocks
  assert (ackMetaInfo->mType == FRAME_TYPE_ACK);
  uint16_t numRanges = 0;
  uint16_t blocksProcessed = 0;
  bool firstPass = true;
  std::array<std::pair<uint64_t, uint64_t>, 257> ackStack;

  uint64_t largestAcked = ackMetaInfo->u.mAck.mLargestAcked;
  const uint8_t blockLengthLen = ackMetaInfo->u.mAck.mAckBlockLengthLen;
  do {
    uint64_t extra = 0;
    memcpy(((char *)&extra) + (8 - blockLengthLen), framePtr, blockLengthLen);
    extra = PR_ntohll(extra);
    framePtr += blockLengthLen;

    if (firstPass || extra) {
      if (!firstPass) {
        extra--;
      }
      firstPass = false;

      AckLog6("ACK RECVD (%s) FOR %lX -> %lX\n",
              fromCleartext ? "cleartext" : "protected",
              largestAcked - extra, largestAcked);
      // form a stack here so we can process them starting at the
      // lowest packet number, which is how mStreamState->mUnAckedData is ordered and
      // do it all in one pass
      assert(numRanges < 257);
      ackStack[numRanges++] =
        std::pair<uint64_t, uint64_t>(largestAcked - extra, extra + 1);

      largestAcked--;
      largestAcked -= extra;
    }
    if (blocksProcessed++ == ackMetaInfo->u.mAck.mNumBlocks) {
      break;
    }
    uint8_t gap = *framePtr;
    largestAcked -= gap;
    framePtr++;
  } while (1);

  auto dataIter = mStreamState->mUnAckedData.begin();
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
      for (; (dataIter != mStreamState->mUnAckedData.end()) && ((*dataIter)->mPacketNumber < haveAckFor); dataIter++);

      if ((dataIter == mStreamState->mUnAckedData.end()) || ((*dataIter)->mPacketNumber > haveAckFor)) {
        AckLog8("ACK'd data not found for %lX ack\n", haveAckFor);
      } else {
        do {
          assert ((*dataIter)->mPacketNumber == haveAckFor);
          AckLog5("ACK'd data found for %lX (frame type %d)\n",
                  haveAckFor, (*dataIter)->mType);
          dataIter = mStreamState->mUnAckedData.erase(dataIter);
        } while ((dataIter != mStreamState->mUnAckedData.end()) &&
                 (*dataIter)->mPacketNumber == haveAckFor);
      }
    }
  }

  // todo read the timestamps
  // and obviously todo feed the times into congestion control

  // obv unacked lists should be combined (data, other frames, acks)
  for (auto iters = numRanges; iters > 0; --iters) {
    uint64_t haveAckFor = ackStack[iters - 1].first;
    uint64_t haveAckForEnd = haveAckFor + ackStack[iters - 1].second;
    for (; haveAckFor < haveAckForEnd; haveAckFor++) {
      bool foundHaveAckFor = false;
      for (auto acklistIter = mStreamState->mAckList.begin(); acklistIter != mStreamState->mAckList.end(); ) {
        bool foundAckFor = false;
        for (auto vectorIter = acklistIter->mTransmits.begin();
             vectorIter != acklistIter->mTransmits.end(); vectorIter++ ) {
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
        AckLog9("haveAckFor %lX CANNOT find corresponding unacked ack\n", haveAckFor);
      }
    } // haveackfor iteration
  } //ranges iteration

  // each ID is absolute, but each ts is relative to previous
  uint64_t timestamp;
  for(int i = 0; i < ackMetaInfo->u.mAck.mNumTS; i++) {
    uint32_t pktID = ackMetaInfo->u.mAck.mLargestAcked;
    assert(pktID > framePtr[0]);
    pktID = pktID - framePtr[0];
    if (!i) {
      memcpy(&timestamp, framePtr + 1, 4);
      timestamp = ntohl(timestamp);
      framePtr += 5;
    } else {
      uint16_t tmp16;
      memcpy(&tmp16, framePtr + 1, 2);
      tmp16 = ntohs(tmp16);
      timestamp = timestamp + (ufloat16_decode(tmp16) / 1000);
      framePtr += 3;
    }
    AckLog9("Timestamp for packet %lX is %lu\n", pktID, timestamp);
  }
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

  // _ptr now points at ack block section
  uint32_t ackBlockSectionLen =
    result->u.mAck.mAckBlockLengthLen +
    (result->u.mAck.mNumBlocks * (result->u.mAck.mAckBlockLengthLen + 1));
  uint32_t timestampSectionLen = result->u.mAck.mNumTS * 3;
  if (timestampSectionLen) {
    timestampSectionLen += 2; // the first one is longer
  }
  assert(pkt + _ptr + ackBlockSectionLen + timestampSectionLen <= endpkt);
  ProcessAck(result, pkt + _ptr, fromCleartext);
  _ptr += ackBlockSectionLen;
  _ptr += timestampSectionLen;
  return MOZQUIC_OK;
}

}
