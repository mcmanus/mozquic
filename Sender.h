/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <stdint.h>

namespace mozquic {

class Sender final
{

    // transmit
    // 1] queue
    // 2] process any credits
    // 3] sched timer

    // cwnd
    // ss or ca
    // rtt

public:
    Sender(MozQuic *session);
    void RTTSample(uint64_t xmit, uint16_t delay);
private:
    MozQuic *mMozQuic;
    uint16_t mSmoothedRTT;
};

} //namespace
