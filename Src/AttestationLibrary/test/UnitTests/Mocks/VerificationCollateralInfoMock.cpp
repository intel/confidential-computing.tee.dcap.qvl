/*
* Copyright (C) 2026 Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "VerificationCollateralInfoMock.h"
#include <gtest/gtest.h>
#include <algorithm> // std::min_element, max_element for windows

namespace intel::sgx::dcap::test {

void VerificationCollateralInfoMock::checkVerCollInfoEmpty() const
{
    ASSERT_FALSE(this->isFilled());
}

void VerificationCollateralInfoMock::checkVerCollInfoFilledEqual(
    const std::vector<time_t>& expectedIssueDates,
    const std::vector<time_t>& expectedNextUpdates,
    const std::vector<unsigned int> &expectedEvaluationNumbers,
    const std::time_t& tcbDate,
    const std::set<std::string>& advisoryIds,
    const std::string& tcbStatus) const
{
    return checkVerCollInfoFilled(expectedIssueDates, expectedNextUpdates, expectedEvaluationNumbers, tcbDate, tcbDate, advisoryIds, advisoryIds, tcbStatus, tcbStatus);
}

void VerificationCollateralInfoMock::checkVerCollInfoFilled(
    const std::vector<time_t>& expectedIssueDates,
    const std::vector<time_t>& expectedNextUpdates,
    const std::vector<unsigned int> &expectedEvaluationNumbers,
    const std::time_t& launchTcbDate,
    const std::time_t& currentTcbDate,
    const std::set<std::string>& launchAdvisoryIds,
    const std::set<std::string>& currentAdvisoryIds,
    const std::string& launchTcbStatus,
    const std::string& currentTcbStatus) const
{
    ASSERT_TRUE(this->isFilled());
    ASSERT_EQ(1, this->getId());
    ASSERT_EQ(2, this->getVersion());
    ASSERT_EQ(expectedIssueDates, this->getIssueDates());
    ASSERT_EQ(expectedNextUpdates, this->getNextUpdates());
    ASSERT_EQ(expectedEvaluationNumbers, this->getTcbEvalNumbers());
    auto minEvalNum = *std::min_element(expectedEvaluationNumbers.begin(), expectedEvaluationNumbers.end());
    ASSERT_GT(minEvalNum, 0); // Use nonzero values in tests

    ASSERT_EQ(launchTcbStatus, this->getLaunchTcbStatus());
    ASSERT_FALSE(launchTcbStatus.empty()); // should be a nonempty string
    ASSERT_EQ(launchTcbDate, this->getLaunchTcbDate());
    ASSERT_NE(launchTcbDate, 0); // 0 value could mean that the field was not filled. Use nonzero values in tests
    ASSERT_EQ(launchAdvisoryIds, this->getLaunchAdvisoryIds()); // empty is allowed

    ASSERT_EQ(currentTcbStatus, this->getCurrentTcbStatus());
    ASSERT_FALSE(currentTcbStatus.empty()); // should be a nonempty string
    ASSERT_EQ(currentTcbDate, this->getCurrentTcbDate());
    ASSERT_NE(currentTcbDate, 0); // 0 value could mean that the field was not filled. Use nonzero values in tests
    ASSERT_EQ(currentAdvisoryIds, this->getCurrentAdvisoryIds()); // empty is allowed

    ASSERT_LE(this->getLaunchTcbDate(), this->getCurrentTcbDate());

}

}
