/*
 * Copyright (C) 2025 Intel Corporation
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

#include <tuple>
#include <algorithm> // std::min_element, max_element for windows
#include <cstring>
#include "QuoteConstants.h"
#include "VerificationCollateralInfo.h"
#include "Utils/Logger.h"

using namespace intel::sgx::dcap;

std::string advisoryIdsToString(const std::set<std::string>& advisoryIds)
{
    std::string advisoryIdsStr;
    for (const auto& advisoryId : advisoryIds) {
        advisoryIdsStr += advisoryId + ",";
    }
    if (!advisoryIdsStr.empty()) {
        advisoryIdsStr.pop_back(); // Remove the last comma
    }

    if (advisoryIdsStr.size() >= constants::VERIFICATION_COLLATERAL_INFO_ADVISORY_IDS_SIZE_BYTE_LEN)
    {
        throw VerCollInfoSizeException("AdvisoryIDs string exceeds the maximum allowed size of " + std::to_string(constants::VERIFICATION_COLLATERAL_INFO_ADVISORY_IDS_SIZE_BYTE_LEN) +
            " bytes. Current size: " + std::to_string(advisoryIdsStr.size()));
    }
    return advisoryIdsStr;
}

VerificationCollateralInfo::VerificationCollateralInfo() : _id(1), _version(2), _isFilled(false) {}

void VerificationCollateralInfo::addLaunchInfo(const std::time_t& tcbDate, const std::vector<std::string>& advisoryIds, const std::string& tcbStatus)
{
    _launchTcbDate = tcbDate;
    _launchAdvisoryIds.insert(advisoryIds.begin(), advisoryIds.end());
    _launchTcbStatus = tcbStatus;
}

void VerificationCollateralInfo::addCurrentInfo(const std::time_t& tcbDate, const std::vector<std::string>& advisoryIds, const std::string& tcbStatus)
{
    _currentTcbDate = tcbDate;
    _currentAdvisoryIds.insert(advisoryIds.begin(), advisoryIds.end());
    _currentTcbStatus = tcbStatus;
}

void VerificationCollateralInfo::addTcbInfoData(const parser::json::TcbInfo& tcbInfo)
{
    _issueDates.push_back(tcbInfo.getIssueDate());
    _nextUpdates.push_back(tcbInfo.getNextUpdate());
    _tcbEvalNumbers.push_back(tcbInfo.getTcbEvaluationDataNumber());
}

void VerificationCollateralInfo::addEnclaveIdentityData(const parser::json::EnclaveIdentity& enclaveIdentity)
{
    _issueDates.push_back(enclaveIdentity.getIssueDate());
    _nextUpdates.push_back(enclaveIdentity.getNextUpdate());
    _tcbEvalNumbers.push_back(enclaveIdentity.getTcbEvaluationDataNumber());
}

std::vector<uint8_t> VerificationCollateralInfo::aggregateDataAndParseToVec() {
    std::vector<uint8_t> byteVec(constants::VERIFICATION_COLLATERAL_INFO_SIZE_BYTE_LEN, 0);
    size_t offset = 0;

    if(_issueDates.empty() || _nextUpdates.empty() || _tcbEvalNumbers.empty())
    {
        return byteVec;
    }

    const auto issueDateMin = *std::min_element(_issueDates.begin(), _issueDates.end());
    const auto issueDateMax = *std::max_element(_issueDates.begin(), _issueDates.end());
    const auto expirationDate = *std::min_element(_nextUpdates.begin(), _nextUpdates.end());
    const auto tcbEvaluationDataNumber = *std::min_element(_tcbEvalNumbers.begin(), _tcbEvalNumbers.end());

    std::memcpy(&byteVec[offset], &_id, constants::VERIFICATION_COLLATERAL_INFO_ID_SIZE_BYTE_LEN);
    offset+=constants::VERIFICATION_COLLATERAL_INFO_ID_SIZE_BYTE_LEN;

    std::memcpy(&byteVec[offset], &_version, constants::VERIFICATION_COLLATERAL_INFO_VERSION_SIZE_BYTE_LEN);
    offset+=constants::VERIFICATION_COLLATERAL_INFO_VERSION_SIZE_BYTE_LEN;

    std::memcpy(&byteVec[offset], &issueDateMin, constants::VERIFICATION_COLLATERAL_INFO_ISSUE_DATE_MIN_SIZE_BYTE_LEN);
    offset+=constants::VERIFICATION_COLLATERAL_INFO_ISSUE_DATE_MIN_SIZE_BYTE_LEN;

    std::memcpy(&byteVec[offset], &issueDateMax, constants::VERIFICATION_COLLATERAL_INFO_ISSUE_DATE_MAX_SIZE_BYTE_LEN);
    offset+=constants::VERIFICATION_COLLATERAL_INFO_ISSUE_DATE_MAX_SIZE_BYTE_LEN;

    std::memcpy(&byteVec[offset], &expirationDate, constants::VERIFICATION_COLLATERAL_INFO_EXPIRATION_DATE_SIZE_BYTE_LEN);
    offset+=constants::VERIFICATION_COLLATERAL_INFO_EXPIRATION_DATE_SIZE_BYTE_LEN;

    std::memcpy(&byteVec[offset], &tcbEvaluationDataNumber, constants::VERIFICATION_COLLATERAL_INFO_TCB_EVALUATION_DATA_NUMBER_SIZE_BYTE_LEN);
    offset+=constants::VERIFICATION_COLLATERAL_INFO_TCB_EVALUATION_DATA_NUMBER_SIZE_BYTE_LEN;

    std::memcpy(&byteVec[offset], &_launchTcbDate, constants::VERIFICATION_COLLATERAL_INFO_TCB_DATE_SIZE_BYTE_LEN);
    offset+=constants::VERIFICATION_COLLATERAL_INFO_TCB_DATE_SIZE_BYTE_LEN;

    std::memcpy(&byteVec[offset], &_currentTcbDate, constants::VERIFICATION_COLLATERAL_INFO_TCB_DATE_SIZE_BYTE_LEN);
    offset+=constants::VERIFICATION_COLLATERAL_INFO_TCB_DATE_SIZE_BYTE_LEN;

    auto advisoryIdsStr = advisoryIdsToString(_launchAdvisoryIds);
    std::memcpy(&byteVec[offset], advisoryIdsStr.c_str(), advisoryIdsStr.size());
    offset+=constants::VERIFICATION_COLLATERAL_INFO_ADVISORY_IDS_SIZE_BYTE_LEN;

    advisoryIdsStr = advisoryIdsToString(_currentAdvisoryIds);
    std::memcpy(&byteVec[offset], advisoryIdsStr.c_str(), advisoryIdsStr.size());
    offset+=constants::VERIFICATION_COLLATERAL_INFO_ADVISORY_IDS_SIZE_BYTE_LEN;

    if (_launchTcbStatus.size() >= constants::VERIFICATION_COLLATERAL_INFO_TCB_STATUS_BYTE_LEN)
    {
        throw VerCollInfoSizeException("Launch TCB Status string exceeds the maximum allowed size of " + std::to_string(constants::VERIFICATION_COLLATERAL_INFO_TCB_STATUS_BYTE_LEN) +
            " bytes. Current size: " + std::to_string(_launchTcbStatus.size()));
    }
    std::memcpy(&byteVec[offset], _launchTcbStatus.c_str(), _launchTcbStatus.size());
    offset+=constants::VERIFICATION_COLLATERAL_INFO_TCB_STATUS_BYTE_LEN;

    if (_currentTcbStatus.size() >= constants::VERIFICATION_COLLATERAL_INFO_TCB_STATUS_BYTE_LEN)
    {
        throw VerCollInfoSizeException("Current TCB Status string exceeds the maximum allowed size of " + std::to_string(constants::VERIFICATION_COLLATERAL_INFO_TCB_STATUS_BYTE_LEN) +
            " bytes. Current size: " + std::to_string(_currentTcbStatus.size()));
    }
    std::memcpy(&byteVec[offset], _currentTcbStatus.c_str(), _currentTcbStatus.size());
    offset+=constants::VERIFICATION_COLLATERAL_INFO_TCB_STATUS_BYTE_LEN;

    if (offset != byteVec.size())
    {
        throw VerCollInfoSizeException("Aggregated data size does not match the expected size. Expected: " + std::to_string(byteVec.size()) +
            " bytes. Actual: " + std::to_string(offset) + " bytes.");
    }

    return byteVec;
}

bool VerificationCollateralInfo::isFilled() const {
    return _isFilled;
}

void VerificationCollateralInfo::setFilled() {
    this->_isFilled = true;
}
