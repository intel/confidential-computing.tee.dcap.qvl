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

#include "SgxEcdsaAttestation/AttestationParsers.h"
#include "OpensslHelpers/Bytes.h"
#include "JsonParser.h"
#include "Utils/Logger.h"
#include "TcbStatus.h"

namespace intel { namespace sgx { namespace dcap { namespace parser { namespace json {

IdentityTcbLevel::IdentityTcbLevel(
        const uint32_t isvSvn,
        const time_t tcbDate,
        const TcbStatus tcbStatus,
        const std::vector<std::string>& advisoryIds)
        : _isvSvn(isvSvn),
          _tcbDate(tcbDate),
          _tcbStatus(tcbStatus),
          _advisoryIds(advisoryIds) {}

uint32_t IdentityTcbLevel::getIsvsvn() const
{
    return _isvSvn;
}

time_t IdentityTcbLevel::getTcbDate() const
{
    return _tcbDate;
}

 TcbStatus IdentityTcbLevel::getTcbStatus() const
{
    return _tcbStatus;
}

const std::vector<std::string>& IdentityTcbLevel::getAdvisoryIds() const
{
    return _advisoryIds;
}

IdentityTcbLevel::IdentityTcbLevel(const ::rapidjson::Value &tcbLevel)
{
    JsonParser jsonParser;
    JsonParser::ParseStatus status;

    if(!tcbLevel.IsObject())
    {
        LOG_AND_THROW(FormatException, "TCB level should be a JSON object");
    }

    if(!tcbLevel.HasMember("tcb"))
    {
        LOG_AND_THROW(FormatException, "TCB level JSON should has [tcb] field");
    }
    const ::rapidjson::Value& tcb = tcbLevel["tcb"];

    std::tie(_isvSvn, status) = jsonParser.getUintFieldOf(tcb, "isvsvn");
    switch (status)
    {
        case JsonParser::ParseStatus::Missing:
            LOG_AND_THROW(FormatException, "EnclaveIdentity JSON should have [isvsvn] field");
        case JsonParser::ParseStatus::Invalid:
            LOG_AND_THROW(InvalidExtensionException, "Could not parse [isvsvn] field of EnclaveIdentity JSON to integer");
        case JsonParser::ParseStatus::OK:
            break;
    }

    std::tie(_tcbDate, status) = jsonParser.getDateFieldOf(tcbLevel, "tcbDate");
    switch (status)
    {
        case JsonParser::ParseStatus::Missing:
            LOG_AND_THROW(FormatException, "TCB level JSON should has [tcbDate] field");
        case JsonParser::ParseStatus::Invalid:
            LOG_AND_THROW(InvalidExtensionException, "Could not parse [tcbDate] field of EnclaveIdentity JSON to date. [tcbDate] should be ISO formatted date");
        case JsonParser::ParseStatus::OK:
            break;
    }

    std::string tcbStatusStr;
    std::tie(tcbStatusStr, status) = jsonParser.getStringFieldOf(tcbLevel, "tcbStatus");
    switch (status)
    {
        case JsonParser::ParseStatus::Missing:
            LOG_AND_THROW(FormatException, "TCB level JSON should has [tcbStatus] field");
        case JsonParser::ParseStatus::Invalid:
            LOG_AND_THROW(InvalidExtensionException, "Could not parse [tcbStatus] field of EnclaveIdentity JSON to date. [tcbDate] should be ISO formatted date");
        case JsonParser::ParseStatus::OK:
            break;
        default:
            LOG_AND_THROW(InvalidExtensionException, "Could not parse [tcbStatus] field of EnclaveIdentity JSON to string");
    }

    static const std::vector<std::string> validStatuses = {{"UpToDate", "OutOfDate", "Revoked"}};
    if(std::find(validStatuses.cbegin(), validStatuses.cend(), tcbStatusStr) == validStatuses.cend())
    {
        LOG_AND_THROW(InvalidExtensionException, "TCB level [tcbStatus] JSON field has invalid value [" + tcbStatusStr + "]");
    }
    _tcbStatus = parseStringToTcbStatus(tcbStatusStr);

    std::tie(_advisoryIds, status) = jsonParser.getStringVecFieldOf(tcbLevel, "advisoryIDs");
    switch (status)
    {
        case JsonParser::ParseStatus::Invalid:
        LOG_AND_THROW(InvalidExtensionException, "Could not parse [advisoryIDs] field of EnclaveIdentity JSON to an array.");
        case JsonParser::ParseStatus::Missing: // advisoryIDs field is optional
        case JsonParser::ParseStatus::OK:
            break;
    }
}

bool IdentityTcbLevel::operator>(const IdentityTcbLevel &other) const {
    if(_isvSvn == other._isvSvn)
    {
        return _tcbDate > other._tcbDate;
    }
    return _isvSvn > other._isvSvn;
}
}}}}}
