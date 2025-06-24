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
#include "X509Constants.h"
#include "JsonParser.h"
#include "Utils/Logger.h"
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <unordered_map>


#include <tuple>

namespace intel { namespace sgx { namespace dcap { namespace parser { namespace json {

EnclaveID EnclaveIdentity::getID() const
{
    return _id;
}

uint32_t EnclaveIdentity::getVersion() const
{
    return _version;
}

time_t EnclaveIdentity::getIssueDate() const
{
    return _issueDate;
}

time_t EnclaveIdentity::getNextUpdate() const
{
    return _nextUpdate;
}

uint32_t EnclaveIdentity::getTcbEvaluationDataNumber() const
{
    return _tcbEvaluationDataNumber;
}

const std::vector<uint8_t>& EnclaveIdentity::getMrsigner() const
{
    return _mrSigner;
}

const std::vector<uint8_t>& EnclaveIdentity::getAttributes() const
{
    return _attributes;
}

const std::vector<uint8_t>& EnclaveIdentity::getAttributesMask() const
{
    return _attributesMask;
}

const std::vector<uint8_t>& EnclaveIdentity::getMiscselect() const
{
    return _miscselect;
}

const std::vector<uint8_t>& EnclaveIdentity::getMiscselectMask() const
{
    return _miscselectMask;
}

uint32_t EnclaveIdentity::getIsvProdId() const
{
    return _isvProdId;
}

const std::set<IdentityTcbLevel, std::greater<IdentityTcbLevel>>& EnclaveIdentity::getIdentityTcbLevels() const
{
    return _identityTcbLevels;
}

const std::vector<uint8_t>& EnclaveIdentity::getBody() const
{
    return _body;
}

const std::vector<uint8_t>& EnclaveIdentity::getSignature() const
{
    return _signature;
}

EnclaveIdentity EnclaveIdentity::parse(const std::string& jsonString)
{
    return EnclaveIdentity(jsonString);
}

IdentityTcbLevel EnclaveIdentity::getTcbLevel(uint32_t p_isvSvn) const
{
    for(const auto & tcbLevel : _identityTcbLevels)
    {
        if (tcbLevel.getIsvsvn() <= p_isvSvn)
        {
            return tcbLevel;
        }
    }
    LOG_AND_THROW(StatusNotSupportedException, "Non-existent tcb status exception");
}

void checkParseStatus(JsonParser::ParseStatus status, const std::string& fieldName)
{
    if(status != JsonParser::ParseStatus::OK)
    {
        LOG_AND_THROW(InvalidExtensionException, "Could not parse [" + fieldName + "] field of EnclaveIdentity JSON");
    }
}

EnclaveIdentity::EnclaveIdentity(const std::string& jsonString)
{
    JsonParser jsonParser;
    JsonParser::ParseStatus status;
    if(!jsonParser.parse(jsonString))
    {
        LOG_AND_THROW(FormatException, "Could not parse EnclaveIdentity JSON");
    }

    const auto* enclaveIdentity = jsonParser.getField("enclaveIdentity");
    if(enclaveIdentity == nullptr)
    {
        LOG_AND_THROW(FormatException, "Missing [enclaveIdentity] field of EnclaveIdentity JSON");
    }

    if(!enclaveIdentity->IsObject())
    {
        LOG_AND_THROW(FormatException, "[enclaveIdentity] field of EnclaveIdentity JSON should be an object");
    }

    const auto* signatureField = jsonParser.getField("signature");
    if(signatureField == nullptr)
    {
        LOG_AND_THROW(FormatException, "Missing [signature] field of EnclaveIdentity JSON");
    }

    const std::string idFieldName = "id";
    std::string idStr;
    std::tie(idStr, status) = jsonParser.getStringFieldOf(*enclaveIdentity, idFieldName);
    checkParseStatus(status, idFieldName);

    const std::unordered_map<std::string, EnclaveID> stringToIdMap = {
            {"QE", QE},
            {"QVE", QVE},
            {"TD_QE", TD_QE}
    };

    auto foundId = stringToIdMap.find(idStr);
    if (foundId == stringToIdMap.end())
    {
        LOG_AND_THROW(InvalidExtensionException, "EnclaveIdentity [id] field is not a valid value of enclaveId");
    }
    _id = foundId->second;


    const std::string versionFieldName = "version";
    std::tie(_version, status) = jsonParser.getUintFieldOf(*enclaveIdentity, versionFieldName);
    checkParseStatus(status, versionFieldName);

    if(_version != V2)
    {
        LOG_AND_THROW(InvalidVersionException, "EnclaveIdentity [version] field is not supported");
    }

    const std::string issueDateFieldName = "issueDate";
    std::tie(_issueDate, status) = jsonParser.getDateFieldOf(*enclaveIdentity, issueDateFieldName);
    checkParseStatus(status, issueDateFieldName);

    const std::string nextUpdateFieldName = "nextUpdate";
    std::tie(_nextUpdate, status) = jsonParser.getDateFieldOf(*enclaveIdentity, nextUpdateFieldName);
    checkParseStatus(status, nextUpdateFieldName);

    const std::string tcbEvalNumberFieldName = "tcbEvaluationDataNumber";
    std::tie(_tcbEvaluationDataNumber, status) = jsonParser.getUintFieldOf(*enclaveIdentity, tcbEvalNumberFieldName);
    checkParseStatus(status, tcbEvalNumberFieldName);

    const std::string miscselectFieldName = "miscselect";
    std::tie(_miscselect, status) = jsonParser.getBytesFieldOf(*enclaveIdentity, miscselectFieldName, constants::MISCSELECT_BYTE_LEN * 2);
    checkParseStatus(status, miscselectFieldName);

    const std::string miscselectMaskFieldName = "miscselectMask";
    std::tie(_miscselectMask, status) = jsonParser.getBytesFieldOf(*enclaveIdentity, miscselectMaskFieldName, constants::MISCSELECT_BYTE_LEN * 2);
    checkParseStatus(status, miscselectMaskFieldName);

    const std::string attributesFieldName = "attributes";
    std::tie(_attributes, status) = jsonParser.getBytesFieldOf(*enclaveIdentity, attributesFieldName, constants::ATTRIBUTES_BYTE_LEN * 2);
    checkParseStatus(status, attributesFieldName);

    const std::string attributesMaskFieldName = "attributesMask";
    std::tie(_attributesMask, status) = jsonParser.getBytesFieldOf(*enclaveIdentity, attributesMaskFieldName, constants::ATTRIBUTES_BYTE_LEN * 2);
    checkParseStatus(status, attributesMaskFieldName);

    const std::string mrSignerFieldName = "mrsigner";
    std::tie(_mrSigner, status) = jsonParser.getBytesFieldOf(*enclaveIdentity, mrSignerFieldName, constants::MRSIGNER_BYTE_LEN * 2);
    checkParseStatus(status, mrSignerFieldName);

    const std::string isvProdIdFieldName = "isvprodid";
    std::tie(_isvProdId, status) = jsonParser.getUintFieldOf(*enclaveIdentity, isvProdIdFieldName);
    checkParseStatus(status, isvProdIdFieldName);

    if(!signatureField->IsString() || signatureField->GetStringLength() != constants::ECDSA_P256_SIGNATURE_BYTE_LEN * 2)
    {
        LOG_AND_THROW(InvalidExtensionException, "Could not parse [signature] field of EnclaveIdentity JSON to bytes");
    }
    _signature = hexStringToBytes(signatureField->GetString());

    if(!enclaveIdentity->HasMember("tcbLevels"))
    {
        LOG_AND_THROW(InvalidExtensionException, "Missing [tcbLevels] field of EnclaveIdentity JSON");
    }

    const auto& identityTcbs = (*enclaveIdentity)["tcbLevels"];
    if(!identityTcbs.IsArray())
    {
        LOG_AND_THROW(InvalidExtensionException, "[tcbLevels] field of EnclaveIdentity JSON should be a nonempty array");
    }

    for(uint32_t tcbLevelIndex = 0; tcbLevelIndex < identityTcbs.Size(); ++tcbLevelIndex)
    {
        bool inserted = false;
        std::tie(std::ignore, inserted) = _identityTcbLevels.emplace(IdentityTcbLevel(identityTcbs[tcbLevelIndex]));
        if (!inserted)
        {
            LOG_AND_THROW(InvalidExtensionException, "Detected duplicated TCB levels");
        }
    }

    if(_identityTcbLevels.empty())
    {
        LOG_AND_THROW(InvalidExtensionException, "Number of parsed [tcbLevels] should not be 0");
    }

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    enclaveIdentity->Accept(writer);

    _body = std::vector<uint8_t>{ buffer.GetString(),
                                  &buffer.GetString()[buffer.GetSize()] };
}
}}}}}
