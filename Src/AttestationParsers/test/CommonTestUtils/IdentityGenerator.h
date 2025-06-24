/*
 * Copyright (C) 2024 Intel Corporation
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

#ifndef SGXECDSAATTESTATION_IDENTITYGENERATOR_H
#define SGXECDSAATTESTATION_IDENTITYGENERATOR_H

#include <random>
#include <string>
#include <array>
#include <utility>
#include <vector>
#include "OpensslHelpers/Bytes.h"

namespace
{
    uint8_t getRandomNumber()
    {
        return (uint8_t)((rand() % 9) + 1);
    }

    std::vector<uint8_t> generateRandomUint8Vector(std::size_t SIZE)
    {
        std::vector<uint8_t> vector;
        std::default_random_engine generator;
        std::uniform_int_distribution<uint32_t > distribution(0, UINT8_MAX);
        for(size_t i = 0; i < SIZE; i++)
        {
            vector.push_back(static_cast<unsigned char>(distribution(generator)));
        }
        return vector;
    }
}

namespace intel { namespace sgx { namespace dcap { namespace test {

struct IdentityTcbLevelModel {
    uint16_t isvsvn = 0;
    std::string tcbDate;
    std::string tcbStatus = "UpToDate";
    std::vector<std::string> advisoryIds{};
};

class IdentityVectorModel {
public:
    virtual ~IdentityVectorModel() = default;
    int version;
    std::string issueDate;
    std::string nextUpdate;
    std::vector<uint8_t> attributes;
    std::vector<uint8_t> attributesMask;
    std::vector<uint8_t> mrsigner;
    std::string id;
    uint32_t tcbEvaluationDataNumber = 1;
    std::vector<IdentityTcbLevelModel> tcbLevels;

    IdentityVectorModel(std::string tcbDate) {
        issueDate = "2018-08-22T10:09:10Z";
        nextUpdate = "2118-08-23T10:09:10Z";
        tcbLevels.push_back({6, tcbDate, "UpToDate"});
        tcbLevels.push_back({5, tcbDate, "OutOfDate"});
        tcbLevels.push_back({4, tcbDate, "Revoked"});
    }

    virtual std::string toJSON() = 0;
};

class EnclaveIdentityVectorModel : public IdentityVectorModel
{
public:
    std::vector<uint8_t> miscselect;
    std::vector<uint8_t> miscselectMask;
    uint8_t isvprodid;
    EnclaveIdentityVectorModel(std::string tcbDate = "2018-08-22T10:09:10Z"): IdentityVectorModel(tcbDate) {
        id = "QE";
        version = 2;
        isvprodid = getRandomNumber();
        attributes = generateRandomUint8Vector(16);
        mrsigner = generateRandomUint8Vector(32);
        miscselect = generateRandomUint8Vector(4);
        miscselectMask = miscselect;
        attributesMask = attributes;
    }
    std::string toJSON() override;
};

struct IdentityTcbLevelStringModel {
    std::string isvsvn = "0";
    std::string tcbDate;
    std::string tcbStatus = "UpToDate";
    std::vector<std::string> advisoryIds{};
};
class IdentityStringModel
{
public:
    virtual ~IdentityStringModel() = default;
    std::string id;
    std::string version;
    std::string issueDate;
    std::string nextUpdate;
    std::string attributes;
    std::string attributesMask;
    std::string mrsigner;
    std::string tcbEvaluationDataNumber;
    std::vector<IdentityTcbLevelStringModel> tcbLevels;

    explicit IdentityStringModel(const IdentityVectorModel& vectorModel) {
        id = vectorModel.id;
        version = std::to_string(vectorModel.version);
        issueDate = vectorModel.issueDate;
        nextUpdate = vectorModel.nextUpdate;
        attributes = bytesToHexString(vectorModel.attributes);
        attributesMask = bytesToHexString(vectorModel.attributesMask);
        mrsigner = bytesToHexString(vectorModel.mrsigner);
        for(const auto& tcbLevel : vectorModel.tcbLevels)
        {
            tcbLevels.push_back({
                                        std::to_string(tcbLevel.isvsvn),
                                        tcbLevel.tcbDate,
                                        tcbLevel.tcbStatus
                                });
        }
        tcbEvaluationDataNumber = std::to_string(vectorModel.tcbEvaluationDataNumber);
    }

    virtual std::string toJSON() = 0;
};

class EnclaveIdentityStringModel : public IdentityStringModel
{
public:
    std::string miscselect;
    std::string miscselectMask;

    std::string isvprodid;
    std::vector<IdentityTcbLevelStringModel> tcbLevels;

    EnclaveIdentityStringModel(std::string tcbDate = "2018-08-22T10:09:10Z") : EnclaveIdentityStringModel(EnclaveIdentityVectorModel(tcbDate))
    {}

    explicit EnclaveIdentityStringModel(const EnclaveIdentityVectorModel& vectorModel)
            : IdentityStringModel(vectorModel)
    {
        miscselect = bytesToHexString(vectorModel.miscselect);
        miscselectMask = bytesToHexString(vectorModel.miscselectMask);
        isvprodid = std::to_string(vectorModel.isvprodid);
        for(const auto& tcbLevel : vectorModel.tcbLevels)
        {
            tcbLevels.push_back({
                                        std::to_string(tcbLevel.isvsvn),
                                        tcbLevel.tcbDate,
                                        tcbLevel.tcbStatus
                                });
        }
        tcbEvaluationDataNumber = std::to_string(vectorModel.tcbEvaluationDataNumber);
    }

    std::string toJSON() override;
};

uint32_t vectorToUint32(const std::vector<uint8_t> &input);

const std::string validEnclaveIdentityTemplate = R"json({
    "id": "QE",
    "version": 2,
    "issueDate": "2018-10-04T11:10:45Z",
    "nextUpdate": "2019-06-21T12:36:02Z",
    "tcbEvaluationDataNumber":0,
    "miscselect": "8fa64472",
    "miscselectMask": "0000fffa",
    "attributes": "1254863548af4a6b2fcc2d3244784452",
    "attributesMask": "ffffffffffffffffffffffffffffffff",
    "mrsigner": "aaff34ffa51981951a61d616b16c16f1651c6516e51f651d26a6166ed5679c79",
    "isvprodid": 3,
    "tcbLevels": [
        {
            "tcb":{ "isvsvn":6 },
            "tcbDate":"2019-06-23T10:41:29Z",
            "tcbStatus":"UpToDate"
        },
        {
            "tcb":{ "isvsvn":5 },
            "tcbDate":"2019-06-23T10:41:29Z",
            "tcbStatus":"OutOfDate"
        },
        {
            "tcb":{ "isvsvn":4 },
            "tcbDate":"2019-06-23T10:41:29Z",
            "tcbStatus":"Revoked"
        }
    ]
})json";
        const std::string validTDIdentityTemplate = R"json({
    "id": "QTD",
    "version": 1,
    "issueDate": "2018-10-04T11:10:45Z",
    "nextUpdate": "2019-06-21T12:36:02Z",
    "tcbEvaluationDataNumber":0,
    "xfam": "8fa64472",
    "xfamMask": "0000fffa",
    "attributes": "1254863548af4a6b",
    "attributesMask": "ffffffffffffffff",
    "mrsigner": "aaff34ffa51981951a61d616b16c16f1651c6516e51f651d26a6166ed5679c79651c6516e51f651d26a6166ed5679c79",
    "isvprodid": "aaff34ffa51981951a61d616b16c16f1",
    "mrConfigId": "aaff34ffa51981951a61d616b16c16f1651c6516e51f651d26a6166ed5679c79651c6516e51f651d26a6166ed5679c79",
    "mrOwner": "aaff34ffa51981951a61d616b16c16f1651c6516e51f651d26a6166ed5679c79651c6516e51f651d26a6166ed5679c79",
    "mrOwnerConfigId": "aaff34ffa51981951a61d616b16c16f1651c6516e51f651d26a6166ed5679c79651c6516e51f651d26a6166ed5679c79",
    "tcbLevels": [
        {
            "tcb":{ "isvsvn":6 },
            "tcbDate":"2019-06-23T10:41:29Z",
            "tcbStatus":"UpToDate"
        },
        {
            "tcb":{ "isvsvn":5 },
            "tcbDate":"2019-06-23T10:41:29Z",
            "tcbStatus":"OutOfDate"
        },
        {
            "tcb":{ "isvsvn":4 },
            "tcbDate":"2019-06-23T10:41:29Z",
            "tcbStatus":"Revoked"
        }
    ]
})json";
const std::string validSignatureTemplate = "fb1530326344ee4baded1120a7a07b1c7c46941cf5f8abff36a63492610e17f5b9d0f8f8b4b9bf06932e1220a74b72e2ab27d14d8bbfe69334046b38363bb568";

std::string enclaveIdentityJsonWithSignature(const std::string &qeIdentityBody = validEnclaveIdentityTemplate, const std::string &signature = validSignatureTemplate);
void removeWordFromString(std::string word, std::string &input);

}}}}

#endif //SGXECDSAATTESTATION_IDENTITYGENERATOR_H