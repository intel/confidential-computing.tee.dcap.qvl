/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "TcbInfoJsonGenerator.h"
#include <iomanip>
#include <sstream>
#include "OpensslHelpers/Bytes.h"

static std::string getTcb(std::array<int, 16> tcb)
{
    std::string sgxtcbcompXXsvn;
    std::string sgxtcbcomp = R"("sgxtcbcomp)";
    std::string svn = R"(svn")";
    std::stringstream number;
    std::string result;

    for(uint32_t i = 0; i < tcb.size(); i++)
    {
        number << std::setw(2) << std::setfill('0') << i + 1;
        sgxtcbcompXXsvn = sgxtcbcomp + number.str() + svn;
        result += sgxtcbcompXXsvn + ":" + std::to_string(tcb[i]) + R"(,)";
        number.str("");
    }

    return result;
}

static std::string getTcbLevelsV1(std::array<int, 16> tcb, int pcesvn, std::string status)
{
    std::string result;
    result = R"([{"tcb":{)" + getTcb(tcb) + R"("pcesvn":)" + std::to_string(pcesvn);
    result += R"(},"status":")" + status + R"("}]})";

    return result;
}

static std::string getTcbLevels(std::array<int, 16> tcb, int pcesvn, std::string status, std::string tcbDate)
{
    std::string result;
    result = R"([{"tcb":{)" + getTcb(tcb) + R"("pcesvn":)" + std::to_string(pcesvn);
    result += R"(},"tcbDate":")" + tcbDate;
    result += R"(","tcbStatus":")" + status + R"("}]})";

    return result;
}

static std::string getTcbComponents(std::array<TcbComponent, 16> components)
{
    std::string result = "[";
    for(auto it = components.begin(); it != components.end(); it++)
    {
        auto component = *it;
        result += R"({"svn":)" + std::to_string(component.svn);
        if(!component.category.empty())
        {
            result += R"(,"category":")" + component.category + R"(")";
        }
        if(!component.type.empty())
        {
            result += R"(,"type":")" + component.type + R"(")";
        }
        result += "},";
    }
    result = result.substr(0, result.length() - 1) + "]";
    return result;
}

static std::string getAdvisoryIds(std::vector<std::string> advisoryIds)
{
    std::string result = "[";
    for (auto& advisory : advisoryIds)
    {
        result += R"(")" + advisory + R"(",)";
    }
    if (!advisoryIds.empty())
    {
        result.pop_back(); // remove last comma
    }
    return result + "]";
}

static std::string getTcbLevels(std::string id, std::vector<TcbLevelV3> tcbLevels)
{
    std::string result = "[";
    for(auto it = tcbLevels.begin(); it != tcbLevels.end(); it++)
    {
        auto tcbLevel = *it;
        result += R"({"tcb":{"sgxtcbcomponents":)" + getTcbComponents(tcbLevel.sgxTcbComponents);
        if(id == "TDX")
        {
            result += R"(,"tdxtcbcomponents":)" + getTcbComponents(tcbLevel.tdxTcbComponents);
        }
        result += R"(,"pcesvn":)" + std::to_string(tcbLevel.pcesvn);
        result += R"(},"tcbDate":")" + tcbLevel.tcbDate;
        result += R"(","tcbStatus":")" + tcbLevel.tcbStatus;
        result += R"(","advisoryIDs":)" + getAdvisoryIds(tcbLevel.advisoryIds);
        result += R"(},)";
    }
    result = result.substr(0, result.length() - 1) + "]";
    return result;
}

std::string tcbInfoJsonV2Body(uint32_t version, std::string issueDate, std::string nextUpdate, std::string fmspc,
                              std::string pceId, std::array<int, 16> tcb, uint16_t pcesvn, std::string tcbStatus,
                              uint32_t tcbType, uint32_t tcbEvaluationDataNumber, std::string tcbDate)
{
    std::string result;
    result = R"({"version":)" + std::to_string(version) + + R"(,"issueDate":")" + issueDate;
    result += R"(","nextUpdate":")" + nextUpdate + R"(","fmspc":")" + fmspc + R"(","pceId":")" + pceId;
    result += R"(","tcbType":)" + std::to_string(tcbType);
    result += R"(,"tcbEvaluationDataNumber":)" + std::to_string(tcbEvaluationDataNumber);
    result += R"(,"tcbLevels":)" + getTcbLevels(tcb, pcesvn, tcbStatus, tcbDate);

    return result;
}

std::string tcbInfoJsonV3Body(std::string id, uint32_t version, std::string issueDate, std::string nextUpdate,
                              std::string fmspc, std::string pceId, uint32_t tcbType, uint32_t tcbEvaluationDataNumber,
                              std::vector<TcbLevelV3> tcbLevels, bool includeTdxModule, TdxModule tdxModule,
                              bool includeTdxModuleIdentities, std::vector<TdxModuleIdentity> tdxModuleIdentities)
{
    std::string result;
    result = R"({"id":")" + id;
    result += R"(","version":)" + std::to_string(version) + + R"(,"issueDate":")" + issueDate;
    result += R"(","nextUpdate":")" + nextUpdate + R"(","fmspc":")" + fmspc + R"(","pceId":")" + pceId;
    result += R"(","tcbType":)" + std::to_string(tcbType);
    result += R"(,"tcbEvaluationDataNumber":)" + std::to_string(tcbEvaluationDataNumber);

    if (includeTdxModule)
    {
        result += R"(,"tdxModule":{"mrsigner":")" + intel::sgx::dcap::bytesToHexString(tdxModule.mrsigner) + R"(","attributes":")"
                + intel::sgx::dcap::bytesToHexString(tdxModule.attributes) + R"(","attributesMask":")" + intel::sgx::dcap::bytesToHexString(tdxModule.attributesMask)
                + R"("})";
    }

    if (includeTdxModuleIdentities)
    {
        result += R"(,"tdxModuleIdentities":[)";
        for (auto& tdxModuleIdentity : tdxModuleIdentities)
        {
            result += R"({"id":")" + tdxModuleIdentity.id + R"(","mrsigner":")" + tdxModuleIdentity.mrsigner;
            result += R"(","attributes":")" + tdxModuleIdentity.attributes + R"(","attributesMask":")" + tdxModuleIdentity.attributesMask;
            result += R"(","tcbLevels":[)";
            for (auto& tdxModuleTcbLevel : tdxModuleIdentity.tcbLevels)
            {
                result += R"({"tcb":{"isvsvn":)" + std::to_string(tdxModuleTcbLevel.isvsvn);
                result += R"(},"tcbDate":")" + tdxModuleTcbLevel.tcbDate;
                result += R"(","tcbStatus":")" + tdxModuleTcbLevel.tcbStatus;
                result += R"(","advisoryIDs":)" + getAdvisoryIds(tdxModuleTcbLevel.advisoryIds);
                result += R"(},)";
            }
            if (!tdxModuleIdentity.tcbLevels.empty())
            {
                result.pop_back(); // remove last comma
            }
            result += R"(]},)";
        }
        if (!tdxModuleIdentities.empty())
        {
            result.pop_back(); // remove last comma
        }
        result += R"(])";
    }

    result += R"(,"tcbLevels":)" + getTcbLevels(id, tcbLevels) + "}";
    return result;
}

std::string tcbInfoJsonGenerator(int version, std::string issueDate, std::string nextUpdate, std::string fmspc,
                                 std::string pceId, std::array<int, 16> tcb, int pcesvn, std::string status,
                                 std::string signature)
{
    std::string result;
    result = R"({"tcbInfo":{"version":)" + std::to_string(version) + + R"(,"issueDate":")" + issueDate;
    result += R"(","nextUpdate":")" + nextUpdate + R"(","fmspc":")" + fmspc + R"(","pceId":")" + pceId;
    result += R"(","tcbLevels":)" + getTcbLevelsV1(tcb, pcesvn, status) + R"(,"signature":")" + signature + R"("})";

    return result;
}

std::string tcbInfoJsonGenerator(std::string tcbInfoBody, std::string signature)
{
    std::string result;
    result = R"({"tcbInfo":)" + tcbInfoBody + R"(,"signature":")" + signature + R"("})";

    return result;
}

std::array<int, 16> getRandomTcb()
{
    std::array<int, 16> tcb;
    for(unsigned long i = 0; i < 16; i ++)
    {
        tcb[i] = (rand() % 255) + 1;
    }

    return tcb;
}

std::array<TcbComponent, 16> getRandomTcbComponent()
{
    std::array<TcbComponent, 16> tcbComponents;
    for(unsigned long i = 0; i < 16; i ++)
    {
        tcbComponents[i].svn = static_cast<uint8_t>(rand() % 255);
        tcbComponents[i].category = "category" + std::to_string(rand() % 255);
        tcbComponents[i].type = "type" + std::to_string(rand() % 255);
    }
    return tcbComponents;
}