/*
 * Copyright (C) 2024 Intel Corporation. All rights reserved.
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

#include "TcbLevelCheck.h"
#include "TDRelaunchCheck.h"
#include "TdxModuleCheck.h"
#include "CertVerification/X509Constants.h"
#include "Utils/StatusUtils.h"
#include "Utils/StatusPrinter.h"

namespace intel::sgx::dcap {

constexpr int CPUSVN_LOWER = false;
constexpr int CPUSVN_EQUAL_OR_HIGHER = true;

static const std::set<std::string> VALID_TCB_INFO_STATUSES =
        {{ "UpToDate", "OutOfDate", "ConfigurationNeeded", "Revoked", "OutOfDateConfigurationNeeded",
           "SWHardeningNeeded", "ConfigurationAndSWHardeningNeeded" }};

bool isCpuSvnHigherOrEqual(const parser::x509::Tcb& tcb,
                           const TcbLevel& tcbLevel)
{
    for(uint32_t index = 0; index < constants::CPUSVN_BYTE_LEN; ++index)
    {
        const auto componentValue = tcb.getSgxTcbComponentSvn(index);
        const auto otherComponentValue = tcbLevel.getSgxTcbComponentSvn(index);
        if(componentValue < otherComponentValue)
        {
            // If *ANY* CPUSVN component is lower, then CPUSVN is considered lower
            return CPUSVN_LOWER;
        }
    }
    // but for CPUSVN to be considered higher it requires that *EVERY* CPUSVN component to be higher or equal
    return CPUSVN_EQUAL_OR_HIGHER;
}

bool isTdxTcbHigherOrEqual(const std::array<uint8_t, 16>& teeTcbSvn,
                           const TcbLevel& tcbLevel)
{
    uint32_t index = 0;
    if (teeTcbSvn[1] > 0)
    {
        index = 2;
    }
    for(; index < constants::CPUSVN_BYTE_LEN; ++index)
    {
        const auto componentValue = teeTcbSvn[index];
        const auto& otherComponentValue = tcbLevel.getTdxTcbComponent(index);
        if(componentValue < otherComponentValue.getSvn())
        {
            // If *ANY* SVN is lower, then TCB level is considered lower
            return false;
        }
    }
    // but for TCB level to be considered higher it requires *EVERY* SVN to be higher or equal
    return true;
}

Status convergeTcbStatusWithQeTcbStatus(Status tcbLevelStatus, Status qeTcbStatus)
{
    if (qeTcbStatus == STATUS_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE)
    {
        LOG_INFO("QE TCB status is \"OutOfDate\" and TCB Level status is \"{}\"",
                 printStatus(tcbLevelStatus));
        if (tcbLevelStatus == STATUS_OK ||
            tcbLevelStatus == STATUS_TCB_SW_HARDENING_NEEDED)
        {
            return STATUS_TCB_OUT_OF_DATE;
        }
        if (tcbLevelStatus == STATUS_TCB_CONFIGURATION_NEEDED ||
            tcbLevelStatus == STATUS_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED)
        {
            return STATUS_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED;
        }
    }
    if (qeTcbStatus == STATUS_SGX_ENCLAVE_REPORT_ISVSVN_REVOKED)
    {
        LOG_INFO("QE TCB status is \"Revoked\"");
        return STATUS_TCB_REVOKED;
    }
    else if (qeTcbStatus == STATUS_SGX_ENCLAVE_REPORT_ISVSVN_NOT_SUPPORTED)
    {
        return STATUS_TCB_NOT_SUPPORTED;
    }
    switch (tcbLevelStatus)
    {
        case STATUS_TCB_TD_RELAUNCH_ADVISED:
        case STATUS_TCB_TD_RELAUNCH_ADVISED_CONFIGURATION_NEEDED:
        case STATUS_TCB_OUT_OF_DATE:
        case STATUS_TCB_REVOKED:
        case STATUS_TCB_CONFIGURATION_NEEDED:
        case STATUS_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED:
        case STATUS_TCB_SW_HARDENING_NEEDED:
        case STATUS_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED:
        case STATUS_TCB_NOT_SUPPORTED:
        case STATUS_OK:
            return tcbLevelStatus;
        default:
            /// 4.1.2.5.18.5
            return STATUS_TCB_UNRECOGNIZED_STATUS;
    }
}

std::tuple<Optional<TcbLevel>, Optional<TcbLevel>>
matchTcbLevels(const std::set<TcbLevel, std::greater<TcbLevel>>& tcbLevels,
               const parser::x509::Tcb& tcb,
               const Optional<std::array<uint8_t, 16>>& teeTcbSvn)
{
    LOG_INFO("PCK TCB - cpuSvn: {}, pceSvn: {}", bytesToHexString(tcb.getCpuSvn()), tcb.getPceSvn());

    Optional<TcbLevel> sgxTcbLevel;
    Optional<TcbLevel> tdxTcbLevel;
    for (const auto& tcbLevel : tcbLevels)
    {
        /// 4.1.2.5.18.1 & 4.1.2.5.18.2
        if(isCpuSvnHigherOrEqual(tcb, tcbLevel) && tcb.getPceSvn() >= tcbLevel.getPceSvn())
        {
            /// 4.1.2.5.18.3
            if (teeTcbSvn.has_value())
            {
                if (!sgxTcbLevel)
                {
                    sgxTcbLevel = tcbLevel;
                    LOG_INFO("Selected SGX TCB Level - sgxSvn: {}, tdxSvn: {}, pceSvn: {}, status: {}",
                             bytesToHexString(sgxTcbLevel->getCpuSvn()),
                             bytesToHexString(tcbComponentsToVectorOfBytes(sgxTcbLevel->getTdxTcbComponents())),
                             sgxTcbLevel->getPceSvn(),
                             sgxTcbLevel->getStatus());
                }

                if (isTdxTcbHigherOrEqual(teeTcbSvn.value(), tcbLevel))
                {
                    tdxTcbLevel = tcbLevel;
                    LOG_INFO("Selected TDX TCB Level - sgxSvn: {}, tdxSvn: {}, pceSvn: {}, status: {}",
                             bytesToHexString(tdxTcbLevel->getCpuSvn()),
                             bytesToHexString(tcbComponentsToVectorOfBytes(tdxTcbLevel->getTdxTcbComponents())),
                             tdxTcbLevel->getPceSvn(),
                             tdxTcbLevel->getStatus());
                    return { sgxTcbLevel, tdxTcbLevel };
                }
            }
            else // deprecated
            {
                LOG_INFO("Selected TCB Level - sgx: {}, pceSvn: {}, status: {},\n"
                         "PCK TCB - cpuSvn: {}, pceSvn: {}",
                         bytesToHexString(tcbLevel.getCpuSvn()),
                         tcbLevel.getPceSvn(),
                         tcbLevel.getStatus(),
                         bytesToHexString(tcb.getCpuSvn()),
                         tcb.getPceSvn());

                return { tcbLevel, tdxTcbLevel };
            }
        }
    }
    return { sgxTcbLevel, tdxTcbLevel };
}

Status checkTcbLevel(const TcbInfo &tcbInfo, const parser::x509::PckCertificate &pckCert, const Quote &quote,
                     const Optional<Status> &qeTcbStatus, Optional<TdxModuleIdentity> &tdxModuleIdentity,
                     dcap::VerificationCollateralInfo& verificationCollateralInfo)
{
    const auto isTdx = tcbInfo.getVersion() >= 3 &&
                       tcbInfo.getId() == parser::json::TcbInfo::TDX_ID &&
                       quote.getHeader().teeType == constants::TEE_TYPE_TDX;

    Optional<std::array<uint8_t, 16>> teeTcbSvn;
    if (isTdx)
    {
        LOG_INFO("TD Report - tdxSvn: {}",
                 bytesToHexString(std::vector<uint8_t>(begin(quote.getTeeTcbSvn()), end(quote.getTeeTcbSvn()))));
        teeTcbSvn = quote.getTeeTcbSvn();
    }
    std::tuple<Optional<TcbLevel>, Optional<TcbLevel>> tcbLevels =
            matchTcbLevels(tcbInfo.getTcbLevels(), pckCert.getTcb(), teeTcbSvn);
    Optional<TcbLevel> sgxTcbLevel = std::get<0>(tcbLevels);
    Optional<TcbLevel> tdxTcbLevel = std::get<1>(tcbLevels);

    if (!sgxTcbLevel)
    {
        LOG_ERROR("SGX TCB Level has not been selected");
        verificationCollateralInfo.setError();
        return STATUS_TCB_NOT_SUPPORTED;
    }

    /// 4.1.2.5.19
    verificationCollateralInfo.addTcbInfoData(tcbInfo, tcbLevels);

    const auto sgxTcbStatus = stringToTcbStatus(sgxTcbLevel->getStatus(), VALID_TCB_INFO_STATUSES);
    if (sgxTcbStatus == STATUS_TCB_REVOKED)
    {
        LOG_ERROR("SGX TCB is revoked"); // do not exit
    }
    if (!isTdx)
    {
        if (qeTcbStatus.has_value())
        {
            return convergeTcbStatusWithQeTcbStatus(sgxTcbStatus, qeTcbStatus.value());
        }
        return sgxTcbStatus;
    }

    // TDX only path below
    if (!tdxTcbLevel)
    {
        LOG_ERROR("TDX TCB Level has not been selected");
        verificationCollateralInfo.setError();
        return STATUS_TCB_NOT_SUPPORTED;
    }
    /// 4.1.2.5.18.4.1
    const auto tdxModuleTcbStatus = checkTdxModuleTcbStatus(tcbInfo, quote, tdxModuleIdentity, verificationCollateralInfo);
    LOG_INFO("TDX Module - TCB Status: {}", printStatus(tdxModuleTcbStatus));
    if (tdxModuleTcbStatus == STATUS_TCB_NOT_SUPPORTED ||
        tdxModuleTcbStatus == STATUS_TDX_MODULE_MISMATCH)
    {
        verificationCollateralInfo.setError();
        return tdxModuleTcbStatus;
    }

    auto tdxTcbStatus = convergeTcbStatusWithTdxModuleStatus(
            stringToTcbStatus(tdxTcbLevel->getStatus(), VALID_TCB_INFO_STATUSES), tdxModuleTcbStatus);
    if (tdxTcbStatus == STATUS_TCB_REVOKED)
    {
        LOG_ERROR("TDX TCB is revoked");
        return tdxTcbStatus;
    }

    /// 4.1.2.5.18.4.3
    if (quote.getBody().bodyType == constants::BODY_TD_REPORT15_TYPE)
    {
        tdxTcbStatus = checkForRelaunch(quote.getTdReport15().teeTcbSvn2, tcbInfo,
                                        sgxTcbStatus, tdxTcbStatus, tdxModuleTcbStatus, qeTcbStatus);
    }

    if (qeTcbStatus.has_value())
    {
        return convergeTcbStatusWithQeTcbStatus(tdxTcbStatus, qeTcbStatus.value());
    }

    return tdxTcbStatus;
}


} // namespace intel::sgx::dcap