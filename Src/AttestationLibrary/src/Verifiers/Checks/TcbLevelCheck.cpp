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

#include "EvaluateTcb.h"
#include "TDRelaunchCheck.h"
#include "TdxModuleCheck.h"
#include "CertVerification/X509Constants.h"
#include "Utils/StatusPrinter.h"

namespace intel::sgx::dcap {

Status checkTcbLevel(const TcbInfo &tcbInfo, const parser::x509::PckCertificate &pckCert, const Quote &quote,
                     const EnclaveIdentity *enclaveIdentity, // optional
                     dcap::VerificationCollateralInfo& verificationCollateralInfo)
{
    Status launchTcbStatus;
    std::time_t launchTcbDate;
    std::vector<std::string> launchAdvisoryIds;

    /// 4.1.2.5.18
    if (quote.getHeader().teeType == dcap::constants::TEE_TYPE_SGX)
    {
        const auto evaluationStatus = sgxEvaluateTCB(pckCert.getTcb().getSgxTcbComponents(),
                                                     pckCert.getTcb().getPceSvn(),
                                                     quote.getQeReport().isvSvn,
                                                     tcbInfo,
                                                     enclaveIdentity,
                                                     launchTcbStatus,
                                                     launchTcbDate,
                                                     launchAdvisoryIds);
        if (evaluationStatus != STATUS_OK)
        {
            return evaluationStatus;
        }
        // copy launch values to current
        verificationCollateralInfo.addCurrentInfo(launchTcbDate, launchAdvisoryIds, printTCBStatus(launchTcbStatus));
    }
    /// 4.1.2.5.19
    else if (quote.getHeader().teeType == dcap::constants::TEE_TYPE_TDX)
    {
        const auto teeTcbSvn = std::vector<uint8_t>(quote.getTeeTcbSvn().begin(), quote.getTeeTcbSvn().end());
        LOG_INFO("TD Report - TdxSvn: {}", bytesToHexString(teeTcbSvn));
        const auto evaluationStatus = tdxEvaluateTCB(pckCert.getTcb().getSgxTcbComponents(),
                                                     pckCert.getTcb().getPceSvn(),
                                                     quote.getQeReport().isvSvn,
                                                     teeTcbSvn,
                                                     tcbInfo,
                                                     enclaveIdentity,
                                                     launchTcbStatus,
                                                     launchTcbDate,
                                                     launchAdvisoryIds);
        if (evaluationStatus != STATUS_OK)
        {
            return evaluationStatus;
        }

        /// 4.1.2.5.1.20
        if (quote.getBody().bodyType >= constants::BODY_TD_REPORT15_TYPE)
        {
            Status currentTcbStatus;
            std::time_t currentTcbDate = {};
            std::vector<std::string> currentAdvisoryIds;

            /// 4.1.2.5.1.20.1
            const auto teeTcbSvn2 = std::vector<uint8_t>(quote.getTeeTcbSvn2().begin(), quote.getTeeTcbSvn2().end());
            LOG_INFO("TD Report - TdxSvn2: {}", bytesToHexString(teeTcbSvn2));
            const auto evaluationStatus2 = tdxEvaluateTCB(pckCert.getTcb().getSgxTcbComponents(),
                                                         pckCert.getTcb().getPceSvn(),
                                                         quote.getQeReport().isvSvn,
                                                         teeTcbSvn2,
                                                         tcbInfo,
                                                         enclaveIdentity,
                                                         currentTcbStatus,
                                                         currentTcbDate,
                                                         currentAdvisoryIds);

            if (evaluationStatus2 != STATUS_OK)
            {
                return evaluationStatus2;
            }

            /// 4.1.2.5.1.20.2
            launchTcbStatus = checkForRelaunch(launchTcbStatus, currentTcbStatus);
            verificationCollateralInfo.addCurrentInfo(currentTcbDate, currentAdvisoryIds, printTCBStatus(currentTcbStatus));
        }
        else
        {
            // copy launch values to current
            verificationCollateralInfo.addCurrentInfo(launchTcbDate, launchAdvisoryIds, printTCBStatus(launchTcbStatus));
        }
    }
    else
    {
        LOG_ERROR("Unknown Quote's TEE type. TCB Level cannot be evaluated");
        return STATUS_UNSUPPORTED_QUOTE_FORMAT;
    }

    verificationCollateralInfo.addLaunchInfo(launchTcbDate, launchAdvisoryIds, printTCBStatus(launchTcbStatus));
    verificationCollateralInfo.addTcbInfoData(tcbInfo);
    verificationCollateralInfo.setFilled();

    return launchTcbStatus;
}


} // namespace intel::sgx::dcap