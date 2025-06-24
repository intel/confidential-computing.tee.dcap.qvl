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

#include "TdxModuleCheck.h"
#include "Utils/StatusPrinter.h"
#include "Utils/StatusUtils.h"

namespace intel::sgx::dcap {

static const std::set<std::string> VALID_MODULE_TCB_STATUSES =
        {{ "UpToDate", "OutOfDate", "Revoked" }};

Optional<TdxModuleIdentity> findTdxModuleIdentity(std::vector<TdxModuleIdentity> tdxModuleIdentities,
                                                       const uint8_t tdxModuleVersion)
{
    const std::string tdxModuleIdentityId = "TDX_" + bytesToHexString({ tdxModuleVersion });

    const auto &found = std::find_if(tdxModuleIdentities.begin(),
                                     tdxModuleIdentities.end(),
                                     [&](const auto &tdxModuleIdentity)
                                     {
                                         std::string id = tdxModuleIdentity.getId();
                                         std::transform(id.begin(), id.end(), id.begin(),
                                                        ::toupper); // convert to uppercase
                                         return (id == tdxModuleIdentityId);
                                     });
    if (found == std::end(tdxModuleIdentities))
    {
        LOG_ERROR("TDX Module - Missing matching Identity ({}) for given TEE TDX version ({})",
                  tdxModuleIdentityId, tdxModuleVersion);
        return {};
    }
    LOG_INFO("TDX Module - Matched Identity ({}) for given TEE TDX version ({})", tdxModuleIdentityId, tdxModuleVersion);
    return *found;
}

Status checkTdxModuleTcbStatus(const TcbInfo &tcbInfo,
                               const Quote &quote,
                               Optional<TdxModuleIdentity> &tdxModuleIdentity,
                               VerificationCollateralInfo& verificationCollateralInfo)
{
    const auto &tdxModuleVersion = quote.getTeeTcbSvn()[1];
    const auto &tdxModuleIsvSvn = quote.getTeeTcbSvn()[0];

    if (quote.getHeader().version > constants::QUOTE_VERSION_3 && tdxModuleVersion == 0)
    {
        return STATUS_OK;
    }
    const std::string tdxModuleIdentityId = "TDX_" + bytesToHexString({ tdxModuleVersion });
    if (!tdxModuleIdentity || tdxModuleIdentity->getId() != tdxModuleIdentityId)
    {
        tdxModuleIdentity = findTdxModuleIdentity(tcbInfo.getTdxModuleIdentities(), tdxModuleVersion);
    }
    if (!tdxModuleIdentity)
    {
        return STATUS_TDX_MODULE_MISMATCH;
    }

    const auto &tdxModuleTcbLevel = std::find_if(tdxModuleIdentity->getTcbLevels().begin(),
                                                 tdxModuleIdentity->getTcbLevels().end(),
                                                 [&](const auto &moduleTcbLevel)
                                                 {
                                                     return tdxModuleIsvSvn >= moduleTcbLevel.getTcb().getIsvSvn();
                                                 });
    if (tdxModuleTcbLevel == std::end(tdxModuleIdentity->getTcbLevels()))
    {
        LOG_ERROR("TDX Module - Could not match to any TCB Level for TDX Module ISVSVN({})", tdxModuleIsvSvn);
        return STATUS_TCB_NOT_SUPPORTED;
    }
    LOG_INFO("TDX Module - Matched to Identity TCB Level with ISVSVN({}) and status({}) from ID({})",
             tdxModuleTcbLevel->getTcb().getIsvSvn(), tdxModuleTcbLevel->getStatus(), tdxModuleIdentity->getId());

    /// 4.1.2.5.19
    verificationCollateralInfo.addTdxModuleData(*tdxModuleTcbLevel);

    return stringToTcbStatus(tdxModuleTcbLevel->getStatus(), VALID_MODULE_TCB_STATUSES);
}

Status convergeTcbStatusWithTdxModuleStatus(Status tcbLevelStatus, Status tdxModuleStatus)
{
    if (tdxModuleStatus == STATUS_TCB_OUT_OF_DATE)
    {
        LOG_INFO("TDX Module TCB status is \"OutOfDate\" and TCB Level status is \"{}\"",
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
    if (tdxModuleStatus == STATUS_TCB_REVOKED)
    {
        LOG_INFO("TDX Module TCB status is \"Revoked\"");
        return STATUS_TCB_REVOKED;
    }

    switch (tcbLevelStatus)
    {
        case STATUS_TCB_OUT_OF_DATE:
        case STATUS_TCB_REVOKED:
        case STATUS_TCB_CONFIGURATION_NEEDED:
        case STATUS_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED:
        case STATUS_TCB_SW_HARDENING_NEEDED:
        case STATUS_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED:
        case STATUS_OK:
            return tcbLevelStatus;
        default:
            return STATUS_TCB_UNRECOGNIZED_STATUS;
    }
}

} // namespace intel::sgx::dcap