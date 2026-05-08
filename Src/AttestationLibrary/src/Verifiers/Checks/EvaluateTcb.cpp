/*
* Copyright (C) 2026 Intel Corporation. All rights reserved.
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

#include "EvaluateTcb.h"

#include <array>
#include <unordered_map>
#include <algorithm> // std::min_element, max_element for windows

#include "CertVerification/X509Constants.h"
#include "TdxModuleCheck.h" // findTdxModuleIdentity
#include "Utils/RuntimeException.h"
#include "Utils/StatusPrinter.h"

using namespace intel::sgx::dcap::parser::json;

namespace intel::sgx::dcap
{

enum class EvaluationStatus
{
    NotSupported,
    UpToDate,
    OutOfDate,
    ConfigurationNeeded,
    Revoked,
    OutOfDateConfigurationNeeded,
    SWHardeningNeeded,
    ConfigurationAndSWHardeningNeeded,
    TdRelaunchAdvised,
    TdRelaunchAdvisedConfigurationNeeded,
};

static const std::unordered_map<EvaluationStatus, Status> EVALUATION_STATUS_TO_STATUS_MAP = {
    { EvaluationStatus::NotSupported, STATUS_TCB_NOT_SUPPORTED },
    { EvaluationStatus::UpToDate, STATUS_OK },
    { EvaluationStatus::OutOfDate, STATUS_TCB_OUT_OF_DATE },
    { EvaluationStatus::ConfigurationNeeded, STATUS_TCB_CONFIGURATION_NEEDED },
    { EvaluationStatus::Revoked, STATUS_TCB_REVOKED },
    { EvaluationStatus::OutOfDateConfigurationNeeded, STATUS_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED },
    { EvaluationStatus::SWHardeningNeeded, STATUS_TCB_SW_HARDENING_NEEDED },
    { EvaluationStatus::ConfigurationAndSWHardeningNeeded, STATUS_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED },
    { EvaluationStatus::TdRelaunchAdvised, STATUS_TCB_TD_RELAUNCH_ADVISED },
    { EvaluationStatus::TdRelaunchAdvisedConfigurationNeeded, STATUS_TCB_TD_RELAUNCH_ADVISED_CONFIGURATION_NEEDED }
};

static const std::unordered_map<TcbStatus, EvaluationStatus> VALID_QE_STATUSES = {
    { TcbStatus::UpToDate, EvaluationStatus::UpToDate },
    { TcbStatus::OutOfDate, EvaluationStatus::OutOfDate },
    { TcbStatus::ConfigurationNeeded, EvaluationStatus::ConfigurationNeeded },
    { TcbStatus::Revoked, EvaluationStatus::Revoked },
    { TcbStatus::OutOfDateConfigurationNeeded, EvaluationStatus::OutOfDateConfigurationNeeded },
};

static const std::unordered_map<std::string, EvaluationStatus> VALID_TCB_INFO_STATUSES = {
    { "UpToDate", EvaluationStatus::UpToDate },
    { "OutOfDate", EvaluationStatus::OutOfDate },
    { "ConfigurationNeeded", EvaluationStatus::ConfigurationNeeded },
    { "Revoked", EvaluationStatus::Revoked },
    { "OutOfDateConfigurationNeeded", EvaluationStatus::OutOfDateConfigurationNeeded },
    { "SWHardeningNeeded", EvaluationStatus::SWHardeningNeeded },
    { "ConfigurationAndSWHardeningNeeded", EvaluationStatus::ConfigurationAndSWHardeningNeeded }
};

static const std::unordered_map<EvaluationStatus, std::string> EVALUATION_STATUS_TO_STRING = {
    { EvaluationStatus::UpToDate, "UpToDate" },
    { EvaluationStatus::OutOfDate, "OutOfDate" },
    { EvaluationStatus::ConfigurationNeeded, "ConfigurationNeeded" },
    { EvaluationStatus::Revoked, "Revoked" },
    { EvaluationStatus::OutOfDateConfigurationNeeded, "OutOfDateConfigurationNeeded" },
    { EvaluationStatus::SWHardeningNeeded, "SWHardeningNeeded" },
    { EvaluationStatus::ConfigurationAndSWHardeningNeeded, "ConfigurationAndSWHardeningNeeded" }
};

static const std::unordered_map<std::string, EvaluationStatus> VALID_TDX_MODULE_STATUSES = {
    { "UpToDate", EvaluationStatus::UpToDate },
    { "OutOfDate", EvaluationStatus::OutOfDate },
    { "Revoked" , EvaluationStatus::Revoked }
};

static constexpr uint16_t TDX_MODULE_MAJOR_SVN_INDEX = 1; // aka TDX_MODULE_VERSION_INDEX
static constexpr uint16_t TDX_MODULE_MINOR_SVN_INDEX = 0;

template <class KeyT, class MapT>
EvaluationStatus mapToEvaluationStatusOrThrow(const KeyT& key, const MapT& mapping)
{
    // KeyT is the key type used to query `mapping` (string, enum class, etc.)
    const auto it = mapping.find(key);
    if (it == mapping.end())
    {
        LOG_ERROR("TCB status of this structure is unrecognized");
        throw RuntimeException(STATUS_TCB_UNRECOGNIZED_STATUS);
    }

    return it->second;
}

template <class T>
std::vector<T> concat_copy(const std::vector<T>& a, const std::vector<T>& b, const std::vector<T>& c)
{
    std::vector<T> out;
    out.reserve(a.size() + b.size() + c.size()); // allocate once
    out.insert(out.end(), a.begin(), a.end()); // copies from a
    out.insert(out.end(), b.begin(), b.end()); // copies from b
    out.insert(out.end(), c.begin(), c.end()); // copies from c
    return out; // NRVO / move
}

bool areSvnsHigherOrEqual(const std::vector<uint8_t>& tcbComponents,
                          const std::vector<TcbComponent>& tcbLevelComponents,
                          const uint32_t start_index=0) // throws std::out_of_range
{
    for(uint32_t index = start_index; index < constants::CPUSVN_BYTE_LEN; ++index)
    {
        const auto& componentValue = tcbComponents.at(index); // throws std::out_of_range
        const auto& otherComponentValue = tcbLevelComponents.at(index).getSvn(); // throws std::out_of_range
        if(componentValue < otherComponentValue)
        {
            // If *ANY* CPUSVN component is lower, then CPUSVN is considered lower
            return false;
        }
    }
    // but for CPUSVN to be considered higher it requires that *EVERY* CPUSVN component to be higher or equal
    return true;
}

// Helper function to safely get evaluation status string
static inline std::string getEvaluationStatusString(const EvaluationStatus status)
{
    const auto it = EVALUATION_STATUS_TO_STRING.find(status);
    if (it != EVALUATION_STATUS_TO_STRING.end())
    {
        return it->second;
    }
    return "Unknown";
}

// Applies QE identity TCB level lookup and appends results to componentStatuses, tcbDates, and qeAdvisoryIds.
// throws StatusNotSupportedException if no TCB level found for the given QE SVN
static void applyQeIdentity(const EnclaveIdentity* qeIdentity,
                            const uint16_t qeSvn,
                            std::vector<EvaluationStatus>& componentStatuses,
                            std::vector<std::time_t>& tcbDates,
                            std::vector<std::string>& qeAdvisoryIds)
{
    if (!qeIdentity)
    {
        return;
    }
    const auto& tcbLevel = qeIdentity->getTcbLevel(qeSvn); // throws StatusNotSupportedException if no TCB level found for the given QE SVN
    componentStatuses.push_back(mapToEvaluationStatusOrThrow(tcbLevel.getTcbStatus(), VALID_QE_STATUSES));
    tcbDates.push_back(tcbLevel.getTcbDate());
    qeAdvisoryIds = tcbLevel.getAdvisoryIds();
}

Status convergeTcbStatuses(const EvaluationStatus platformTcbStatus, const std::vector<EvaluationStatus>& componentStatuses)
{
    const bool anyOutOfDate =
    std::any_of(componentStatuses.begin(), componentStatuses.end(),
                [](const EvaluationStatus s) { return s == EvaluationStatus::OutOfDate; });

    const bool anyRevoked =
        std::any_of(componentStatuses.begin(), componentStatuses.end(),
                    [](const EvaluationStatus s) { return s == EvaluationStatus::Revoked; });

    EvaluationStatus effectiveStatus = platformTcbStatus;
    if (anyOutOfDate)
    {
        LOG_INFO("Component status is \"OutOfDate\" and TCB Level status is \"{}\"",
                 getEvaluationStatusString(platformTcbStatus));
        if (platformTcbStatus == EvaluationStatus::UpToDate ||
            platformTcbStatus == EvaluationStatus::SWHardeningNeeded)
        {
            effectiveStatus = EvaluationStatus::OutOfDate;
        }
        if (platformTcbStatus == EvaluationStatus::ConfigurationNeeded ||
            platformTcbStatus == EvaluationStatus::ConfigurationAndSWHardeningNeeded)
        {
            effectiveStatus = EvaluationStatus::OutOfDateConfigurationNeeded;
        }
    }
    if (anyRevoked)
    {
        LOG_INFO("Component status is \"Revoked\"");
        effectiveStatus = EvaluationStatus::Revoked;
    }

    const auto tcbStatusIt = EVALUATION_STATUS_TO_STATUS_MAP.find(effectiveStatus);
    if (tcbStatusIt == EVALUATION_STATUS_TO_STATUS_MAP.end())
    {
        return STATUS_TCB_UNRECOGNIZED_STATUS;
    }

    return tcbStatusIt->second;
}

// Writes the converged tcbStatus, minimum tcbDate, and merged advisoryIds, then returns STATUS_OK.
static Status finalizeTcbEvaluation(const EvaluationStatus platformTcbStatus,
                                    const std::vector<EvaluationStatus>& componentStatuses,
                                    const std::vector<std::time_t>& tcbDates,
                                    const std::vector<std::string>& platformAdvisoryIds,
                                    const std::vector<std::string>& qeAdvisoryIds,
                                    const std::vector<std::string>& extraAdvisoryIds,
                                    Status& tcbStatus,
                                    std::time_t& tcbDate,
                                    std::vector<std::string>& advisoryIds)
{
    tcbStatus  = convergeTcbStatuses(platformTcbStatus, componentStatuses);
    tcbDate    = *std::min_element(tcbDates.begin(), tcbDates.end());
    advisoryIds = concat_copy(platformAdvisoryIds, qeAdvisoryIds, extraAdvisoryIds);
    return STATUS_OK;
}

// 4.1.2.5.1
Status sgxEvaluateTCB(const std::vector<uint8_t>& tcbComponents, // in
                      const uint32_t pceSvn, // in
                      const uint16_t qeSvn, // in
                      const TcbInfo& tcbInfo, // in
                      const EnclaveIdentity* qeIdentity, // in
                      Status& tcbStatus, // out
                      std::time_t& tcbDate, // out
                      std::vector<std::string>& advisoryIds) // out
{
    try
    {
        std::time_t platformTcbDate = 0;
        auto platformTcbStatus = EvaluationStatus::NotSupported;
        std::vector<std::string> platformAdvisoryIds = {};

        // 4.1.2.5.1.1
        for (const auto& tcbLevel : tcbInfo.getTcbLevels())
        {
            // 4.1.2.5.1.1.1
            if (areSvnsHigherOrEqual(tcbComponents, tcbLevel.getSgxTcbComponents()))
            {
                // 4.1.2.5.1.1.2
                if (pceSvn >= tcbLevel.getPceSvn())
                {
                    // 4.1.2.5.1.1.3
                    platformTcbDate = tcbLevel.getTcbDate();
                    platformTcbStatus = mapToEvaluationStatusOrThrow(tcbLevel.getStatus(), VALID_TCB_INFO_STATUSES);
                    platformAdvisoryIds = tcbLevel.getAdvisoryIDs();
                    break;
                }
            }
        }

        if (platformTcbStatus == EvaluationStatus::NotSupported)
        {
            LOG_ERROR("SGX Platform TCB status not matched");
            return STATUS_TCB_NOT_SUPPORTED;
        }

        std::vector<EvaluationStatus> componentStatuses = {};
        std::vector<std::time_t> tcbDates = { platformTcbDate };
        std::vector<std::string> qeAdvisoryIds = {};

        // 4.1.2.5.1.2: 4.1.2.5.1.2.1 && 4.1.2.5.1.2.2
        applyQeIdentity(qeIdentity, qeSvn, componentStatuses, tcbDates, qeAdvisoryIds);

        // 4.1.2.5.1.3, 4.1.2.5.1.4, 4.1.2.5.1.5, 4.1.2.5.1.6
        return finalizeTcbEvaluation(platformTcbStatus, componentStatuses, tcbDates,
                                     platformAdvisoryIds, qeAdvisoryIds, {},
                                     tcbStatus, tcbDate, advisoryIds);
    }
    catch (const std::exception &e) // std::out_of_range/StatusNotSupportedException, but also to catch any other unexpected exception
    {
        LOG_ERROR("Error while evaluating SGX TCB: {}", e.what());
        return STATUS_TCB_NOT_SUPPORTED;
    }
}

// 4.1.2.5.2
Status tdxEvaluateTCB(const std::vector<uint8_t>& tcbComponents, // in
                      const uint32_t pceSvn, // in
                      const uint16_t qeSvn, // in
                      const std::vector<uint8_t>& teeTcbSvns, // in
                      const TcbInfo& tcbInfo, // in
                      const EnclaveIdentity* qeIdentity, // in optional
                      Status& tcbStatus, // out
                      std::time_t& tcbDate, // out
                      std::vector<std::string>& advisoryIds) // out
{
    try
    {
        std::time_t platformTcbDate = 0;
        auto platformTcbStatus = EvaluationStatus::NotSupported;
        std::vector<std::string> platformAdvisoryIds = {};
        const uint32_t start_index = teeTcbSvns.at(TDX_MODULE_MAJOR_SVN_INDEX) > 0 ? 2 : 0; // throws std::out_of_range

        // 4.1.2.5.2.1
        for (const auto& tcbLevel : tcbInfo.getTcbLevels())
        {
            // 4.1.2.5.2.1.1
            if (areSvnsHigherOrEqual(tcbComponents, tcbLevel.getSgxTcbComponents()))
            {
                // 4.1.2.5.2.1.2
                if (pceSvn >= tcbLevel.getPceSvn())
                {
                    // 4.1.2.5.2.1.3
                    if (areSvnsHigherOrEqual(teeTcbSvns, tcbLevel.getTdxTcbComponents(), start_index))
                    {
                        // 4.1.2.5.2.1.4
                        platformTcbDate = tcbLevel.getTcbDate();
                        platformTcbStatus = mapToEvaluationStatusOrThrow(tcbLevel.getStatus(), VALID_TCB_INFO_STATUSES);
                        platformAdvisoryIds = tcbLevel.getAdvisoryIDs();
                        break;
                    }
                }
            }
        }

        if (platformTcbStatus == EvaluationStatus::NotSupported)
        {
            LOG_ERROR("TDX Platform TCB status not matched");
            return STATUS_TCB_NOT_SUPPORTED;
        }

        std::vector<EvaluationStatus> componentStatuses = {};
        std::vector<std::time_t> tcbDates = { platformTcbDate };
        std::vector<std::string> tdxModuleAdvisoryIds = {};

        // 4.1.2.5.2.2
        const auto tdxModuleVersion = teeTcbSvns.at(TDX_MODULE_MAJOR_SVN_INDEX); // throws std::out_of_range
        if (tdxModuleVersion > 0)
        {
            std::time_t tdxModuleTcbDate = 0;
            auto tdxModuleTcbStatus = EvaluationStatus::NotSupported;

            // 4.1.2.5.2.2.1
            const auto& tdxModuleIdentity = findTdxModuleIdentity(tcbInfo.getTdxModuleIdentities(), tdxModuleVersion);
            if (!tdxModuleIdentity)
            {
                return STATUS_TCB_NOT_SUPPORTED;
            }
            for (const auto& tcbLevel : tdxModuleIdentity->getTcbLevels())
            {
                if (teeTcbSvns.at(TDX_MODULE_MINOR_SVN_INDEX) >= tcbLevel.getTcb().getIsvSvn())
                {
                    // 4.1.2.5.2.2.2
                    tdxModuleTcbDate = tcbLevel.getTcbDate();
                    tdxModuleTcbStatus = mapToEvaluationStatusOrThrow(tcbLevel.getStatus(), VALID_TDX_MODULE_STATUSES);
                    tdxModuleAdvisoryIds = tcbLevel.getAdvisoryIDs();
                    break;
                }
            }
            if (tdxModuleTcbStatus == EvaluationStatus::NotSupported)
            {
                LOG_ERROR("TDX Module TCB status not matched");
                return STATUS_TCB_NOT_SUPPORTED;
            }

            componentStatuses.push_back(tdxModuleTcbStatus);
            tcbDates.push_back(tdxModuleTcbDate);
        }

        std::vector<std::string> qeAdvisoryIds = {};

        // 4.1.2.5.1.3: 4.1.2.5.1.3.1 && 4.1.2.5.1.3.2
        applyQeIdentity(qeIdentity, qeSvn, componentStatuses, tcbDates, qeAdvisoryIds);

        // 4.1.2.5.1.4, 4.1.2.5.1.5, 4.1.2.5.1.6, 4.1.2.5.1.7
        return finalizeTcbEvaluation(platformTcbStatus, componentStatuses, tcbDates,
                                     platformAdvisoryIds, qeAdvisoryIds, tdxModuleAdvisoryIds,
                                     tcbStatus, tcbDate, advisoryIds);
    }
    catch (const std::exception &e) // std::out_of_range/StatusNotSupportedException, but also to catch any other unexpected exception
    {
        LOG_ERROR("Error while evaluating TDX TCB: {}", e.what());
        return STATUS_TCB_NOT_SUPPORTED;
    }
}

}
