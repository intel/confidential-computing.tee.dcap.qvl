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

#include <SgxEcdsaAttestation/AttestationParsers.h>
#include <gtest/gtest.h>

#include <utility>
#include "Utils/StatusPrinter.h"
#include "Verifiers/Checks/TcbLevelCheck.h"

#include "QuoteVerifierTcbStatusHelpers.h"

using namespace intel::sgx;
using namespace dcap::parser::json;
using namespace dcap::parser::x509;
using namespace ::testing;

struct QuoteVerifierTcbStatusUT: public ::testing::TestWithParam<Params> {};

/* Possible SGX and TDX TCB statuses:
 * UpToDate
 * OutOfDate
 * ConfigurationNeeded
 * Revoked
 * OutOfDateConfigurationNeeded
 * SWHardeningNeeded
 * ConfigurationAndSWHardeningNeeded
 *
 * Possible TDX Module Statuses:
 * UpToDate
 * OutOfDate
 * Revoked
 *
 * QE Statuses:
 * <not_present>
 * STATUS_OK
 * STATUS_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE
 * STATUS_SGX_ENCLAVE_REPORT_ISVSVN_REVOKED
 * STATUS_SGX_ENCLAVE_REPORT_ISVSVN_NOT_SUPPORTED
 *
 * Possible TCB results:
 * STATUS_OK
 * STATUS_TCB_OUT_OF_DATE
 * STATUS_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED
 * STATUS_TCB_SW_HARDENING_NEEDED
 * STATUS_TCB_CONFIGURATION_NEEDED
 * STATUS_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED
 * STATUS_TCB_TD_RELAUNCH_ADVISED
 * STATUS_TCB_TD_RELAUNCH_ADVISED_CONFIGURATION_NEEDED
 * STATUS_TCB_REVOKED
 * STATUS_TCB_NOT_SUPPORTED
 */

// TcbInfo(LatestStatus, EarliestStatus, LatestTdxModuleStatus, EarliestTdxModuleStatus), Cert, Quote(teeTcbSvn,teeTcbSvn2), QeTcbStatus(optional), result
// Params(ti(latest(UTD), earliest(OOD), module(UTD, OOD)), latestCert(), q(latestSvn, latestSvn), {}, STATUS_OK),

INSTANTIATE_TEST_SUITE_P(StatusOK, QuoteVerifierTcbStatusUT, ::testing::Values(
Params(ti(latest(UTD), earliest(OOD), module(UTD, OOD)), latestCert(), q(latestSvn, latestSvn), {}, STATUS_OK),
Params(ti(latest(UTD), earliest(OOD), module(UTD, OOD)), latestCert(), q(latestSvn, latestSvn), STATUS_OK, STATUS_OK),
// revoked earliest should not affect us when using latest cert and quote
Params(ti(latest(UTD), earliest(RKD), module(UTD, OOD)), latestCert(), q(latestSvn, latestSvn), {}, STATUS_OK),
Params(ti(latest(UTD), earliest(RKD), module(UTD, OOD)), latestCert(), q(latestSvn, latestSvn), STATUS_OK, STATUS_OK)
), CaseName);

INSTANTIATE_TEST_SUITE_P(StatusRevoked, QuoteVerifierTcbStatusUT, ::testing::Values(
// Revoked w/o QeTcbStatus
Params(ti(latest(RKD), earliest(OOD), module(UTD, OOD)), latestCert(), q(latestSvn, latestSvn), {}, STATUS_TCB_REVOKED),
Params(ti(latest(UTD), earliest(OOD), module(RKD, OOD)), latestCert(), q(latestSvn, latestSvn), {}, STATUS_TCB_REVOKED),
// Revoked w/ QeTcbStatus
Params(ti(latest(RKD), earliest(OOD), module(UTD, OOD)), latestCert(), q(latestSvn, latestSvn), STATUS_OK, STATUS_TCB_REVOKED),
Params(ti(latest(UTD), earliest(OOD), module(RKD, OOD)), latestCert(), q(latestSvn, latestSvn), STATUS_OK, STATUS_TCB_REVOKED),
Params(ti(latest(UTD), earliest(OOD), module(UTD, OOD)), latestCert(), q(latestSvn, latestSvn), STATUS_SGX_ENCLAVE_REPORT_ISVSVN_REVOKED, STATUS_TCB_REVOKED)
), CaseName);

INSTANTIATE_TEST_SUITE_P(StatusOutOfDate, QuoteVerifierTcbStatusUT, ::testing::Values(
Params(ti(latest(UTD), earliest(OOD), module(UTD, OOD)), earliestCert(), q(earliestSvn, earliestSvn), {}, STATUS_TCB_OUT_OF_DATE),
Params(ti(latest(UTD), earliest(OOD), module(UTD, OOD)), earliestCert(), q(latestSvn, latestSvn), {}, STATUS_TCB_OUT_OF_DATE),
Params(ti(latest(RKD), earliest(OOD), module(OOD, OOD)), latestCert(), q(earliestSvn, latestSvn), {}, STATUS_TCB_OUT_OF_DATE),
Params(ti(latest(OOD), earliest(OOD), module(UTD, OOD)), latestCert(), q(latestSvn, latestSvn), {}, STATUS_TCB_OUT_OF_DATE),
Params(ti(latest(UTD), earliest(OOD), module(UTD, OOD)), latestCert(), q(latestSvn, latestSvn), STATUS_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE, STATUS_TCB_OUT_OF_DATE)
), CaseName);

INSTANTIATE_TEST_SUITE_P(StatusSwHardeningNeeded, QuoteVerifierTcbStatusUT, ::testing::Values(
Params(ti(latest(SHN), earliest(OOD), module(UTD, OOD)), latestCert(), q(latestSvn, latestSvn), {}, STATUS_TCB_SW_HARDENING_NEEDED),
Params(ti(latest(UTD), earliest(SHN), module(UTD, OOD)), earliestCert(), q(latestSvn, latestSvn), STATUS_OK, STATUS_TCB_SW_HARDENING_NEEDED)
), CaseName);

INSTANTIATE_TEST_SUITE_P(StatusConfigurationAndSwHardeningNeeded, QuoteVerifierTcbStatusUT, ::testing::Values(
Params(ti(latest(CN_SHN), earliest(OOD), module(UTD, OOD)), latestCert(), q(latestSvn, latestSvn), {}, STATUS_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED),
Params(ti(latest(UTD), earliest(CN_SHN), module(UTD, OOD)), earliestCert(), q(latestSvn, latestSvn), STATUS_OK, STATUS_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED)
), CaseName);

INSTANTIATE_TEST_SUITE_P(StatusTdRelaunchAdvised, QuoteVerifierTcbStatusUT, ::testing::Values(
Params(ti(latest(UTD), earliest(OOD), module(OOD, OOD)), latestCert(), q(earliestSvn, latestSvn), {}, STATUS_TCB_TD_RELAUNCH_ADVISED),
Params(ti(latest(UTD), earliest(OOD), module(OOD, OOD)), latestCert(), q(earliestSvn, latestSvn), STATUS_OK, STATUS_TCB_TD_RELAUNCH_ADVISED)

), CaseName);

INSTANTIATE_TEST_SUITE_P(StatusTdRelaunchAdvisedConfigurationNeeded, QuoteVerifierTcbStatusUT, ::testing::Values(
Params(ti(latest(UTD), earliest(OOD_CN), module(OOD, OOD)), latestCert(), q(earliestSvn, latestSvn), {}, STATUS_TCB_TD_RELAUNCH_ADVISED_CONFIGURATION_NEEDED),
Params(ti(latest(CN), earliest(OOD), module(OOD, OOD)), latestCert(), q(earliestSvn, latestSvn), STATUS_OK, STATUS_TCB_TD_RELAUNCH_ADVISED_CONFIGURATION_NEEDED)

), CaseName);

TEST_P(QuoteVerifierTcbStatusUT, checkStatuses)
{
    Optional<TdxModuleIdentity> tdxModuleIdentity; // ignore, it is not important in the current implementation
    const Params &params = GetParam();
    VerificationCollateralInfo verCollInfo;

    const auto result = checkTcbLevel(params.tcbInfo,
                                      params.certificate,
                                      params.quote,
                                      params.qeTcbStatus,
                                      tdxModuleIdentity,
                                      verCollInfo);
    EXPECT_EQ(printStatus(result), printStatus(params.result));
}
