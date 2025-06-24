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

#include "QuoteV3Generator.h"
#include "IdentityGenerator.h"

#include <SgxEcdsaAttestation/QuoteVerification.h>
#include <QuoteVerification/Quote.h>
#include <Verifiers/EnclaveReportVerifier.h>
#include "EcdsaSignatureGenerator.h"
#include "X509CertGenerator.h"
#include "Mocks/VerificationCollateralInfoMock.h"
#include "Utils/TimeUtils.h"

#include <gtest/gtest.h>

#include <array>

using namespace testing;
using namespace ::intel::sgx::dcap;
using namespace ::intel::sgx::dcap::test;
using namespace ::intel::sgx::dcap::parser::test;
using namespace std;
using namespace intel::sgx::dcap::parser::json;

struct EnclaveReportVerifierUT : public Test
{
    EnclaveReportVerifier enclaveReportVerifier;
    QuoteV3Generator quoteGenerator;
    QuoteV3Generator::EnclaveReport enclaveReport;

    X509CertGenerator certGenerator = X509CertGenerator{};
    crypto::EVP_PKEY_uptr tcbSigningKey;
    EnclaveIdentityVectorModel model;
    VerificationCollateralInfoMock verificationCollateralInfo;
    std::string tcbDate = "2025-06-10T10:11:12Z";
    std::string outOfDateLevelAdvisory = "INTEL-SA-00002";
    std::string revokedLevelAdvisory = "INTEL-SA-00001";
    EnclaveReportVerifierUT(): tcbSigningKey(certGenerator.generateEcKeypair())
    {
    }

    void SetUp() override
    {
        model = EnclaveIdentityVectorModel(tcbDate);
        const std::vector<IdentityTcbLevelModel> tcbLevels = {
                {6, tcbDate, "UpToDate"},
                {5, tcbDate, "OutOfDate", {outOfDateLevelAdvisory}},
                {4, tcbDate, "Revoked", {revokedLevelAdvisory}}
        };
        model.tcbLevels = tcbLevels;

        verificationCollateralInfo = VerificationCollateralInfoMock();
    }

    EnclaveReport getEnclaveReport()
    {
        quoteGenerator.withEnclaveReport(enclaveReport);
        const auto enclaveReportBody = quoteGenerator.getEnclaveReport();
        EnclaveReport eReport{};
        eReport.cpuSvn = enclaveReportBody.cpuSvn;
        eReport.miscSelect = enclaveReportBody.miscSelect;
        eReport.reserved1 = enclaveReportBody.reserved1;
        eReport.attributes = enclaveReportBody.attributes;
        eReport.mrEnclave = enclaveReportBody.mrEnclave;
        eReport.reserved2 = enclaveReportBody.reserved2;
        eReport.mrSigner = enclaveReportBody.mrSigner;
        eReport.reserved3 = enclaveReportBody.reserved3;
        eReport.isvProdID = enclaveReportBody.isvProdID;
        eReport.isvSvn = enclaveReportBody.isvSvn;
        eReport.reserved4 = enclaveReportBody.reserved4;
        eReport.reportData = enclaveReportBody.reportData;

        return eReport;
    }

    void checkVerCollInfoEmpty()
    {
        ASSERT_EQ(1, verificationCollateralInfo.getId());
        ASSERT_EQ(1, verificationCollateralInfo.getVersion());
        ASSERT_EQ(std::vector<time_t>(), verificationCollateralInfo.getIssueDates());
        ASSERT_EQ(std::vector<time_t>(), verificationCollateralInfo.getNextUpdates());
        ASSERT_EQ(std::vector<unsigned int>(), verificationCollateralInfo.getTcbEvalNumbers());
        ASSERT_EQ(std::vector<time_t>(), verificationCollateralInfo.getTcbDates());
        ASSERT_EQ(std::set<std::string>(), verificationCollateralInfo.getAdvisoryIds());
    }

    void checkVerCollInfoFilled(const std::set<std::string>& advisoryIds)
    {
        ASSERT_EQ(1, verificationCollateralInfo.getId());
        ASSERT_EQ(1, verificationCollateralInfo.getVersion());
        ASSERT_EQ((std::vector<time_t>){getEpochTimeFromString(model.issueDate)}, verificationCollateralInfo.getIssueDates());
        ASSERT_EQ((std::vector<time_t>){getEpochTimeFromString(model.nextUpdate)}, verificationCollateralInfo.getNextUpdates());
        ASSERT_EQ((std::vector<unsigned int>){model.tcbEvaluationDataNumber}, verificationCollateralInfo.getTcbEvalNumbers());
        ASSERT_EQ((std::vector<time_t>){getEpochTimeFromString(tcbDate)}, verificationCollateralInfo.getTcbDates());
        ASSERT_EQ(advisoryIds, verificationCollateralInfo.getAdvisoryIds());
    }

    std::string generateEnclaveIdentity(std::string bodyJson);
};

std::string EnclaveReportVerifierUT::generateEnclaveIdentity(std::string bodyJson)
{
    std::vector<uint8_t> enclaveIdentityBodyBytes(bodyJson.begin(), bodyJson.end());
    auto signature = EcdsaSignatureGenerator::signECDSA_SHA256(enclaveIdentityBodyBytes, tcbSigningKey.get());

    return enclaveIdentityJsonWithSignature(bodyJson, EcdsaSignatureGenerator::signatureToHexString(signature));
}


TEST_F(EnclaveReportVerifierUT, shouldReturnEnclaveReportMiscselectMismatchWhenMiscselectIsDifferent)
{
    model.miscselect = {{1, 1, 1, 1}};
    enclaveReport.applyEnclaveIdentity(model);
    string json = model.toJSON();

    auto enclaveIdentity = EnclaveIdentity::parse(generateEnclaveIdentity(json));

    auto result = enclaveReportVerifier.verify(&enclaveIdentity, getEnclaveReport(), &verificationCollateralInfo);

    ASSERT_EQ(STATUS_SGX_ENCLAVE_REPORT_MISCSELECT_MISMATCH, result);
    checkVerCollInfoEmpty();
}

TEST_F(EnclaveReportVerifierUT, shouldReturnEnclaveReportAttributestMismatchWhenAttributesIsDifferent)
{
    enclaveReport.applyEnclaveIdentity(model);
    model.attributes = {{9, 9, 9, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
    string json = model.toJSON();

    auto enclaveIdentity = EnclaveIdentity::parse(generateEnclaveIdentity(json));

    auto result = enclaveReportVerifier.verify(&enclaveIdentity, getEnclaveReport(), &verificationCollateralInfo);

    ASSERT_EQ(STATUS_SGX_ENCLAVE_REPORT_ATTRIBUTES_MISMATCH, result);
    checkVerCollInfoEmpty();
}

TEST_F(EnclaveReportVerifierUT, shouldReturnEnclaveReportAttributestMismatchWhenIdentityAttributesHasIncorrectSize)
{
    model.attributesMask = {{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9}};
    enclaveReport.applyEnclaveIdentity(model);
    string json = model.toJSON();

    ASSERT_THROW(EnclaveIdentity::parse(generateEnclaveIdentity(json)), parser::InvalidExtensionException);
}

TEST_F(EnclaveReportVerifierUT, shouldReturnStausStausSgxEnclaveIndentityWhenMrsignerIsNotPresent)
{
    enclaveReport.applyEnclaveIdentity(model);
    string json = model.toJSON();

    removeWordFromString("mrsigner", json);

    ASSERT_THROW(EnclaveIdentity::parse(generateEnclaveIdentity(json)), parser::InvalidExtensionException);
}

TEST_F(EnclaveReportVerifierUT, shouldReturnStausStausSgxEnclaveIndentityWhenIsvprodidIsNotPresent)
{
    enclaveReport.applyEnclaveIdentity(model);
    string json = model.toJSON();

    removeWordFromString("isvprodid", json);

    ASSERT_THROW(EnclaveIdentity::parse(generateEnclaveIdentity(json)), parser::InvalidExtensionException);
}

TEST_F(EnclaveReportVerifierUT, shouldReturnStausStausSgxEnclaveIndentityWhenIsvsvnIsNotPresent)
{
    enclaveReport.applyEnclaveIdentity(model);
    string json = model.toJSON();

    removeWordFromString("isvsvn", json);

    ASSERT_THROW(EnclaveIdentity::parse(generateEnclaveIdentity(json)), parser::FormatException);
}

TEST_F(EnclaveReportVerifierUT, shouldReturnEnclaveReportMrsignerMismatchWhenMrsignerIsDifferent)
{
    enclaveReport.applyEnclaveIdentity(model);
    model.mrsigner = {{8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
    string json = model.toJSON();

    auto enclaveIdentity = EnclaveIdentity::parse(generateEnclaveIdentity(json));

    auto result = enclaveReportVerifier.verify(&enclaveIdentity, getEnclaveReport(), &verificationCollateralInfo);

    ASSERT_EQ(STATUS_SGX_ENCLAVE_REPORT_MRSIGNER_MISMATCH, result);
    checkVerCollInfoEmpty();
}

TEST_F(EnclaveReportVerifierUT, shouldReturnEnclaveReportIsvprodidMismatchWhenIsvprodidIsDifferent)
{
    enclaveReport.applyEnclaveIdentity(model);
    model.isvprodid = 11;
    string json = model.toJSON();

    auto enclaveIdentity = EnclaveIdentity::parse(generateEnclaveIdentity(json));

    auto result = enclaveReportVerifier.verify(&enclaveIdentity, getEnclaveReport(), &verificationCollateralInfo);

    ASSERT_EQ(STATUS_SGX_ENCLAVE_REPORT_ISVPRODID_MISMATCH, result);
    checkVerCollInfoEmpty();
}

TEST_F(EnclaveReportVerifierUT, shouldReturnEnclaveReportNotSupportedWhenIsvsvnIsBelowAllLevels)
{
    enclaveReport.applyEnclaveIdentity(model);
    enclaveReport.isvSvn = 2;
    string json = model.toJSON();

    auto enclaveIdentity = EnclaveIdentity::parse(generateEnclaveIdentity(json));

    auto result = enclaveReportVerifier.verify(&enclaveIdentity, getEnclaveReport(), &verificationCollateralInfo);

    ASSERT_EQ(STATUS_SGX_ENCLAVE_REPORT_ISVSVN_NOT_SUPPORTED, result);
    checkVerCollInfoEmpty();
}

TEST_F(EnclaveReportVerifierUT, shouldReturnEnclaveReportRevokedWhenIsvsvnIsOnRevokedLevel)
{
    enclaveReport.applyEnclaveIdentity(model);
    enclaveReport.isvSvn = 4;
    string json = model.toJSON();

    auto enclaveIdentity = EnclaveIdentity::parse(generateEnclaveIdentity(json));

    auto result = enclaveReportVerifier.verify(&enclaveIdentity, getEnclaveReport(), &verificationCollateralInfo);

    ASSERT_EQ(STATUS_SGX_ENCLAVE_REPORT_ISVSVN_REVOKED, result);
    checkVerCollInfoFilled({revokedLevelAdvisory});
}

TEST_F(EnclaveReportVerifierUT, shouldReturnEnclaveReportOutOfDateWhenIsvsvnIsOnOutOfDateLevel)
{
    enclaveReport.applyEnclaveIdentity(model);
    enclaveReport.isvSvn = 5;
    string json = model.toJSON();

    auto enclaveIdentity = EnclaveIdentity::parse(generateEnclaveIdentity(json));

    auto result = enclaveReportVerifier.verify(&enclaveIdentity, getEnclaveReport(), &verificationCollateralInfo);

    ASSERT_EQ(STATUS_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE, result);
    checkVerCollInfoFilled({outOfDateLevelAdvisory});
}

TEST_F(EnclaveReportVerifierUT, shouldReturnStatusOkWhenJsonIsOk)
{
    enclaveReport.applyEnclaveIdentity(model);
    string json = model.toJSON();

    auto enclaveIdentity = EnclaveIdentity::parse(generateEnclaveIdentity(json));

    auto result = enclaveReportVerifier.verify(&enclaveIdentity, getEnclaveReport(), &verificationCollateralInfo);

    ASSERT_EQ(STATUS_OK, result);
    checkVerCollInfoFilled({});
}

TEST_F(EnclaveReportVerifierUT, shouldReturnEnclaveReportNotSupportedWhenIsvSvnisOneAndEnclaveIdentityHavingTcbsBelowFive)
{
    EnclaveIdentityVectorModel modelISVSVN2;
    EnclaveIdentityVectorModel modelISVSVN3;

    modelISVSVN2.tcbLevels.push_back({2, "2018-08-22T12:00:00Z", "Revoked"});
    modelISVSVN3.tcbLevels.push_back({3, "2018-08-22T12:00:00Z", "Revoked"});

    enclaveReport.applyEnclaveIdentity(modelISVSVN2);
    enclaveReport.isvSvn = 1;
    string json = modelISVSVN2.toJSON();
    auto enclaveIdentityISVSVN2 = EnclaveIdentity::parse(generateEnclaveIdentity(json));
    auto resultISVSVN2 = enclaveReportVerifier.verify(&enclaveIdentityISVSVN2, getEnclaveReport(), &verificationCollateralInfo);

    enclaveReport.applyEnclaveIdentity(modelISVSVN3);
    enclaveReport.isvSvn = 1;
    json = modelISVSVN3.toJSON();
    auto enclaveIdentityISVSVN3 = EnclaveIdentity::parse(generateEnclaveIdentity(json));
    auto resultISVSVN3 = enclaveReportVerifier.verify(&enclaveIdentityISVSVN3, getEnclaveReport(), &verificationCollateralInfo);

    ASSERT_EQ(STATUS_SGX_ENCLAVE_REPORT_ISVSVN_NOT_SUPPORTED, resultISVSVN2);
    checkVerCollInfoEmpty();
    ASSERT_EQ(STATUS_SGX_ENCLAVE_REPORT_ISVSVN_NOT_SUPPORTED, resultISVSVN3);
    checkVerCollInfoEmpty();
}