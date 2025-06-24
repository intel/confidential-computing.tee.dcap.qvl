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

#include <gtest/gtest.h>

#include <numeric>
#include <IdentityGenerator.h>
#include "SgxEcdsaAttestation/AttestationParsers.h"
#include "Utils/TimeUtils.h"

using namespace testing;
using namespace ::intel::sgx::dcap;
using namespace intel::sgx::dcap::test;
using namespace std;
using namespace intel::sgx::dcap::parser::json;

struct EnclaveIdentityUT : public Test
{
};

TEST_F(EnclaveIdentityUT, shouldParseWhenJsonIsOk)
{
    string json = enclaveIdentityJsonWithSignature(EnclaveIdentityVectorModel().toJSON());
    ASSERT_NO_THROW(EnclaveIdentity::parse(json));
}

TEST_F(EnclaveIdentityUT, shouldThrowInvalidExtensionExceptionWhenMiscselectIsWrong)
{
    EnclaveIdentityVectorModel model;
    model.miscselect = {{1, 1}};
    string json = enclaveIdentityJsonWithSignature(model.toJSON());
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldThrowInvalidExtensionExceptionWhenOptionalFieldIsInvalid)
{
    string json = enclaveIdentityJsonWithSignature(EnclaveIdentityVectorModel().toJSON());
    removeWordFromString("mrenclave", json);
    removeWordFromString("mrsigner", json);
    removeWordFromString("isvprodid", json);
    removeWordFromString("isvsvn", json);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldThrowInvalidExtensionExceptionWhenVerionFieldIsInvalid)
{
    string json = enclaveIdentityJsonWithSignature(EnclaveIdentityVectorModel().toJSON());
    removeWordFromString("version", json);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldThrowInvalidExtensionExceptionWhenMiscselectHasIncorrectSize)
{
    EnclaveIdentityVectorModel model;
    model.miscselect= {{1, 1}};
    string json = enclaveIdentityJsonWithSignature(model.toJSON());
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldThrowInvalidExtensionExceptionWhenMiscselectIsNotHexString)
{
    EnclaveIdentityStringModel model;
    model.miscselect = "xyz00000";
    string json = enclaveIdentityJsonWithSignature(model.toJSON());
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldThrowInvalidExtensionExceptionWhenMiscselectMaskHasIncorrectSize)
{
    EnclaveIdentityVectorModel model;
    model.miscselectMask = {{1, 1}};
    string json = enclaveIdentityJsonWithSignature(model.toJSON());
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldThrowInvalidExtensionExceptionWhenMiscselectMaskIsNotHexString)
{
    EnclaveIdentityStringModel model;
    model.miscselectMask = "xyz00000";
    string json = enclaveIdentityJsonWithSignature(model.toJSON());
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldThrowInvalidExtensionExceptionWhenAttributesHasIncorrectSize)
{
    EnclaveIdentityVectorModel model;
    model.attributes = {{1, 1}};
    string json = enclaveIdentityJsonWithSignature(model.toJSON());
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldThrowInvalidExtensionExceptionWhenAttributesIsNotHexString)
{
    EnclaveIdentityStringModel model;
    model.attributes = "xyz45678900000000000000123456789";
    string json = enclaveIdentityJsonWithSignature(model.toJSON());
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldReturnEnclaveIdentityInvalidWhenAttributesMaskHasIncorrectSize)
{
    EnclaveIdentityVectorModel model;
    model.attributesMask = {{1, 1}};
    string json = enclaveIdentityJsonWithSignature(model.toJSON());
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldReturnEnclaveIdentityInvalidWhenAttributesMaskIsNotHexString)
{
    EnclaveIdentityStringModel model;
    model.attributesMask = "xyz45678900000000000000123456789";
    string json = enclaveIdentityJsonWithSignature(model.toJSON());
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldReturnEnclaveIdentityInvalidWhenIssuedateIsWrong)
{
    EnclaveIdentityStringModel model;
    model.issueDate = "2018-08-22T10:09:";
    string json = enclaveIdentityJsonWithSignature(model.toJSON());
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldReturnEnclaveIdentityInvalidWhenNextUpdateIsWrong)
{
    EnclaveIdentityStringModel model;
    model.nextUpdate = "2018-08-22T10:09:";
    string json = enclaveIdentityJsonWithSignature(model.toJSON());
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldThrowInvalidVersionExceptionWhenVersionIsWrong)
{
    EnclaveIdentityVectorModel model;
    model.version = 5;
    string json = enclaveIdentityJsonWithSignature(model.toJSON());
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidVersionException);
}


TEST_F(EnclaveIdentityUT, positiveQE)
{
    auto json = enclaveIdentityJsonWithSignature();

    std::vector<uint8_t> expectedMiscSelect = {0x8f, 0xa6, 0x44, 0x72};
    std::vector<uint8_t> expectedMiscSelectMask = {0x00, 0x00, 0xff, 0xfa};
    std::vector<uint8_t> expectedAttributes = {0x12, 0x54, 0x86, 0x35, 0x48, 0xaf, 0x4a, 0x6b, 0x2f, 0xcc, 0x2d, 0x32, 0x44, 0x78, 0x44, 0x52};
    std::vector<uint8_t> expectedAttributesMask = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    std::vector<uint8_t> expectedMrSigner = {0xaa, 0xff, 0x34, 0xff, 0xa5, 0x19, 0x81, 0x95, 0x1a, 0x61, 0xd6, 0x16, 0xb1,
                                             0x6c, 0x16, 0xf1, 0x65, 0x1c, 0x65, 0x16, 0xe5, 0x1f, 0x65, 0x1d, 0x26, 0xa6, 0x16, 0x6e, 0xd5, 0x67, 0x9c, 0x79};
    uint32_t expectedIsvProdId = 3;
    
    auto enclaveIdentity = EnclaveIdentity::parse(json);
    EXPECT_EQ(enclaveIdentity.getVersion(), 2);
    EXPECT_EQ(enclaveIdentity.getMiscselect(), expectedMiscSelect);
    EXPECT_EQ(enclaveIdentity.getMiscselectMask(), expectedMiscSelectMask);
    EXPECT_EQ(enclaveIdentity.getAttributes(), expectedAttributes);
    EXPECT_EQ(enclaveIdentity.getAttributesMask(), expectedAttributesMask);
    EXPECT_EQ(enclaveIdentity.getMrsigner(), expectedMrSigner);
    EXPECT_EQ(enclaveIdentity.getIsvProdId(), expectedIsvProdId);
    EXPECT_EQ(enclaveIdentity.getID(), EnclaveID::QE);
    EXPECT_EQ(enclaveIdentity.getTcbEvaluationDataNumber(), 0);
    EXPECT_EQ(enclaveIdentity.getTcbLevel(6).getTcbStatus(), TcbStatus::UpToDate);
    EXPECT_EQ(enclaveIdentity.getTcbLevel(5).getTcbStatus(), TcbStatus::OutOfDate);
    EXPECT_EQ(enclaveIdentity.getTcbLevel(4).getTcbStatus(), TcbStatus::Revoked);
    EXPECT_THROW({
                    try
                    {
                        enclaveIdentity.getTcbLevel(3);
                    }
                    catch (const StatusNotSupportedException  &e)
                    {
                        EXPECT_STREQ(e.what(), "Non-existent tcb status exception");
                        throw;
                    }
                 },StatusNotSupportedException);
}

TEST_F(EnclaveIdentityUT, positiveQVE)
{
    auto json = enclaveIdentityJsonWithSignature(R"json({
            "id": "QVE",
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
        })json");

    std::vector<uint8_t> expectedMiscSelect = {0x8f, 0xa6, 0x44, 0x72};
    std::vector<uint8_t> expectedMiscSelectMask = {0x00, 0x00, 0xff, 0xfa};
    std::vector<uint8_t> expectedAttributes = {0x12, 0x54, 0x86, 0x35, 0x48, 0xaf, 0x4a, 0x6b, 0x2f, 0xcc, 0x2d, 0x32, 0x44, 0x78, 0x44, 0x52};
    std::vector<uint8_t> expectedAttributesMask = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    std::vector<uint8_t> expectedMrSigner = {0xaa, 0xff, 0x34, 0xff, 0xa5, 0x19, 0x81, 0x95, 0x1a, 0x61, 0xd6, 0x16, 0xb1,
                                             0x6c, 0x16, 0xf1, 0x65, 0x1c, 0x65, 0x16, 0xe5, 0x1f, 0x65, 0x1d, 0x26, 0xa6, 0x16, 0x6e, 0xd5, 0x67, 0x9c, 0x79};
    uint32_t expectedIsvProdId = 3;
    
    auto enclaveIdentity = EnclaveIdentity::parse(json);
    EXPECT_EQ(enclaveIdentity.getVersion(), 2);
    EXPECT_EQ(enclaveIdentity.getMiscselect(), expectedMiscSelect);
    EXPECT_EQ(enclaveIdentity.getMiscselectMask(), expectedMiscSelectMask);
    EXPECT_EQ(enclaveIdentity.getAttributes(), expectedAttributes);
    EXPECT_EQ(enclaveIdentity.getAttributesMask(), expectedAttributesMask);
    EXPECT_EQ(enclaveIdentity.getMrsigner(), expectedMrSigner);
    EXPECT_EQ(enclaveIdentity.getIsvProdId(), expectedIsvProdId);
    EXPECT_EQ(enclaveIdentity.getID(), EnclaveID::QVE);
    EXPECT_EQ(enclaveIdentity.getTcbEvaluationDataNumber(), 0);
    EXPECT_EQ(enclaveIdentity.getTcbLevel(6).getTcbStatus(), TcbStatus::UpToDate);
    EXPECT_EQ(enclaveIdentity.getTcbLevel(5).getTcbStatus(), TcbStatus::OutOfDate);
    EXPECT_EQ(enclaveIdentity.getTcbLevel(4).getTcbStatus(), TcbStatus::Revoked);
    EXPECT_THROW({
                     try
                     {
                         enclaveIdentity.getTcbLevel(3);
                     }
                     catch (const StatusNotSupportedException  &e)
                     {
                         EXPECT_STREQ(e.what(), "Non-existent tcb status exception");
                         throw;
                     }
                 },StatusNotSupportedException);
}

TEST_F(EnclaveIdentityUT, positiveTD_QE)
{
    auto json = enclaveIdentityJsonWithSignature(R"json({
            "id": "TD_QE",
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
        })json");

    std::vector<uint8_t> expectedMiscSelect = {0x8f, 0xa6, 0x44, 0x72};
    std::vector<uint8_t> expectedMiscSelectMask = {0x00, 0x00, 0xff, 0xfa};
    std::vector<uint8_t> expectedAttributes = {0x12, 0x54, 0x86, 0x35, 0x48, 0xaf, 0x4a, 0x6b, 0x2f, 0xcc, 0x2d, 0x32, 0x44, 0x78, 0x44, 0x52};
    std::vector<uint8_t> expectedAttributesMask = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    std::vector<uint8_t> expectedMrSigner = {0xaa, 0xff, 0x34, 0xff, 0xa5, 0x19, 0x81, 0x95, 0x1a, 0x61, 0xd6, 0x16, 0xb1,
                                             0x6c, 0x16, 0xf1, 0x65, 0x1c, 0x65, 0x16, 0xe5, 0x1f, 0x65, 0x1d, 0x26, 0xa6, 0x16, 0x6e, 0xd5, 0x67, 0x9c, 0x79};
    uint32_t expectedIsvProdId = 3;
   
    auto enclaveIdentity = EnclaveIdentity::parse(json);
    EXPECT_EQ(enclaveIdentity.getVersion(), 2);
    EXPECT_EQ(enclaveIdentity.getMiscselect(), expectedMiscSelect);
    EXPECT_EQ(enclaveIdentity.getMiscselectMask(), expectedMiscSelectMask);
    EXPECT_EQ(enclaveIdentity.getAttributes(), expectedAttributes);
    EXPECT_EQ(enclaveIdentity.getAttributesMask(), expectedAttributesMask);
    EXPECT_EQ(enclaveIdentity.getMrsigner(), expectedMrSigner);
    EXPECT_EQ(enclaveIdentity.getIsvProdId(), expectedIsvProdId);
    EXPECT_EQ(enclaveIdentity.getID(), EnclaveID::TD_QE);
    EXPECT_EQ(enclaveIdentity.getTcbEvaluationDataNumber(), 0);
    EXPECT_EQ(enclaveIdentity.getTcbLevel(6).getTcbStatus(), TcbStatus::UpToDate);
    EXPECT_EQ(enclaveIdentity.getTcbLevel(5).getTcbStatus(), TcbStatus::OutOfDate);
    EXPECT_EQ(enclaveIdentity.getTcbLevel(4).getTcbStatus(), TcbStatus::Revoked);
    EXPECT_THROW({
                     try
                     {
                         enclaveIdentity.getTcbLevel(3);
                     }
                     catch (const StatusNotSupportedException  &e)
                     {
                         EXPECT_STREQ(e.what(), "Non-existent tcb status exception");
                         throw;
                     }
                 },StatusNotSupportedException);
}

TEST_F(EnclaveIdentityUT, positiveWithExtraField)
{
    auto json = R"json({
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
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ],
            "extraField": "ExtraValue"
        })json";

    ASSERT_NO_THROW(EnclaveIdentity::parse(enclaveIdentityJsonWithSignature(json)));
}

TEST_F(EnclaveIdentityUT, shouldFailWhenInitializedWithEmptyString)
{
    ASSERT_THROW(EnclaveIdentity::parse(""), parser::FormatException);
}

TEST_F(EnclaveIdentityUT, shouldFailWHenInitializedWithInvalidJSON)
{
    ASSERT_THROW(EnclaveIdentity::parse("Plain string."), parser::FormatException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenQEIdentityFieldIsMissing)
{
    ASSERT_THROW(EnclaveIdentity::parse(R"json({"signature": "adad"})json"), parser::FormatException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenSignatureFieldIsMissing)
{
    auto json = R"json({"enclaveIdentity": {
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
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        }})json";

    ASSERT_THROW(EnclaveIdentity::parse(json), parser::FormatException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenQeIdentityIsArray)
{
    auto qeidTemplate = R"json([])json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::FormatException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenIdFieldIsMissing)
{
    auto qeidTemplate = R"json({
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
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);

    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenVersionFieldIsMissing)
{
    auto qeidTemplate = R"json({
            "id": "QE",
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
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";

    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenIssueDateFieldIsMissing)
{
    auto qeidTemplate = R"json({
            "id": "QE",
            "version": 2,
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
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";

    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenNextUpdateFieldIsMissing)
{
    auto qeidTemplate = R"json({
            "id": "QE",
            "version": 2,
            "issueDate": "2018-10-04T11:10:45Z",
            "tcbEvaluationDataNumber":0,
            "miscselect": "8fa64472",
            "miscselectMask": "0000fffa",
            "attributes": "1254863548af4a6b2fcc2d3244784452",
            "attributesMask": "ffffffffffffffffffffffffffffffff",
            "mrsigner": "aaff34ffa51981951a61d616b16c16f1651c6516e51f651d26a6166ed5679c79",
            "isvprodid": 3,
            "tcbLevels": [
                {
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenTcbEvaluationDataNumberFieldIsMissing)
{
    auto qeidTemplate = R"json({
            "id": "QE",
            "version": 2,
            "issueDate": "2018-10-04T11:10:45Z",
            "nextUpdate": "2019-06-21T12:36:02Z",
            "miscselect": "8fa64472",
            "miscselectMask": "0000fffa",
            "attributes": "1254863548af4a6b2fcc2d3244784452",
            "attributesMask": "ffffffffffffffffffffffffffffffff",
            "mrsigner": "aaff34ffa51981951a61d616b16c16f1651c6516e51f651d26a6166ed5679c79",
            "isvprodid": 3,
            "tcbLevels": [
                {
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenMiscselectFieldIsMissing)
{
    auto qeidTemplate = R"json({
            "id": "QE",
            "version": 2,
            "issueDate": "2018-10-04T11:10:45Z",
            "nextUpdate": "2019-06-21T12:36:02Z",
            "tcbEvaluationDataNumber":0,
            "miscselectMask": "0000fffa",
            "attributes": "1254863548af4a6b2fcc2d3244784452",
            "attributesMask": "ffffffffffffffffffffffffffffffff",
            "mrsigner": "aaff34ffa51981951a61d616b16c16f1651c6516e51f651d26a6166ed5679c79",
            "isvprodid": 3,
            "tcbLevels": [
                {
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenMiscselectMaskFieldIsMissing)
{
    auto qeidTemplate = R"json({
            "id": "QE",
            "version": 2,
            "issueDate": "2018-10-04T11:10:45Z",
            "nextUpdate": "2019-06-21T12:36:02Z",
            "tcbEvaluationDataNumber":0,
            "miscselect": "8fa64472",
            "attributes": "1254863548af4a6b2fcc2d3244784452",
            "attributesMask": "ffffffffffffffffffffffffffffffff",
            "mrsigner": "aaff34ffa51981951a61d616b16c16f1651c6516e51f651d26a6166ed5679c79",
            "isvprodid": 3,
            "tcbLevels": [
                {
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenAttributesFieldIsMissing)
{
    auto qeidTemplate = R"json({
            "id": "QE",
            "version": 2,
            "issueDate": "2018-10-04T11:10:45Z",
            "nextUpdate": "2019-06-21T12:36:02Z",
            "tcbEvaluationDataNumber":0,
            "miscselect": "8fa64472",
            "miscselectMask": "0000fffa",
            "attributesMask": "ffffffffffffffffffffffffffffffff",
            "mrsigner": "aaff34ffa51981951a61d616b16c16f1651c6516e51f651d26a6166ed5679c79",
            "isvprodid": 3,
            "tcbLevels": [
                {
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenAttributesMaskFieldIsMissing)
{
    auto qeidTemplate = R"json({
            "id": "QE",
            "version": 2,
            "issueDate": "2018-10-04T11:10:45Z",
            "nextUpdate": "2019-06-21T12:36:02Z",
            "tcbEvaluationDataNumber":0,
            "miscselect": "8fa64472",
            "miscselectMask": "0000fffa",
            "attributes": "1254863548af4a6b2fcc2d3244784452",
            "mrsigner": "aaff34ffa51981951a61d616b16c16f1651c6516e51f651d26a6166ed5679c79",
            "isvprodid": 3,
            "tcbLevels": [
                {
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenMrsignerFieldIsMissing)
{
    auto qeidTemplate = R"json({
            "id": "QE",
            "version": 2,
            "issueDate": "2018-10-04T11:10:45Z",
            "nextUpdate": "2019-06-21T12:36:02Z",
            "tcbEvaluationDataNumber":0,
            "miscselect": "8fa64472",
            "miscselectMask": "0000fffa",
            "attributes": "1254863548af4a6b2fcc2d3244784452",
            "attributesMask": "ffffffffffffffffffffffffffffffff",
            "isvprodid": 3,
            "tcbLevels": [
                {
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenIsvprodidFieldIsMissing)
{
    auto qeidTemplate = R"json({
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
            "tcbLevels": [
                {
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenTcbLevelsFieldIsMissing)
{
    auto qeidTemplate = R"json({
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
            "isvprodid": 3
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenTcbLevelsTcbFieldIsMissing)
{
    auto qeidTemplate = R"json({
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
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::FormatException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenTcbLevelsTcbIsvSvnFieldIsMissing)
{
    auto qeidTemplate = R"json({
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
                    "tcb":{ },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::FormatException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenTcbLevelsTcbDateFieldIsMissing)
{
    auto qeidTemplate = R"json({
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
                    "tcb":{ "isvsvn":8 },
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::FormatException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenTcbLevelsTcbStatusFieldIsMissing)
{
    auto qeidTemplate = R"json({
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
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::FormatException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenVersionFieldIsNotEqual2)
{
    auto qeidTemplate = R"json({
            "id": "QE",
            "version": 23,
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
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidVersionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenVersionFieldIsNotANumber)
{
    auto qeidTemplate = R"json({
            "id": "QE",
            "version": "2",
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
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenIdFieldHasInvalidType)
{
    auto qeidTemplate = R"json({
            "id": 0,
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
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenIdFieldHasInvalidValue)
{
    auto qeidTemplate = R"json({
            "id": "QC",
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
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenIssueDateIsMalformed)
{
    auto qeidTemplate = R"json({
            "id": "QE",
            "version": 2,
            "issueDate": "2018-10-04T11:10:45:00",
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
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenIssueDateIsNotAString)
{
    auto qeidTemplate = R"json({
            "id": "QE",
            "version": 2,
            "issueDate": 123,
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
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenNextUpdateIsMalformed)
{
    auto qeidTemplate = R"json({
            "id": "QE",
            "version": 2,
            "issueDate": "2018-10-04T11:10:45Z",
            "nextUpdate": "219-06-21T12:36:02Z",
            "tcbEvaluationDataNumber":0,
            "miscselect": "8fa64472",
            "miscselectMask": "0000fffa",
            "attributes": "1254863548af4a6b2fcc2d3244784452",
            "attributesMask": "ffffffffffffffffffffffffffffffff",
            "mrsigner": "aaff34ffa51981951a61d616b16c16f1651c6516e51f651d26a6166ed5679c79",
            "isvprodid": 3,
            "tcbLevels": [
                {
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenNextUpdateIsNotAString)
{
    auto qeidTemplate = R"json({
            "id": "QE",
            "version": 2,
            "issueDate": "2018-10-04T11:10:45Z",
            "nextUpdate": 2019,
            "tcbEvaluationDataNumber":0,
            "miscselect": "8fa64472",
            "miscselectMask": "0000fffa",
            "attributes": "1254863548af4a6b2fcc2d3244784452",
            "attributesMask": "ffffffffffffffffffffffffffffffff",
            "mrsigner": "aaff34ffa51981951a61d616b16c16f1651c6516e51f651d26a6166ed5679c79",
            "isvprodid": 3,
            "tcbLevels": [
                {
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenMiscselectIsMalformed)
{
    auto qeidTemplate = R"json({
            "id": "QE",
            "version": 2,
            "issueDate": "2018-10-04T11:10:45Z",
            "nextUpdate": "2019-06-21T12:36:02Z",
            "tcbEvaluationDataNumber":0,
            "miscselect": "qwe-4472",
            "miscselectMask": "0000fffa",
            "attributes": "1254863548af4a6b2fcc2d3244784452",
            "attributesMask": "ffffffffffffffffffffffffffffffff",
            "mrsigner": "aaff34ffa51981951a61d616b16c16f1651c6516e51f651d26a6166ed5679c79",
            "isvprodid": 3,
            "tcbLevels": [
                {
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenMiscselectIsNotAString)
{
    auto qeidTemplate = R"json({
            "id": "QE",
            "version": 2,
            "issueDate": "2018-10-04T11:10:45Z",
            "nextUpdate": "2019-06-21T12:36:02Z",
            "tcbEvaluationDataNumber":0,
            "miscselect": 44,
            "miscselectMask": "0000fffa",
            "attributes": "1254863548af4a6b2fcc2d3244784452",
            "attributesMask": "ffffffffffffffffffffffffffffffff",
            "mrsigner": "aaff34ffa51981951a61d616b16c16f1651c6516e51f651d26a6166ed5679c79",
            "isvprodid": 3,
            "tcbLevels": [
                {
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenMiscselectIsTooShort)
{
    auto qeidTemplate = R"json({
            "id": "QE",
            "version": 2,
            "issueDate": "2018-10-04T11:10:45Z",
            "nextUpdate": "2019-06-21T12:36:02Z",
            "tcbEvaluationDataNumber":0,
            "miscselect": "8fa6447",
            "miscselectMask": "0000fffa",
            "attributes": "1254863548af4a6b2fcc2d3244784452",
            "attributesMask": "ffffffffffffffffffffffffffffffff",
            "mrsigner": "aaff34ffa51981951a61d616b16c16f1651c6516e51f651d26a6166ed5679c79",
            "isvprodid": 3,
            "tcbLevels": [
                {
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenMiscselectIsTooLong)
{
    auto qeidTemplate = R"json({
            "id": "QE",
            "version": 2,
            "issueDate": "2018-10-04T11:10:45Z",
            "nextUpdate": "2019-06-21T12:36:02Z",
            "tcbEvaluationDataNumber":0,
            "miscselect": "8fa64472f",
            "miscselectMask": "0000fffa",
            "attributes": "1254863548af4a6b2fcc2d3244784452",
            "attributesMask": "ffffffffffffffffffffffffffffffff",
            "mrsigner": "aaff34ffa51981951a61d616b16c16f1651c6516e51f651d26a6166ed5679c79",
            "isvprodid": 3,
            "tcbLevels": [
                {
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenMiscselectMaskIsMalformed)
{
    auto qeidTemplate = R"json({
            "id": "QE",
            "version": 2,
            "issueDate": "2018-10-04T11:10:45Z",
            "nextUpdate": "2019-06-21T12:36:02Z",
            "tcbEvaluationDataNumber":0,
            "miscselect": "8fa64472",
            "miscselectMask": "asdfgh56",
            "attributes": "1254863548af4a6b2fcc2d3244784452",
            "attributesMask": "ffffffffffffffffffffffffffffffff",
            "mrsigner": "aaff34ffa51981951a61d616b16c16f1651c6516e51f651d26a6166ed5679c79",
            "isvprodid": 3,
            "tcbLevels": [
                {
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenMiscselectMaskIsNotAString)
{
    auto qeidTemplate = R"json({
            "id": "QE",
            "version": 2,
            "issueDate": "2018-10-04T11:10:45Z",
            "nextUpdate": "2019-06-21T12:36:02Z",
            "tcbEvaluationDataNumber":0,
            "miscselect": "8fa64472",
            "miscselectMask": 234,
            "attributes": "1254863548af4a6b2fcc2d3244784452",
            "attributesMask": "ffffffffffffffffffffffffffffffff",
            "mrsigner": "aaff34ffa51981951a61d616b16c16f1651c6516e51f651d26a6166ed5679c79",
            "isvprodid": 3,
            "tcbLevels": [
                {
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenMiscselectMaskIsTooShort)
{
    auto qeidTemplate = R"json({
            "id": "QE",
            "version": 2,
            "issueDate": "2018-10-04T11:10:45Z",
            "nextUpdate": "2019-06-21T12:36:02Z",
            "tcbEvaluationDataNumber":0,
            "miscselect": "8fa64472",
            "miscselectMask": "0000fff",
            "attributes": "1254863548af4a6b2fcc2d3244784452",
            "attributesMask": "ffffffffffffffffffffffffffffffff",
            "mrsigner": "aaff34ffa51981951a61d616b16c16f1651c6516e51f651d26a6166ed5679c79",
            "isvprodid": 3,
            "tcbLevels": [
                {
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenMiscselectMaskIsTooLong)
{
    auto qeidTemplate = R"json({
            "id": "QE",
            "version": 2,
            "issueDate": "2018-10-04T11:10:45Z",
            "nextUpdate": "2019-06-21T12:36:02Z",
            "tcbEvaluationDataNumber":0,
            "miscselect": "8fa64472",
            "miscselectMask": "000012345",
            "attributes": "1254863548af4a6b2fcc2d3244784452",
            "attributesMask": "ffffffffffffffffffffffffffffffff",
            "mrsigner": "aaff34ffa51981951a61d616b16c16f1651c6516e51f651d26a6166ed5679c79",
            "isvprodid": 3,
            "tcbLevels": [
                {
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenAttributesAreMalformed)
{
    auto qeidTemplate = R"json({
            "id": "QE",
            "version": 2,
            "issueDate": "2018-10-04T11:10:45Z",
            "nextUpdate": "2019-06-21T12:36:02Z",
            "tcbEvaluationDataNumber":0,
            "miscselect": "8fa64472",
            "miscselectMask": "0000fffa",
            "attributes": "qwp4863548af4a6b2fcc2d3244784452",
            "attributesMask": "ffffffffffffffffffffffffffffffff",
            "mrsigner": "aaff34ffa51981951a61d616b16c16f1651c6516e51f651d26a6166ed5679c79",
            "isvprodid": 3,
            "tcbLevels": [
                {
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenAttributesAreNotAString)
{
    auto qeidTemplate = R"json({
            "id": "QE",
            "version": 2,
            "issueDate": "2018-10-04T11:10:45Z",
            "nextUpdate": "2019-06-21T12:36:02Z",
            "tcbEvaluationDataNumber":0,
            "miscselect": "8fa64472",
            "miscselectMask": "0000fffa",
            "attributes": true,
            "attributesMask": "ffffffffffffffffffffffffffffffff",
            "mrsigner": "aaff34ffa51981951a61d616b16c16f1651c6516e51f651d26a6166ed5679c79",
            "isvprodid": 3,
            "tcbLevels": [
                {
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenAttributesAreTooShort)
{
    auto qeidTemplate = R"json({
            "id": "QE",
            "version": 2,
            "issueDate": "2018-10-04T11:10:45Z",
            "nextUpdate": "2019-06-21T12:36:02Z",
            "tcbEvaluationDataNumber":0,
            "miscselect": "8fa64472",
            "miscselectMask": "0000fffa",
            "attributes": "1254863548af4a6b2fcc2d324478445",
            "attributesMask": "ffffffffffffffffffffffffffffffff",
            "mrsigner": "aaff34ffa51981951a61d616b16c16f1651c6516e51f651d26a6166ed5679c79",
            "isvprodid": 3,
            "tcbLevels": [
                {
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenAttributesAreTooLong)
{
    auto qeidTemplate = R"json({
            "id": "QE",
            "version": 2,
            "issueDate": "2018-10-04T11:10:45Z",
            "nextUpdate": "2019-06-21T12:36:02Z",
            "tcbEvaluationDataNumber":0,
            "miscselect": "8fa64472",
            "miscselectMask": "0000fffa",
            "attributes": "1254863548af4a6b2fcc2d32447844521",
            "attributesMask": "ffffffffffffffffffffffffffffffff",
            "mrsigner": "aaff34ffa51981951a61d616b16c16f1651c6516e51f651d26a6166ed5679c79",
            "isvprodid": 3,
            "tcbLevels": [
                {
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenAttributesMaskIsMalformed)
{
    auto qeidTemplate = R"json({
            "id": "QE",
            "version": 2,
            "issueDate": "2018-10-04T11:10:45Z",
            "nextUpdate": "2019-06-21T12:36:02Z",
            "tcbEvaluationDataNumber":0,
            "miscselect": "8fa64472",
            "miscselectMask": "0000fffa",
            "attributes": "1254863548af4a6b2fcc2d3244784452",
            "attributesMask": "ffffffffffffffffffffffffffff****",
            "mrsigner": "aaff34ffa51981951a61d616b16c16f1651c6516e51f651d26a6166ed5679c79",
            "isvprodid": 3,
            "tcbLevels": [
                {
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenAttributesMaskIsNotAString)
{
    auto qeidTemplate = R"json({
            "id": "QE",
            "version": 2,
            "issueDate": "2018-10-04T11:10:45Z",
            "nextUpdate": "2019-06-21T12:36:02Z",
            "tcbEvaluationDataNumber":0,
            "miscselect": "8fa64472",
            "miscselectMask": "0000fffa",
            "attributes": "1254863548af4a6b2fcc2d3244784452",
            "attributesMask": 0,
            "mrsigner": "aaff34ffa51981951a61d616b16c16f1651c6516e51f651d26a6166ed5679c79",
            "isvprodid": 3,
            "tcbLevels": [
                {
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenAttributesMaskIsTooShort)
{
    auto qeidTemplate = R"json({
            "id": "QE",
            "version": 2,
            "issueDate": "2018-10-04T11:10:45Z",
            "nextUpdate": "2019-06-21T12:36:02Z",
            "tcbEvaluationDataNumber":0,
            "miscselect": "8fa64472",
            "miscselectMask": "0000fffa",
            "attributes": "1254863548af4a6b2fcc2d3244784452",
            "attributesMask": "fffffffffffffffffffffffffffffff",
            "mrsigner": "aaff34ffa51981951a61d616b16c16f1651c6516e51f651d26a6166ed5679c79",
            "isvprodid": 3,
            "tcbLevels": [
                {
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenAttributesMaskIsTooLong)
{
    auto qeidTemplate = R"json({
            "id": "QE",
            "version": 2,
            "issueDate": "2018-10-04T11:10:45Z",
            "nextUpdate": "2019-06-21T12:36:02Z",
            "tcbEvaluationDataNumber":0,
            "miscselect": "8fa64472",
            "miscselectMask": "0000fffa",
            "attributes": "1254863548af4a6b2fcc2d3244784452",
            "attributesMask": "ffffffffffffffffffffffffffffffff0",
            "mrsigner": "aaff34ffa51981951a61d616b16c16f1651c6516e51f651d26a6166ed5679c79",
            "isvprodid": 3,
            "tcbLevels": [
                {
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenMrsignerIsMalformed)
{
    auto qeidTemplate = R"json({
            "id": "QE",
            "version": 2,
            "issueDate": "2018-10-04T11:10:45Z",
            "nextUpdate": "2019-06-21T12:36:02Z",
            "tcbEvaluationDataNumber":0,
            "miscselect": "8fa64472",
            "miscselectMask": "0000fffa",
            "attributes": "1254863548af4a6b2fcc2d3244784452",
            "attributesMask": "ffffffffffffffffffffffffffffffff",
            "mrsigner": "**++lkffa51981951a61d616b16c16f1651c6516e51f651d26a6166ed5679c79",
            "isvprodid": 3,
            "tcbLevels": [
                {
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenMrsignerIsNotAString)
{
    auto qeidTemplate = R"json({
            "id": "QE",
            "version": 2,
            "issueDate": "2018-10-04T11:10:45Z",
            "nextUpdate": "2019-06-21T12:36:02Z",
            "tcbEvaluationDataNumber":0,
            "miscselect": "8fa64472",
            "miscselectMask": "0000fffa",
            "attributes": "1254863548af4a6b2fcc2d3244784452",
            "attributesMask": "ffffffffffffffffffffffffffffffff",
            "mrsigner": 45,
            "isvprodid": 3,
            "tcbLevels": [
                {
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenMrsignerIsTooShort)
{
    auto qeidTemplate = R"json({
            "id": "QE",
            "version": 2,
            "issueDate": "2018-10-04T11:10:45Z",
            "nextUpdate": "2019-06-21T12:36:02Z",
            "tcbEvaluationDataNumber":0,
            "miscselect": "8fa64472",
            "miscselectMask": "0000fffa",
            "attributes": "1254863548af4a6b2fcc2d3244784452",
            "attributesMask": "ffffffffffffffffffffffffffffffff",
            "mrsigner": "aaff34ffa51981951a61d616b16c16f1651c6516e51f651d26a6166ed5679c7",
            "isvprodid": 3,
            "tcbLevels": [
                {
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenMrSignerIsTooLong)
{
    auto qeidTemplate = R"json({
            "id": "QE",
            "version": 2,
            "issueDate": "2018-10-04T11:10:45Z",
            "nextUpdate": "2019-06-21T12:36:02Z",
            "tcbEvaluationDataNumber":0,
            "miscselect": "8fa64472",
            "miscselectMask": "0000fffa",
            "attributes": "1254863548af4a6b2fcc2d3244784452",
            "attributesMask": "ffffffffffffffffffffffffffffffff",
            "mrsigner": "aaff34ffa51981951a61d616b16c16f1651c6516e51f651d26a6166ed5679c790",
            "isvprodid": 3,
            "tcbLevels": [
                {
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenIsvprodidIsNotANumber)
{
    auto qeidTemplate = R"json({
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
            "isvprodid": "3",
            "tcbLevels": [
                {
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenIsvsvnIsNotANumber)
{
    auto qeidTemplate = R"json({
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
                    "tcb":{ "isvsvn": "8" },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenTcbLevelsMaskFieldIsAnEmptyArray)
{
    auto qeidTemplate = R"json({
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
            "tcbLevels": []
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenTcbLevelsTcbStatusFieldInvalidValue)
{
    auto qeidTemplate = R"json({
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
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:29Z",
                    "tcbStatus":"NotUpToDate"
                }
            ]
        })json";
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenTcbLevelsTcbDateFieldInvalidValue)
{
    auto qeidTemplate = R"json({
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
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:290Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json"; // changed ":29Z" to ":290Z"
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::InvalidExtensionException);
}

TEST_F(EnclaveIdentityUT, shouldFailWhenTcbLevelIsInvalidType)
{
    auto qeidTemplate = R"json({
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
                1,
                {
                    "tcb":{ "isvsvn":8 },
                    "tcbDate":"2019-06-23T10:41:290Z",
                    "tcbStatus":"UpToDate"
                }
            ]
        })json"; // changed ":29Z" to ":290Z"
    auto json = enclaveIdentityJsonWithSignature(qeidTemplate);
    ASSERT_THROW(EnclaveIdentity::parse(json), parser::FormatException);
}
