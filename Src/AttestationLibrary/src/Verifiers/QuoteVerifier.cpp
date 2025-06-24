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

#include "QuoteVerifier.h"
#include "Checks/TcbLevelCheck.h" // checkTcbLevel
#include "Checks/TdxModuleCheck.h" // findTdxModuleIdentity
#include "Utils/RuntimeException.h"
#include "Utils/Logger.h"
#include "Utils/StatusPrinter.h"

#include <functional>

#include <CertVerification/X509Constants.h>
#include <QuoteVerification/QuoteConstants.h>
#include <OpensslHelpers/DigestUtils.h>
#include <OpensslHelpers/KeyUtils.h>
#include <OpensslHelpers/SignatureVerification.h>
#include <Verifiers/PckCertVerifier.h>

using namespace intel::sgx::dcap::parser::json;

namespace intel::sgx::dcap {

Status QuoteVerifier::verify(const Quote& quote,
                             const dcap::parser::x509::PckCertificate& pckCert,
                             const pckparser::CrlStore& crl,
                             const dcap::parser::json::TcbInfo& tcbInfo,
                             const EnclaveIdentity *enclaveIdentity,
                             const EnclaveReportVerifier& enclaveReportVerifier,
                             VerificationCollateralInfo& verificationCollateralInfo)
{
    Optional<Status> qeIdentityStatus;

    /// 4.1.2.5.5
    if (!_baseVerififer.commonNameContains(pckCert.getSubject(), constants::SGX_PCK_CN_PHRASE)) {
        LOG_ERROR("PCK Certificate. CN in Subject field does not contain \"SGX PCK Certificate\" phrase");
        return STATUS_INVALID_PCK_CERT;
    }

    /// 4.1.2.5.7
    if(!PckCrlVerifier{}.checkIssuer(crl))
    {
        LOG_ERROR("PCK Revocation List. CN in Issuer field does not contain \"CA\" phrase");
        return STATUS_INVALID_PCK_CRL;
    }

    const auto crlIssuerRaw = crl.getIssuer().raw;
    const auto pckCertIssuerRaw = pckCert.getIssuer().getRaw();
    if(crlIssuerRaw != pckCertIssuerRaw)
    {
        LOG_ERROR("Issuers in PCK revocation List and PCK Certificate are not the same. RL: {}, Cert: {}",
                  crlIssuerRaw, pckCertIssuerRaw);
        return STATUS_INVALID_PCK_CRL;
    }

    /// 4.1.2.5.8
    if(crl.isRevoked(pckCert))
    {
        LOG_ERROR("PCK Certificate is revoked by PCK Revocation List");
        return STATUS_PCK_REVOKED;
    }

    /// 4.1.2.5.10
    if(tcbInfo.getVersion() >= 3)
    {
        if(tcbInfo.getId() == parser::json::TcbInfo::TDX_ID && quote.getHeader().teeType != dcap::constants::TEE_TYPE_TDX)
        {
            LOG_ERROR("TcbInfo is generated for TDX and does not match Quote's TEE");
            return STATUS_TCB_INFO_MISMATCH;
        }
        if(tcbInfo.getId() == parser::json::TcbInfo::SGX_ID && quote.getHeader().teeType != dcap::constants::TEE_TYPE_SGX)
        {
            LOG_ERROR("TcbInfo is generated for SGX and does not match Quote's TEE");
            return STATUS_TCB_INFO_MISMATCH;
        }
    }
    else // deprecated
    {
        if(quote.getHeader().teeType == dcap::constants::TEE_TYPE_TDX)
        {
            LOG_ERROR("TcbInfo version {} is invalid for TDX TEE", tcbInfo.getVersion());
            return STATUS_TCB_INFO_MISMATCH;
        }
    }

    /// 4.1.2.5.11
    if(pckCert.getFmspc() != tcbInfo.getFmspc())
    {
        LOG_ERROR("FMSPC value from TcbInfo ({}) and SGX Extension in PCK Cert ({}) do not match",
                  bytesToHexString(tcbInfo.getFmspc()), bytesToHexString(pckCert.getFmspc()));
        return STATUS_TCB_INFO_MISMATCH;
    }

    if(pckCert.getPceId() != tcbInfo.getPceId())
    {
        LOG_ERROR("PCEID value from TcbInfo ({}) and SGX Extension in PCK Cert ({}) do not match",
                  bytesToHexString(tcbInfo.getPceId()), bytesToHexString(pckCert.getPceId()));
        return STATUS_TCB_INFO_MISMATCH;
    }

    const auto certificationDataVerificationStatus = verifyCertificationData(quote.getCertificationData());
    if(certificationDataVerificationStatus != STATUS_OK)
    {
        return certificationDataVerificationStatus;
    }

    auto pubKey = crypto::rawToP256PubKey(pckCert.getPubKey());
    if (pubKey == nullptr)
    {
        LOG_ERROR("Public key parsing error. PCK Certificate is invalid");
        return STATUS_INVALID_PCK_CERT; // if there were issues with parsing public key it means cert was invalid.
                                        // Probably it will never happen because parsing cert should fail earlier.
    }

    Optional<TdxModuleIdentity> tdxModuleIdentity;

    if (tcbInfo.getVersion() >= 3 && tcbInfo.getId() == parser::json::TcbInfo::TDX_ID)
    {
        /// 4.1.2.5.12
        const auto& tdxModule = tcbInfo.getTdxModule();
        const auto& quoteMrSignerSeam = quote.getMrSignerSeam();
        const auto& quoteSeamAttributes = quote.getSeamAttributes();

        const auto& tdxModuleVersion = quote.getTeeTcbSvn()[1];
        auto tdxModuleMrSigner = tdxModule.getMrSigner(); // can be overwritten by value from TDX Module Identity
        auto tdxModuleAttributes = tdxModule.getAttributes(); // can be overwritten by value from TDX Module Identity
        auto tdxModuleAttributesMask = tdxModule.getAttributesMask(); // can be overwritten by value from TDX Module Identity

        if (quote.getHeader().version > constants::QUOTE_VERSION_3 && tdxModuleVersion > 0)
        {
            try
            {
                tcbInfo.getTdxModuleIdentities();
            }
            catch (const parser::FormatException& ex)
            {
                LOG_ERROR("TDX Module version is {} but TCB Info structure returned: {}", tdxModuleVersion, ex.what());
                return STATUS_TCB_INFO_MISMATCH;
            }

            tdxModuleIdentity = findTdxModuleIdentity(tcbInfo.getTdxModuleIdentities(), tdxModuleVersion);
            if (!tdxModuleIdentity)
            {
                return STATUS_TDX_MODULE_MISMATCH;
            }
            tdxModuleMrSigner = tdxModuleIdentity->getMrSigner();
            tdxModuleAttributes = tdxModuleIdentity->getAttributes();
            tdxModuleAttributesMask = tdxModuleIdentity->getAttributesMask();
        }

        /// 4.1.2.5.12.1
        if (quoteMrSignerSeam.size() != tdxModuleMrSigner.size())
        {
            LOG_ERROR("MRSIGNERSEAM value size from TdReport in Quote ({}) and MRSIGNER value size from TcbInfo ({}) are not the same",
                      quoteMrSignerSeam.size(), tdxModuleMrSigner.size());
            return STATUS_TDX_MODULE_MISMATCH;
        }

        for(uint32_t i = 0; i < tdxModuleMrSigner.size(); i++)
        {
            if (tdxModuleMrSigner[i] != quoteMrSignerSeam[i])
            {
                LOG_ERROR("MRSIGNERSEAM value from TdReport in Quote ({}) and MRSIGNER value from TcbInfo ({}) are not the same",
                          bytesToHexString(std::vector<uint8_t>(begin(quoteMrSignerSeam), end(quoteMrSignerSeam))),
                          bytesToHexString(std::vector<uint8_t>(begin(tdxModuleMrSigner), end(tdxModuleMrSigner))));
                return STATUS_TDX_MODULE_MISMATCH;
            }
        }

        /// 4.1.2.5.12.2
        if (quoteSeamAttributes.size() != tdxModuleAttributes.size())
        {
            LOG_ERROR("SEAMATTRIBUTES value size from TdReport in Quote ({}) and TDXMODULEATTRIBUTES value size from TcbInfo ({}) are not the same",
                      quoteMrSignerSeam.size(), tdxModuleMrSigner.size());
            return STATUS_TDX_MODULE_MISMATCH;
        }

        for (uint32_t i = 0; i < quoteSeamAttributes.size(); i++)
        {
            if (quoteSeamAttributes[i] != 0 || quoteSeamAttributes[i] != tdxModuleAttributes[i])
            {
                LOG_ERROR("SEAMATTRIBUTES values from TdReport in Quote ({}) and TDXMODULEATTRIBUTES from TcbInfo ({}) are not the same or not zeroed",
                          bytesToHexString(Bytes(quoteSeamAttributes.begin(), quoteSeamAttributes.end())),
                          bytesToHexString(tdxModuleAttributes));
                return STATUS_TDX_MODULE_MISMATCH;
            }
        }
    }

    /// 4.1.2.5.13
    if (!crypto::verifySha256EcdsaSignature(quote.getQeReportSignature(), quote.getQeReport().rawBlob(), *pubKey))
    {
        LOG_ERROR("QE Report Signature extracted from quote ({}) cannot be verified with the Public Key extracted from PCK Certificate ({})",
                  bytesToHexString(std::vector<uint8_t>(begin(quote.getQeReportSignature()), end(quote.getQeReportSignature()))),
                  bytesToHexString(pckCert.getPubKey()));
        return STATUS_INVALID_QE_REPORT_SIGNATURE;
    }

    /// 4.1.2.5.14
    const auto hashedConcatOfAttestKeyAndQeReportData = [&]() -> std::vector<uint8_t>
    {
        std::vector<uint8_t> ret;
        ret.reserve(quote.getAttestKeyData().size() + quote.getQeAuthData().size());
        std::copy(quote.getAttestKeyData().begin(), quote.getAttestKeyData().end(), std::back_inserter(ret));
        std::copy(quote.getQeAuthData().begin(), quote.getQeAuthData().end(), std::back_inserter(ret));

        return crypto::sha256Digest(ret);
    }();

    if(hashedConcatOfAttestKeyAndQeReportData.empty() || !std::equal(hashedConcatOfAttestKeyAndQeReportData.begin(),
                                                                     hashedConcatOfAttestKeyAndQeReportData.end(),
                                                                     quote.getQeReport().reportData.begin()))
    {
        LOG_ERROR("Report Data value extracted from QE Report in Quote ({}) and the value of SHA256 calculated over the concatenation of ECDSA Attestation Key and QE Authenticated Data extracted from Quote ({}) are not the same",
                  bytesToHexString(std::vector<uint8_t>(begin(quote.getQeReport().reportData), end(quote.getQeReport().reportData))),
                  bytesToHexString(hashedConcatOfAttestKeyAndQeReportData));
        return STATUS_INVALID_QE_REPORT_DATA;
    }

    if (enclaveIdentity)
    {
        /// 4.1.2.5.15
        if(quote.getHeader().teeType == dcap::constants::TEE_TYPE_TDX)
        {
            if(enclaveIdentity->getVersion() == 1)
            {
                LOG_ERROR("Enclave Identity version 1 is invalid for TDX TEE");
                return STATUS_QE_IDENTITY_MISMATCH;
            }
            else if(enclaveIdentity->getVersion() == 2)
            {
                if(enclaveIdentity->getID() != EnclaveID::TD_QE)
                {
                    LOG_ERROR("Enclave Identity is not generated for TDX and does not match Quote's TEE");
                    return STATUS_QE_IDENTITY_MISMATCH;
                }
            }
        }
        else if(quote.getHeader().teeType == dcap::constants::TEE_TYPE_SGX)
        {
            if(enclaveIdentity->getID() != EnclaveID::QE)
            {
                LOG_ERROR("Enclave Identity is not generated for SGX and does not match Quote's TEE");
                return STATUS_QE_IDENTITY_MISMATCH;
            }
        }
        else
        {
            LOG_ERROR("Unknown Quote's TEE. Enclave Identity cannot be valid");
            return STATUS_QE_IDENTITY_MISMATCH;
        }

        /// 4.1.2.5.16
        qeIdentityStatus = enclaveReportVerifier.verify(enclaveIdentity, quote.getQeReport(), &verificationCollateralInfo);
        LOG_INFO("QE Identity - Status: {}", printStatus(qeIdentityStatus.value()));
        switch(qeIdentityStatus.value()) {
            case STATUS_SGX_ENCLAVE_REPORT_UNSUPPORTED_FORMAT:
                return STATUS_UNSUPPORTED_QUOTE_FORMAT;
            case STATUS_SGX_ENCLAVE_IDENTITY_UNSUPPORTED_FORMAT:
            case STATUS_SGX_ENCLAVE_IDENTITY_INVALID:
            case STATUS_SGX_ENCLAVE_IDENTITY_UNSUPPORTED_VERSION:
                return STATUS_UNSUPPORTED_QE_IDENTITY_FORMAT;
            case STATUS_SGX_ENCLAVE_REPORT_MISCSELECT_MISMATCH:
            case STATUS_SGX_ENCLAVE_REPORT_ATTRIBUTES_MISMATCH:
            case STATUS_SGX_ENCLAVE_REPORT_MRSIGNER_MISMATCH:
            case STATUS_SGX_ENCLAVE_REPORT_ISVPRODID_MISMATCH:
                return STATUS_QE_IDENTITY_MISMATCH;
            case STATUS_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE:
            case STATUS_SGX_ENCLAVE_REPORT_ISVSVN_REVOKED:
            default:
                break;
        }
    }

    const auto attestKey = crypto::rawToP256PubKey(quote.getAttestKeyData());
    if(!attestKey)
    {
        verificationCollateralInfo.setError();
        return STATUS_UNSUPPORTED_QUOTE_FORMAT;
    }

    /// 4.1.2.5.17
    if (!crypto::verifySha256EcdsaSignature(quote.getQuoteSignature(),
                                            quote.getSignedData(),
                                            *attestKey))
    {
        LOG_ERROR("Quote Signature ({}) cannot be verified with ECDSA Attestation Key ({})",
                  bytesToHexString(std::vector<uint8_t>(begin(quote.getQuoteSignature()), end(quote.getQuoteSignature()))),
                  bytesToHexString(std::vector<uint8_t>(begin(quote.getAttestKeyData()), end(quote.getAttestKeyData()))));
        verificationCollateralInfo.setError();
        return STATUS_INVALID_QUOTE_SIGNATURE;
    }

    try
    {
        /// 4.1.2.5.18
        return checkTcbLevel(tcbInfo, pckCert, quote, qeIdentityStatus, tdxModuleIdentity, verificationCollateralInfo);
    }
    catch (const RuntimeException &ex)
    {
        verificationCollateralInfo.setError();
        return ex.getStatus();
    }
}

Status QuoteVerifier::verifyCertificationData(const CertificationData& certificationData)
{
    if (certificationData.parsedDataSize != certificationData.data.size())
    {
        LOG_ERROR("Unexpected parsed data size, expected: {}, actual: {}",
                  certificationData.data.size(), certificationData.parsedDataSize);
        return STATUS_UNSUPPORTED_QUOTE_FORMAT;
    }

    return STATUS_OK;
}

} // namespace intel::sgx::dcap
