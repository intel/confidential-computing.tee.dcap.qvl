/*
 * Copyright (C) 2025 Intel Corporation
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

#ifndef SGXECDSAATTESTATION_TCBSTATUS_H
#define SGXECDSAATTESTATION_TCBSTATUS_H

#include <string>
#include <unordered_map>
#include <stdexcept>

#include "SgxEcdsaAttestation/AttestationParsers.h"

namespace intel::sgx::dcap::parser::json {

    inline TcbStatus parseStringToTcbStatus(const std::string& status)
    {
        // Constructed once, reused on subsequent calls (since C++11, thread-safe init)
        static const std::unordered_map<std::string, TcbStatus> kMap{
            {"UpToDate", TcbStatus::UpToDate},
            {"ConfigurationNeeded", TcbStatus::ConfigurationNeeded},
            {"OutOfDate", TcbStatus::OutOfDate},
            {"OutOfDateConfigurationNeeded", TcbStatus::OutOfDateConfigurationNeeded},
            {"Revoked", TcbStatus::Revoked},
        };

        const auto it = kMap.find(status);
        if (it == kMap.end())
            throw std::runtime_error("Cannot parse TCB status - unknown value");

        return it->second;
    }

} // namespace intel::sgx::dcap::parser::json

#endif //SGXECDSAATTESTATION_TCBSTATUS_H