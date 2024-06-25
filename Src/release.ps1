# Copyright (C) 2024 Intel Corporation
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 3. Neither the name of the copyright holder nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#
# SPDX-License-Identifier: BSD-3-Clause
#

param (
	[Parameter(Mandatory=$false)]
	[int]$vs = 2017,
	[Parameter(Mandatory=$false)]
	[String]$buildTools
)

function Invoke-VS-Env {
	param(
		[int] $vs
	)
	$scriptName = $(
	Get-Childitem -Path "C:\Program Files*\Microsoft Visual Studio\$vs\*\VC\Auxiliary\Build\vcvars64.bat" -Recurse |
			Select-Object FullName |
			Select-Object -Last 1
	).FullName

	if ([string]::IsNullOrWhiteSpace($scriptName)) {
		Write-Error "Environment for Visual Studio $vs was not found"
		exit 1
	}
	# Run vcvars64 and get environment variables
	$cmdline = """$scriptName"" & set"
	& cmd.exe /c $cmdline | Foreach-Object {
		if ($_ -match "^(.*?)=(.*)$")
		{
			Set-Content "env:\$($matches[1])" $matches[2]
		}
	}
}

Invoke-VS-Env $vs

New-Item -ItemType Directory -Force -Path ${PSScriptRoot}\Build
$cwd = Get-Location

$generator = "Visual Studio 15 2017"
if ($vs -eq 2019) {
	$generator = "Visual Studio 16 2019"
}

if ($vs -eq 2022) {
	$generator = "Visual Studio 17 2022"
}

$cmakeGenerateArguments = @('-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_CONFIGURATION_TYPES="Release"', '-DBUILD_TEE=ON', '-G', $generator, '-A', 'x64')

if (![string]::IsNullOrWhiteSpace($buildTools)) {
	$cmakeGenerateArguments += "-T$($buildTools)"
}

if ($vs -eq 2017) {
	# workaround for old cmake that is included in VS2017 and doesn't support -B and -S command line arguments.
	Set-Location -Path ${PSScriptRoot}\Build\
	$cmakeGenerateArguments += ${PSScriptRoot}
}
else {
	$cmakeGenerateArguments += @( '-B', "${PSScriptRoot}\Build", '-S', ${PSScriptRoot})
}

Write-Host "Running CMake with arguments: $cmakeGenerateArguments"
& cmake $cmakeGenerateArguments
if($LastExitCode -ne 0)
{
	Write-Error "CMake generation failed: $LastExitCode"
	Set-Location -Path $cwd
	exit $LastExitCode
}

Write-Host "Running MSBuild"
$cmakeBuildlArguments = @('--build', "${PSScriptRoot}\Build", "--config", "Release", "--target", "install")
& cmake $cmakeBuildlArguments
if($LastExitCode -ne 0)
{
    Write-Error "CMake build failed: $LastExitCode"
	Set-Location -Path $cwd
	exit $LastExitCode
}

Write-Host "Running tests"
$ctestArguments = @("-C", "Release", "--test-dir", "${PSScriptRoot}\Build")
& ctest $ctestArguments
if($LastExitCode -ne 0)
{
	Write-Error "CTest failed: $LastExitCode"
	Set-Location -Path $cwd
	exit $LastExitCode
}

Set-Location -Path $cwd
Write-Host "Finished successfully"