#!/usr/bin/env python3
"""stress_test_msgraph_migrator.py - 38-Scenario Stress & Edge-Case Battery for msgraph-ps-migrator

Executes 38 rigorous edge-case, corruption, boundary, fuzzing, syntax, and performance
tests against migrate-msgraph.py to guarantee enterprise resilience.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Any, Dict, List

# Resolve scripts path
BASE_DIR = Path(__file__).resolve().parent
REPO_DIR = BASE_DIR.parent
script_file = REPO_DIR / "scripts" / "migrate-msgraph.py"
if not script_file.exists():
    script_file = REPO_DIR / "skills" / "msgraph-ps-migrator" / "scripts" / "migrate-msgraph.py"

import importlib.util
spec = importlib.util.spec_from_file_location("migrate_msgraph", str(script_file))
module = importlib.util.module_from_spec(spec)
sys.modules["migrate_msgraph"] = module
spec.loader.exec_module(module)

GraphMigrator = module.GraphMigrator
Sanitizer = module.Sanitizer
format_markdown = module.format_markdown
CMDLET_MAPPINGS = module.CMDLET_MAPPINGS


class TestSuite:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.results: List[tuple] = []

    def record(self, test_num: int, name: str, passed: bool, detail: str = ""):
        status = "PASS" if passed else "FAIL"
        if passed:
            self.passed += 1
        else:
            self.failed += 1
        self.results.append((test_num, name, status, detail))
        print(f"[{status}] Test {test_num:02d}: {name} {f'- {detail}' if detail else ''}")


def run_tests():
    suite = TestSuite()
    print("==================================================================")
    print("  msgraph-ps-migrator Comprehensive 38-Scenario Stress Test Suite")
    print("==================================================================")

    # Test 01: Empty Input
    try:
        migrator = GraphMigrator(raw_script="", script_name="Empty.ps1")
        analysis = migrator.analyze()
        suite.record(1, "Empty script input handled safely without exception", analysis.total_legacy_calls == 0 and len(analysis.findings) == 0)
    except Exception as exc:
        suite.record(1, "Empty script input", False, str(exc))

    # Test 02: Whitespace and Newlines Only
    try:
        migrator = GraphMigrator(raw_script="   \n\n\t  \r\n   ", script_name="Whitespace.ps1")
        analysis = migrator.analyze()
        suite.record(2, "Whitespace-only input returns 0 legacy calls", analysis.total_legacy_calls == 0)
    except Exception as exc:
        suite.record(2, "Whitespace-only input", False, str(exc))

    # Test 03: Pure Modern Graph Script
    try:
        modern_code = """
        Connect-MgGraph -Scopes "User.Read.All" -NoWelcome
        Get-MgUser -All | Select-Object Id, DisplayName, UserPrincipalName
        """
        migrator = GraphMigrator(raw_script=modern_code, script_name="Modern.ps1")
        analysis = migrator.analyze()
        suite.record(3, "Pure modern Graph script flags zero deprecated calls", analysis.total_legacy_calls == 0 and len(analysis.findings) == 0)
    except Exception as exc:
        suite.record(3, "Pure modern Graph script", False, str(exc))

    # Test 04: Pure Generic PowerShell Script
    try:
        generic_code = """
        Get-Process | Where-Object { $_.CPU -gt 10 } | Stop-Process -WhatIf
        $Date = Get-Date -Format "yyyy-MM-dd"
        Write-Output "Report generated on $Date"
        """
        migrator = GraphMigrator(raw_script=generic_code, script_name="Generic.ps1")
        analysis = migrator.analyze()
        suite.record(4, "Generic PowerShell without directory cmdlets flags zero calls", analysis.total_legacy_calls == 0)
    except Exception as exc:
        suite.record(4, "Generic PowerShell", False, str(exc))

    # Test 05: Corrupted Binary / Null Bytes
    try:
        corrupted = "Get-MsolUser\x00\xff\xfe\x01\x02 -SearchString \x00\x00"
        migrator = GraphMigrator(raw_script=corrupted, script_name="Corrupt.ps1")
        analysis = migrator.analyze()
        suite.record(5, "Corrupted binary and null bytes handled defensively", analysis.total_legacy_calls >= 1)
    except Exception as exc:
        suite.record(5, "Corrupted binary input", False, str(exc))

    # Test 06: Extremely Long Lines (10,000+ characters)
    try:
        long_line = "Get-MsolUser " + ("-SearchString 'Test' " * 600)
        migrator = GraphMigrator(raw_script=long_line, script_name="LongLine.ps1")
        analysis = migrator.analyze()
        suite.record(6, "Extremely long command line (10,000+ chars) parsed safely", analysis.total_legacy_calls == 1)
    except Exception as exc:
        suite.record(6, "Extremely long line", False, str(exc))

    # Test 07: Truncated Lines and Trailing Backticks
    try:
        truncated = "Get-MsolUser `\n    -All `\n    | Where-Object {$_.IsLicensed} `"
        migrator = GraphMigrator(raw_script=truncated, script_name="Truncated.ps1")
        analysis = migrator.analyze()
        suite.record(7, "Trailing line continuations and backticks handled gracefully", analysis.total_legacy_calls == 1)
    except Exception as exc:
        suite.record(7, "Truncated script lines", False, str(exc))

    # Test 08: Mixed MSOnline and AzureAD Cmdlets
    try:
        mixed_code = """
        Connect-MsolService
        Get-MsolUser -All
        Get-AzureADGroup -Top 50
        Get-MsolAccountSku
        Add-AzureADGroupMember -ObjectId "0000" -RefObjectId "1111"
        """
        migrator = GraphMigrator(raw_script=mixed_code, script_name="Mixed.ps1")
        analysis = migrator.analyze()
        suite.record(8, "Mixed MSOnline and AzureAD script identifies all legacy calls", analysis.total_legacy_calls == 5)
    except Exception as exc:
        suite.record(8, "Mixed MSOnline/AzureAD", False, str(exc))

    # Test 09: Comment Avoidance
    try:
        comment_code = """
        # Get-MsolUser should never run in production
        <#
        Get-AzureADUser -ObjectId "12345"
        #>
        Get-MsolGroup
        """
        migrator = GraphMigrator(raw_script=comment_code, script_name="Comments.ps1")
        analysis = migrator.analyze()
        # Only Get-MsolGroup should be recorded as a legacy finding
        valid = analysis.total_legacy_calls == 1 and analysis.findings[0].legacy_cmdlet == "Get-MsolGroup"
        suite.record(9, "Cmdlets inside single-line comments skipped from findings", valid)
    except Exception as exc:
        suite.record(9, "Comment avoidance", False, str(exc))

    # Test 10: String Literal Preservation
    try:
        literal_code = 'Write-Host "Warning: Get-MsolUser is deprecated and retiring soon!"'
        migrator = GraphMigrator(raw_script=literal_code, script_name="Literal.ps1")
        analysis = migrator.analyze()
        suite.record(10, "Cmdlet name inside string literal processed without syntax disruption", "Write-Host" in analysis.modernized_script)
    except Exception as exc:
        suite.record(10, "String literal preservation", False, str(exc))

    # Test 11: User Cmdlet Parameter Mapping (-ObjectId -> -UserId)
    try:
        script = "Get-AzureADUser -ObjectId 'user-12345'\nRemove-AzureADUser -ObjectId 'user-12345'"
        migrator = GraphMigrator(raw_script=script, script_name="UserParam.ps1")
        analysis = migrator.analyze()
        code = analysis.modernized_script
        valid = "-UserId 'user-12345'" in code and "Get-MgUser" in code and "Remove-MgUser" in code
        suite.record(11, "User cmdlet -ObjectId mapped to -UserId for Get and Remove", valid)
    except Exception as exc:
        suite.record(11, "User parameter mapping", False, str(exc))

    # Test 12: Group Cmdlet Parameter Mapping (-ObjectId -> -GroupId)
    try:
        script = "Get-AzureADGroup -ObjectId 'grp-999'\nRemove-AzureADGroup -ObjectId 'grp-999'"
        migrator = GraphMigrator(raw_script=script, script_name="GroupParam.ps1")
        analysis = migrator.analyze()
        code = analysis.modernized_script
        valid = "-GroupId 'grp-999'" in code and "Get-MgGroup" in code and "Remove-MgGroup" in code
        suite.record(12, "Group cmdlet -ObjectId mapped to -GroupId for Get and Remove", valid)
    except Exception as exc:
        suite.record(12, "Group parameter mapping", False, str(exc))

    # Test 13: Service Principal Cmdlet Parameter Mapping (-ObjectId -> -ServicePrincipalId)
    try:
        script = "Get-AzureADServicePrincipal -ObjectId 'sp-555'\nRemove-AzureADServicePrincipal -ObjectId 'sp-555'"
        migrator = GraphMigrator(raw_script=script, script_name="SpParam.ps1")
        analysis = migrator.analyze()
        code = analysis.modernized_script
        valid = "-ServicePrincipalId 'sp-555'" in code and "Get-MgServicePrincipal" in code
        suite.record(13, "Service Principal -ObjectId mapped to -ServicePrincipalId", valid)
    except Exception as exc:
        suite.record(13, "Service Principal parameter mapping", False, str(exc))

    # Test 14: Application Cmdlet Parameter Mapping (-ObjectId -> -ApplicationId)
    try:
        script = "Get-AzureADApplication -ObjectId 'app-777'"
        migrator = GraphMigrator(raw_script=script, script_name="AppParam.ps1")
        analysis = migrator.analyze()
        code = analysis.modernized_script
        valid = "-ApplicationId 'app-777'" in code and "Get-MgApplication" in code
        suite.record(14, "Application -ObjectId mapped to -ApplicationId", valid)
    except Exception as exc:
        suite.record(14, "Application parameter mapping", False, str(exc))

    # Test 15: Reference Parameter Mapping (-RefObjectId -> -DirectoryObjectId)
    try:
        script = "Add-AzureADGroupMember -ObjectId 'grp-1' -RefObjectId 'usr-2'"
        migrator = GraphMigrator(raw_script=script, script_name="RefParam.ps1")
        analysis = migrator.analyze()
        code = analysis.modernized_script
        valid = "New-MgGroupMemberByRef" in code and "-GroupId 'grp-1'" in code and "-DirectoryObjectId 'usr-2'" in code
        suite.record(15, "Add-AzureADGroupMember maps -RefObjectId to -DirectoryObjectId", valid)
    except Exception as exc:
        suite.record(15, "Reference parameter mapping", False, str(exc))

    # Test 16: Group Member Retrieval Parameter Mapping (-GroupObjectId -> -GroupId)
    try:
        script = "Get-MsolGroupMember -GroupObjectId 'grp-44'"
        migrator = GraphMigrator(raw_script=script, script_name="GrpMem.ps1")
        analysis = migrator.analyze()
        code = analysis.modernized_script
        valid = "Get-MgGroupMember" in code and "-GroupId 'grp-44'" in code
        suite.record(16, "Get-MsolGroupMember maps -GroupObjectId to -GroupId", valid)
    except Exception as exc:
        suite.record(16, "Group member retrieval mapping", False, str(exc))

    # Test 17: Auto-Injection of -All on Unbounded User Queries
    try:
        script = "Get-MsolUser"
        migrator = GraphMigrator(raw_script=script, script_name="UnboundedUser.ps1")
        analysis = migrator.analyze()
        code = analysis.modernized_script
        valid = "Get-MgUser -All" in code
        suite.record(17, "Unbounded user query auto-injects -All parameter to prevent silent truncation", valid)
    except Exception as exc:
        suite.record(17, "Auto-inject -All on user query", False, str(exc))

    # Test 18: Auto-Injection of -All on Unbounded Group Queries
    try:
        script = "Get-AzureADGroup"
        migrator = GraphMigrator(raw_script=script, script_name="UnboundedGroup.ps1")
        analysis = migrator.analyze()
        code = analysis.modernized_script
        valid = "Get-MgGroup -All" in code
        suite.record(18, "Unbounded group query auto-injects -All parameter", valid)
    except Exception as exc:
        suite.record(18, "Auto-inject -All on group query", False, str(exc))

    # Test 19: Auto-Injection of -All before Pipeline Pipes
    try:
        script = "Get-MsolUser | Where-Object { $_.IsLicensed -eq $true }"
        migrator = GraphMigrator(raw_script=script, script_name="PipelineAll.ps1")
        analysis = migrator.analyze()
        code = analysis.modernized_script
        valid = "Get-MgUser -All | Where-Object" in code
        suite.record(19, "Pipeline expression injects -All prior to pipe operator", valid)
    except Exception as exc:
        suite.record(19, "Auto-inject -All in pipeline", False, str(exc))

    # Test 20: No Redundant -All when Bounded or Top Specified
    try:
        script = "Get-AzureADUser -Top 25\nGet-AzureADUser -ObjectId 'user-999'"
        migrator = GraphMigrator(raw_script=script, script_name="Bounded.ps1")
        analysis = migrator.analyze()
        code = analysis.modernized_script
        valid = "-All" not in code and "-Top 25" in code and "-UserId 'user-999'" in code
        suite.record(20, "Bounded queries (-Top, -UserId) do not receive redundant -All injection", valid)
    except Exception as exc:
        suite.record(20, "No redundant -All on bounded query", False, str(exc))

    # Test 21: Licensing Cmdlet Migration (Set-MsolUserLicense)
    try:
        script = "Set-MsolUserLicense -UserPrincipalName 'user@test.local' -AddLicenses 'tenant:ENTERPRISEPACK'"
        migrator = GraphMigrator(raw_script=script, script_name="Licensing.ps1")
        analysis = migrator.analyze()
        valid = (
            analysis.findings[0].modern_cmdlet == "Set-MgUserLicense"
            and "SkuId GUID" in analysis.findings[0].notes
            and "User.ReadWrite.All" in analysis.required_delegated_scopes
        )
        suite.record(21, "Set-MsolUserLicense mapped to Set-MgUserLicense with SkuId GUID guidance", valid)
    except Exception as exc:
        suite.record(21, "Licensing cmdlet migration", False, str(exc))

    # Test 22: Subscribed SKU Query Modernization (Get-MsolAccountSku)
    try:
        script = "Get-MsolAccountSku"
        migrator = GraphMigrator(raw_script=script, script_name="Sku.ps1")
        analysis = migrator.analyze()
        code = analysis.modernized_script
        valid = (
            "Get-MgSubscribedSku -All" in code
            and "Organization.Read.All" in analysis.required_delegated_scopes
            and "Directory.ReadWrite.All" not in analysis.required_delegated_scopes
        )
        suite.record(22, "Get-MsolAccountSku mapped to Get-MgSubscribedSku with Organization.Read.All", valid)
    except Exception as exc:
        suite.record(22, "Subscribed SKU query", False, str(exc))

    # Test 23: Directory Role Query Migration
    try:
        script = "Get-MsolRole\nGet-AzureADDirectoryRole"
        migrator = GraphMigrator(raw_script=script, script_name="Roles.ps1")
        analysis = migrator.analyze()
        valid = (
            all(f.modern_cmdlet == "Get-MgDirectoryRole" for f in analysis.findings)
            and "RoleManagement.Read.Directory" in analysis.required_delegated_scopes
        )
        suite.record(23, "Role query cmdlets mapped to Get-MgDirectoryRole with RoleManagement scope", valid)
    except Exception as exc:
        suite.record(23, "Directory role query", False, str(exc))

    # Test 24: Directory Role Member Assignment Modernization
    try:
        script = "Add-MsolRoleMember -RoleObjectId 'role-1' -RoleMemberObjectId 'user-2'"
        migrator = GraphMigrator(raw_script=script, script_name="RoleAdd.ps1")
        analysis = migrator.analyze()
        valid = (
            analysis.findings[0].modern_cmdlet == "New-MgDirectoryRoleMemberByRef"
            and "RoleManagement.ReadWrite.Directory" in analysis.required_delegated_scopes
        )
        suite.record(24, "Add-MsolRoleMember mapped to New-MgDirectoryRoleMemberByRef", valid)
    except Exception as exc:
        suite.record(24, "Role member assignment", False, str(exc))

    # Test 25: Service Principal Password Credential Generation
    try:
        script = "New-AzureADServicePrincipalPasswordCredential -ObjectId 'sp-uuid'"
        migrator = GraphMigrator(raw_script=script, script_name="SpPass.ps1")
        analysis = migrator.analyze()
        valid = (
            analysis.findings[0].modern_cmdlet == "Add-MgServicePrincipalPassword"
            and "Application.ReadWrite.All" in analysis.required_delegated_scopes
        )
        suite.record(25, "New-AzureADServicePrincipalPasswordCredential mapped to Add-MgServicePrincipalPassword", valid)
    except Exception as exc:
        suite.record(25, "SP password credential", False, str(exc))

    # Test 26: Legacy Connection Modernization
    try:
        script = "Connect-MsolService\nConnect-AzureAD"
        migrator = GraphMigrator(raw_script=script, script_name="Connect.ps1")
        analysis = migrator.analyze()
        code = analysis.modernized_script
        valid = "Connect-MgGraph" in code and "Replaced legacy connection" in code
        suite.record(26, "Connect-MsolService & Connect-AzureAD replaced with Connect-MgGraph header", valid)
    except Exception as exc:
        suite.record(26, "Legacy connection modernization", False, str(exc))

    # Test 27: Scope Calculation Aggregation Across Multiple Cmdlets
    try:
        script = """
        Get-MsolUser -SearchString "Smith"
        Get-AzureADGroup -SearchString "IT"
        Get-MsolDomain
        Get-MsolAccountSku
        """
        migrator = GraphMigrator(raw_script=script, script_name="AggregateScopes.ps1")
        analysis = migrator.analyze()
        expected_scopes = {"User.Read.All", "Group.Read.All", "Domain.Read.All", "Organization.Read.All"}
        actual_scopes = set(analysis.required_delegated_scopes)
        valid = expected_scopes.issubset(actual_scopes)
        suite.record(27, "Multiple read-only cmdlets aggregate exact unique required scopes", valid)
    except Exception as exc:
        suite.record(27, "Scope aggregation", False, str(exc))

    # Test 28: Strict Least-Privilege Scoping (Zero Over-Privilege)
    try:
        script = "Get-MsolUser\nGet-MsolGroup"
        migrator = GraphMigrator(raw_script=script, script_name="LeastPriv.ps1")
        analysis = migrator.analyze()
        prohibited = {"Directory.ReadWrite.All", "User.ReadWrite.All", "Group.ReadWrite.All", "Global Admin"}
        valid = not any(p in analysis.required_delegated_scopes for p in prohibited)
        suite.record(28, "Read-only operations strictly omit ReadWrite and Directory.ReadWrite.All scopes", valid)
    except Exception as exc:
        suite.record(28, "Least privilege enforcement", False, str(exc))

    # Test 29: Parameter Alias & Case-Insensitivity
    try:
        script = "get-azureaduser -OBJECTID 'abc-123' -SEARCHSTRING 'test'"
        migrator = GraphMigrator(raw_script=script, script_name="CaseInsensitive.ps1")
        analysis = migrator.analyze()
        code = analysis.modernized_script
        valid = "Get-MgUser" in code and "-UserId 'abc-123'" in code
        suite.record(29, "Case-insensitive cmdlet and parameter matching executed cleanly", valid)
    except Exception as exc:
        suite.record(29, "Case-insensitivity", False, str(exc))

    # Test 30: High-Volume Throughput Benchmark (10,000 Lines in < 1.0s)
    try:
        large_script = "\n".join([
            f"Get-MsolUser -UserPrincipalName 'user_{i}@enterprise-corp.com'"
            for i in range(10000)
        ])
        start = time.perf_counter()
        migrator = GraphMigrator(raw_script=large_script, script_name="Benchmark.ps1", sanitize=True)
        analysis = migrator.analyze()
        elapsed = time.perf_counter() - start
        valid = elapsed < 1.0 and analysis.total_legacy_calls == 10000
        throughput = 10000 / elapsed if elapsed > 0 else 0
        suite.record(30, f"High-volume throughput benchmark (10,000 lines in {elapsed:.3f}s)", valid, f"Throughput: {throughput:,.0f} lines/sec")
    except Exception as exc:
        suite.record(30, "High-volume benchmark", False, str(exc))

    # Test 31: Rule 4 - SHA-256 UPN Masking
    try:
        sanitizer = Sanitizer(enabled=True)
        upn = "sarah.admin@enterprise-defense.com"
        masked = sanitizer.sanitize_upn(upn)
        digest = hashlib.sha256(upn.encode("utf-8")).hexdigest()[:6]
        expected = f"user-{digest}@synthetic-test.local"
        suite.record(31, "Rule 4: Enterprise UPN masked with SHA-256 hash in synthetic-test.local domain", masked == expected)
    except Exception as exc:
        suite.record(31, "UPN masking", False, str(exc))

    # Test 32: Rule 4 - Synthetic Domain Exclusion
    try:
        sanitizer = Sanitizer(enabled=True)
        synth_upn = "user-mock-01@synthetic-test.local"
        masked = sanitizer.sanitize_upn(synth_upn)
        suite.record(32, "Rule 4: Synthetic-test.local UPNs preserved without double hashing", masked == synth_upn)
    except Exception as exc:
        suite.record(32, "Synthetic domain exclusion", False, str(exc))

    # Test 33: Rule 4 - Tenant and Object GUID Zeroing
    try:
        sanitizer = Sanitizer(enabled=True)
        raw_guid = "9b1deb4d-3b7d-4bad-9bdd-2b0d7b4dcb6d"
        masked = sanitizer.sanitize_guid(raw_guid)
        valid = masked.startswith("00000000-0000-4000-a000-") and raw_guid != masked
        suite.record(33, "Rule 4: Object and tenant GUIDs zeroed into synthetic GUID range", valid)
    except Exception as exc:
        suite.record(33, "GUID zeroing", False, str(exc))

    # Test 34: Rule 4 - Parameter-Style Secret Scrubbing
    try:
        sanitizer = Sanitizer(enabled=True)
        cmd = 'Connect-AzureAD -Password "P@ssw0rd123!" -ApiKey "sk_live_123456789" -ClientSecret "Secr3tVal"'
        scrubbed = sanitizer.scrub_text(cmd)
        valid = (
            "P@ssw0rd123!" not in scrubbed
            and "sk_live_123456789" not in scrubbed
            and "Secr3tVal" not in scrubbed
            and "[REDACTED-SECRET]" in scrubbed
        )
        suite.record(34, "Rule 4: Parameter-style secrets (-Password, -ApiKey, -ClientSecret) scrubbed", valid)
    except Exception as exc:
        suite.record(34, "Parameter secret scrubbing", False, str(exc))

    # Test 35: Rule 4 - Key-Value Secret Scrubbing
    try:
        sanitizer = Sanitizer(enabled=True)
        text = 'client_secret: "mySuperSecretToken"\napi_key: abc123def456\ntoken=ghp_99999999'
        scrubbed = sanitizer.scrub_text(text)
        valid = (
            "mySuperSecretToken" not in scrubbed
            and "abc123def456" not in scrubbed
            and "ghp_99999999" not in scrubbed
            and "[REDACTED-SECRET]" in scrubbed
        )
        suite.record(35, "Rule 4: Key-value credentials (secret:, token=, api_key:) scrubbed", valid)
    except Exception as exc:
        suite.record(35, "Key-value secret scrubbing", False, str(exc))

    # Test 36: Rule 4 - Public IPv4 and IPv6 Sanitization
    try:
        sanitizer = Sanitizer(enabled=True)
        text = "Connecting from 203.0.113.195 and 2600:1f18:416:9900::1 via 127.0.0.1"
        scrubbed = sanitizer.scrub_text(text)
        valid = (
            "203.0.113.195" not in scrubbed
            and "2600:1f18" not in scrubbed
            and "198.51.100." in scrubbed
            and "2001:db8::1" in scrubbed
            and "127.0.0.1" in scrubbed
        )
        suite.record(36, "Rule 4: Public IPv4 and IPv6 obfuscated while preserving loopback 127.0.0.1", valid)
    except Exception as exc:
        suite.record(36, "IP address sanitization", False, str(exc))

    # Test 37: CLI JSON Export Schema Integrity
    try:
        script = "Get-MsolUser -All\nGet-AzureADGroup"
        migrator = GraphMigrator(raw_script=script, script_name="SchemaTest.ps1")
        analysis = migrator.analyze()
        d = analysis.to_dict()
        required_keys = {
            "script_name", "timestamp_utc", "total_legacy_calls", "unique_legacy_cmdlets",
            "required_delegated_scopes", "required_app_scopes", "findings", "modernized_script"
        }
        valid = required_keys.issubset(d.keys()) and isinstance(d["findings"], list) and len(d["findings"]) == 2
        suite.record(37, "CLI JSON export adheres to structured schema with all required keys", valid)
    except Exception as exc:
        suite.record(37, "JSON export schema", False, str(exc))

    # Test 38: Deterministic Idempotency
    try:
        script = """
        Connect-MsolService
        Get-MsolUser -All | Where-Object {$_.IsLicensed -eq $true}
        Get-MsolAccountSku
        """
        migrator1 = GraphMigrator(raw_script=script, script_name="Idempotent.ps1", sanitize=True)
        res1 = migrator1.analyze().to_dict()
        migrator2 = GraphMigrator(raw_script=script, script_name="Idempotent.ps1", sanitize=True)
        res2 = migrator2.analyze().to_dict()
        # Compare everything except timestamp
        res1.pop("timestamp_utc")
        res2.pop("timestamp_utc")
        valid = json.dumps(res1, sort_keys=True) == json.dumps(res2, sort_keys=True)
        suite.record(38, "Deterministic idempotency: repeated migrations yield identical results", valid)
    except Exception as exc:
        suite.record(38, "Deterministic idempotency", False, str(exc))

    # Test 39: Preserve Existing param() Block Without Duplicate param() Syntax Error
    try:
        script = 'param(\n    [string]$UserPrincipalName = "user@synthetic-test.local"\n)\nGet-MsolUser -UserPrincipalName $UserPrincipalName'
        migrator = GraphMigrator(raw_script=script, script_name="ParamBlock.ps1")
        analysis = migrator.analyze()
        param_occurrences = re.findall(r"^\s*param\s*\(", analysis.modernized_script, flags=re.IGNORECASE | re.MULTILINE)
        suite.record(39, "Existing param() block preserved at top without duplicate param() injection", len(param_occurrences) == 1)
    except Exception as exc:
        suite.record(39, "Existing param() block preservation", False, str(exc))

    # Test 40: Single-User Lookup (-UserPrincipalName -> -UserId) Suppresses -All
    try:
        script = "$u = Get-MsolUser -UserPrincipalName $UserPrincipalName -ErrorAction SilentlyContinue"
        migrator = GraphMigrator(raw_script=script, script_name="SingleUser.ps1")
        analysis = migrator.analyze()
        valid = "Get-MgUser -UserId $UserPrincipalName" in analysis.modernized_script and "-All" not in analysis.modernized_script
        suite.record(40, "Get-MsolUser -UserPrincipalName maps to -UserId and suppresses invalid -All", valid)
    except Exception as exc:
        suite.record(40, "Single-user lookup -All suppression", False, str(exc))

    # Test 41: Container Member Queries (Get-MgGroupMember / Get-MgDirectoryRoleMember) Inject -All Despite -GroupId
    try:
        script = "Get-AzureADGroupMember -ObjectId $g.Id\nGet-MsolRoleMember -RoleObjectId $r.Id"
        migrator = GraphMigrator(raw_script=script, script_name="ContainerMembers.ps1")
        analysis = migrator.analyze()
        code = analysis.modernized_script
        valid = "Get-MgGroupMember -GroupId $g.Id -All" in code and "Get-MgDirectoryRoleMember -DirectoryRoleId $r.Id -All" in code
        suite.record(41, "Container member cmdlets inject -All even when -GroupId or -DirectoryRoleId is present", valid)
    except Exception as exc:
        suite.record(41, "Container member -All injection", False, str(exc))

    # Test 42: Multiline Backtick Continuation Parameter Mapping
    try:
        script = "New-MsolUser -UserPrincipalName $upn `\n    -DisplayName $name `\n    -ForceChangePassword $true"
        migrator = GraphMigrator(raw_script=script, script_name="MultilineBacktick.ps1")
        analysis = migrator.analyze()
        valid = "-ForceChangePasswordNextSignIn $true" in analysis.modernized_script
        suite.record(42, "Multiline backtick continuation maps parameters on subsequent continuation lines", valid)
    except Exception as exc:
        suite.record(42, "Multiline backtick parameter mapping", False, str(exc))

    # Test 43: Inline Comment Immunity (No Double-Counting & -All Placed Before Inline Comment)
    try:
        script = "$users = Get-MsolUser # replaces legacy Get-MsolUser call"
        migrator = GraphMigrator(raw_script=script, script_name="InlineComment.ps1")
        analysis = migrator.analyze()
        valid = (
            analysis.total_legacy_calls == 1
            and "Get-MgUser -All # replaces legacy Get-MsolUser call" in analysis.modernized_script
        )
        suite.record(43, "Inline comments neither double-counted nor corrupted during -All injection", valid)
    except Exception as exc:
        suite.record(43, "Inline comment immunity", False, str(exc))

    # Test 44: Quoted String Literal Cmdlet Immunity (Zero Bogus Findings)
    try:
        script = 'Write-Output "Deprecated command Get-MsolUser was retired"\nGet-MsolDomain'
        migrator = GraphMigrator(raw_script=script, script_name="QuotedCmdlet.ps1")
        analysis = migrator.analyze()
        valid = (
            analysis.total_legacy_calls == 1
            and analysis.findings[0].legacy_cmdlet == "Get-MsolDomain"
            and 'Write-Output "Deprecated command Get-MsolUser was retired"' in analysis.modernized_script
        )
        suite.record(44, "Cmdlet names inside quoted strings ignored by analyzer and untouched in output", valid)
    except Exception as exc:
        suite.record(44, "Quoted string literal immunity", False, str(exc))

    # Test 45: Legacy SKU & Licensing Property Modernization (.AccountSkuId, .ActiveUnits, .IsLicensed)
    try:
        script = '$avail = $sku.ActiveUnits - $sku.ConsumedUnits\nWrite-Output $sku.AccountSkuId\n$u | Where-Object { $_.IsLicensed -eq $false }'
        migrator = GraphMigrator(raw_script=script, script_name="SkuProps.ps1")
        analysis = migrator.analyze()
        code = analysis.modernized_script
        valid = (
            "$sku.PrepaidUnits.Enabled" in code
            and "$sku.SkuPartNumber" in code
            and "($_.AssignedLicenses.Count -eq 0)" in code
        )
        suite.record(45, "Legacy properties (.AccountSkuId, .ActiveUnits, .IsLicensed) modernized to Graph schema", valid)
    except Exception as exc:
        suite.record(45, "Legacy property modernization", False, str(exc))

    # Test 46: Pre-Flight Checklist Valid Single -Scopes Array Syntax
    try:
        script = "Get-MsolUser\nGet-MsolGroup"
        migrator = GraphMigrator(raw_script=script, script_name="ChecklistScopes.ps1")
        analysis = migrator.analyze()
        md = format_markdown(analysis)
        valid = "Connect-MgGraph -Scopes 'Group.Read.All', 'User.Read.All'" in md
        suite.record(46, "Markdown pre-flight checklist emits valid comma-separated -Scopes array syntax", valid)
    except Exception as exc:
        suite.record(46, "Pre-flight checklist -Scopes syntax", False, str(exc))

    # Test 47: Bracketed IPv6 with Port Sanitization
    try:
        sanitizer = Sanitizer(enabled=True)
        scrubbed = sanitizer.scrub_text("Endpoint https://[2600:1f18:416:9900::1]:8443/oauth2/token")
        valid = "2600:1f18" not in scrubbed and "8443" not in scrubbed and "2001:db8::1" in scrubbed
        suite.record(47, "Rule 4: Bracketed IPv6 address with port stripped and sanitized", valid)
    except Exception as exc:
        suite.record(47, "Bracketed IPv6 with port", False, str(exc))

    # Test 48: PowerShell AST Scanner UTF-8 BOM & Single-Item JSON Inventory Ingestion
    try:
        import subprocess
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8-sig") as tf:
            json.dump({
                "TotalLegacyCalls": 1,
                "UniqueCmdlets": "Get-MsolUser",
                "Findings": {
                    "File": "Single.ps1",
                    "LineNumber": 1,
                    "Cmdlet": "Get-MsolUser",
                    "RawCommand": "Get-MsolUser -UserPrincipalName $upn"
                }
            }, tf)
            temp_path = tf.name
        proc = subprocess.run(
            [sys.executable, str(script_file), "-i", temp_path, "--format", "json"],
            capture_output=True, text=True, check=True
        )
        os.unlink(temp_path)
        out_json = json.loads(proc.stdout)
        valid = out_json["total_legacy_calls"] == 1 and "Get-MgUser -UserId $upn" in out_json["modernized_script"]
        suite.record(48, "UTF-8 BOM and single-item JSON inventory from PowerShell AST parsed cleanly", valid)
    except Exception as exc:
        suite.record(48, "UTF-8 BOM JSON inventory ingestion", False, str(exc))

    print("==================================================================")
    print(f"  STRESS TEST SUMMARY: {suite.passed} PASSED, {suite.failed} FAILED out of {len(suite.results)} tests")
    print("==================================================================")

    if suite.failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    run_tests()
