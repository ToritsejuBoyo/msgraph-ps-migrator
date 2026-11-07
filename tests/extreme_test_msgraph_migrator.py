#!/usr/bin/env python3
"""extreme_test_msgraph_migrator.py - Extreme Edge-Case Battery for msgraph-ps-migrator

Executes 23 extreme scenarios covering PowerShell parser traps (here-strings, inline block
comments, nested subexpressions, script blocks, statement separators, colon-bound and
splatted parameters), semantic translation traps (-SearchString, -All $true, module
loading, unattended app-only authentication), Rule 4 sanitization traps (Unicode UPNs,
hashtable secrets, SecureString plaintext, JWT bearer tokens), regular-expression denial of
service, binary garbage, 50,000-line throughput, file encodings, and CLI failure handling.

Returns exit code 0 only when every scenario passes.
"""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import random
import re
import subprocess
import sys
import tempfile
import time

BASE_DIR = Path(__file__).resolve().parent
REPO_DIR = BASE_DIR.parent
script_file = REPO_DIR / "scripts" / "migrate-msgraph.py"

spec = importlib.util.spec_from_file_location("migrate_msgraph_extreme", str(script_file))
module = importlib.util.module_from_spec(spec)
sys.modules["migrate_msgraph_extreme"] = module
spec.loader.exec_module(module)

GraphMigrator = module.GraphMigrator
Sanitizer = module.Sanitizer


def migrate(script: str, sanitize: bool = False):
    return GraphMigrator(raw_script=script, script_name="Extreme.ps1", sanitize=sanitize).analyze()


def run_cli(args, timeout=60):
    return subprocess.run(
        [sys.executable, str(script_file)] + args,
        capture_output=True, text=True, timeout=timeout
    )


class Suite:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.total = 0

    def record(self, num, name, ok, detail=""):
        self.total += 1
        if ok:
            self.passed += 1
        else:
            self.failed += 1
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] Extreme {num:02d}: {name}{' - ' + detail if detail else ''}")


def main() -> int:
    s = Suite()
    print("==================================================================")
    print("  msgraph-ps-migrator Extreme Edge-Case Battery (23 Scenarios)")
    print("==================================================================")

    # E01: Here-string immunity
    try:
        script = (
            '$body = @"\nGet-MsolUser -All\nSet-MsolUser -UserPrincipalName x -ObjectId y\n"@\n'
            "$lit = @'\nRemove-MsolUser -ObjectId z\n'@\nGet-MsolDomain"
        )
        a = migrate(script)
        code = a.modernized_script
        ok = (
            a.total_legacy_calls == 1
            and "Set-MsolUser -UserPrincipalName x -ObjectId y" in code
            and "Remove-MsolUser -ObjectId z" in code
            and "Get-MgDomain -All" in code
        )
        s.record(1, "Here-string bodies are neither counted nor rewritten", ok, f"calls={a.total_legacy_calls}")
    except Exception as exc:
        s.record(1, "Here-string immunity", False, repr(exc))

    # E02: Inline single-line block comment followed by executable code
    try:
        a = migrate("<# inline note #> Get-MsolUser\nGet-MsolGroup")
        ok = a.total_legacy_calls == 2 and "<# inline note #> Get-MgUser -All" in a.modernized_script
        s.record(2, "Code after a single-line <# ... #> comment is still migrated", ok, f"calls={a.total_legacy_calls}")
    except Exception as exc:
        s.record(2, "Inline block comment", False, repr(exc))

    # E03: '<#' and '#>' inside string literals must not open/close comment mode
    try:
        a = migrate('Write-Host "Scanning <# not a comment"\nGet-MsolUser\nWrite-Host \'Done #> here\'')
        ok = a.total_legacy_calls == 1 and "Get-MgUser -All" in a.modernized_script
        s.record(3, "Comment tokens inside strings do not swallow the rest of the script", ok, f"calls={a.total_legacy_calls}")
    except Exception as exc:
        s.record(3, "Comment tokens in strings", False, repr(exc))

    # E04: -All placed inside parenthesized subexpressions
    try:
        a = migrate("$count = (Get-MsolUser).Count\n$first = (Get-MsolGroup | Select-Object -First 1)")
        code = a.modernized_script
        ok = "(Get-MgUser -All).Count" in code and "(Get-MgGroup -All | Select-Object -First 1)" in code
        s.record(4, "-All injected inside (subexpression) instead of after .Count", ok)
    except Exception as exc:
        s.record(4, "Subexpression -All placement", False, repr(exc))

    # E05: Nested legacy cmdlet inside ForEach-Object script block
    try:
        a = migrate("Get-MsolGroup | ForEach-Object { Get-MsolGroupMember -GroupObjectId $_.ObjectId }")
        ok = "Get-MgGroup -All | ForEach-Object { Get-MgGroupMember -GroupId $_.Id -All }" in a.modernized_script
        s.record(5, "Each cmdlet in a pipeline/script block receives its own -All", ok)
    except Exception as exc:
        s.record(5, "Script block nesting", False, repr(exc))

    # E06: Parameter bleed between outer and nested cmdlets
    try:
        script = (
            "Add-AzureADGroupMember -ObjectId $g -RefObjectId (Get-AzureADUser -ObjectId $u).ObjectId\n"
            'Get-MsolGroupMember -GroupObjectId (Get-MsolGroup -SearchString "Ops").ObjectId'
        )
        code = migrate(script).modernized_script
        ok = (
            "New-MgGroupMemberByRef -GroupId $g -DirectoryObjectId (Get-MgUser -UserId $u).Id" in code
            and "Get-MgGroupMember -GroupId (Get-MgGroup -Filter \"startswith(displayName,'Ops')\" -All).Id -All" in code
        )
        s.record(6, "Nested cmdlet parameters mapped per-command (no -ObjectId bleed)", ok)
    except Exception as exc:
        s.record(6, "Parameter bleed", False, repr(exc))

    # E07: Semicolon-separated statements on one line
    try:
        code = migrate('Get-MsolUser -UserPrincipalName $a; Get-MsolUser; Get-MsolDomain -DomainName "contoso.com"').modernized_script
        ok = 'Get-MgUser -UserId $a; Get-MgUser -All; Get-MgDomain -DomainId "contoso.com"' in code
        s.record(7, "Statements separated by ';' are evaluated independently", ok)
    except Exception as exc:
        s.record(7, "Semicolon statements", False, repr(exc))

    # E08: Colon-bound parameter syntax
    try:
        code = migrate('Get-MsolUser -UserPrincipalName:$upn\nSet-MsolUser -UserPrincipalName:$upn -Department:"Ops"').modernized_script
        ok = "Get-MgUser -UserId:$upn" in code and 'Update-MgUser -UserId:$upn -Department:"Ops"' in code and "-All" not in code
        s.record(8, "Colon-bound parameters (-Param:$value) mapped without bogus -All", ok)
    except Exception as exc:
        s.record(8, "Colon-bound parameters", False, repr(exc))

    # E09: -SearchString converted into a valid OData filter
    try:
        script = 'Get-MsolUser -SearchString "Smith"\nGet-AzureADGroup -SearchString $GroupName\nGet-AzureADUser -SearchString $cfg.Prefix'
        code = migrate(script).modernized_script
        ok = (
            "Get-MgUser -Filter \"startswith(displayName,'Smith')\" -All" in code
            and "Get-MgGroup -Filter \"startswith(displayName,'$GroupName')\" -All" in code
            and "Get-MgUser -Filter \"startswith(displayName,'$($cfg.Prefix)')\" -All" in code
        )
        s.record(9, "-SearchString rewritten to valid OData startswith() filter", ok)
    except Exception as exc:
        s.record(9, "SearchString translation", False, repr(exc))

    # E10: #Requires / Import-Module / Install-Module referencing retired modules
    try:
        script = (
            "#Requires -Modules MSOnline, ActiveDirectory\n"
            "Import-Module AzureAD -ErrorAction Stop\n"
            "Install-Module -Name MSOnline -RequiredVersion 1.1.183.66 -Scope CurrentUser\n"
            "Get-MsolUser\nGet-AzureADGroup"
        )
        code = migrate(script).modernized_script
        req_line = next((ln for ln in code.splitlines() if ln.lstrip().lower().startswith("#requires")), "")
        ok = (
            "MSOnline" not in req_line
            and "ActiveDirectory" in req_line
            and "Microsoft.Graph.Users" in req_line
            and "Microsoft.Graph.Groups" in req_line
            and "Import-Module AzureAD" not in code
            and "Import-Module Microsoft.Graph" in code
            and "Install-Module -Name Microsoft.Graph -Scope CurrentUser" in code
            and "RequiredVersion" not in code
        )
        s.record(10, "Retired module loading (#Requires/Import/Install) rewritten to Microsoft.Graph", ok)
    except Exception as exc:
        s.record(10, "Module loading rewrite", False, repr(exc))

    # E11: Splatted parameters flagged for manual review
    try:
        a = migrate("$p = @{ ObjectId = $id }\nGet-AzureADUser @p")
        ok = "MIGRATION-REVIEW" in a.modernized_script and any("splat" in f.notes.lower() for f in a.findings)
        s.record(11, "Splatted hashtable parameters flagged with MIGRATION-REVIEW marker", ok)
    except Exception as exc:
        s.record(11, "Splatting review", False, repr(exc))

    # E12: Unicode / internationalized UPN sanitization
    try:
        out = Sanitizer(enabled=True).scrub_text("Owner: jos\u00e9.garc\u00eda@contoso-m\u00fcnchen.de and \u00dcnal@\u00f6rnek.com.tr")
        ok = "jos\u00e9" not in out and "m\u00fcnchen" not in out and "\u00dcnal" not in out and "synthetic-test.local" in out
        s.record(12, "Rule 4: Unicode/IDN UPNs fully masked (no partial PII leak)", ok, out if not ok else "")
    except Exception as exc:
        s.record(12, "Unicode UPN sanitization", False, repr(exc))

    # E13: Secrets in hashtables and variables redacted while preserving valid syntax
    try:
        out = Sanitizer(enabled=True).scrub_text('$cred = @{ Password = "Hunter2!"; User = "x" }\n$secret = \'abc123\'\n$token=xyz789')
        ok = (
            "Hunter2!" not in out and "abc123" not in out and "xyz789" not in out
            and 'Password = "[REDACTED-SECRET]"' in out
            and '$secret = "[REDACTED-SECRET]"' in out
            and '$token="[REDACTED-SECRET]"' in out
        )
        s.record(13, "Rule 4: Hashtable/variable secrets redacted with syntax preserved", ok, out.replace("\n", " | ") if not ok else "")
    except Exception as exc:
        s.record(13, "Hashtable secret redaction", False, repr(exc))

    # E14: ConvertTo-SecureString -AsPlainText literals
    try:
        out = Sanitizer(enabled=True).scrub_text(
            '$pw = ConvertTo-SecureString "Plain$Text99" -AsPlainText -Force\n'
            "$pw2 = ConvertTo-SecureString -String 'Sup3r!' -AsPlainText -Force"
        )
        ok = "Plain$Text99" not in out and "Sup3r!" not in out
        s.record(14, "Rule 4: ConvertTo-SecureString plaintext literals redacted", ok, out.replace("\n", " | ") if not ok else "")
    except Exception as exc:
        s.record(14, "SecureString plaintext", False, repr(exc))

    # E15: JWT / Bearer access tokens
    try:
        out = Sanitizer(enabled=True).scrub_text(
            '$h = @{ Authorization = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abcDEF123_-xyz" }\n'
            '$raw = "eyJ0eXAiOiJKV1QifQ.eyJhdWQiOiJncmFwaCJ9.Zm9vYmFy"'
        )
        ok = "eyJhbGci" not in out and "eyJ0eXAi" not in out
        s.record(15, "Rule 4: JWT bearer access tokens redacted", ok, out.replace("\n", " | ") if not ok else "")
    except Exception as exc:
        s.record(15, "JWT redaction", False, repr(exc))

    # E16: Regular-expression denial of service + unbalanced quote recovery
    try:
        lines = [
            '"' + "`" * 100000,
            "'" * 100001,
            '"' + "`a" * 50000,
            "password=" + "a" * 100000,
            "a." * 60000 + "@",
            "[" + "a:" * 50000,
            "<" * 100000,
            "Get-MsolDomain",
        ]
        t0 = time.perf_counter()
        a = migrate("\n".join(lines), sanitize=True)
        el = time.perf_counter() - t0
        found = any(f.legacy_cmdlet == "Get-MsolDomain" for f in a.findings)
        s.record(16, f"ReDoS-resistant on 1.2M pathological chars ({el:.2f}s) with unbalanced-quote recovery",
                 el < 3.0 and found, f"found_after_garbage={found}")
    except Exception as exc:
        s.record(16, "ReDoS resistance", False, repr(exc))

    # E17: 1 MB of random binary garbage
    try:
        blob = random.Random(1337).randbytes(1_000_000).decode("utf-8", errors="replace")
        t0 = time.perf_counter()
        migrate(blob, sanitize=True)
        el = time.perf_counter() - t0
        s.record(17, f"1 MB random binary input processed without crash ({el:.2f}s)", el < 10.0)
    except Exception as exc:
        s.record(17, "Binary garbage", False, repr(exc))

    # E18: 50,000-line realistic script throughput
    try:
        block = [
            "# audit block {i}",
            '$u = Get-MsolUser -UserPrincipalName "user{i}@contoso.com"',
            "Get-MsolGroup | ForEach-Object {{ Get-MsolGroupMember -GroupObjectId $_.ObjectId }}",
            "$c = (Get-MsolUser).Count",
            '$body = @"',
            "Get-MsolUser inside here-string {i}",
            '"@',
            "Set-MsolUser -UserPrincipalName $u.UserPrincipalName `",
            '    -Department "Ops"',
            'Write-Output "done {i}" # Get-MsolUser comment',
        ]
        script = "\n".join(ln.format(i=i) for i in range(5000) for ln in block)
        t0 = time.perf_counter()
        a = migrate(script, sanitize=True)
        el = time.perf_counter() - t0
        ok = el < 5.0 and a.total_legacy_calls == 25000
        s.record(18, f"50,000-line mixed-construct script ({el:.2f}s, {50000/el:,.0f} lines/sec)", ok,
                 f"calls={a.total_legacy_calls} (expected 25000)")
    except Exception as exc:
        s.record(18, "50k-line throughput", False, repr(exc))

    # E19: CLI failure handling (directory input, nested output directory)
    try:
        with tempfile.TemporaryDirectory() as td:
            r1 = run_cli(["-i", td])
            out_path = Path(td) / "a" / "b" / "c" / "plan.md"
            fixture = REPO_DIR / "tests" / "fixtures" / "fixture-user-onboarding.ps1"
            r2 = run_cli(["-i", str(fixture), "-o", str(out_path)])
            ok = (
                r1.returncode == 1 and "Traceback" not in r1.stderr
                and r2.returncode == 0 and out_path.exists()
            )
            s.record(19, "CLI: directory input rejected cleanly; nested output directories created", ok,
                     f"dir_rc={r1.returncode} out_rc={r2.returncode}")
    except Exception as exc:
        s.record(19, "CLI failure handling", False, repr(exc))

    # E20: Unattended app-only certificate authentication and PSCredential sign-in
    try:
        script = "Connect-AzureAD -TenantId $tid `\n    -ApplicationId $appId `\n    -CertificateThumbprint $thumb\nGet-AzureADUser"
        code = migrate(script).modernized_script
        cred_code = migrate("Connect-MsolService -Credential $cred\nGet-MsolUser").modernized_script
        cred_exec = [ln for ln in cred_code.splitlines() if "-Credential $cred" in ln and not ln.lstrip().startswith("#")]
        ok = (
            "Connect-MgGraph -TenantId $tid `" in code
            and "-ClientId $appId `" in code
            and "-CertificateThumbprint $thumb -NoWelcome" in code
            and "Connect-MgGraph -Scopes" not in code
            and "MIGRATION-REVIEW" in cred_code
            and "Connect-MgGraph -Identity" in cred_code
            and not cred_exec
        )
        s.record(20, "App-only cert auth preserved (no interactive prompt, no orphaned continuation lines)", ok)
    except Exception as exc:
        s.record(20, "App-only authentication", False, repr(exc))

    # E21: Mixed line endings (CRLF, CR, LF) and tab indentation
    try:
        a = migrate("Get-MsolDomain\r\nGet-MsolUser\rGet-MsolGroup\n\tGet-MsolRole")
        nums = [f.line_number for f in a.findings]
        s.record(21, "Mixed CRLF/CR/LF line endings yield correct line numbers", nums == [1, 2, 3, 4], str(nums))
    except Exception as exc:
        s.record(21, "Mixed line endings", False, repr(exc))

    # E22: UTF-16 (ISE default), BOM-less UTF-16 and Windows-1252 encoded scripts
    try:
        with tempfile.TemporaryDirectory() as td:
            p1 = Path(td) / "utf16bom.ps1"
            p1.write_bytes(b"\xff\xfe" + "Get-MsolUser\r\nGet-MsolGroup".encode("utf-16-le"))
            p2 = Path(td) / "utf16nobom.ps1"
            p2.write_bytes("Get-MsolUser\r\nGet-MsolGroup".encode("utf-16-le"))
            p3 = Path(td) / "cp1252.ps1"
            p3.write_bytes("# Propri\u00e9taire du script\r\nGet-MsolDomain".encode("cp1252"))
            counts = []
            for p in (p1, p2, p3):
                r = run_cli(["-i", str(p), "--format", "json"])
                counts.append(json.loads(r.stdout)["total_legacy_calls"] if r.returncode == 0 else -1)
            s.record(22, "UTF-16 LE (BOM and BOM-less) and Windows-1252 scripts decoded correctly",
                     counts == [2, 2, 1], f"counts={counts} (expected [2, 2, 1])")
    except Exception as exc:
        s.record(22, "File encodings", False, repr(exc))

    # E23: Legacy boolean -All $true / -All $false
    try:
        code = migrate("Get-AzureADUser -All $true\nGet-AzureADGroup -All $false").modernized_script
        lines = code.splitlines()
        user_line = next((ln for ln in lines if ln.startswith("Get-MgUser")), "")
        group_line = next((ln for ln in lines if ln.startswith("Get-MgGroup")), "")
        ok = user_line.strip() == "Get-MgUser -All" and group_line.strip() == "Get-MgGroup -Top 100"
        s.record(23, "Legacy -All $true/$false converted to Graph switch/-Top semantics", ok,
                 f"{user_line!r} / {group_line!r}" if not ok else "")
    except Exception as exc:
        s.record(23, "Boolean -All conversion", False, repr(exc))

    print("==================================================================")
    print(f"  EXTREME TEST SUMMARY: {s.passed} PASSED, {s.failed} FAILED out of {s.total} scenarios")
    print("==================================================================")
    return 0 if s.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

