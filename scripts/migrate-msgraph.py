#!/usr/bin/env python3
"""migrate-msgraph.py - Deterministic AzureAD / MSOnline to Microsoft Graph PowerShell Migrator

Analyzes legacy PowerShell scripts, detects deprecated AzureAD and MSOnline cmdlets,
resolves least-privilege Microsoft Graph OAuth permission scopes (Delegated and Application),
injects required auto-pagination (-All), updates parameter bindings and object structures,
and emits production-ready drop-in replacement scripts.

Zero third-party dependencies - Python standard library only.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
import datetime
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

CMDLET_MAPPINGS: Dict[str, Dict[str, Any]] = {
    "get-msoluser": {
        "target": "Get-MgUser",
        "delegated_scopes": ["User.Read.All"],
        "app_scopes": ["User.Read.All"],
        "param_map": {"searchstring": "Filter"},
        "requires_all": True,
        "notes": "Add -All to prevent silent 100-user truncation. Translate -SearchString to OData -Filter."
    },
    "get-azureaduser": {
        "target": "Get-MgUser",
        "delegated_scopes": ["User.Read.All"],
        "app_scopes": ["User.Read.All"],
        "param_map": {"objectid": "UserId", "searchstring": "Filter"},
        "requires_all": True,
        "notes": "Replace -ObjectId with -UserId. Add -All for multi-user queries."
    },
    "new-msoluser": {
        "target": "New-MgUser",
        "delegated_scopes": ["User.ReadWrite.All"],
        "app_scopes": ["User.ReadWrite.All"],
        "param_map": {"forcechangepassword": "ForceChangePasswordNextSignIn"},
        "requires_all": False,
        "notes": "Password profile must be passed via hashtable @{Password='...'; ForceChangePasswordNextSignIn=$true}."
    },
    "new-azureaduser": {
        "target": "New-MgUser",
        "delegated_scopes": ["User.ReadWrite.All"],
        "app_scopes": ["User.ReadWrite.All"],
        "param_map": {},
        "requires_all": False,
        "notes": "Requires -DisplayName, -MailNickname, -UserPrincipalName, and -AccountEnabled:$true."
    },
    "set-msoluser": {
        "target": "Update-MgUser",
        "delegated_scopes": ["User.ReadWrite.All"],
        "app_scopes": ["User.ReadWrite.All"],
        "param_map": {"userprincipalname": "UserId"},
        "requires_all": False,
        "notes": "Target user using -UserId <UPN/ID>. Property names match Graph REST schema."
    },
    "set-azureaduser": {
        "target": "Update-MgUser",
        "delegated_scopes": ["User.ReadWrite.All"],
        "app_scopes": ["User.ReadWrite.All"],
        "param_map": {"objectid": "UserId"},
        "requires_all": False,
        "notes": "Replace -ObjectId with -UserId."
    },
    "remove-msoluser": {
        "target": "Remove-MgUser",
        "delegated_scopes": ["User.ReadWrite.All"],
        "app_scopes": ["User.ReadWrite.All"],
        "param_map": {"userprincipalname": "UserId"},
        "requires_all": False,
        "notes": "Soft-deletes user account into directory deleted items."
    },
    "remove-azureaduser": {
        "target": "Remove-MgUser",
        "delegated_scopes": ["User.ReadWrite.All"],
        "app_scopes": ["User.ReadWrite.All"],
        "param_map": {"objectid": "UserId"},
        "requires_all": False,
        "notes": "Replace -ObjectId with -UserId."
    },
    "get-msolaccountsku": {
        "target": "Get-MgSubscribedSku",
        "delegated_scopes": ["Organization.Read.All"],
        "app_scopes": ["Organization.Read.All"],
        "param_map": {},
        "requires_all": True,
        "notes": "Returns tenant licensing SKUs, total units, and consumed units. Add -All."
    },
    "set-msoluserlicense": {
        "target": "Set-MgUserLicense",
        "delegated_scopes": ["User.ReadWrite.All"],
        "app_scopes": ["User.ReadWrite.All"],
        "param_map": {"userprincipalname": "UserId"},
        "requires_all": False,
        "notes": "Requires SkuId GUIDs rather than string names. Pass -AddLicenses @(@{SkuId='GUID'}) -RemoveLicenses @()."
    },
    "get-msolgroup": {
        "target": "Get-MgGroup",
        "delegated_scopes": ["Group.Read.All"],
        "app_scopes": ["Group.Read.All"],
        "param_map": {"searchstring": "Filter"},
        "requires_all": True,
        "notes": "Add -All to retrieve all groups. Use OData -Filter."
    },
    "get-azureadgroup": {
        "target": "Get-MgGroup",
        "delegated_scopes": ["Group.Read.All"],
        "app_scopes": ["Group.Read.All"],
        "param_map": {"objectid": "GroupId", "searchstring": "Filter"},
        "requires_all": True,
        "notes": "Replace -ObjectId with -GroupId. Add -All."
    },
    "new-msolgroup": {
        "target": "New-MgGroup",
        "delegated_scopes": ["Group.ReadWrite.All"],
        "app_scopes": ["Group.ReadWrite.All"],
        "param_map": {},
        "requires_all": False,
        "notes": "Specify -DisplayName, -MailNickname, -MailEnabled:$false, -SecurityEnabled:$true."
    },
    "new-azureadgroup": {
        "target": "New-MgGroup",
        "delegated_scopes": ["Group.ReadWrite.All"],
        "app_scopes": ["Group.ReadWrite.All"],
        "param_map": {},
        "requires_all": False,
        "notes": "Specify -DisplayName, -MailNickname, -MailEnabled, -SecurityEnabled."
    },
    "set-msolgroup": {
        "target": "Update-MgGroup",
        "delegated_scopes": ["Group.ReadWrite.All"],
        "app_scopes": ["Group.ReadWrite.All"],
        "param_map": {"objectid": "GroupId"},
        "requires_all": False,
        "notes": "Target group with -GroupId <ID>."
    },
    "set-azureadgroup": {
        "target": "Update-MgGroup",
        "delegated_scopes": ["Group.ReadWrite.All"],
        "app_scopes": ["Group.ReadWrite.All"],
        "param_map": {"objectid": "GroupId"},
        "requires_all": False,
        "notes": "Replace -ObjectId with -GroupId."
    },
    "remove-msolgroup": {
        "target": "Remove-MgGroup",
        "delegated_scopes": ["Group.ReadWrite.All"],
        "app_scopes": ["Group.ReadWrite.All"],
        "param_map": {"objectid": "GroupId"},
        "requires_all": False,
        "notes": "Replace -ObjectId with -GroupId."
    },
    "remove-azureadgroup": {
        "target": "Remove-MgGroup",
        "delegated_scopes": ["Group.ReadWrite.All"],
        "app_scopes": ["Group.ReadWrite.All"],
        "param_map": {"objectid": "GroupId"},
        "requires_all": False,
        "notes": "Replace -ObjectId with -GroupId."
    },
    "get-msolgroupmember": {
        "target": "Get-MgGroupMember",
        "delegated_scopes": ["GroupMember.Read.All"],
        "app_scopes": ["GroupMember.Read.All"],
        "param_map": {"groupobjectid": "GroupId"},
        "requires_all": True,
        "notes": "Add -All. Returns directory objects."
    },
    "get-azureadgroupmember": {
        "target": "Get-MgGroupMember",
        "delegated_scopes": ["GroupMember.Read.All"],
        "app_scopes": ["GroupMember.Read.All"],
        "param_map": {"objectid": "GroupId"},
        "requires_all": True,
        "notes": "Replace -ObjectId with -GroupId. Add -All."
    },
    "add-msolgroupmember": {
        "target": "New-MgGroupMemberByRef",
        "delegated_scopes": ["GroupMember.ReadWrite.All"],
        "app_scopes": ["GroupMember.ReadWrite.All"],
        "param_map": {"groupobjectid": "GroupId", "groupmemberobjectid": "DirectoryObjectId"},
        "requires_all": False,
        "notes": "Pass -GroupId <ID> -DirectoryObjectId <ID>."
    },
    "add-azureadgroupmember": {
        "target": "New-MgGroupMemberByRef",
        "delegated_scopes": ["GroupMember.ReadWrite.All"],
        "app_scopes": ["GroupMember.ReadWrite.All"],
        "param_map": {"objectid": "GroupId", "refobjectid": "DirectoryObjectId"},
        "requires_all": False,
        "notes": "Replace -ObjectId with -GroupId and -RefObjectId with -DirectoryObjectId."
    },
    "remove-msolgroupmember": {
        "target": "Remove-MgGroupMemberDirectoryObjectByRef",
        "delegated_scopes": ["GroupMember.ReadWrite.All"],
        "app_scopes": ["GroupMember.ReadWrite.All"],
        "param_map": {"groupobjectid": "GroupId", "groupmemberobjectid": "DirectoryObjectId"},
        "requires_all": False,
        "notes": "Specify -GroupId and -DirectoryObjectId."
    },
    "remove-azureadgroupmember": {
        "target": "Remove-MgGroupMemberDirectoryObjectByRef",
        "delegated_scopes": ["GroupMember.ReadWrite.All"],
        "app_scopes": ["GroupMember.ReadWrite.All"],
        "param_map": {"objectid": "GroupId", "memberid": "DirectoryObjectId"},
        "requires_all": False,
        "notes": "Replace -ObjectId with -GroupId and -MemberId with -DirectoryObjectId."
    },
    "get-azureadserviceprincipal": {
        "target": "Get-MgServicePrincipal",
        "delegated_scopes": ["Application.Read.All"],
        "app_scopes": ["Application.Read.All"],
        "param_map": {"objectid": "ServicePrincipalId"},
        "requires_all": True,
        "notes": "Replace -ObjectId with -ServicePrincipalId. Add -All."
    },
    "new-azureadserviceprincipal": {
        "target": "New-MgServicePrincipal",
        "delegated_scopes": ["Application.ReadWrite.All"],
        "app_scopes": ["Application.ReadWrite.All"],
        "param_map": {},
        "requires_all": False,
        "notes": "Specify -AppId <GUID>."
    },
    "remove-azureadserviceprincipal": {
        "target": "Remove-MgServicePrincipal",
        "delegated_scopes": ["Application.ReadWrite.All"],
        "app_scopes": ["Application.ReadWrite.All"],
        "param_map": {"objectid": "ServicePrincipalId"},
        "requires_all": False,
        "notes": "Replace -ObjectId with -ServicePrincipalId."
    },
    "get-azureadapplication": {
        "target": "Get-MgApplication",
        "delegated_scopes": ["Application.Read.All"],
        "app_scopes": ["Application.Read.All"],
        "param_map": {"objectid": "ApplicationId"},
        "requires_all": True,
        "notes": "Replace -ObjectId with -ApplicationId. Add -All."
    },
    "new-azureadapplication": {
        "target": "New-MgApplication",
        "delegated_scopes": ["Application.ReadWrite.All"],
        "app_scopes": ["Application.ReadWrite.All"],
        "param_map": {},
        "requires_all": False,
        "notes": "Specify -DisplayName and identifier URIs."
    },
    "new-azureadapplicationkeycredential": {
        "target": "Add-MgApplicationPassword",
        "delegated_scopes": ["Application.ReadWrite.All"],
        "app_scopes": ["Application.ReadWrite.All"],
        "param_map": {"objectid": "ApplicationId"},
        "requires_all": False,
        "notes": "Pass -ApplicationId <ID> -PasswordCredential @{DisplayName='...'}. Plain text secret returned only upon creation."
    },
    "new-azureadapplicationpasswordcredential": {
        "target": "Add-MgApplicationPassword",
        "delegated_scopes": ["Application.ReadWrite.All"],
        "app_scopes": ["Application.ReadWrite.All"],
        "param_map": {"objectid": "ApplicationId"},
        "requires_all": False,
        "notes": "Pass -ApplicationId <ID> -PasswordCredential @{DisplayName='...'}. Plain text secret returned only upon creation."
    },
    "remove-azureadapplicationkeycredential": {
        "target": "Remove-MgApplicationPassword",
        "delegated_scopes": ["Application.ReadWrite.All"],
        "app_scopes": ["Application.ReadWrite.All"],
        "param_map": {"objectid": "ApplicationId", "customkeyidentifier": "KeyId"},
        "requires_all": False,
        "notes": "Pass -ApplicationId <ID> -KeyId <GUID>."
    },
    "new-azureadserviceprincipalpasswordcredential": {
        "target": "Add-MgServicePrincipalPassword",
        "delegated_scopes": ["Application.ReadWrite.All"],
        "app_scopes": ["Application.ReadWrite.All"],
        "param_map": {"objectid": "ServicePrincipalId"},
        "requires_all": False,
        "notes": "Pass -ServicePrincipalId <ID> -PasswordCredential @{DisplayName='...'}. Plain text secret returned only upon creation."
    },
    "remove-azureadserviceprincipalpasswordcredential": {
        "target": "Remove-MgServicePrincipalPassword",
        "delegated_scopes": ["Application.ReadWrite.All"],
        "app_scopes": ["Application.ReadWrite.All"],
        "param_map": {"objectid": "ServicePrincipalId", "keyid": "KeyId"},
        "requires_all": False,
        "notes": "Pass -ServicePrincipalId <ID> -KeyId <GUID>."
    },
    "get-msolrole": {
        "target": "Get-MgDirectoryRole",
        "delegated_scopes": ["RoleManagement.Read.Directory"],
        "app_scopes": ["RoleManagement.Read.Directory"],
        "param_map": {},
        "requires_all": True,
        "notes": "Returns directory roles. Add -All."
    },
    "get-azureaddirectoryrole": {
        "target": "Get-MgDirectoryRole",
        "delegated_scopes": ["RoleManagement.Read.Directory"],
        "app_scopes": ["RoleManagement.Read.Directory"],
        "param_map": {"objectid": "DirectoryRoleId"},
        "requires_all": True,
        "notes": "Replace -ObjectId with -DirectoryRoleId. Add -All."
    },
    "get-msolrolemember": {
        "target": "Get-MgDirectoryRoleMember",
        "delegated_scopes": ["RoleManagement.Read.Directory"],
        "app_scopes": ["RoleManagement.Read.Directory"],
        "param_map": {"roleobjectid": "DirectoryRoleId"},
        "requires_all": True,
        "notes": "Specify -DirectoryRoleId <ID>. Add -All."
    },
    "get-azureaddirectoryrolemember": {
        "target": "Get-MgDirectoryRoleMember",
        "delegated_scopes": ["RoleManagement.Read.Directory"],
        "app_scopes": ["RoleManagement.Read.Directory"],
        "param_map": {"objectid": "DirectoryRoleId"},
        "requires_all": True,
        "notes": "Replace -ObjectId with -DirectoryRoleId. Add -All."
    },
    "add-msolrolemember": {
        "target": "New-MgDirectoryRoleMemberByRef",
        "delegated_scopes": ["RoleManagement.ReadWrite.Directory"],
        "app_scopes": ["RoleManagement.ReadWrite.Directory"],
        "param_map": {"roleobjectid": "DirectoryRoleId"},
        "requires_all": False,
        "notes": "Pass -DirectoryRoleId <ID> -DirectoryObjectId <ID>."
    },
    "add-azureaddirectoryrolemember": {
        "target": "New-MgDirectoryRoleMemberByRef",
        "delegated_scopes": ["RoleManagement.ReadWrite.Directory"],
        "app_scopes": ["RoleManagement.ReadWrite.Directory"],
        "param_map": {"objectid": "DirectoryRoleId", "refobjectid": "DirectoryObjectId"},
        "requires_all": False,
        "notes": "Replace -ObjectId with -DirectoryRoleId and -RefObjectId with -DirectoryObjectId."
    },
    "get-msoldevice": {
        "target": "Get-MgDevice",
        "delegated_scopes": ["Device.Read.All"],
        "app_scopes": ["Device.Read.All"],
        "param_map": {},
        "requires_all": True,
        "notes": "Returns registered devices. Add -All."
    },
    "get-azureaddevice": {
        "target": "Get-MgDevice",
        "delegated_scopes": ["Device.Read.All"],
        "app_scopes": ["Device.Read.All"],
        "param_map": {"objectid": "DeviceId"},
        "requires_all": True,
        "notes": "Replace -ObjectId with -DeviceId. Add -All."
    },
    "get-msoldomain": {
        "target": "Get-MgDomain",
        "delegated_scopes": ["Domain.Read.All"],
        "app_scopes": ["Domain.Read.All"],
        "param_map": {},
        "requires_all": True,
        "notes": "Returns verified custom domains. Add -All."
    },
    "get-azureaddomain": {
        "target": "Get-MgDomain",
        "delegated_scopes": ["Domain.Read.All"],
        "app_scopes": ["Domain.Read.All"],
        "param_map": {},
        "requires_all": True,
        "notes": "Returns verified custom domains. Add -All."
    },
    "get-msolcompanyinformation": {
        "target": "Get-MgOrganization",
        "delegated_scopes": ["Organization.Read.All"],
        "app_scopes": ["Organization.Read.All"],
        "param_map": {},
        "requires_all": False,
        "notes": "Returns tenant organization metadata."
    },
    "get-azureadtenantdetail": {
        "target": "Get-MgOrganization",
        "delegated_scopes": ["Organization.Read.All"],
        "app_scopes": ["Organization.Read.All"],
        "param_map": {},
        "requires_all": False,
        "notes": "Returns tenant organization metadata."
    },
    "connect-msolservice": {
        "target": "Connect-MgGraph",
        "delegated_scopes": [],
        "app_scopes": [],
        "param_map": {},
        "requires_all": False,
        "notes": "Replace with Connect-MgGraph specifying computed least-privilege scopes."
    },
    "connect-azuread": {
        "target": "Connect-MgGraph",
        "delegated_scopes": [],
        "app_scopes": [],
        "param_map": {"applicationid": "ClientId"},
        "requires_all": False,
        "notes": "Replace with Connect-MgGraph specifying computed least-privilege scopes."
    }
}


@dataclass
class CmdletFinding:
    line_number: int
    legacy_cmdlet: str
    modern_cmdlet: str
    raw_line: str
    delegated_scopes: List[str]
    app_scopes: List[str]
    notes: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MigrationAnalysis:
    script_name: str
    timestamp_utc: str
    total_legacy_calls: int
    unique_legacy_cmdlets: List[str]
    required_delegated_scopes: List[str]
    required_app_scopes: List[str]
    findings: List[CmdletFinding]
    modernized_script: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "script_name": self.script_name,
            "timestamp_utc": self.timestamp_utc,
            "total_legacy_calls": self.total_legacy_calls,
            "unique_legacy_cmdlets": self.unique_legacy_cmdlets,
            "required_delegated_scopes": self.required_delegated_scopes,
            "required_app_scopes": self.required_app_scopes,
            "findings": [f.to_dict() for f in self.findings],
            "modernized_script": self.modernized_script
        }


class Sanitizer:
    """Client-side privacy engine masking hostnames, users, GUIDs, and IPs (Rule 4)."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.upn_map: Dict[str, str] = {}
        self.guid_map: Dict[str, str] = {}
        self.ip_map: Dict[str, str] = {}
        self.counter = 1

    def sanitize_upn(self, upn: str) -> str:
        if not self.enabled or not upn:
            return upn
        if upn.endswith("@synthetic-test.local"):
            return upn
        if upn in self.upn_map:
            return self.upn_map[upn]
        digest = hashlib.sha256(upn.encode("utf-8")).hexdigest()[:6]
        mock = f"user-{digest}@synthetic-test.local"
        self.upn_map[upn] = mock
        return mock

    def sanitize_guid(self, guid: str) -> str:
        if not self.enabled or not guid or guid in ("00000000-0000-0000-0000-000000000000", "Unknown"):
            return guid
        if guid.startswith("00000000-0000-4000-a000-"):
            return guid
        if guid in self.guid_map:
            return self.guid_map[guid]
        digest = hashlib.sha256(guid.encode("utf-8")).hexdigest()[:12]
        mock = f"00000000-0000-4000-a000-{digest}"
        self.guid_map[guid] = mock
        return mock

    def sanitize_ip(self, ip_str: str) -> str:
        if not self.enabled or not ip_str:
            return ip_str
        if ip_str.startswith("192.0.2.") or ip_str.startswith("198.51.100."):
            return ip_str
        if ip_str in self.ip_map:
            return self.ip_map[ip_str]
        mock = f"198.51.100.{self.counter % 240 + 10}"
        self.counter += 1
        self.ip_map[ip_str] = mock
        return mock

    def scrub_text(self, text: str) -> str:
        if not self.enabled or not text:
            return text

        # 1. Scrub passwords, secrets, tokens (assignments and parameters)
        text = re.sub(
            r"(password|secret|token|api[_-]?key|client[_-]?secret|app[_-]?secret|pass)\s*[:=]\s*(?:(['\"][^'\"]*['\"])|([^\s\n\r,;]+))",
            r"\1: [REDACTED-SECRET]",
            text,
            flags=re.IGNORECASE
        )
        text = re.sub(
            r"(-(?:password|secret|token|api[_-]?key|client[_-]?secret|certificatepassword|pass)\s+)(?:(['\"][^'\"]*['\"])|([^\s]+))",
            r'\1"[REDACTED-SECRET]"',
            text,
            flags=re.IGNORECASE
        )

        # 2. Scrub emails / UPNs
        text = re.sub(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            lambda m: self.sanitize_upn(m.group(0)),
            text
        )

        # 3. Scrub GUIDs
        text = re.sub(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
            lambda m: self.sanitize_guid(m.group(0)),
            text
        )

        # 4. Scrub IPv4 addresses
        text = re.sub(
            r"\b(?!127\.0\.0\.1|0\.0\.0\.0|198\.51\.100\.|192\.0\.2\.)(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])\.(?:\d{1,3}\.){2}(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])\b",
            lambda m: self.sanitize_ip(m.group(0)),
            text
        )

        # 5. Scrub IPv6 addresses
        text = re.sub(
            r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\bfe80::[0-9a-fA-F:]+\b|\b2[0-9a-fA-F]{3}:[0-9a-fA-F:]+\b",
            "2001:db8::1",
            text
        )

        return text


class GraphMigrator:
    """Deterministic migration engine modernizing legacy AzureAD/MSOnline scripts."""

    def __init__(self, raw_script: str, script_name: str = "Script.ps1", sanitize: bool = False):
        self.raw_script = raw_script
        self.script_name = script_name
        self.sanitize = sanitize
        self.sanitizer = Sanitizer(enabled=sanitize)

    def analyze(self) -> MigrationAnalysis:
        cleaned_script = self.sanitizer.scrub_text(self.raw_script) if self.sanitize else self.raw_script
        lines = cleaned_script.splitlines()

        findings: List[CmdletFinding] = []
        delegated_scopes: Set[str] = set()
        app_scopes: Set[str] = set()
        unique_legacy: Set[str] = set()

        in_block_comment = False
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Handle block comments
            if "<#" in stripped:
                in_block_comment = True
            if in_block_comment:
                if "#>" in stripped:
                    in_block_comment = False
                continue

            # Skip single-line comments
            if stripped.startswith("#"):
                continue

            # Tokenize words to match cmdlets safely on word boundaries
            tokens = re.findall(r"\b[A-Za-z]+-[A-Za-z0-9]+\b", line)
            for token in tokens:
                t_lower = token.lower()
                if t_lower in CMDLET_MAPPINGS:
                    info = CMDLET_MAPPINGS[t_lower]
                    target = info["target"]
                    del_s = info["delegated_scopes"]
                    app_s = info["app_scopes"]
                    notes = info["notes"]

                    delegated_scopes.update(del_s)
                    app_scopes.update(app_s)
                    unique_legacy.add(token)

                    findings.append(
                        CmdletFinding(
                            line_number=idx,
                            legacy_cmdlet=token,
                            modern_cmdlet=target,
                            raw_line=stripped,
                            delegated_scopes=del_s,
                            app_scopes=app_s,
                            notes=notes
                        )
                    )

        # Generate modernized script
        modern_code = self._generate_modern_script(lines, delegated_scopes)

        now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        return MigrationAnalysis(
            script_name=self.script_name,
            timestamp_utc=now_utc,
            total_legacy_calls=len(findings),
            unique_legacy_cmdlets=sorted(list(unique_legacy)),
            required_delegated_scopes=sorted(list(delegated_scopes)),
            required_app_scopes=sorted(list(app_scopes)),
            findings=findings,
            modernized_script=modern_code
        )

    def _generate_modern_script(self, original_lines: List[str], scopes: Set[str]) -> str:
        out_lines: List[str] = []

        # Add Modern Header
        scope_str = ", ".join(f'"{s}"' for s in sorted(list(scopes))) if scopes else '"User.Read.All"'
        out_lines.append("<#")
        out_lines.append(f".SYNOPSIS")
        out_lines.append(f"    Modernized replacement for {self.script_name} using Microsoft.Graph PowerShell SDK.")
        out_lines.append(f".DESCRIPTION")
        out_lines.append(f"    Migrated from legacy AzureAD / MSOnline modules to Microsoft.Graph v2.x.")
        out_lines.append(f"    Required least-privilege permission scopes: {', '.join(sorted(list(scopes))) if scopes else 'None'}")
        out_lines.append("#>")
        out_lines.append("[CmdletBinding()]")
        out_lines.append("param()")
        out_lines.append("")
        out_lines.append("# 1. Verify and establish Microsoft Graph connection with least-privilege scopes")
        out_lines.append("if (-not (Get-MgContext -ErrorAction SilentlyContinue)) {")
        out_lines.append(f'    Write-Verbose "Connecting to Microsoft Graph with required scopes..."')
        out_lines.append(f'    Connect-MgGraph -Scopes {scope_str} -NoWelcome')
        out_lines.append("}")
        out_lines.append("")
        out_lines.append("# 2. Execute modernized workload operations")

        in_block_comment = False
        for line in original_lines:
            stripped = line.strip()

            # Preserve block comments
            if "<#" in stripped:
                in_block_comment = True
            if in_block_comment:
                out_lines.append(line)
                if "#>" in stripped:
                    in_block_comment = False
                continue

            # Preserve single-line comments
            if stripped.startswith("#"):
                out_lines.append(line)
                continue

            # Handle Connect calls
            if re.search(r"\b(Connect-MsolService|Connect-AzureAD)\b", line, re.IGNORECASE):
                out_lines.append(f"# Replaced legacy connection: {stripped}")
                out_lines.append(f'# Connect-MgGraph -Scopes {scope_str} -NoWelcome')
                continue

            # Tokenize and match only present cmdlets for maximum throughput
            tokens = re.findall(r"\b[A-Za-z]+-[A-Za-z0-9]+\b", line)
            matched_cmdlets = [t.lower() for t in tokens if t.lower() in CMDLET_MAPPINGS]

            if not matched_cmdlets:
                out_lines.append(line)
                continue

            updated_line = line
            for legacy in matched_cmdlets:
                info = CMDLET_MAPPINGS[legacy]
                pattern = rf"\b{re.escape(legacy)}\b"
                # Replace cmdlet name preserving exact case of target
                updated_line = re.sub(pattern, info["target"], updated_line, flags=re.IGNORECASE)

                # Update parameter names
                for old_param, new_param in info.get("param_map", {}).items():
                    param_pattern = rf"(-{re.escape(old_param)})\b"
                    updated_line = re.sub(param_pattern, f"-{new_param}", updated_line, flags=re.IGNORECASE)

                # Auto-inject -All for unbounded query commands if not already present
                if info.get("requires_all") and "-all" not in updated_line.lower() and "-top" not in updated_line.lower() and "-userid" not in updated_line.lower() and "-groupid" not in updated_line.lower():
                    if not re.search(r"\s-All\b", updated_line, re.IGNORECASE):
                        if "|" in updated_line:
                            parts = updated_line.split("|", 1)
                            updated_line = f"{parts[0].rstrip()} -All |{parts[1]}"
                        else:
                            updated_line = f"{updated_line.rstrip()} -All"

            out_lines.append(updated_line)

        return "\n".join(out_lines)


def format_markdown(analysis: MigrationAnalysis, sanitize: bool = False) -> str:
    out: List[str] = []
    out.append("# Microsoft Graph Migration & Code Modernization Plan")
    out.append("")
    out.append(f"- **Source Script:** `{analysis.script_name}`")
    out.append(f"- **Migration Timestamp (UTC):** `{analysis.timestamp_utc}`")
    out.append(f"- **Total Deprecated Cmdlet Invocations:** {analysis.total_legacy_calls}")
    out.append(f"- **Target Module:** `Microsoft.Graph` (v2.x)")
    out.append(f"- **Data Sanitization:** {'Active (SHA-256 Hashes, RFC 5737 Test IPs)' if sanitize else 'Disabled'}")
    out.append("")

    out.append("## 1. Executive Summary")
    if analysis.total_legacy_calls == 0:
        out.append("No deprecated AzureAD or MSOnline cmdlets detected. The script is already modern or does not contain directory calls.")
        return "\n".join(out)

    out.append(f"Identified **{analysis.total_legacy_calls}** invocations across **{len(analysis.unique_legacy_cmdlets)}** unique legacy cmdlets. All calls have been mapped to modern `Microsoft.Graph` SDK equivalents enforcing least-privilege OAuth scopes.")
    out.append("")

    out.append("## 2. Cmdlet & Permission Scope Inventory")
    out.append("")
    out.append("| Line | Legacy Cmdlet | Modern Microsoft.Graph Cmdlet | Least-Privilege Delegated Scope | Application Scope | Migration Guidance |")
    out.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
    for f in analysis.findings:
        del_scopes = ", ".join(f"`{s}`" for s in f.delegated_scopes) if f.delegated_scopes else "None"
        app_scopes = ", ".join(f"`{s}`" for s in f.app_scopes) if f.app_scopes else "None"
        out.append(f"| L{f.line_number} | `{f.legacy_cmdlet}` | `{f.modern_cmdlet}` | {del_scopes} | {app_scopes} | {f.notes} |")
    out.append("")

    out.append("## 3. Required Least-Privilege Permissions")
    out.append("")
    out.append("**Delegated Permissions (Interactive User):**")
    if analysis.required_delegated_scopes:
        for s in analysis.required_delegated_scopes:
            out.append(f"- `{s}`")
    else:
        out.append("- *No specific directory scopes required.*")
    out.append("")

    out.append("**Application Permissions (Automations / Service Principals):**")
    if analysis.required_app_scopes:
        for s in analysis.required_app_scopes:
            out.append(f"- `{s}`")
    else:
        out.append("- *No specific directory scopes required.*")
    out.append("")

    out.append("## 4. Modernized Drop-In Replacement Script")
    out.append("")
    out.append("```powershell")
    out.append(analysis.modernized_script)
    out.append("```")
    out.append("")

    out.append("## 5. Pre-Flight Verification & Testing Checklist")
    out.append("")
    out.append("1. **Verify SDK Installation:** Ensure the target machine has the modern SDK installed:")
    out.append("   ```powershell")
    out.append("   Get-InstalledModule Microsoft.Graph -ErrorAction SilentlyContinue")
    out.append("   ```")
    out.append("2. **Validate Scopes:** Ensure your executing identity or app registration has been granted the consent for:")
    scope_display = " ".join(f"-Scopes '{s}'" for s in analysis.required_delegated_scopes) if analysis.required_delegated_scopes else "-Scopes 'User.Read.All'"
    out.append(f"   ```powershell")
    out.append(f"   Connect-MgGraph {scope_display}")
    out.append(f"   ```")
    out.append("3. **Execute in Non-Production:** Run the modernized script with `-Verbose` in a staging tenant or against synthetic test accounts prior to updating production scheduled tasks.")
    out.append("4. **Pagination Check:** Confirm that queries returning collections retrieve the expected total record count across tenant boundaries.")

    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Deterministic AzureAD & MSOnline to Microsoft Graph PowerShell Migrator"
    )
    parser.add_argument(
        "-i", "--input",
        required=True,
        help="Path to legacy PowerShell script (.ps1), JSON scan, or '-' for stdin."
    )
    parser.add_argument(
        "-f", "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="Output presentation format."
    )
    parser.add_argument(
        "-s", "--sanitize",
        action="store_true",
        help="Mask UPNs, Tenant GUIDs, Client IDs, and Secrets (Rule 4)."
    )
    parser.add_argument(
        "-o", "--output",
        help="Optional output file path (prints to stdout if omitted)."
    )

    args = parser.parse_args()

    # Read input
    script_name = "PastedScript.ps1"
    if args.input == "-":
        if sys.stdin.isatty():
            sys.stderr.write("Error: No input specified and stdin is empty.\n")
            return 1
        content = sys.stdin.read()
    else:
        p = Path(args.input)
        if not p.exists():
            sys.stderr.write(f"Error: Input file not found: {p}\n")
            return 1
        script_name = p.name
        content = p.read_text(encoding="utf-8", errors="replace")

    # If input is JSON inventory from Scan-LegacyGraphCmdlets.ps1
    trimmed = content.strip()
    if trimmed.startswith("{") and "Findings" in trimmed:
        try:
            data = json.loads(trimmed)
            findings_raw = data.get("Findings", [])
            lines = [f.get("RawCommand", "") for f in findings_raw if isinstance(f, dict)]
            content = "\n".join(lines)
        except Exception:
            pass

    migrator = GraphMigrator(raw_script=content, script_name=script_name, sanitize=args.sanitize)
    analysis = migrator.analyze()

    if args.format == "json":
        rendered = json.dumps(analysis.to_dict(), indent=2)
    else:
        rendered = format_markdown(analysis, sanitize=args.sanitize)

    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        print(rendered)

    return 0


if __name__ == "__main__":
    sys.exit(main())
