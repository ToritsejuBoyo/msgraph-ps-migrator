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
from dataclasses import asdict, dataclass
import datetime
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Shared residual sanitization pass (vendored: scripts/sanitizer.py).
# Runs last, after this skill's domain-specific masking, so that every skill in
# the library enforces an identical credential/PII floor. See
# tests/sanitizer_conformance_test.py for the contract this must satisfy.
# ---------------------------------------------------------------------------
try:
    from sanitizer import residual_scrub as _residual_scrub
except ImportError:  # pragma: no cover - direct execution from another cwd
    import os as _os
    import sys as _sys
    _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
    from sanitizer import residual_scrub as _residual_scrub


CMDLET_MAPPINGS: Dict[str, Dict[str, Any]] = {
    # 1. User Management
    "get-msoluser": {
        "target": "Get-MgUser",
        "delegated_scopes": ["User.Read.All"],
        "app_scopes": ["User.Read.All"],
        "param_map": {
            "userprincipalname": "UserId",
            "objectid": "UserId",
            "searchstring": "Filter",
            "maxresults": "Top"
        },
        "single_id_params": ["userid"],
        "requires_all": True,
        "notes": "Add -All to prevent silent 100-user truncation. Translate -SearchString to OData -Filter and -UserPrincipalName to -UserId."
    },
    "get-azureaduser": {
        "target": "Get-MgUser",
        "delegated_scopes": ["User.Read.All"],
        "app_scopes": ["User.Read.All"],
        "param_map": {
            "objectid": "UserId",
            "searchstring": "Filter",
            "top": "Top"
        },
        "single_id_params": ["userid"],
        "requires_all": True,
        "notes": "Replace -ObjectId with -UserId. Add -All for multi-user queries."
    },
    "new-msoluser": {
        "target": "New-MgUser",
        "delegated_scopes": ["User.ReadWrite.All"],
        "app_scopes": ["User.ReadWrite.All"],
        "param_map": {"forcechangepassword": "ForceChangePasswordNextSignIn"},
        "single_id_params": [],
        "requires_all": False,
        "notes": "Password profile must be passed via hashtable @{Password='...'; ForceChangePasswordNextSignIn=$true}."
    },
    "new-azureaduser": {
        "target": "New-MgUser",
        "delegated_scopes": ["User.ReadWrite.All"],
        "app_scopes": ["User.ReadWrite.All"],
        "param_map": {},
        "single_id_params": [],
        "requires_all": False,
        "notes": "Requires -DisplayName, -MailNickname, -UserPrincipalName, and -AccountEnabled:$true."
    },
    "set-msoluser": {
        "target": "Update-MgUser",
        "delegated_scopes": ["User.ReadWrite.All"],
        "app_scopes": ["User.ReadWrite.All"],
        "param_map": {"userprincipalname": "UserId", "objectid": "UserId"},
        "single_id_params": ["userid"],
        "requires_all": False,
        "notes": "Target user using -UserId <UPN/ID>. Property names match Graph REST schema."
    },
    "set-azureaduser": {
        "target": "Update-MgUser",
        "delegated_scopes": ["User.ReadWrite.All"],
        "app_scopes": ["User.ReadWrite.All"],
        "param_map": {"objectid": "UserId"},
        "single_id_params": ["userid"],
        "requires_all": False,
        "notes": "Replace -ObjectId with -UserId."
    },
    "remove-msoluser": {
        "target": "Remove-MgUser",
        "delegated_scopes": ["User.ReadWrite.All"],
        "app_scopes": ["User.ReadWrite.All"],
        "param_map": {"userprincipalname": "UserId", "objectid": "UserId"},
        "single_id_params": ["userid"],
        "requires_all": False,
        "notes": "Soft-deletes user account into directory deleted items."
    },
    "remove-azureaduser": {
        "target": "Remove-MgUser",
        "delegated_scopes": ["User.ReadWrite.All"],
        "app_scopes": ["User.ReadWrite.All"],
        "param_map": {"objectid": "UserId"},
        "single_id_params": ["userid"],
        "requires_all": False,
        "notes": "Replace -ObjectId with -UserId."
    },
    "restore-msoluser": {
        "target": "Restore-MgDirectoryDeletedItem",
        "delegated_scopes": ["Directory.ReadWrite.All"],
        "app_scopes": ["Directory.ReadWrite.All"],
        "param_map": {"objectid": "DirectoryObjectId", "userprincipalname": "DirectoryObjectId"},
        "single_id_params": ["directoryobjectid"],
        "requires_all": False,
        "notes": "Pass -DirectoryObjectId <GUID> to restore soft-deleted user."
    },
    "restore-azureadmsdeleteddirectoryobject": {
        "target": "Restore-MgDirectoryDeletedItem",
        "delegated_scopes": ["Directory.ReadWrite.All"],
        "app_scopes": ["Directory.ReadWrite.All"],
        "param_map": {"id": "DirectoryObjectId"},
        "single_id_params": ["directoryobjectid"],
        "requires_all": False,
        "notes": "Replace -Id with -DirectoryObjectId."
    },
    "get-msoluserbymanager": {
        "target": "Get-MgUserManager",
        "delegated_scopes": ["User.Read.All"],
        "app_scopes": ["User.Read.All"],
        "param_map": {"userprincipalname": "UserId", "objectid": "UserId"},
        "single_id_params": ["userid"],
        "requires_all": False,
        "notes": "Retrieve manager directory object using -UserId <UPN/ID>."
    },
    "get-azureadusermanager": {
        "target": "Get-MgUserManager",
        "delegated_scopes": ["User.Read.All"],
        "app_scopes": ["User.Read.All"],
        "param_map": {"objectid": "UserId"},
        "single_id_params": ["userid"],
        "requires_all": False,
        "notes": "Replace -ObjectId with -UserId."
    },
    "set-azureadusermanager": {
        "target": "Set-MgUserManagerByRef",
        "delegated_scopes": ["User.ReadWrite.All"],
        "app_scopes": ["User.ReadWrite.All"],
        "param_map": {"objectid": "UserId", "refobjectid": "AdditionalProperties"},
        "single_id_params": ["userid"],
        "requires_all": False,
        "notes": "Pass -UserId <ID> -BodyParameter @{'@odata.id'='https://graph.microsoft.com/v1.0/users/<ManagerId>'}."
    },
    "revoke-azureaduserallrefreshtoken": {
        "target": "Revoke-MgUserSignInSession",
        "delegated_scopes": ["User.ReadWrite.All"],
        "app_scopes": ["User.ReadWrite.All"],
        "param_map": {"objectid": "UserId"},
        "single_id_params": ["userid"],
        "requires_all": False,
        "notes": "Replace -ObjectId with -UserId to invalidate active refresh tokens."
    },

    # 2. Licensing & Subscriptions
    "get-msolaccountsku": {
        "target": "Get-MgSubscribedSku",
        "delegated_scopes": ["Organization.Read.All"],
        "app_scopes": ["Organization.Read.All"],
        "param_map": {},
        "single_id_params": ["subscribedskuid"],
        "requires_all": True,
        "notes": "Returns tenant licensing SKUs, total units, and consumed units. Add -All."
    },
    "get-msolsubscription": {
        "target": "Get-MgSubscribedSku",
        "delegated_scopes": ["Organization.Read.All"],
        "app_scopes": ["Organization.Read.All"],
        "param_map": {"subscriptionid": "SubscribedSkuId"},
        "single_id_params": ["subscribedskuid"],
        "requires_all": True,
        "notes": "Modern Graph models subscriptions via Get-MgSubscribedSku. Add -All."
    },
    "get-azureadsubscribedsku": {
        "target": "Get-MgSubscribedSku",
        "delegated_scopes": ["Organization.Read.All"],
        "app_scopes": ["Organization.Read.All"],
        "param_map": {"objectid": "SubscribedSkuId"},
        "single_id_params": ["subscribedskuid"],
        "requires_all": True,
        "notes": "Replace -ObjectId with -SubscribedSkuId. Add -All."
    },
    "set-msoluserlicense": {
        "target": "Set-MgUserLicense",
        "delegated_scopes": ["User.ReadWrite.All"],
        "app_scopes": ["User.ReadWrite.All"],
        "param_map": {"userprincipalname": "UserId", "objectid": "UserId"},
        "single_id_params": ["userid"],
        "requires_all": False,
        "notes": "Requires SkuId GUIDs rather than string names. Pass -AddLicenses @(@{SkuId='GUID'}) -RemoveLicenses @()."
    },
    "set-azureaduserlicense": {
        "target": "Set-MgUserLicense",
        "delegated_scopes": ["User.ReadWrite.All"],
        "app_scopes": ["User.ReadWrite.All"],
        "param_map": {"objectid": "UserId"},
        "single_id_params": ["userid"],
        "requires_all": False,
        "notes": "Pass -UserId <ID> -AddLicenses @(@{SkuId='GUID'}) -RemoveLicenses @()."
    },

    # 3. Group Management
    "get-msolgroup": {
        "target": "Get-MgGroup",
        "delegated_scopes": ["Group.Read.All"],
        "app_scopes": ["Group.Read.All"],
        "param_map": {"objectid": "GroupId", "searchstring": "Filter", "maxresults": "Top"},
        "single_id_params": ["groupid"],
        "requires_all": True,
        "notes": "Add -All to retrieve all groups. Use OData -Filter."
    },
    "get-azureadgroup": {
        "target": "Get-MgGroup",
        "delegated_scopes": ["Group.Read.All"],
        "app_scopes": ["Group.Read.All"],
        "param_map": {"objectid": "GroupId", "searchstring": "Filter"},
        "single_id_params": ["groupid"],
        "requires_all": True,
        "notes": "Replace -ObjectId with -GroupId. Add -All."
    },
    "new-msolgroup": {
        "target": "New-MgGroup",
        "delegated_scopes": ["Group.ReadWrite.All"],
        "app_scopes": ["Group.ReadWrite.All"],
        "param_map": {},
        "single_id_params": [],
        "requires_all": False,
        "notes": "Specify -DisplayName, -MailNickname, -MailEnabled:$false, -SecurityEnabled:$true."
    },
    "new-azureadgroup": {
        "target": "New-MgGroup",
        "delegated_scopes": ["Group.ReadWrite.All"],
        "app_scopes": ["Group.ReadWrite.All"],
        "param_map": {},
        "single_id_params": [],
        "requires_all": False,
        "notes": "Specify -DisplayName, -MailNickname, -MailEnabled, -SecurityEnabled."
    },
    "set-msolgroup": {
        "target": "Update-MgGroup",
        "delegated_scopes": ["Group.ReadWrite.All"],
        "app_scopes": ["Group.ReadWrite.All"],
        "param_map": {"objectid": "GroupId"},
        "single_id_params": ["groupid"],
        "requires_all": False,
        "notes": "Target group with -GroupId <ID>."
    },
    "set-azureadgroup": {
        "target": "Update-MgGroup",
        "delegated_scopes": ["Group.ReadWrite.All"],
        "app_scopes": ["Group.ReadWrite.All"],
        "param_map": {"objectid": "GroupId"},
        "single_id_params": ["groupid"],
        "requires_all": False,
        "notes": "Replace -ObjectId with -GroupId."
    },
    "remove-msolgroup": {
        "target": "Remove-MgGroup",
        "delegated_scopes": ["Group.ReadWrite.All"],
        "app_scopes": ["Group.ReadWrite.All"],
        "param_map": {"objectid": "GroupId"},
        "single_id_params": ["groupid"],
        "requires_all": False,
        "notes": "Replace -ObjectId with -GroupId."
    },
    "remove-azureadgroup": {
        "target": "Remove-MgGroup",
        "delegated_scopes": ["Group.ReadWrite.All"],
        "app_scopes": ["Group.ReadWrite.All"],
        "param_map": {"objectid": "GroupId"},
        "single_id_params": ["groupid"],
        "requires_all": False,
        "notes": "Replace -ObjectId with -GroupId."
    },
    "get-msolgroupmember": {
        "target": "Get-MgGroupMember",
        "delegated_scopes": ["GroupMember.Read.All"],
        "app_scopes": ["GroupMember.Read.All"],
        "param_map": {"groupobjectid": "GroupId", "objectid": "GroupId"},
        "single_id_params": [],
        "requires_all": True,
        "notes": "Add -All. Returns directory objects."
    },
    "get-azureadgroupmember": {
        "target": "Get-MgGroupMember",
        "delegated_scopes": ["GroupMember.Read.All"],
        "app_scopes": ["GroupMember.Read.All"],
        "param_map": {"objectid": "GroupId"},
        "single_id_params": [],
        "requires_all": True,
        "notes": "Replace -ObjectId with -GroupId. Add -All."
    },
    "add-msolgroupmember": {
        "target": "New-MgGroupMemberByRef",
        "delegated_scopes": ["GroupMember.ReadWrite.All"],
        "app_scopes": ["GroupMember.ReadWrite.All"],
        "param_map": {"groupobjectid": "GroupId", "groupmemberobjectid": "DirectoryObjectId"},
        "single_id_params": [],
        "requires_all": False,
        "notes": "Pass -GroupId <ID> -DirectoryObjectId <ID>."
    },
    "add-azureadgroupmember": {
        "target": "New-MgGroupMemberByRef",
        "delegated_scopes": ["GroupMember.ReadWrite.All"],
        "app_scopes": ["GroupMember.ReadWrite.All"],
        "param_map": {"objectid": "GroupId", "refobjectid": "DirectoryObjectId"},
        "single_id_params": [],
        "requires_all": False,
        "notes": "Replace -ObjectId with -GroupId and -RefObjectId with -DirectoryObjectId."
    },
    "remove-msolgroupmember": {
        "target": "Remove-MgGroupMemberDirectoryObjectByRef",
        "delegated_scopes": ["GroupMember.ReadWrite.All"],
        "app_scopes": ["GroupMember.ReadWrite.All"],
        "param_map": {"groupobjectid": "GroupId", "groupmemberobjectid": "DirectoryObjectId"},
        "single_id_params": [],
        "requires_all": False,
        "notes": "Specify -GroupId and -DirectoryObjectId."
    },
    "remove-azureadgroupmember": {
        "target": "Remove-MgGroupMemberDirectoryObjectByRef",
        "delegated_scopes": ["GroupMember.ReadWrite.All"],
        "app_scopes": ["GroupMember.ReadWrite.All"],
        "param_map": {"objectid": "GroupId", "memberid": "DirectoryObjectId"},
        "single_id_params": [],
        "requires_all": False,
        "notes": "Replace -ObjectId with -GroupId and -MemberId with -DirectoryObjectId."
    },
    "get-azureadgroupowner": {
        "target": "Get-MgGroupOwner",
        "delegated_scopes": ["Group.Read.All"],
        "app_scopes": ["Group.Read.All"],
        "param_map": {"objectid": "GroupId"},
        "single_id_params": [],
        "requires_all": True,
        "notes": "Replace -ObjectId with -GroupId. Add -All."
    },
    "add-azureadgroupowner": {
        "target": "New-MgGroupOwnerByRef",
        "delegated_scopes": ["Group.ReadWrite.All"],
        "app_scopes": ["Group.ReadWrite.All"],
        "param_map": {"objectid": "GroupId", "refobjectid": "DirectoryObjectId"},
        "single_id_params": [],
        "requires_all": False,
        "notes": "Replace -ObjectId with -GroupId and -RefObjectId with -DirectoryObjectId."
    },
    "remove-azureadgroupowner": {
        "target": "Remove-MgGroupOwnerByRef",
        "delegated_scopes": ["Group.ReadWrite.All"],
        "app_scopes": ["Group.ReadWrite.All"],
        "param_map": {"objectid": "GroupId", "ownerid": "DirectoryObjectId"},
        "single_id_params": [],
        "requires_all": False,
        "notes": "Replace -ObjectId with -GroupId and -OwnerId with -DirectoryObjectId."
    },

    # 4. Service Principals & Applications
    "get-azureadserviceprincipal": {
        "target": "Get-MgServicePrincipal",
        "delegated_scopes": ["Application.Read.All"],
        "app_scopes": ["Application.Read.All"],
        "param_map": {"objectid": "ServicePrincipalId", "searchstring": "Filter"},
        "single_id_params": ["serviceprincipalid"],
        "requires_all": True,
        "notes": "Replace -ObjectId with -ServicePrincipalId. Add -All."
    },
    "new-azureadserviceprincipal": {
        "target": "New-MgServicePrincipal",
        "delegated_scopes": ["Application.ReadWrite.All"],
        "app_scopes": ["Application.ReadWrite.All"],
        "param_map": {},
        "single_id_params": [],
        "requires_all": False,
        "notes": "Specify -AppId <GUID>."
    },
    "set-azureadserviceprincipal": {
        "target": "Update-MgServicePrincipal",
        "delegated_scopes": ["Application.ReadWrite.All"],
        "app_scopes": ["Application.ReadWrite.All"],
        "param_map": {"objectid": "ServicePrincipalId"},
        "single_id_params": ["serviceprincipalid"],
        "requires_all": False,
        "notes": "Replace -ObjectId with -ServicePrincipalId."
    },
    "remove-azureadserviceprincipal": {
        "target": "Remove-MgServicePrincipal",
        "delegated_scopes": ["Application.ReadWrite.All"],
        "app_scopes": ["Application.ReadWrite.All"],
        "param_map": {"objectid": "ServicePrincipalId"},
        "single_id_params": ["serviceprincipalid"],
        "requires_all": False,
        "notes": "Replace -ObjectId with -ServicePrincipalId."
    },
    "get-azureadapplication": {
        "target": "Get-MgApplication",
        "delegated_scopes": ["Application.Read.All"],
        "app_scopes": ["Application.Read.All"],
        "param_map": {"objectid": "ApplicationId", "searchstring": "Filter"},
        "single_id_params": ["applicationid"],
        "requires_all": True,
        "notes": "Replace -ObjectId with -ApplicationId. Add -All."
    },
    "new-azureadapplication": {
        "target": "New-MgApplication",
        "delegated_scopes": ["Application.ReadWrite.All"],
        "app_scopes": ["Application.ReadWrite.All"],
        "param_map": {},
        "single_id_params": [],
        "requires_all": False,
        "notes": "Specify -DisplayName and identifier URIs."
    },
    "set-azureadapplication": {
        "target": "Update-MgApplication",
        "delegated_scopes": ["Application.ReadWrite.All"],
        "app_scopes": ["Application.ReadWrite.All"],
        "param_map": {"objectid": "ApplicationId"},
        "single_id_params": ["applicationid"],
        "requires_all": False,
        "notes": "Replace -ObjectId with -ApplicationId."
    },
    "remove-azureadapplication": {
        "target": "Remove-MgApplication",
        "delegated_scopes": ["Application.ReadWrite.All"],
        "app_scopes": ["Application.ReadWrite.All"],
        "param_map": {"objectid": "ApplicationId"},
        "single_id_params": ["applicationid"],
        "requires_all": False,
        "notes": "Replace -ObjectId with -ApplicationId."
    },
    "new-azureadapplicationkeycredential": {
        "target": "Add-MgApplicationPassword",
        "delegated_scopes": ["Application.ReadWrite.All"],
        "app_scopes": ["Application.ReadWrite.All"],
        "param_map": {"objectid": "ApplicationId"},
        "single_id_params": ["applicationid"],
        "requires_all": False,
        "notes": "Pass -ApplicationId <ID> -PasswordCredential @{DisplayName='...'}. Plain text secret returned only upon creation."
    },
    "new-azureadapplicationpasswordcredential": {
        "target": "Add-MgApplicationPassword",
        "delegated_scopes": ["Application.ReadWrite.All"],
        "app_scopes": ["Application.ReadWrite.All"],
        "param_map": {"objectid": "ApplicationId"},
        "single_id_params": ["applicationid"],
        "requires_all": False,
        "notes": "Pass -ApplicationId <ID> -PasswordCredential @{DisplayName='...'}. Plain text secret returned only upon creation."
    },
    "remove-azureadapplicationkeycredential": {
        "target": "Remove-MgApplicationPassword",
        "delegated_scopes": ["Application.ReadWrite.All"],
        "app_scopes": ["Application.ReadWrite.All"],
        "param_map": {"objectid": "ApplicationId", "customkeyidentifier": "KeyId"},
        "single_id_params": ["applicationid"],
        "requires_all": False,
        "notes": "Pass -ApplicationId <ID> -KeyId <GUID>."
    },
    "remove-azureadapplicationpasswordcredential": {
        "target": "Remove-MgApplicationPassword",
        "delegated_scopes": ["Application.ReadWrite.All"],
        "app_scopes": ["Application.ReadWrite.All"],
        "param_map": {"objectid": "ApplicationId", "keyid": "KeyId"},
        "single_id_params": ["applicationid"],
        "requires_all": False,
        "notes": "Pass -ApplicationId <ID> -KeyId <GUID>."
    },
    "new-azureadserviceprincipalpasswordcredential": {
        "target": "Add-MgServicePrincipalPassword",
        "delegated_scopes": ["Application.ReadWrite.All"],
        "app_scopes": ["Application.ReadWrite.All"],
        "param_map": {"objectid": "ServicePrincipalId"},
        "single_id_params": ["serviceprincipalid"],
        "requires_all": False,
        "notes": "Pass -ServicePrincipalId <ID> -PasswordCredential @{DisplayName='...'}. Plain text secret returned only upon creation."
    },
    "remove-azureadserviceprincipalpasswordcredential": {
        "target": "Remove-MgServicePrincipalPassword",
        "delegated_scopes": ["Application.ReadWrite.All"],
        "app_scopes": ["Application.ReadWrite.All"],
        "param_map": {"objectid": "ServicePrincipalId", "keyid": "KeyId"},
        "single_id_params": ["serviceprincipalid"],
        "requires_all": False,
        "notes": "Pass -ServicePrincipalId <ID> -KeyId <GUID>."
    },

    # 5. Directory Roles & Administrative Units
    "get-msolrole": {
        "target": "Get-MgDirectoryRole",
        "delegated_scopes": ["RoleManagement.Read.Directory"],
        "app_scopes": ["RoleManagement.Read.Directory"],
        "param_map": {"objectid": "DirectoryRoleId"},
        "single_id_params": ["directoryroleid"],
        "requires_all": True,
        "notes": "Returns directory roles. Add -All."
    },
    "get-azureaddirectoryrole": {
        "target": "Get-MgDirectoryRole",
        "delegated_scopes": ["RoleManagement.Read.Directory"],
        "app_scopes": ["RoleManagement.Read.Directory"],
        "param_map": {"objectid": "DirectoryRoleId"},
        "single_id_params": ["directoryroleid"],
        "requires_all": True,
        "notes": "Replace -ObjectId with -DirectoryRoleId. Add -All."
    },
    "get-msolrolemember": {
        "target": "Get-MgDirectoryRoleMember",
        "delegated_scopes": ["RoleManagement.Read.Directory"],
        "app_scopes": ["RoleManagement.Read.Directory"],
        "param_map": {"roleobjectid": "DirectoryRoleId"},
        "single_id_params": [],
        "requires_all": True,
        "notes": "Specify -DirectoryRoleId <ID>. Add -All."
    },
    "get-azureaddirectoryrolemember": {
        "target": "Get-MgDirectoryRoleMember",
        "delegated_scopes": ["RoleManagement.Read.Directory"],
        "app_scopes": ["RoleManagement.Read.Directory"],
        "param_map": {"objectid": "DirectoryRoleId"},
        "single_id_params": [],
        "requires_all": True,
        "notes": "Replace -ObjectId with -DirectoryRoleId. Add -All."
    },
    "add-msolrolemember": {
        "target": "New-MgDirectoryRoleMemberByRef",
        "delegated_scopes": ["RoleManagement.ReadWrite.Directory"],
        "app_scopes": ["RoleManagement.ReadWrite.Directory"],
        "param_map": {
            "roleobjectid": "DirectoryRoleId",
            "rolememberobjectid": "DirectoryObjectId"
        },
        "single_id_params": [],
        "requires_all": False,
        "notes": "Pass -DirectoryRoleId <ID> -DirectoryObjectId <ID>."
    },
    "add-azureaddirectoryrolemember": {
        "target": "New-MgDirectoryRoleMemberByRef",
        "delegated_scopes": ["RoleManagement.ReadWrite.Directory"],
        "app_scopes": ["RoleManagement.ReadWrite.Directory"],
        "param_map": {"objectid": "DirectoryRoleId", "refobjectid": "DirectoryObjectId"},
        "single_id_params": [],
        "requires_all": False,
        "notes": "Replace -ObjectId with -DirectoryRoleId and -RefObjectId with -DirectoryObjectId."
    },
    "remove-msolrolemember": {
        "target": "Remove-MgDirectoryRoleMemberDirectoryObjectByRef",
        "delegated_scopes": ["RoleManagement.ReadWrite.Directory"],
        "app_scopes": ["RoleManagement.ReadWrite.Directory"],
        "param_map": {
            "roleobjectid": "DirectoryRoleId",
            "rolememberobjectid": "DirectoryObjectId"
        },
        "single_id_params": [],
        "requires_all": False,
        "notes": "Pass -DirectoryRoleId <ID> -DirectoryObjectId <ID>."
    },
    "remove-azureaddirectoryrolemember": {
        "target": "Remove-MgDirectoryRoleMemberDirectoryObjectByRef",
        "delegated_scopes": ["RoleManagement.ReadWrite.Directory"],
        "app_scopes": ["RoleManagement.ReadWrite.Directory"],
        "param_map": {"objectid": "DirectoryRoleId", "memberid": "DirectoryObjectId"},
        "single_id_params": [],
        "requires_all": False,
        "notes": "Specify -DirectoryRoleId and -DirectoryObjectId."
    },
    "get-azureadadministrativeunit": {
        "target": "Get-MgAdministrativeUnit",
        "delegated_scopes": ["AdministrativeUnit.Read.All"],
        "app_scopes": ["AdministrativeUnit.Read.All"],
        "param_map": {"objectid": "AdministrativeUnitId"},
        "single_id_params": ["administrativeunitid"],
        "requires_all": True,
        "notes": "Replace -ObjectId with -AdministrativeUnitId. Add -All."
    },
    "get-azureadadministrativeunitmember": {
        "target": "Get-MgAdministrativeUnitMember",
        "delegated_scopes": ["AdministrativeUnit.Read.All"],
        "app_scopes": ["AdministrativeUnit.Read.All"],
        "param_map": {"objectid": "AdministrativeUnitId"},
        "single_id_params": [],
        "requires_all": True,
        "notes": "Replace -ObjectId with -AdministrativeUnitId. Add -All."
    },

    # 6. Devices, Contacts, Domains & Organization
    "get-msoldevice": {
        "target": "Get-MgDevice",
        "delegated_scopes": ["Device.Read.All"],
        "app_scopes": ["Device.Read.All"],
        "param_map": {"objectid": "DeviceId"},
        "single_id_params": ["deviceid"],
        "requires_all": True,
        "notes": "Returns registered devices. Add -All."
    },
    "get-azureaddevice": {
        "target": "Get-MgDevice",
        "delegated_scopes": ["Device.Read.All"],
        "app_scopes": ["Device.Read.All"],
        "param_map": {"objectid": "DeviceId", "searchstring": "Filter"},
        "single_id_params": ["deviceid"],
        "requires_all": True,
        "notes": "Replace -ObjectId with -DeviceId. Add -All."
    },
    "set-azureaddevice": {
        "target": "Update-MgDevice",
        "delegated_scopes": ["Device.ReadWrite.All"],
        "app_scopes": ["Device.ReadWrite.All"],
        "param_map": {"objectid": "DeviceId"},
        "single_id_params": ["deviceid"],
        "requires_all": False,
        "notes": "Replace -ObjectId with -DeviceId."
    },
    "remove-msoldevice": {
        "target": "Remove-MgDevice",
        "delegated_scopes": ["Device.ReadWrite.All"],
        "app_scopes": ["Device.ReadWrite.All"],
        "param_map": {"objectid": "DeviceId"},
        "single_id_params": ["deviceid"],
        "requires_all": False,
        "notes": "Replace -ObjectId with -DeviceId."
    },
    "remove-azureaddevice": {
        "target": "Remove-MgDevice",
        "delegated_scopes": ["Device.ReadWrite.All"],
        "app_scopes": ["Device.ReadWrite.All"],
        "param_map": {"objectid": "DeviceId"},
        "single_id_params": ["deviceid"],
        "requires_all": False,
        "notes": "Replace -ObjectId with -DeviceId."
    },
    "get-msolcontact": {
        "target": "Get-MgContact",
        "delegated_scopes": ["OrgContact.Read.All"],
        "app_scopes": ["OrgContact.Read.All"],
        "param_map": {"objectid": "OrgContactId"},
        "single_id_params": ["orgcontactid"],
        "requires_all": True,
        "notes": "Returns organizational contacts. Add -All."
    },
    "get-azureadcontact": {
        "target": "Get-MgContact",
        "delegated_scopes": ["OrgContact.Read.All"],
        "app_scopes": ["OrgContact.Read.All"],
        "param_map": {"objectid": "OrgContactId"},
        "single_id_params": ["orgcontactid"],
        "requires_all": True,
        "notes": "Replace -ObjectId with -OrgContactId. Add -All."
    },
    "get-msoldomain": {
        "target": "Get-MgDomain",
        "delegated_scopes": ["Domain.Read.All"],
        "app_scopes": ["Domain.Read.All"],
        "param_map": {"domainname": "DomainId"},
        "single_id_params": ["domainid"],
        "requires_all": True,
        "notes": "Returns verified custom domains. Add -All."
    },
    "get-azureaddomain": {
        "target": "Get-MgDomain",
        "delegated_scopes": ["Domain.Read.All"],
        "app_scopes": ["Domain.Read.All"],
        "param_map": {"name": "DomainId"},
        "single_id_params": ["domainid"],
        "requires_all": True,
        "notes": "Returns verified custom domains. Add -All."
    },
    "get-msolcompanyinformation": {
        "target": "Get-MgOrganization",
        "delegated_scopes": ["Organization.Read.All"],
        "app_scopes": ["Organization.Read.All"],
        "param_map": {},
        "single_id_params": [],
        "requires_all": False,
        "notes": "Returns tenant organization metadata."
    },
    "get-azureadtenantdetail": {
        "target": "Get-MgOrganization",
        "delegated_scopes": ["Organization.Read.All"],
        "app_scopes": ["Organization.Read.All"],
        "param_map": {},
        "single_id_params": [],
        "requires_all": False,
        "notes": "Returns tenant organization metadata."
    },

    # 7. Audit & Authentication
    "get-azureadauditsigninlogs": {
        "target": "Get-MgAuditLogSignIn",
        "delegated_scopes": ["AuditLog.Read.All"],
        "app_scopes": ["AuditLog.Read.All"],
        "param_map": {},
        "single_id_params": [],
        "requires_all": True,
        "notes": "Requires AuditLog.Read.All. Add -All or -Top."
    },
    "get-azureadauditdirectorylogs": {
        "target": "Get-MgAuditLogDirectoryAudit",
        "delegated_scopes": ["AuditLog.Read.All"],
        "app_scopes": ["AuditLog.Read.All"],
        "param_map": {},
        "single_id_params": [],
        "requires_all": True,
        "notes": "Requires AuditLog.Read.All. Add -All or -Top."
    },
    "connect-msolservice": {
        "target": "Connect-MgGraph",
        "delegated_scopes": [],
        "app_scopes": [],
        "param_map": {},
        "single_id_params": [],
        "requires_all": False,
        "notes": "Replace with Connect-MgGraph specifying computed least-privilege scopes."
    },
    "connect-azuread": {
        "target": "Connect-MgGraph",
        "delegated_scopes": [],
        "app_scopes": [],
        "param_map": {"applicationid": "ClientId"},
        "single_id_params": [],
        "requires_all": False,
        "notes": "Replace with Connect-MgGraph specifying computed least-privilege scopes."
    },
    "disconnect-azuread": {
        "target": "Disconnect-MgGraph",
        "delegated_scopes": [],
        "app_scopes": [],
        "param_map": {},
        "single_id_params": [],
        "requires_all": False,
        "notes": "Replace with Disconnect-MgGraph."
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

        # 0. ConvertTo-SecureString plaintext literals
        text = re.sub(
            r'(ConvertTo-SecureString\s+(?:-String\s+)?)(["\'][^"\']+["\']|[^\s]+)(\s+-AsPlainText)',
            r'\1"[REDACTED-SECRET]"\3',
            text,
            flags=re.IGNORECASE
        )

        # 1. JWT bearer tokens and raw JWTs
        text = re.sub(
            r'Bearer\s+eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+',
            'Bearer "[REDACTED-TOKEN]"',
            text,
            flags=re.IGNORECASE
        )
        text = re.sub(
            r'["\']eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+["\']',
            '"[REDACTED-TOKEN]"',
            text
        )

        # 2. Variable assignments: $secret = "...", $token='...', $password=...
        text = re.sub(
            r'(\$(?:password|secret|token|api[_-]?key|client[_-]?secret|app[_-]?secret)\w*\s*=\s*)(?:(["\'][^"\']*["\'])|([A-Za-z0-9_\-\.]+))',
            r'\1"[REDACTED-SECRET]"',
            text,
            flags=re.IGNORECASE
        )

        # 3. Hashtable entries or parameter pairs: Password = "...", Secret: "..."
        text = re.sub(
            r'(\b(?:password|secret|token|api[_-]?key|client[_-]?secret|app[_-]?secret|pass)\s*([:=])\s*)(?:(["\'][^"\']*["\'])|([A-Za-z0-9_\-\.]+))',
            r'\1"[REDACTED-SECRET]"',
            text,
            flags=re.IGNORECASE
        )

        # 4. Cmdlet parameters: -Password "...", -Secret '...', etc.
        text = re.sub(
            r'(-(?:password|secret|token|api[_-]?key|client[_-]?secret|certificatepassword|pass)\s+)(?:(["\'][^"\']*["\'])|([^\s]+))',
            r'\1"[REDACTED-SECRET]"',
            text,
            flags=re.IGNORECASE
        )

        # 5. Unicode / IDN UPNs & Emails (bounded quantifier prevents ReDoS backtracking)
        text = re.sub(
            r'(?<![\w._%+-])[\w._%+-]{1,64}@[\w.-]{1,255}\.[\w-]{2,24}\b',
            lambda m: self.sanitize_upn(m.group(0)),
            text,
            flags=re.UNICODE
        )

        # 6. Scrub GUIDs
        text = re.sub(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
            lambda m: self.sanitize_guid(m.group(0)),
            text
        )

        # 7. Scrub IPv4 addresses
        text = re.sub(
            r"\b(?!127\.0\.0\.1|0\.0\.0\.0|198\.51\.100\.|192\.0\.2\.)(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])\.(?:\d{1,3}\.){2}(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])\b",
            lambda m: self.sanitize_ip(m.group(0)),
            text
        )

        # 8. Scrub IPv6 addresses (including bracketed IPv6 with port)
        text = re.sub(
            r"\[(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F:]+\](?::\d+)?|\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\bfe80::[0-9a-fA-F:]+\b|\b2[0-9a-fA-F]{3}:[0-9a-fA-F:]+\b",
            "2001:db8::1",
            text
        )

        text = _residual_scrub(text)
        return text


_QUOTED_LITERAL_RE = re.compile(r'"(?:`."|[^"])*"' + r"|'(?:[^'])*'")
_WORD_TOKEN_RE = re.compile(r"\b[A-Za-z]+-[A-Za-z0-9]+\b")
_ACCOUNT_SKUID_RE = re.compile(r"(\$[A-Za-z0-9_]+)\.AccountSkuId\b", re.IGNORECASE)
_ACTIVE_UNITS_RE = re.compile(r"(\$[A-Za-z0-9_]+)\.ActiveUnits\b", re.IGNORECASE)
_IS_LICENSED_FALSE_RE = re.compile(r"\$_\.IsLicensed\s+-eq\s+\$false\b", re.IGNORECASE)
_IS_LICENSED_TRUE_RE = re.compile(r"\$_\.IsLicensed\s+-eq\s+\$true\b", re.IGNORECASE)
_BOUND_LIMIT_RE = re.compile(r"-(?:all|top)\b", re.IGNORECASE)
_CONNECT_CMD_RE = re.compile(r"\b(Connect-MsolService|Connect-AzureAD)\b", re.IGNORECASE)


def _split_inline_comment(line: str) -> Tuple[str, str]:
    """Splits a PowerShell line into (code_part, inline_comment_part) outside string quotes."""
    if "#" not in line:
        return line, ""
    in_single = False
    in_double = False
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if ch == "`" and i + 1 < n:
            i += 2
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            # Ignore <# and #>
            if (i > 0 and line[i - 1] == "<") or (i + 1 < n and line[i + 1] == ">"):
                i += 1
                continue
            return line[:i], line[i:]
        i += 1
    return line, ""


def _strip_quoted_literals(code_part: str) -> str:
    """Replaces contents of quoted strings with empty quotes so cmdlets inside string literals are not misidentified."""
    if '"' not in code_part and "'" not in code_part:
        return code_part
    return _QUOTED_LITERAL_RE.sub('""', code_part)


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
        in_here_string: Optional[str] = None

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Handle here-strings (@" ... "@ and @' ... '@)
            if in_here_string is not None:
                if stripped == f"{in_here_string}@" or stripped == '"@' or stripped == "'@":
                    in_here_string = None
                continue
            if line.rstrip().endswith('@"') or re.search(r'=\s*@"\s*$', line):
                in_here_string = '"'
                continue
            elif line.rstrip().endswith("@'") or re.search(r"=\s*@'\s*$", line):
                in_here_string = "'"
                continue

            # Handle block comments (<# ... #>) outside strings
            code_line = line
            if in_block_comment:
                if "#>" in line:
                    in_block_comment = False
                    code_line = line.split("#>", 1)[1]
                else:
                    continue

            # Strip any inline block comments like <# ... #>
            if "<#" in code_line:
                masked = _strip_quoted_literals(code_line)
                if "<#" in masked:
                    if "#>" in masked:
                        code_line = re.sub(r"<#.*?#>", "", code_line)
                    else:
                        in_block_comment = True
                        code_line = code_line[:code_line.index("<#")]

            stripped_code = code_line.strip()
            if not stripped_code or stripped_code.startswith("#"):
                continue

            # Strip inline comments and string literals before scanning for executable cmdlets
            code_only, _ = _split_inline_comment(code_line)
            unquoted_code = _strip_quoted_literals(code_only)

            # Tokenize words to match cmdlets safely on word boundaries
            tokens = _WORD_TOKEN_RE.findall(unquoted_code)
            for token in tokens:
                t_lower = token.lower()
                if t_lower in CMDLET_MAPPINGS:
                    info = CMDLET_MAPPINGS[t_lower]
                    target = info["target"]
                    del_s = info["delegated_scopes"]
                    app_s = info["app_scopes"]
                    notes = info["notes"]

                    if "@" in code_only and re.search(r"@[A-Za-z0-9_]+", code_only):
                        notes += "; Splatted parameter hashtable detected - verify parameter hashtable keys for Microsoft Graph"

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

    def _find_header_and_param_end(self, lines: List[str]) -> Tuple[int, bool]:
        """Finds the line index immediately after any leading comment blocks and param(...) block."""
        idx = 0
        n = len(lines)
        in_block_comment = False
        has_param_block = False

        while idx < n:
            stripped = lines[idx].strip()
            if not stripped:
                idx += 1
                continue
            if "<#" in stripped:
                in_block_comment = True
            if in_block_comment:
                if "#>" in stripped:
                    in_block_comment = False
                idx += 1
                continue
            if stripped.startswith("#"):
                idx += 1
                continue
            if re.match(r"^\[CmdletBinding\(.*\)\]$", stripped, re.IGNORECASE):
                idx += 1
                continue
            if re.match(r"^param\s*\(", stripped, re.IGNORECASE):
                has_param_block = True
                paren_depth = 0
                while idx < n:
                    code_part, _ = _split_inline_comment(lines[idx])
                    unquoted = _strip_quoted_literals(code_part)
                    paren_depth += unquoted.count("(") - unquoted.count(")")
                    idx += 1
                    if paren_depth <= 0:
                        break
                break
            break

        return (idx if has_param_block else 0), has_param_block

    def _modernize_properties(self, code_part: str) -> str:
        """Modernizes legacy AzureAD/MSOnline property references to Microsoft.Graph SDK properties."""
        if "." not in code_part and "$" not in code_part:
            return code_part
        code_part = _ACCOUNT_SKUID_RE.sub(r"\1.SkuPartNumber", code_part)
        code_part = _ACTIVE_UNITS_RE.sub(r"\1.PrepaidUnits.Enabled", code_part)
        if "islicensed" in code_part.lower():
            code_part = _IS_LICENSED_FALSE_RE.sub(r"($_.AssignedLicenses.Count -eq 0)", code_part)
            code_part = _IS_LICENSED_TRUE_RE.sub(r"($_.AssignedLicenses.Count -gt 0)", code_part)
        return code_part

    def _modernize_single_cmdlet(self, cmd_part: str) -> str:
        """Modernizes a single cmdlet invocation, updating parameters and auto-injecting -All."""
        # Handle legacy boolean -All $true / -All $false
        cmd_part = re.sub(r"-All\s+\$true\b", "-All", cmd_part, flags=re.IGNORECASE)
        cmd_part = re.sub(r"-All\s+\$false\b", "-Top 100", cmd_part, flags=re.IGNORECASE)

        # Translate -SearchString to OData startswith() filter
        def _repl_search(m):
            val = m.group(1).strip()
            if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                inner = val[1:-1]
                return f'-Filter "startswith(displayName,\'{inner}\')"'
            elif "." in val and val.startswith("$"):
                return f'-Filter "startswith(displayName,\'$({val})\')"'
            else:
                return f'-Filter "startswith(displayName,\'{val}\')"'

        cmd_part = re.sub(
            r"-SearchString\s+((?:\"[^\"]*\"|'[^']*'|\$[A-Za-z0-9_.]+|[^\s\)]+))",
            _repl_search,
            cmd_part,
            flags=re.IGNORECASE
        )

        # Find cmdlet
        m_cmd = re.search(r"\b([A-Za-z]+-[A-Za-z0-9]+)\b", cmd_part)
        if not m_cmd:
            return cmd_part

        legacy_name = m_cmd.group(1)
        legacy_key = legacy_name.lower()
        if legacy_key not in CMDLET_MAPPINGS:
            return cmd_part

        info = CMDLET_MAPPINGS[legacy_key]
        target = info["target"]

        # Replace cmdlet name
        updated = cmd_part[:m_cmd.start()] + target + cmd_part[m_cmd.end():]

        # Update parameter names (supporting colon-binding e.g. -Param:val)
        for old_param, new_param in info.get("param_map", {}).items():
            updated = re.sub(rf"(-{re.escape(old_param)})\b", f"-{new_param}", updated, flags=re.IGNORECASE)

        # Inject -All if required
        if info.get("requires_all"):
            lower = updated.lower()
            single_id_params = info.get("single_id_params", [])
            has_single_id = any(re.search(rf"-{re.escape(p)}\b", lower) for p in single_id_params)
            has_bound_limit = bool(re.search(r"-(?:all|top)\b", lower))

            if not has_single_id and not has_bound_limit:
                is_continued = updated.rstrip().endswith("`")
                if is_continued:
                    trimmed = updated.rstrip()
                    updated = trimmed[:-1].rstrip() + " -All `"
                else:
                    updated = f"{updated.rstrip()} -All"

        # Check for splatting on legacy cmdlet
        if re.search(r"@[A-Za-z0-9_]+", updated):
            updated = f"{updated} # <# MIGRATION-REVIEW: Splatted parameter hashtable detected. Verify Graph parameter keys. #>"

        return updated

    def _modernize_clause(self, clause: str) -> str:
        """Modernizes a single pipeline or expression clause."""
        pipe_parts = re.split(r"(?<=[^\s])\s*\|\s*", clause)
        if len(pipe_parts) > 1:
            return " | ".join(self._modernize_clause(p) for p in pipe_parts)
        return self._modernize_single_cmdlet(clause)

    def _modernize_expression(self, expr: str) -> str:
        """Decomposes an expression inside-out to prevent parameter bleed across nested subexpressions."""
        placeholders: Dict[str, str] = {}
        counter = 0

        # 1. Extract and modernize script blocks { ... }
        while True:
            m_brace = re.search(r"\{([^{}]+)\}", expr)
            if not m_brace:
                break
            inner = m_brace.group(1)
            mod_inner = self._modernize_expression(inner)
            tag = f"__PH_BRACE_{counter}__"
            counter += 1
            prefix_space = " " if inner.startswith(" ") else ""
            suffix_space = " " if inner.endswith(" ") else ""
            placeholders[tag] = "{" + prefix_space + mod_inner.strip() + suffix_space + "}"
            expr = expr[:m_brace.start()] + tag + expr[m_brace.end():]

        # 2. Extract and modernize parenthesized subexpressions ( ... )
        while True:
            m_paren = re.search(r"\(([^()]+)\)", expr)
            if not m_paren:
                break
            inner = m_paren.group(1)
            mod_inner = self._modernize_expression(inner)
            tag = f"__PH_PAREN_{counter}__"
            counter += 1
            placeholders[tag] = "(" + mod_inner + ")"
            expr = expr[:m_paren.start()] + tag + expr[m_paren.end():]

        # 3. Modernize outer clause
        expr = self._modernize_clause(expr)

        # 4. Property updates on parenthesized results and pipeline objects
        expr = re.sub(r"(__PH_PAREN_\d+__)\.ObjectId\b", r"\1.Id", expr, flags=re.IGNORECASE)
        expr = re.sub(r"\$_\.ObjectId\b", "$_.Id", expr, flags=re.IGNORECASE)
        expr = self._modernize_properties(expr)

        # 5. Restore placeholders in reverse order
        for tag in reversed(list(placeholders.keys())):
            expr = expr.replace(tag, placeholders[tag])

        return expr

    def _rewrite_module_loading(self, line: str) -> Optional[str]:
        """Rewrites retired module loading statements (#Requires, Import-Module, Install-Module)."""
        stripped = line.strip()

        # 1. #Requires -Modules
        if stripped.lower().startswith("#requires"):
            m = re.match(r"(#Requires\s+-Modules\s+)(.*)", line, re.IGNORECASE)
            if m:
                prefix, mod_str = m.group(1), m.group(2)
                mods = [x.strip() for x in mod_str.split(",") if x.strip()]
                new_mods = []
                has_graph = False
                for mod in mods:
                    if mod.lower() in ("msonline", "azuread", "azureadpreview"):
                        if not has_graph:
                            new_mods.extend(["Microsoft.Graph.Users", "Microsoft.Graph.Groups"])
                            has_graph = True
                    else:
                        new_mods.append(mod)
                return f"{prefix}{', '.join(new_mods)}"

        # 2. Import-Module
        if re.search(r"\bImport-Module\s+(AzureAD|MSOnline|AzureADPreview)\b", line, re.IGNORECASE):
            return re.sub(
                r"\bImport-Module\s+(AzureAD|MSOnline|AzureADPreview)\b",
                "Import-Module Microsoft.Graph",
                line,
                flags=re.IGNORECASE
            )

        # 3. Install-Module
        if re.search(r"\bInstall-Module\s+.*?(MSOnline|AzureAD)\b", line, re.IGNORECASE):
            mod_line = re.sub(r"(-Name\s+)(MSOnline|AzureAD|AzureADPreview)\b", r"\1Microsoft.Graph", line, flags=re.IGNORECASE)
            mod_line = re.sub(r"-RequiredVersion\s+[0-9a-zA-Z\.\-]+\s*", "", mod_line, flags=re.IGNORECASE)
            return mod_line

        return None

    def _generate_modern_script(self, original_lines: List[str], scopes: Set[str]) -> str:
        out_lines: List[str] = []

        full_text = "\n".join(original_lines)
        has_cert_auth = bool(re.search(r"Connect-(?:AzureAD|MsolService).*?-Certificate(?:Thumbprint)?\b", full_text, re.DOTALL | re.IGNORECASE))

        scope_str = ", ".join(f'"{s}"' for s in sorted(list(scopes))) if scopes else '"User.Read.All"'
        param_end_idx, has_param_block = self._find_header_and_param_end(original_lines)

        # Add Modern Header
        out_lines.append("<#")
        out_lines.append(".SYNOPSIS")
        out_lines.append(f"    Modernized replacement for {self.script_name} using Microsoft.Graph PowerShell SDK.")
        out_lines.append(".DESCRIPTION")
        out_lines.append("    Migrated from legacy AzureAD / MSOnline modules to Microsoft.Graph v2.x.")
        out_lines.append(f"    Required least-privilege permission scopes: {', '.join(sorted(list(scopes))) if scopes else 'None'}")
        out_lines.append("#>")

        if has_param_block:
            for idx in range(param_end_idx):
                out_lines.append(original_lines[idx])
        else:
            out_lines.append("[CmdletBinding()]")
            out_lines.append("param()")

        out_lines.append("")
        if not has_cert_auth:
            out_lines.append("# 1. Verify and establish Microsoft Graph connection with least-privilege scopes")
            out_lines.append("if (-not (Get-MgContext -ErrorAction SilentlyContinue)) {")
            out_lines.append('    Write-Verbose "Connecting to Microsoft Graph with required scopes..."')
            out_lines.append(f"    Connect-MgGraph -Scopes {scope_str} -NoWelcome")
            out_lines.append("}")
        else:
            out_lines.append("# 1. Verify and establish Microsoft Graph connection (App-Only Certificate Authentication)")
        out_lines.append("")
        out_lines.append("# 2. Execute modernized workload operations")

        in_block_comment = False
        in_here_string: Optional[str] = None
        active_continuation_info: Optional[Dict[str, Any]] = None
        active_cert_continuation = False

        for line in original_lines[param_end_idx:]:
            stripped = line.strip()

            # Preserve here-strings
            if in_here_string is not None:
                out_lines.append(line)
                if stripped == f"{in_here_string}@" or stripped == '"@' or stripped == "'@":
                    in_here_string = None
                continue
            if line.rstrip().endswith('@"') or re.search(r'=\s*@"\s*$', line):
                in_here_string = '"'
                out_lines.append(line)
                continue
            elif line.rstrip().endswith("@'") or re.search(r"=\s*@'\s*$", line):
                in_here_string = "'"
                out_lines.append(line)
                continue

            # Preserve block comments
            inline_block_comments: Dict[str, str] = {}
            ibc_counter = 0
            if "<#" in stripped and not in_block_comment:
                masked = _strip_quoted_literals(stripped)
                if "<#" in masked:
                    if "#>" in masked:
                        def repl_ibc(m_ibc):
                            nonlocal ibc_counter
                            tag = f"__PH_IBC_{ibc_counter}__"
                            ibc_counter += 1
                            inline_block_comments[tag] = m_ibc.group(0)
                            return tag
                        line = re.sub(r"<#.*?#>", repl_ibc, line)
                        stripped = line.strip()
                    else:
                        in_block_comment = True
                        out_lines.append(line)
                        continue
            if in_block_comment:
                out_lines.append(line)
                if "#>" in stripped:
                    in_block_comment = False
                continue

            # Check module loading rewrites
            mod_rewritten = self._rewrite_module_loading(line)
            if mod_rewritten is not None:
                out_lines.append(mod_rewritten)
                continue

            # Preserve pure comment lines
            if stripped.startswith("#"):
                out_lines.append(line)
                continue

            code_part, comment_part = _split_inline_comment(line)
            unquoted_code = _strip_quoted_literals(code_part)

            # Handle Connect / Disconnect calls
            if "connect-" in unquoted_code.lower() and _CONNECT_CMD_RE.search(unquoted_code):
                # Check for PSCredential basic auth
                if "-credential" in unquoted_code.lower():
                    out_lines.append(f"# <# MIGRATION-REVIEW: Legacy PSCredential basic auth is not supported by Microsoft Graph. Use Connect-MgGraph -Identity (Managed Identity) or certificate-based authentication. #>")
                    out_lines.append(f"# {stripped}")
                    out_lines.append("# Connect-MgGraph -Identity")
                    continue
                # Check for Certificate app-only auth
                if has_cert_auth or "-certificate" in unquoted_code.lower():
                    updated_conn = re.sub(r"\bConnect-(?:AzureAD|MsolService)\b", "Connect-MgGraph", code_part, flags=re.IGNORECASE)
                    updated_conn = re.sub(r"-ApplicationId\b", "-ClientId", updated_conn, flags=re.IGNORECASE)
                    if updated_conn.rstrip().endswith("`"):
                        active_cert_continuation = True
                    else:
                        updated_conn = f"{updated_conn.rstrip()} -NoWelcome"
                    out_lines.append(updated_conn + (" " + comment_part if comment_part else ""))
                    continue
                else:
                    out_lines.append(f"# Replaced legacy connection: {stripped}")
                    out_lines.append(f"# Connect-MgGraph -Scopes {scope_str} -NoWelcome")
                    active_continuation_info = None
                    continue

            # Continuation line for certificate connection
            if active_cert_continuation:
                updated_conn = re.sub(r"-ApplicationId\b", "-ClientId", code_part, flags=re.IGNORECASE)
                if not updated_conn.rstrip().endswith("`"):
                    active_cert_continuation = False
                    updated_conn = f"{updated_conn.rstrip()} -NoWelcome"
                out_lines.append(updated_conn + (" " + comment_part if comment_part else ""))
                continue

            # Continuation line from a previous backtick cmdlet
            if active_continuation_info is not None:
                updated_code = code_part
                for old_param, new_param in active_continuation_info.get("param_map", {}).items():
                    param_pattern = rf"(-{re.escape(old_param)})\b"
                    updated_code = re.sub(param_pattern, f"-{new_param}", updated_code, flags=re.IGNORECASE)
                updated_code = self._modernize_properties(updated_code)
                sep = " " if (comment_part and not updated_code.endswith(" ")) else ""
                out_lines.append(updated_code + sep + comment_part)
                if not updated_code.rstrip().endswith("`"):
                    active_continuation_info = None
                continue

            # Check if this line continues onto the next line
            is_backtick_continued = code_part.rstrip().endswith("`")

            # Check if line contains a legacy cmdlet
            tokens = _WORD_TOKEN_RE.findall(unquoted_code)
            matched_cmdlets = [t.lower() for t in tokens if t.lower() in CMDLET_MAPPINGS]

            if not matched_cmdlets:
                res = self._modernize_properties(code_part) + ((" " + comment_part) if comment_part else "")
                for tag, orig_c in inline_block_comments.items():
                    res = res.replace(tag, orig_c)
                out_lines.append(res)
                continue

            # Semicolon statements handled independently
            if ";" in code_part:
                stmts = code_part.split(";")
                mod_stmts = [self._modernize_expression(s.strip()) for s in stmts]
                updated_code = "; ".join(mod_stmts)
            else:
                updated_code = self._modernize_expression(code_part)

            if is_backtick_continued and matched_cmdlets:
                active_continuation_info = CMDLET_MAPPINGS[matched_cmdlets[0]]

            sep = " " if (comment_part and not updated_code.endswith(" ")) else ""
            res = updated_code + sep + comment_part
            for tag, orig_c in inline_block_comments.items():
                res = res.replace(tag, orig_c)
            out_lines.append(res)

        return "\n".join(out_lines)


def format_markdown(analysis: MigrationAnalysis, sanitize: bool = False) -> str:
    out: List[str] = []
    out.append("# Microsoft Graph Migration & Code Modernization Plan")
    out.append("")
    out.append(f"- **Source Script:** `{analysis.script_name}`")
    out.append(f"- **Migration Timestamp (UTC):** `{analysis.timestamp_utc}`")
    out.append(f"- **Total Deprecated Cmdlet Invocations:** {analysis.total_legacy_calls}")
    out.append("- **Target Module:** `Microsoft.Graph` (v2.x)")
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
    out.append("2. **Validate Scopes:** Ensure your executing identity or app registration has been granted consent for:")
    scope_list_str = ", ".join(f"'{s}'" for s in analysis.required_delegated_scopes) if analysis.required_delegated_scopes else "'User.Read.All'"
    out.append("   ```powershell")
    out.append(f"   Connect-MgGraph -Scopes {scope_list_str}")
    out.append("   ```")
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

    script_name = "PastedScript.ps1"
    if args.input == "-":
        if sys.stdin.isatty():
            sys.stderr.write("Error: No input specified and stdin is empty.\n")
            return 1
        content = sys.stdin.read().lstrip("\ufeff")
    else:
        p = Path(args.input)
        if p.is_dir():
            sys.stderr.write(f"Error: Input path is a directory, not a script file: {p}\n")
            return 1
        if not p.exists():
            sys.stderr.write(f"Error: Input file not found: {p}\n")
            return 1
        script_name = p.name
        raw = p.read_bytes()
        # Multi-encoding support: UTF-16 LE (BOM and BOM-less), UTF-16 BE, UTF-8, CP1252
        if raw.startswith(b"\xff\xfe"):
            content = raw.decode("utf-16-le")
        elif raw.startswith(b"\xfe\xff"):
            content = raw.decode("utf-16-be")
        elif b"\x00" in raw[:1024]:
            content = raw.decode("utf-16-le", errors="replace")
        else:
            try:
                content = raw.decode("utf-8-sig")
            except UnicodeDecodeError:
                try:
                    content = raw.decode("cp1252")
                except UnicodeDecodeError:
                    content = raw.decode("utf-8", errors="replace")
        content = content.lstrip("\ufeff")

    # If input is JSON inventory from Scan-LegacyGraphCmdlets.ps1
    trimmed = content.strip()
    if trimmed.startswith("{") and "Findings" in trimmed:
        try:
            data = json.loads(trimmed)
            findings_raw = data.get("Findings", [])
            if isinstance(findings_raw, dict):
                findings_raw = [findings_raw]
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
        out_p = Path(args.output)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(rendered, encoding="utf-8")
    else:
        print(rendered)

    return 0


if __name__ == "__main__":
    sys.exit(main())
