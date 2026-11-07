# Microsoft Graph Migration & Code Replacement Plan

**Script Name:** `{{SCRIPT_NAME}}`  
**Migration Date (UTC):** `{{TIMESTAMP_UTC}}`  
**Target Module:** `Microsoft.Graph` (v2.x)

---

## 1. Cmdlet & Permission Scope Inventory

| Legacy Cmdlet | Modern MgGraph Cmdlet | Delegated Scope | Application Scope |
| --- | --- | --- | --- |
| `{{LEGACY_CMDLET_1}}` | `{{MODERN_CMDLET_1}}` | `{{SCOPE_1}}` | `{{APP_SCOPE_1}}` |
| `{{LEGACY_CMDLET_2}}` | `{{MODERN_CMDLET_2}}` | `{{SCOPE_2}}` | `{{APP_SCOPE_2}}` |

---

## 2. Modernized PowerShell Script Drop-In Replacement

```powershell
<#
.SYNOPSIS
    Modernized replacement for {{SCRIPT_NAME}} using Microsoft.Graph SDK.
#>
[CmdletBinding()]
param(
    [switch]$WhatIf
)

# Required scopes: {{SCOPES_LIST}}
Import-Module Microsoft.Graph.Users -ErrorAction Stop

if (-not (Get-MgContext)) {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    Connect-MgGraph -Scopes "{{SCOPES_LIST}}" -NoWelcome
}

{{MODERN_SCRIPT_BODY}}
```

---

## 3. Testing & Verification Steps
1. Run pre-flight check in read-only mode.
2. Confirm pagination retrieves the complete dataset.
3. Verify tenant audit log records appropriate service principal access.
