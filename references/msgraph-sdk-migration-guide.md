# Microsoft Graph PowerShell SDK Migration Engineering Guide

Technical architecture, operational patterns, and pitfalls when modernizing legacy `AzureAD` and `MSOnline` scripts to the `Microsoft.Graph` PowerShell SDK (v2.x).

---

## 1. Authentication & Session Architecture

### 1.1 Least-Privilege Scope Calculation
Unlike `Connect-AzureAD`, which requested broad directory-level permissions depending on the admin role, `Connect-MgGraph` enforces granular OAuth permission scopes.

- **Delegated Context (User Interactive):**
  ```powershell
  Connect-MgGraph -Scopes "User.Read.All", "Group.Read.All" -NoWelcome
  ```
- **App-Only Context (Automated Tasks / Service Principals):**
  ```powershell
  # Certificate authentication (recommended for production automations)
  Connect-MgGraph -ClientId "00000000-0000-0000-0000-000000000000" `
                  -TenantId "00000000-0000-0000-0000-000000000000" `
                  -CertificateThumbprint "A1B2C3D4E5F6789012345678901234567890ABCD" `
                  -NoWelcome
  ```
- **Managed Identity (Azure Automation / Azure VM / Functions):**
  ```powershell
  Connect-MgGraph -Identity -NoWelcome
  ```

### 1.2 Session Context Verification
Before executing queries, always check whether an active Graph context exists:
```powershell
$context = Get-MgContext
if (-not $context) {
    throw "No active Microsoft Graph session found. Execute Connect-MgGraph first."
}
```

---

## 2. Querying, Pagination, and Filtering

### 2.1 The Silent Truncation Trap (Pagination)
In legacy `AzureAD` and `MSOnline`, queries returned all matching records by default (or up to specified limits). In `Microsoft.Graph`:
- **Default Page Size:** Returns only the first 100 to 999 records.
- **Remediation:** You MUST add `-All` to return the complete dataset across all pages.
  ```powershell
  # INCORRECT: Will silently truncate large tenants
  $users = Get-MgUser

  # CORRECT: Auto-paginates until all records are retrieved
  $users = Get-MgUser -All
  ```

### 2.2 Advanced Filtering (`-ConsistencyLevel eventual`)
Certain complex queries (such as counting, filtering on empty properties, `NOT` filters, or dynamic group lookups) require the `ConsistencyLevel: eventual` header:
```powershell
# Counting total users with advanced filter
Get-MgUser -ConsistencyLevel eventual -CountVariable totalUsers -Filter "accountEnabled eq true"
Write-Host "Total enabled users: $totalUsers"
```

### 2.3 Filter Syntax Quotation Rules
Graph filter strings require single quotes around string literals inside double quotes:
```powershell
$targetDept = "Engineering"
# CORRECT
Get-MgUser -Filter "department eq '$targetDept'" -All

# INCORRECT (Graph REST syntax error)
Get-MgUser -Filter "department eq $targetDept"
```

---

## 3. License Assignment Modernization

In MSOnline, `Set-MsolUserLicense` accepted comma-separated strings such as `tenant:ENTERPRISEPACK`. In modern Graph:
1. Licenses are identified by **SkuId (GUID)**, not string part numbers.
2. The payload is passed as structured hashtables to `Set-MgUserLicense`.

### Migration Pattern:
```powershell
# Step 1: Resolve SkuId from SkuPartNumber
$sku = Get-MgSubscribedSku -All | Where-Object { $_.SkuPartNumber -eq "ENTERPRISEPACK" }
if (-not $sku) {
    throw "Target licensing SKU 'ENTERPRISEPACK' not found in tenant."
}

# Step 2: Assign License via Set-MgUserLicense
$addLicenses = @(
    @{ SkuId = $sku.SkuId }
)
Set-MgUserLicense -UserId "user@corp.example.com" -AddLicenses $addLicenses -RemoveLicenses @()
```

---

## 4. Property Name Mapping & Projection

Microsoft Graph property names align directly with the Microsoft Graph REST API v1.0 schema:

| Legacy Property (MSOnline / AzureAD) | Modern Graph Property (`Get-MgUser`) |
| :--- | :--- |
| `UserPrincipalName` | `UserPrincipalName` |
| `ObjectId` | `Id` |
| `DisplayName` | `DisplayName` |
| `IsLicensed` | Check `($user.AssignedLicenses.Count -gt 0)` |
| `Licenses` | `AssignedLicenses` |
| `AccountEnabled` | `AccountEnabled` |
| `MobilePhone` | `MobilePhone` |
| `UsageLocation` | `UsageLocation` |
| `SignInNames` | `Identities` (B2C / external identities) |
| `LastDirSyncTime` | `OnPremisesLastSyncDateTime` |
| `PasswordNeverExpires` | `PasswordPolicies -match 'DisablePasswordExpiration'` |

### Property Projection with `-Property`
By default, Graph returns a default property set. Additional fields like `OnPremisesDistinguishedName` or `SignInActivity` must be explicitly requested:
```powershell
Get-MgUser -UserId "user@corp.example.com" -Property Id,DisplayName,UserPrincipalName,SignInActivity
```

---

## 5. Throttling and HTTP 429 Handling

Microsoft Graph enforces per-tenant and per-app request limits. When running high-volume batch operations:
1. Catch `[Microsoft.Graph.PowerShell.Runtime.RestException]` or HTTP 429.
2. Respect the `Retry-After` response header.
```powershell
function Invoke-MgQueryWithRetry {
    param([scriptblock]$ScriptBlock, [int]$MaxRetries = 3)

    $retryCount = 0
    while ($retryCount -lt $MaxRetries) {
        try {
            return & $ScriptBlock
        } catch {
            if ($_.Exception.Message -match "429" -or $_.Exception.Message -match "TooManyRequests") {
                $retryCount++
                $backoffSec = [Math]::Pow(2, $retryCount) * 2
                Start-Sleep -Seconds $backoffSec
            } else {
                throw $_
            }
        }
    }
    throw "Exceeded maximum retry attempts ($MaxRetries) due to rate limiting."
}
```
