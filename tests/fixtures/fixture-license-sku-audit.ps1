<#
.SYNOPSIS
    Synthetic Mock Fixture: Tenant Licensing & Consumed SKU Audit Report
.DESCRIPTION
    Audits tenant licenses and identifies unassigned or unlicensed users using legacy MSOnline.
#>

# Connect legacy MSOnline
Connect-MsolService

Write-Output "Auditing Tenant Subscribed SKUs..."
$skus = Get-MsolAccountSku

foreach ($sku in $skus) {
    $available = $sku.ActiveUnits - $sku.ConsumedUnits
    Write-Output "SKU: $($sku.AccountSkuId) | Total: $($sku.ActiveUnits) | Consumed: $($sku.ConsumedUnits) | Available: $available"
}

Write-Output "Auditing Unlicensed Accounts..."
$allUsers = Get-MsolUser -All
$unlicensedUsers = $allUsers | Where-Object { $_.IsLicensed -eq $false }

Write-Output "Total users: $($allUsers.Count) | Unlicensed count: $($unlicensedUsers.Count)"
