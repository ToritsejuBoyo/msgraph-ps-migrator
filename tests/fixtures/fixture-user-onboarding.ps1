<#
.SYNOPSIS
    Synthetic Mock Fixture: Legacy User Onboarding & Licensing Script
.DESCRIPTION
    Uses legacy MSOnline and AzureAD cmdlets for user provisioning.
#>
param(
    [string]$UserPrincipalName = "mock-user-01@synthetic-test.local",
    [string]$DisplayName = "Synthetic Mock User",
    [string]$Department = "Engineering",
    [string]$UsageLocation = "US",
    [string]$AccountSkuId = "syntheticlab:ENTERPRISEPACK"
)

# Connect to legacy service
Connect-MsolService

# Check if user already exists
$existingUser = Get-MsolUser -UserPrincipalName $UserPrincipalName -ErrorAction SilentlyContinue

if (-not $existingUser) {
    Write-Output "Creating new user account for $UserPrincipalName..."
    New-MsolUser -UserPrincipalName $UserPrincipalName `
                -DisplayName $DisplayName `
                -Department $Department `
                -UsageLocation $UsageLocation `
                -Password "MockP@ssw0rd!12345" `
                -ForceChangePassword $true

    # Assign Enterprise license
    Set-MsolUserLicense -UserPrincipalName $UserPrincipalName -AddLicenses $AccountSkuId
    Write-Output "User created and licensed successfully."
} else {
    Write-Output "User already exists. Updating department."
    Set-MsolUser -UserPrincipalName $UserPrincipalName -Department $Department
}

