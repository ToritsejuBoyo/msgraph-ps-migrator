<#
.SYNOPSIS
    Synthetic Mock Fixture: Service Principal & Application Secret Audit
.DESCRIPTION
    Inspects application registrations and adds client secrets using legacy AzureAD.
#>
param(
    [string]$AppId = "00000000-0000-4000-a000-000000000010"
)

# Connect legacy AzureAD
Connect-AzureAD -TenantId "00000000-0000-4000-a000-000000000001"

Write-Output "Querying Service Principal for App: $AppId"
$sp = Get-AzureADServicePrincipal -Filter "appId eq '$AppId'"

if ($sp) {
    Write-Output "Service Principal found: $($sp.DisplayName) (ObjectId: $($sp.ObjectId))"
    $app = Get-AzureADApplication -Filter "appId eq '$AppId'"
    Write-Output "Adding new client secret credential..."
    $cred = New-AzureADApplicationKeyCredential -ObjectId $app.ObjectId `
                                               -CustomKeyIdentifier "BackupSecret2026" `
                                               -Type "Symmetric" `
                                               -Usage "Verify"
} else {
    Write-Output "Service Principal not found."
}

