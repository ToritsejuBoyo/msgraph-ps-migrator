<#
.SYNOPSIS
    Synthetic Mock Fixture: Legacy Group Lifecycle & Membership Sync
.DESCRIPTION
    Uses legacy AzureAD module cmdlets for group creation and membership sync.
#>
param(
    [string]$GroupName = "SG-Synthetic-Engineering-Team",
    [string]$MemberUpn = "mock-user-02@synthetic-test.local"
)

# Authenticate via legacy AzureAD
Connect-AzureAD

# Query target security group
$group = Get-AzureADGroup -SearchString $GroupName | Where-Object { $_.DisplayName -eq $GroupName }

if (-not $group) {
    Write-Output "Group $GroupName not found. Provisioning new security group..."
    $group = New-AzureADGroup -DisplayName $GroupName `
                              -MailEnabled $false `
                              -SecurityEnabled $true `
                              -MailNickName "syn-eng-team"
}

# Resolve target user
$user = Get-AzureADUser -ObjectId $MemberUpn

# Retrieve existing group members
$members = Get-AzureADGroupMember -ObjectId $group.ObjectId

if ($members.ObjectId -notcontains $user.ObjectId) {
    Write-Output "Adding $MemberUpn to $GroupName..."
    Add-AzureADGroupMember -ObjectId $group.ObjectId -RefObjectId $user.ObjectId
} else {
    Write-Output "$MemberUpn is already a member of $GroupName."
}

