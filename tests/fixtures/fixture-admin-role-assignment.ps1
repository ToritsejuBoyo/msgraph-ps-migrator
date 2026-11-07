<#
.SYNOPSIS
    Synthetic Mock Fixture: Directory Role Inspection & Administrator Assignment
.DESCRIPTION
    Audits directory roles and assigns an administrative role using legacy AzureAD and MSOnline.
#>
param(
    [string]$RoleName = "Helpdesk Administrator",
    [string]$AdminUpn = "mock-admin-01@synthetic-test.local"
)

# Connect legacy MSOnline
Connect-MsolService

Write-Output "Auditing Directory Role: $RoleName"
$role = Get-MsolRole | Where-Object { $_.Name -eq $RoleName }

if ($role) {
    Write-Output "Role found: $($role.Name) (RoleId: $($role.ObjectId))"
    $members = Get-MsolRoleMember -RoleObjectId $role.ObjectId
    Write-Output "Current role members count: $($members.Count)"

    if ($members.EmailAddress -notcontains $AdminUpn) {
        Write-Output "Assigning $AdminUpn to $RoleName..."
        Add-MsolRoleMember -RoleObjectId $role.ObjectId -RoleMemberEmailAddress $AdminUpn
    }
}
