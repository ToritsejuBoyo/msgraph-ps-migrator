# Legacy AzureAD & MSOnline to Microsoft Graph PowerShell Mapping Reference

Comprehensive technical mapping reference for migrating deprecated `AzureAD`, `AzureADPreview`, and `MSOnline` (MSOL) cmdlets to the modern `Microsoft.Graph` PowerShell SDK (v2.x).

---

## 1. User Management Cmdlets

| Legacy Cmdlet (AzureAD / MSOnline) | Modern Microsoft.Graph Cmdlet | Required Delegated Scope | Required Application Scope | Key Parameter & Syntax Transformations |
| :--- | :--- | :--- | :--- | :--- |
| `Get-MsolUser` | `Get-MgUser` | `User.Read.All` | `User.Read.All` | Add `-All` to return full tenant list (default page size is 100). Use `-Filter` instead of `-SearchString`. Property `UserPrincipalName` is preserved. |
| `Get-AzureADUser` | `Get-MgUser` | `User.Read.All` | `User.Read.All` | Replace `-ObjectId` with `-UserId`. Add `-All` for unbounded queries. Use `-Property` to project specific fields. |
| `New-MsolUser` | `New-MgUser` | `User.ReadWrite.All` | `User.ReadWrite.All` | Pass `-PasswordProfile @{Password="..."; ForceChangePasswordNextSignIn=$true}`. Account enabled specified via `-AccountEnabled:$true`. |
| `New-AzureADUser` | `New-MgUser` | `User.ReadWrite.All` | `User.ReadWrite.All` | Same password profile hash structure. Set `-MailNickname` and `-DisplayName`. |
| `Set-MsolUser` | `Update-MgUser` | `User.ReadWrite.All` | `User.ReadWrite.All` | Replace `-UserPrincipalName` targeting with `-UserId <UPN/ID>`. Usage location mapped to `-UsageLocation "US"`. |
| `Set-AzureADUser` | `Update-MgUser` | `User.ReadWrite.All` | `User.ReadWrite.All` | Replace `-ObjectId` with `-UserId`. Update properties directly as parameters. |
| `Remove-MsolUser` | `Remove-MgUser` | `User.ReadWrite.All` | `User.ReadWrite.All` | Replace `-UserPrincipalName` with `-UserId`. Soft-deletes user into deleted items. |
| `Remove-AzureADUser` | `Remove-MgUser` | `User.ReadWrite.All` | `User.ReadWrite.All` | Replace `-ObjectId` with `-UserId`. |
| `Restore-MsolUser` | `Restore-MgDirectoryDeletedItem` | `Directory.ReadWrite.All` | `Directory.ReadWrite.All` | Pass `-DirectoryObjectId <ID>` to restore from recycle bin. |
| `Get-MsolUserByManager` | `Get-MgUserManager` | `User.Read.All` | `User.Read.All` | Retrieve manager object reference using `-UserId <UPN/ID>`. |

---

## 2. Licensing & Subscriptions Cmdlets

| Legacy Cmdlet (AzureAD / MSOnline) | Modern Microsoft.Graph Cmdlet | Required Delegated Scope | Required Application Scope | Key Parameter & Syntax Transformations |
| :--- | :--- | :--- | :--- | :--- |
| `Get-MsolAccountSku` | `Get-MgSubscribedSku` | `Organization.Read.All` | `Organization.Read.All` | Add `-All`. Returns tenant SKU identifiers (`SkuPartNumber`, `SkuId`, `ActiveUnits`, `ConsumedUnits`). |
| `Set-MsolUserLicense` | `Set-MgUserLicense` | `User.ReadWrite.All` | `User.ReadWrite.All` | Requires explicit hashtable structure: `-AddLicenses @(@{SkuId="GUID"}) -RemoveLicenses @("GUID")`. Does not take tenant prefix strings like `tenant:ENTERPRISEPACK`. |
| `Get-MsolSubscription` | `Get-MgSubscribedSku` | `Organization.Read.All` | `Organization.Read.All` | Modern Graph models subscriptions through `subscribedSkus` endpoint. |

---

## 3. Group Management Cmdlets

| Legacy Cmdlet (AzureAD / MSOnline) | Modern Microsoft.Graph Cmdlet | Required Delegated Scope | Required Application Scope | Key Parameter & Syntax Transformations |
| :--- | :--- | :--- | :--- | :--- |
| `Get-MsolGroup` | `Get-MgGroup` | `Group.Read.All` | `Group.Read.All` | Add `-All`. Replace `-SearchString` with `-Filter "displayName eq '...'"` or `-Filter "startswith(displayName, '...')"`. |
| `Get-AzureADGroup` | `Get-MgGroup` | `Group.Read.All` | `Group.Read.All` | Replace `-ObjectId` with `-GroupId`. Filtering on dynamic rules requires `-ConsistencyLevel eventual -CountVariable c`. |
| `New-MsolGroup` | `New-MgGroup` | `Group.ReadWrite.All` | `Group.ReadWrite.All` | Specify `-DisplayName`, `-MailNickname`, and `-MailEnabled:$false -SecurityEnabled:$true` for security groups. |
| `New-AzureADGroup` | `New-MgGroup` | `Group.ReadWrite.All` | `Group.ReadWrite.All` | Same property hash structure. Group types specified via `-GroupTypes @("Unified")` for M365 groups. |
| `Set-MsolGroup` | `Update-MgGroup` | `Group.ReadWrite.All` | `Group.ReadWrite.All` | Target `-GroupId <ID>`. Update `-DisplayName` or `-Description`. |
| `Set-AzureADGroup` | `Update-MgGroup` | `Group.ReadWrite.All` | `Group.ReadWrite.All` | Replace `-ObjectId` with `-GroupId`. |
| `Remove-MsolGroup` | `Remove-MgGroup` | `Group.ReadWrite.All` | `Group.ReadWrite.All` | Replace `-ObjectId` with `-GroupId`. |
| `Remove-AzureADGroup` | `Remove-MgGroup` | `Group.ReadWrite.All` | `Group.ReadWrite.All` | Replace `-ObjectId` with `-GroupId`. |
| `Get-MsolGroupMember` | `Get-MgGroupMember` | `GroupMember.Read.All` | `GroupMember.Read.All` | Add `-All`. Returns directory objects; pipe to `Get-MgUser` if user properties are required. |
| `Get-AzureADGroupMember` | `Get-MgGroupMember` | `GroupMember.Read.All` | `GroupMember.Read.All` | Replace `-ObjectId` with `-GroupId`. Add `-All`. |
| `Add-MsolGroupMember` | `New-MgGroupMemberByRef` | `GroupMember.ReadWrite.All` | `GroupMember.ReadWrite.All` | Pass `-GroupId <ID> -DirectoryObjectId <ID>` or `-BodyParameter @{"@odata.id"="https://graph.microsoft.com/v1.0/directoryObjects/<ID>"}`. |
| `Add-AzureADGroupMember` | `New-MgGroupMemberByRef` | `GroupMember.ReadWrite.All` | `GroupMember.ReadWrite.All` | Replace `-ObjectId` with `-GroupId` and `-RefObjectId` with `-DirectoryObjectId`. |
| `Remove-MsolGroupMember` | `Remove-MgGroupMemberDirectoryObjectByRef` | `GroupMember.ReadWrite.All` | `GroupMember.ReadWrite.All` | Specify `-GroupId <ID> -DirectoryObjectId <ID>`. |
| `Remove-AzureADGroupMember` | `Remove-MgGroupMemberDirectoryObjectByRef` | `GroupMember.ReadWrite.All` | `GroupMember.ReadWrite.All` | Replace `-ObjectId` with `-GroupId` and `-MemberId` with `-DirectoryObjectId`. |

---

## 4. Service Principals & Applications

| Legacy Cmdlet (AzureAD / MSOnline) | Modern Microsoft.Graph Cmdlet | Required Delegated Scope | Required Application Scope | Key Parameter & Syntax Transformations |
| :--- | :--- | :--- | :--- | :--- |
| `Get-AzureADServicePrincipal` | `Get-MgServicePrincipal` | `Application.Read.All` | `Application.Read.All` | Replace `-ObjectId` with `-ServicePrincipalId`. Filter by `appId` with `-Filter "appId eq '...'"` |
| `New-AzureADServicePrincipal` | `New-MgServicePrincipal` | `Application.ReadWrite.All` | `Application.ReadWrite.All` | Specify `-AppId <GUID>`. |
| `Remove-AzureADServicePrincipal` | `Remove-MgServicePrincipal` | `Application.ReadWrite.All` | `Application.ReadWrite.All` | Replace `-ObjectId` with `-ServicePrincipalId`. |
| `Get-AzureADApplication` | `Get-MgApplication` | `Application.Read.All` | `Application.Read.All` | Replace `-ObjectId` with `-ApplicationId`. |
| `New-AzureADApplication` | `New-MgApplication` | `Application.ReadWrite.All` | `Application.ReadWrite.All` | Specify `-DisplayName` and identifier URIs. |
| `Set-AzureADApplication` | `Update-MgApplication` | `Application.ReadWrite.All` | `Application.ReadWrite.All` | Replace `-ObjectId` with `-ApplicationId`. |
| `Remove-AzureADApplication` | `Remove-MgApplication` | `Application.ReadWrite.All` | `Application.ReadWrite.All` | Replace `-ObjectId` with `-ApplicationId`. |
| `New-AzureADApplicationKeyCredential` | `Add-MgApplicationPassword` | `Application.ReadWrite.All` | `Application.ReadWrite.All` | Pass `-ApplicationId <ID> -PasswordCredential @{DisplayName="Key"}`. Returns plain-text secret once. |
| `Remove-AzureADApplicationKeyCredential` | `Remove-MgApplicationPassword` | `Application.ReadWrite.All` | `Application.ReadWrite.All` | Pass `-ApplicationId <ID> -KeyId <GUID>`. |

---

## 5. Directory Roles & Administrative Units

| Legacy Cmdlet (AzureAD / MSOnline) | Modern Microsoft.Graph Cmdlet | Required Delegated Scope | Required Application Scope | Key Parameter & Syntax Transformations |
| :--- | :--- | :--- | :--- | :--- |
| `Get-MsolRole` | `Get-MgDirectoryRole` | `RoleManagement.Read.Directory` | `RoleManagement.Read.Directory` | Add `-All`. Note: Roles must be activated in tenant before listing. |
| `Get-AzureADDirectoryRole` | `Get-MgDirectoryRole` | `RoleManagement.Read.Directory` | `RoleManagement.Read.Directory` | Replace `-ObjectId` with `-DirectoryRoleId`. |
| `Get-MsolRoleMember` | `Get-MgDirectoryRoleMember` | `RoleManagement.Read.Directory` | `RoleManagement.Read.Directory` | Target `-DirectoryRoleId <ID>`. Add `-All`. |
| `Get-AzureADDirectoryRoleMember` | `Get-MgDirectoryRoleMember` | `RoleManagement.Read.Directory` | `RoleManagement.Read.Directory` | Replace `-ObjectId` with `-DirectoryRoleId`. |
| `Add-MsolRoleMember` | `New-MgDirectoryRoleMemberByRef` | `RoleManagement.ReadWrite.Directory` | `RoleManagement.ReadWrite.Directory` | Pass `-DirectoryRoleId <ID> -DirectoryObjectId <ID>`. |
| `Add-AzureADDirectoryRoleMember` | `New-MgDirectoryRoleMemberByRef` | `RoleManagement.ReadWrite.Directory` | `RoleManagement.ReadWrite.Directory` | Replace `-ObjectId` with `-DirectoryRoleId` and `-RefObjectId` with `-DirectoryObjectId`. |
| `Remove-AzureADDirectoryRoleMember` | `Remove-MgDirectoryRoleMemberDirectoryObjectByRef` | `RoleManagement.ReadWrite.Directory` | `RoleManagement.ReadWrite.Directory` | Specify role and member directory IDs. |
| `Get-AzureADAdministrativeUnit` | `Get-MgAdministrativeUnit` | `AdministrativeUnit.Read.All` | `AdministrativeUnit.Read.All` | Add `-All`. |

---

## 6. Devices & Organization

| Legacy Cmdlet (AzureAD / MSOnline) | Modern Microsoft.Graph Cmdlet | Required Delegated Scope | Required Application Scope | Key Parameter & Syntax Transformations |
| :--- | :--- | :--- | :--- | :--- |
| `Get-MsolDevice` | `Get-MgDevice` | `Device.Read.All` | `Device.Read.All` | Add `-All`. Properties include `DeviceId`, `DisplayName`, `OperatingSystem`. |
| `Get-AzureADDevice` | `Get-MgDevice` | `Device.Read.All` | `Device.Read.All` | Replace `-ObjectId` with `-DeviceId`. |
| `Set-AzureADDevice` | `Update-MgDevice` | `Device.ReadWrite.All` | `Device.ReadWrite.All` | Disable device via `-AccountEnabled:$false`. |
| `Remove-AzureADDevice` | `Remove-MgDevice` | `Device.ReadWrite.All` | `Device.ReadWrite.All` | Replace `-ObjectId` with `-DeviceId`. |
| `Get-MsolDomain` | `Get-MgDomain` | `Domain.Read.All` | `Domain.Read.All` | Returns verified custom domains. |
| `Get-AzureADDomain` | `Get-MgDomain` | `Domain.Read.All` | `Domain.Read.All` | Same. |
| `Get-MsolCompanyInformation` | `Get-MgOrganization` | `Organization.Read.All` | `Organization.Read.All` | Returns tenant root metadata, display name, verified domains. |
| `Get-AzureADTenantDetail` | `Get-MgOrganization` | `Organization.Read.All` | `Organization.Read.All` | Same. |

---

## 7. Authentication & Connection Helpers

| Legacy Connection Command | Modern Microsoft.Graph SDK Command | Authentication Context |
| :--- | :--- | :--- |
| `Connect-MsolService` | `Connect-MgGraph -Scopes "User.Read.All", "Group.Read.All"` | Interactive Delegated User |
| `Connect-AzureAD` | `Connect-MgGraph -Scopes "User.Read.All", "Group.Read.All"` | Interactive Delegated User |
| `Connect-AzureAD -TenantId $tid -ApplicationId $appId -CertificateThumbprint $thumb` | `Connect-MgGraph -TenantId $tid -ClientId $appId -CertificateThumbprint $thumb` | App-Only Certificate Auth |
| Legacy PSCredential auth | `Connect-MgGraph -Identity` | Azure Managed Identity (Workload Identity) |
