---
name: msgraph-ps-migrator
description: Migrates legacy AzureAD and MSOnline PowerShell scripts to modern Microsoft.Graph PowerShell SDK cmdlets with least-privilege Graph scopes, robust error handling, and auto-pagination.
---

# Legacy AzureAD to Microsoft Graph SDK Migrator (`msgraph-ps-migrator`)

## Purpose & Target Roles
Designed for **PowerShell Automation Engineers, M365 Administrators, and Systems Administrators**. With Microsoft fully deprecating the legacy `AzureAD` and `MSOnline` modules, organizations must modernize scripts. This skill converts legacy cmdlets, handles complex Graph SDK syntax quirks, specifies least-privilege scopes, and resolves pagination and filter limitations.

## Operating Rules & Safety Guardrails
1. **Least-Privilege Scopes:** NEVER suggest `Directory.ReadWrite.All` or `Global Administrator` permissions if read-only scopes (e.g., `User.Read.All`, `Group.Read.All`) suffice.
2. **Handling Auto-Pagination:** Microsoft Graph cmdlets default to returning only the first 100 to 999 records. Always inject `-All` or proper pagination loops when migrating queries.
3. **Filter Syntax Differences:** Translate legacy client-side or OData filter syntax into Microsoft Graph advanced query parameters (e.g., `-ConsistencyLevel eventual`, `-CountVariable`, `$filter=startswith(...)`).
4. **Preserve Business Logic:** Modernize the cmdlet invocation while preserving all upstream parameters, error-logging logic, and export formats.

---

## Step 1: Telemetry & Input Acquisition
- **Mode A – Static AST Scan from `scripts/Scan-LegacyGraphCmdlets.ps1` (Recommended):**
  Run the bundled static analysis script over the script or folder:
  ```powershell
  powershell.exe -ExecutionPolicy Bypass -File .\scripts\Scan-LegacyGraphCmdlets.ps1 -ScriptPath .\Audit-Users.ps1
  ```
- **Mode B – Pasted PowerShell Script:**
  The engineer pastes the legacy script content containing `Get-MsolUser`, `Get-AzureADUser`, `Set-MsolUserLicense`, etc.

---

## Step 2: Diagnostic & Analysis Workflow
1. **Cmdlet Mapping:**
   Identify all deprecated cmdlets and map them to their `Microsoft.Graph` v2 equivalents using `references/legacy-to-msgraph-mapping.md`.
2. **Permission Scope Identification:**
   Determine the exact Microsoft Graph permission scopes required to execute each cmdlet (both Delegated and Application permissions).
3. **Pagination & Query Optimization:**
   Verify if the legacy command expected all records; add `-All` to prevent truncated results.
4. **Output Script Generation:**
   Output the modernized, linted PowerShell script complete with connection helpers (`Connect-MgGraph -Scopes ...`).

---

## Step 3: Output Deliverable Structure
Always structure output using the template in `assets/migration-plan-template.md`:
1. **Migration Inventory Table:** Legacy Cmdlet -> Modern MgGraph Cmdlet -> Required Minimum Scope.
2. **Complete Modernized PowerShell Script:** Full drop-in replacement with error handling and comments.
3. **Pre-Flight Testing Guide:** Commands to safely test modern cmdlets in a non-production tenant or dry-run mode.
