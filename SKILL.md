---
name: msgraph-ps-migrator
description: >-
  Migrates legacy AzureAD and MSOnline PowerShell scripts to modern Microsoft.Graph PowerShell SDK
  cmdlets with least-privilege Graph scopes, robust error handling, and auto-pagination. Use when
  modernizing a script that calls Get-MsolUser, Get-AzureADUser or other deprecated
  AzureAD/MSOnline cmdlets, choosing minimum Graph permission scopes, or fixing truncated Graph
  results and OData filter syntax after a migration.
license: MIT
version: 1.0.0
metadata:
  standard: agentskills.io
  dependencies: none (Python standard library only)
  access: read-only collectors; no state is modified on target systems
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

## Step 2: Run the Deterministic Migration Engine (Required First)

Always run the bundled migration engine before hand-translating cmdlets. It performs
the full deprecated-cmdlet inventory, scope mapping, pagination injection, and filter
rewriting deterministically, so the migration is reproducible and complete:

```powershell
# Markdown migration plan (default)
python scripts/migrate-msgraph.py -i .\Audit-Users.ps1

# Structured JSON for programmatic inspection
python scripts/migrate-msgraph.py -i .\Audit-Users.ps1 -f json

# Mask UPNs, tenant GUIDs, client IDs, and secrets (Rule 4)
python scripts/migrate-msgraph.py -i .\Audit-Users.ps1 --sanitize -o .\migration-plan.md
```

Pass `-i -` to read a pasted script from stdin. Use the engine's inventory table as
the authoritative mapping, then apply the analysis workflow below to review scope
choices and business-logic preservation. Consult
[`references/msgraph-sdk-migration-guide.md`](references/msgraph-sdk-migration-guide.md)
for SDK syntax quirks the engine flags but cannot auto-resolve.

---

## Step 3: Diagnostic & Analysis Workflow
1. **Cmdlet Mapping:**
   Identify all deprecated cmdlets and map them to their `Microsoft.Graph` v2 equivalents using `references/legacy-to-msgraph-mapping.md`.
2. **Permission Scope Identification:**
   Determine the exact Microsoft Graph permission scopes required to execute each cmdlet (both Delegated and Application permissions).
3. **Pagination & Query Optimization:**
   Verify if the legacy command expected all records; add `-All` to prevent truncated results.
4. **Output Script Generation:**
   Output the modernized, linted PowerShell script complete with connection helpers (`Connect-MgGraph -Scopes ...`).

---

## Step 4: Output Deliverable Structure
Always structure output using the template in `assets/migration-plan-template.md`:
1. **Migration Inventory Table:** Legacy Cmdlet -> Modern MgGraph Cmdlet -> Required Minimum Scope.
2. **Complete Modernized PowerShell Script:** Full drop-in replacement with error handling and comments.
3. **Pre-Flight Testing Guide:** Commands to safely test modern cmdlets in a non-production tenant or dry-run mode.

---

## Data Handling & Sanitization

Sanitization runs **client-side, before any output is produced**, so credentials and
personal data are removed on the operator's machine rather than being sent to a model
or pasted into a ticket.

Two layers apply:

1. This skill's own domain-aware masking (hostnames, accounts, and the identifiers
   specific to this domain).
2. A shared residual pass, [`scripts/sanitizer.py`](scripts/sanitizer.py), vendored
   identically across every skill in the library. It is the common floor: private keys,
   cloud provider keys, JWTs and bearer tokens, connection-string passwords, assigned
   secrets, emails, IPv4/IPv6 addresses, MAC addresses, GUIDs, SSNs, payment card
   numbers, and phone numbers.

The contract is enforced by `tests/sanitizer_conformance_test.py`, which runs the same
adversarial corpus in every skill. Documentation placeholders (RFC 5737/3849 addresses,
RFC 7042 MAC ranges, `example.com` names, and existing `[REDACTED-*]` tokens) are
preserved, so the pass is safe to apply more than once.

Sanitization is thorough and tested, but it is not a substitute for reading output
before sharing it outside your organization.
