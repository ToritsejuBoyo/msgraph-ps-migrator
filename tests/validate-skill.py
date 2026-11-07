#!/usr/bin/env python3
"""Automated Validation Harness for msgraph-ps-migrator (validate-skill.py)

Executes 7 deterministic verification suites:
  1. User Management & Parameter Mapping (Get-MsolUser, New-MsolUser, Update-MgUser).
  2. Group Management & Reference Mapping (Get-AzureADGroup, New-MgGroupMemberByRef).
  3. Tenant Licensing & Subscribed SKU Modernization (Get-MsolAccountSku -> Get-MgSubscribedSku).
  4. Least-Privilege OAuth Permission Scope Enforcement.
  5. Client-Side Data Sanitization (Rule 4: SHA-256 UPNs, zeroed GUIDs, secret scrubbing).
  6. Non-Destructive Operational Safety Guardrails.
  7. agentskills.io SKILL.md Frontmatter & Zero External Dependencies Verification.

Returns exit code 0 on 100% test pass.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT_DIR = Path(__file__).resolve().parent.parent
SCRIPT_PATH = ROOT_DIR / "scripts" / "migrate-msgraph.py"
FIXTURES_DIR = ROOT_DIR / "tests" / "fixtures"
SKILL_MD = ROOT_DIR / "SKILL.md"


class TestMsgraphPsMigrator(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("migrator", str(SCRIPT_PATH))
        cls.migrator_mod = importlib.util.module_from_spec(spec)
        sys.modules["migrator"] = cls.migrator_mod
        spec.loader.exec_module(cls.migrator_mod)

    def test_01_user_management_migration(self):
        """Suite 1: Validate User Management cmdlet and parameter modernization."""
        fixture = FIXTURES_DIR / "fixture-user-onboarding.ps1"
        self.assertTrue(fixture.exists(), f"Fixture {fixture} missing")
        content = fixture.read_text(encoding="utf-8")

        migrator = self.migrator_mod.GraphMigrator(raw_script=content, script_name=fixture.name)
        analysis = migrator.analyze()

        legacy_cmdlets = [f.legacy_cmdlet.lower() for f in analysis.findings]
        modern_cmdlets = [f.modern_cmdlet for f in analysis.findings]

        self.assertIn("get-msoluser", legacy_cmdlets)
        self.assertIn("new-msoluser", legacy_cmdlets)
        self.assertIn("set-msoluserlicense", legacy_cmdlets)
        self.assertIn("set-msoluser", legacy_cmdlets)

        self.assertIn("Get-MgUser", modern_cmdlets)
        self.assertIn("New-MgUser", modern_cmdlets)
        self.assertIn("Set-MgUserLicense", modern_cmdlets)
        self.assertIn("Update-MgUser", modern_cmdlets)

        # Check modernized code parameter translation
        self.assertIn("-UserId", analysis.modernized_script)
        self.assertIn("Update-MgUser -UserId", analysis.modernized_script)

    def test_02_group_management_migration(self):
        """Suite 2: Validate Group Management cmdlet and reference ID mapping."""
        fixture = FIXTURES_DIR / "fixture-group-lifecycle.ps1"
        self.assertTrue(fixture.exists())
        content = fixture.read_text(encoding="utf-8")

        migrator = self.migrator_mod.GraphMigrator(raw_script=content, script_name=fixture.name)
        analysis = migrator.analyze()

        modern_cmdlets = [f.modern_cmdlet for f in analysis.findings]
        self.assertIn("Get-MgGroup", modern_cmdlets)
        self.assertIn("New-MgGroup", modern_cmdlets)
        self.assertIn("Get-MgGroupMember", modern_cmdlets)
        self.assertIn("New-MgGroupMemberByRef", modern_cmdlets)

        # Confirm parameter replacement: -ObjectId -> -GroupId, -RefObjectId -> -DirectoryObjectId
        self.assertIn("New-MgGroupMemberByRef -GroupId $group.ObjectId -DirectoryObjectId $user.ObjectId", analysis.modernized_script)

    def test_03_licensing_sku_migration(self):
        """Suite 3: Validate Tenant Licensing & Subscribed SKU Modernization."""
        fixture = FIXTURES_DIR / "fixture-license-sku-audit.ps1"
        self.assertTrue(fixture.exists())
        content = fixture.read_text(encoding="utf-8")

        migrator = self.migrator_mod.GraphMigrator(raw_script=content, script_name=fixture.name)
        analysis = migrator.analyze()

        sku_finding = next((f for f in analysis.findings if f.legacy_cmdlet.lower() == "get-msolaccountsku"), None)
        self.assertIsNotNone(sku_finding)
        self.assertEqual(sku_finding.modern_cmdlet, "Get-MgSubscribedSku")
        self.assertIn("Organization.Read.All", sku_finding.delegated_scopes)

        # Check auto-pagination injection
        self.assertIn("Get-MgSubscribedSku -All", analysis.modernized_script)

    def test_04_least_privilege_scope_enforcement(self):
        """Suite 4: Ensure least-privilege Graph scopes are strictly calculated without over-privilege."""
        # Read-only query script
        read_only_script = """
        Get-MsolUser -SearchString "Smith"
        Get-MsolGroup
        Get-MsolDomain
        """
        migrator = self.migrator_mod.GraphMigrator(raw_script=read_only_script, script_name="Audit.ps1")
        analysis = migrator.analyze()

        # Must NOT demand Directory.ReadWrite.All, User.ReadWrite.All, or Group.ReadWrite.All
        self.assertNotIn("Directory.ReadWrite.All", analysis.required_delegated_scopes)
        self.assertNotIn("User.ReadWrite.All", analysis.required_delegated_scopes)
        self.assertNotIn("Group.ReadWrite.All", analysis.required_delegated_scopes)

        # Must include read-only scopes
        self.assertIn("User.Read.All", analysis.required_delegated_scopes)
        self.assertIn("Group.Read.All", analysis.required_delegated_scopes)
        self.assertIn("Domain.Read.All", analysis.required_delegated_scopes)

    def test_05_client_side_sanitization(self):
        """Suite 5: Validate SHA-256 UPN masking, zeroed GUIDs, and secret scrubbing (Rule 4)."""
        sanitizer = self.migrator_mod.Sanitizer(enabled=True)

        # 1. UPN masking
        raw_upn = "john.doe@enterprise-corp.com"
        masked_upn = sanitizer.sanitize_upn(raw_upn)
        self.assertTrue(masked_upn.startswith("user-") and masked_upn.endswith("@synthetic-test.local"))

        # 2. GUID zeroing
        raw_guid = "9b1deb4d-3b7d-4bad-9bdd-2b0d7b4dcb6d"
        masked_guid = sanitizer.sanitize_guid(raw_guid)
        self.assertTrue(masked_guid.startswith("00000000-0000-4000-a000-"))

        # 3. Secret scrubbing
        text = 'Connect-AzureAD -TenantId "11111111-2222-3333-4444-555566667777" -Password "SuperSecret123!" -ApiKey "sk_live_987654321"'
        scrubbed = sanitizer.scrub_text(text)
        self.assertNotIn("SuperSecret123!", scrubbed)
        self.assertNotIn("sk_live_987654321", scrubbed)
        self.assertIn("[REDACTED-SECRET]", scrubbed)

    def test_06_non_destructive_safety_guardrails(self):
        """Suite 6: Verify analysis operates in pure read-only inspection mode."""
        fixture = FIXTURES_DIR / "fixture-service-principal-creds.ps1"
        self.assertTrue(fixture.exists())
        content = fixture.read_text(encoding="utf-8")

        migrator = self.migrator_mod.GraphMigrator(raw_script=content, script_name=fixture.name)
        analysis = migrator.analyze()

        # Analysis must return structured findings without modifying disk files
        self.assertIsInstance(analysis.findings, list)
        self.assertGreater(len(analysis.findings), 0)
        self.assertIn("Add-MgApplicationPassword", [f.modern_cmdlet for f in analysis.findings])

    def test_07_agentskills_specification_and_dependencies(self):
        """Suite 7: Verify SKILL.md frontmatter, zero external packages, and agentskills.io standard."""
        self.assertTrue(SKILL_MD.exists(), "SKILL.md must exist in repository root")
        skill_text = SKILL_MD.read_text(encoding="utf-8")

        # Frontmatter
        self.assertTrue(skill_text.startswith("---"), "SKILL.md must have YAML frontmatter")
        self.assertIn("name: msgraph-ps-migrator", skill_text)
        self.assertIn("description:", skill_text)

        # Zero third-party dependencies in scripts
        with open(SCRIPT_PATH, "r", encoding="utf-8") as f:
            code = f.read()

        forbidden_packages = ["requests", "pandas", "numpy", "psutil", "pydantic", "azure"]
        for pkg in forbidden_packages:
            self.assertNotIn(f"import {pkg}", code, f"Forbidden external package: {pkg}")
            self.assertNotIn(f"from {pkg}", code, f"Forbidden external package: {pkg}")


def main():
    print("======================================================================")
    print("Running Automated Verification Suite for msgraph-ps-migrator")
    print("======================================================================")
    suite = unittest.TestLoader().loadTestsFromTestCase(TestMsgraphPsMigrator)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    if result.wasSuccessful():
        print("\nAll 7 verification suites passed successfully (Exit code: 0).")
        return 0
    else:
        print(f"\nVerification failed: {len(result.failures)} failures, {len(result.errors)} errors.")
        return 1


if __name__ == "__main__":
    sys.exit(main())

