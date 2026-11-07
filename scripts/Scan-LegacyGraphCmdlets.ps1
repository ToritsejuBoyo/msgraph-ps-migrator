<#
.SYNOPSIS
    Scans PowerShell scripts for deprecated AzureAD and MSOnline cmdlets using AST.
.DESCRIPTION
    Parses .ps1 and .psm1 files using PowerShell Abstract Syntax Tree (AST), identifies
    legacy AzureAD/MSOnline cmdlets, and outputs an inventory JSON.
.PARAMETER ScriptPath
    Path to the script or directory to inspect.
.EXAMPLE
    .\Scan-LegacyGraphCmdlets.ps1 -ScriptPath .\my-scripts\
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ScriptPath,
    [string]$OutputPath = ".\legacy-cmdlet-inventory.json"
)

$LegacyCmdletPrefixes = @('*-Msol*', '*-AzureAD*', '*-AzureADMS*')
$FilesToScan = @()

if (Test-Path -Path $ScriptPath -PathType Container) {
    $FilesToScan = Get-ChildItem -Path $ScriptPath -Include *.ps1,*.psm1 -Recurse
} else {
    $FilesToScan = Get-Item -Path $ScriptPath
}

$Findings = @()

foreach ($file in $FilesToScan) {
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)

    $commandAsts = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)

    foreach ($cmd in $commandAsts) {
        $cmdName = $cmd.GetCommandName()
        if ($cmdName) {
            foreach ($prefix in $LegacyCmdletPrefixes) {
                if ($cmdName -like $prefix) {
                    $Findings += [PSCustomObject]@{
                        File       = $file.Name
                        FullPath   = $file.FullName
                        LineNumber = $cmd.Extent.StartLineNumber
                        Cmdlet     = $cmdName
                        RawCommand = $cmd.Extent.Text
                    }
                    break
                }
            }
        }
    }
}

$Summary = [PSCustomObject]@{
    TotalLegacyCalls = $Findings.Count
    UniqueCmdlets    = ($Findings | Select-Object -ExpandProperty Cmdlet -Unique)
    Findings         = $Findings
}

$Summary | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputPath -Encoding utf8
Write-Host "Found $($Findings.Count) legacy cmdlet references across $($FilesToScan.Count) files. Saved to $OutputPath" -ForegroundColor Green
