#======================================================================================#
#                                                                                      #
#                    Intune Policy Pre-Stager / JSON Prefix Renamer                    #
##   This script prepares a clean Working_Import set from Baseline_Policies or        ##
##   Exported_Policies, optionally replacing the leading name prefix in JSON files.   ##
#                                                                                      #
#                 Script Created by Andreas Daneville / ChatGPT                        #
#======================================================================================#

[CmdletBinding()]
param(
    [string]$SourceRootPath,
    [string]$WorkingRootPath,
    [string]$TargetOS,
    [string[]]$SelectedPolicyKeys,
    [string]$CustomerPrefix
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# =========================
# Resolve paths / state
# =========================
if (-not $SourceRootPath) {
    if ($Global:IntuneImportRoot) {
        $SourceRootPath = $Global:IntuneImportRoot
    }
    elseif ($Global:IntuneBaselineRoot) {
        $SourceRootPath = $Global:IntuneBaselineRoot
    }
    elseif ($Global:IntuneToolRoot) {
        $SourceRootPath = Join-Path $Global:IntuneToolRoot 'Baseline_Policies'
    }
    else {
        $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
        $SourceRootPath = Join-Path (Split-Path -Parent $scriptDir) 'Baseline_Policies'
    }
}

if (-not $WorkingRootPath) {
    if ($Global:IntuneWorkingImportRoot) {
        $WorkingRootPath = $Global:IntuneWorkingImportRoot
    }
    elseif ($Global:IntuneToolRoot) {
        $WorkingRootPath = Join-Path $Global:IntuneToolRoot 'Working_Import'
    }
    else {
        $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
        $WorkingRootPath = Join-Path (Split-Path -Parent $scriptDir) 'Working_Import'
    }
}

if (-not $TargetOS) {
    if ($Global:IntuneTargetOS) {
        $TargetOS = $Global:IntuneTargetOS
    }
    else {
        $TargetOS = 'Windows'
    }
}

if (-not $SelectedPolicyKeys -or $SelectedPolicyKeys.Count -eq 0) {
    if ($Global:IntuneSelectedPolicyKeys -and $Global:IntuneSelectedPolicyKeys.Count -gt 0) {
        $SelectedPolicyKeys = @($Global:IntuneSelectedPolicyKeys)
    }
    else {
        throw 'No selected policy keys were supplied to the pre-stager.'
    }
}

if (-not $PSBoundParameters.ContainsKey('CustomerPrefix')) {
    $CustomerPrefix = $Global:IntuneCustomerPrefix
}

Write-Host "Source root path resolved to: $SourceRootPath" -ForegroundColor DarkCyan
Write-Host "Working import path resolved to: $WorkingRootPath" -ForegroundColor DarkCyan
Write-Host "Target OS resolved to: $TargetOS" -ForegroundColor DarkCyan
if ([string]::IsNullOrWhiteSpace($CustomerPrefix)) {
    Write-Host 'Customer prefix: <none> (files will be copied without prefix replacement)' -ForegroundColor DarkYellow
}
else {
    Write-Host "Customer prefix resolved to: $CustomerPrefix" -ForegroundColor DarkCyan
}

if (-not (Test-Path -LiteralPath $SourceRootPath)) {
    throw "Source root path does not exist: $SourceRootPath"
}

# =========================
# Folder map (must match exporter/importer)
# =========================
$FolderMap = @{
    SecurityBaselines   = '1. Security Baselines'
    Antivirus           = '2. Antivirus'
    DiskEncryption      = '3. Disk Encryption'
    Firewall            = '4. Firewall'
    EPM                 = '5. Endpoint Privilege Management'
    EDR                 = '6. Endpoint Detection and Response'
    AppControl          = '7. App Control for Business'
    ASR                 = '8. Attack surface reduction'
    AccountProtection   = '9. Account protection'
    DeviceCompliance    = '10. Device Compliance'
    ConditionalAccess   = '11. Conditional Access'
    Uncategorized       = '99. Uncategorized'
}

$UncategorizedSubfolders = @{
    ConfigPolicies       = 'ConfigurationPolicies'
    DeviceConfigurations = 'DeviceConfigurations'
}

$SelectionKeyMap = @{
    'EndpointSecurity-Baselines'         = @{ Type = 'OS'; RelativePath = $FolderMap.SecurityBaselines }
    'EndpointSecurity-Antivirus'         = @{ Type = 'OS'; RelativePath = $FolderMap.Antivirus }
    'EndpointSecurity-DiskEncryption'    = @{ Type = 'OS'; RelativePath = $FolderMap.DiskEncryption }
    'EndpointSecurity-Firewall'          = @{ Type = 'OS'; RelativePath = $FolderMap.Firewall }
    'EndpointSecurity-EPM'               = @{ Type = 'OS'; RelativePath = $FolderMap.EPM }
    'EndpointSecurity-EDR'               = @{ Type = 'OS'; RelativePath = $FolderMap.EDR }
    'EndpointSecurity-AppControl'        = @{ Type = 'OS'; RelativePath = $FolderMap.AppControl }
    'EndpointSecurity-ASR'               = @{ Type = 'OS'; RelativePath = $FolderMap.ASR }
    'EndpointSecurity-AccountProtection' = @{ Type = 'OS'; RelativePath = $FolderMap.AccountProtection }
    'DeviceCompliance'                   = @{ Type = 'OS'; RelativePath = $FolderMap.DeviceCompliance }
    'Uncategorized'                      = @(
        @{ Type = 'OS'; RelativePath = (Join-Path $FolderMap.Uncategorized $UncategorizedSubfolders.ConfigPolicies) }
        @{ Type = 'OS'; RelativePath = (Join-Path $FolderMap.Uncategorized $UncategorizedSubfolders.DeviceConfigurations) }
    )
    'ConditionalAccess'                  = @{ Type = 'CA'; RelativePath = (Join-Path 'Conditional_Access' $FolderMap.ConditionalAccess) }
}

# =========================
# Helpers
# =========================
function New-CleanDirectory {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Recurse -Force
    }
    $null = New-Item -Path $Path -ItemType Directory -Force
}

function Initialize-WorkingImportStructure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RootPath,
        [Parameter(Mandatory)][string]$OSName
    )

    New-CleanDirectory -Path $RootPath

    $osRoot = Join-Path $RootPath $OSName
    $null = New-Item -Path $osRoot -ItemType Directory -Force

    foreach ($folderName in @(
        $FolderMap.SecurityBaselines,
        $FolderMap.Antivirus,
        $FolderMap.DiskEncryption,
        $FolderMap.Firewall,
        $FolderMap.EPM,
        $FolderMap.EDR,
        $FolderMap.AppControl,
        $FolderMap.ASR,
        $FolderMap.AccountProtection,
        $FolderMap.DeviceCompliance,
        $FolderMap.Uncategorized
    )) {
        $null = New-Item -Path (Join-Path $osRoot $folderName) -ItemType Directory -Force
    }

    foreach ($sub in $UncategorizedSubfolders.Values) {
        $null = New-Item -Path (Join-Path (Join-Path $osRoot $FolderMap.Uncategorized) $sub) -ItemType Directory -Force
    }

    $caRoot = Join-Path $RootPath 'Conditional_Access'
    $null = New-Item -Path $caRoot -ItemType Directory -Force
    $null = New-Item -Path (Join-Path $caRoot $FolderMap.ConditionalAccess) -ItemType Directory -Force
}

function Get-BasePolicyTitle {
    [CmdletBinding()]
    param([AllowNull()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }

    $split = $Value -split ' - ', 2
    if ($split.Count -eq 2) {
        return $split[1].Trim()
    }

    return $Value.Trim()
}

function Get-RenamedPolicyValue {
    [CmdletBinding()]
    param(
        [AllowNull()][string]$Value,
        [AllowNull()][string]$Prefix
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    if ([string]::IsNullOrWhiteSpace($Prefix)) { return $Value.Trim() }

    $baseTitle = Get-BasePolicyTitle -Value $Value
    return ('{0} - {1}' -f $Prefix.Trim(), $baseTitle)
}

function Update-JsonNameFields {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SourceFile,
        [Parameter(Mandatory)][string]$DestinationFile,
        [AllowNull()][string]$Prefix
    )

    $raw = Get-Content -LiteralPath $SourceFile -Raw -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw "Source JSON file is empty: $SourceFile"
    }

    $obj = $raw | ConvertFrom-Json

    if ($obj.PSObject.Properties.Name -contains 'displayName') {
        $obj.displayName = Get-RenamedPolicyValue -Value $obj.displayName -Prefix $Prefix
    }
    if ($obj.PSObject.Properties.Name -contains 'name') {
        $obj.name = Get-RenamedPolicyValue -Value $obj.name -Prefix $Prefix
    }

    $json = $obj | ConvertTo-Json -Depth 100
    [System.IO.File]::WriteAllText($DestinationFile, $json, [System.Text.UTF8Encoding]::new($false))
}

function Copy-StagedFolderContent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SourceFolder,
        [Parameter(Mandatory)][string]$DestinationFolder,
        [AllowNull()][string]$Prefix,
        [Parameter()][bool]$RenameJsonNames = $true
    )

    if (-not (Test-Path -LiteralPath $SourceFolder)) {
        Write-Host "Source folder not found, skipping: $SourceFolder" -ForegroundColor DarkYellow
        return [pscustomobject]@{ Copied = 0; Skipped = 1 }
    }

    $null = New-Item -Path $DestinationFolder -ItemType Directory -Force

    $copied = 0
    $skipped = 0

    $files = Get-ChildItem -LiteralPath $SourceFolder -File -Recurse
    foreach ($file in $files) {
        $relative = $file.FullName.Substring($SourceFolder.Length).TrimStart([char]'\',[char]'/')
        $targetFile = Join-Path $DestinationFolder $relative
        $targetDir = Split-Path -Parent $targetFile

        if (-not (Test-Path -LiteralPath $targetDir)) {
            $null = New-Item -Path $targetDir -ItemType Directory -Force
        }

        if ($file.Extension -ieq '.json' -and $RenameJsonNames) {
            Update-JsonNameFields -SourceFile $file.FullName -DestinationFile $targetFile -Prefix $Prefix
        }
        else {
            Copy-Item -LiteralPath $file.FullName -Destination $targetFile -Force
        }

        $copied++
    }

    return [pscustomobject]@{ Copied = $copied; Skipped = $skipped }
}


# =========================
# Build fresh Working_Import
# =========================
Initialize-WorkingImportStructure -RootPath $WorkingRootPath -OSName $TargetOS

$totalCopied  = 0
$totalSkipped = 0
$processedMappings = New-Object System.Collections.Generic.HashSet[string]

foreach ($selectionKey in $SelectedPolicyKeys) {
    if (-not $SelectionKeyMap.ContainsKey($selectionKey)) {
        Write-Host "Unknown selection key '$selectionKey' - skipping." -ForegroundColor Yellow
        $totalSkipped++
        continue
    }

    $mappings = @($SelectionKeyMap[$selectionKey])
    foreach ($mapping in $mappings) {
        $mappingKey = '{0}|{1}' -f $mapping.Type, $mapping.RelativePath
        if (-not $processedMappings.Add($mappingKey)) {
            continue
        }

        switch ($mapping.Type) {
            'OS' {
                $sourceFolder = Join-Path (Join-Path $SourceRootPath $TargetOS) $mapping.RelativePath
                $destFolder   = Join-Path (Join-Path $WorkingRootPath $TargetOS) $mapping.RelativePath
            }
            'CA' {
                $sourceFolder = Join-Path $SourceRootPath $mapping.RelativePath
                $destFolder   = Join-Path $WorkingRootPath $mapping.RelativePath
            }
            default {
                Write-Host "Unknown mapping type '$($mapping.Type)' for '$selectionKey' - skipping." -ForegroundColor Yellow
                $totalSkipped++
                continue
            }
        }

        $renameJsonNames = ($mapping.Type -ne 'CA')
        $modeText = if ($renameJsonNames) { 'copy + rename' } else { 'copy only' }

        Write-Host "Staging '$selectionKey' from '$sourceFolder' to '$destFolder' ($modeText)" -ForegroundColor Cyan

        if (Test-Path -LiteralPath $sourceFolder) {
            $foundFiles = @(Get-ChildItem -LiteralPath $sourceFolder -File -Recurse -ErrorAction SilentlyContinue).Count
            Write-Host "Files found in source: $foundFiles" -ForegroundColor DarkGray
        }
        else {
            Write-Host "Source folder does not exist." -ForegroundColor Yellow
        }

        $result = Copy-StagedFolderContent -SourceFolder $sourceFolder -DestinationFolder $destFolder -Prefix $CustomerPrefix -RenameJsonNames:$renameJsonNames
        $totalCopied  += $result.Copied
        $totalSkipped += $result.Skipped
    }
}

# Point importer at the staged root
$Global:IntuneImportRoot = $WorkingRootPath

Write-Host ''
Write-Host 'Working_Import preparation complete.' -ForegroundColor Green
Write-Host "Files staged: $totalCopied" -ForegroundColor Green
Write-Host "Folders skipped/missing: $totalSkipped" -ForegroundColor DarkYellow
Write-Host "Importer root now set to: $($Global:IntuneImportRoot)" -ForegroundColor DarkCyan
