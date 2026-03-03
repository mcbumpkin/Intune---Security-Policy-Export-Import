#======================================================================================#
#                                                                                      #
#                         Intune Endpoint Security Exporter                            #
## This script exports targeted Intune security policies + catch-all config profiles   ##
#                                                                                      #
#                 Script Created by Andreas Daneville 03-03-2026                       #
#======================================================================================#

[CmdletBinding()]
param(
    # If not provided, we'll resolve this based on globals or script location.
    [string]$ExportRootPath,
    [switch]$UseDeviceCode
)

# =========================
# Resolve ExportRootPath
# =========================
# NEW ROOT: Intune_Policy (instead of Export)
if (-not $ExportRootPath) {
    if ($Global:IntuneToolRoot) {
        # Preferred: tool root from BootStrapper
        $ExportRootPath = Join-Path $Global:IntuneToolRoot 'Intune_Policy'
    }
    else {
        # Final fallback: local script-based resolution
        $scriptPath = $MyInvocation.MyCommand.Path

        if ($scriptPath) {
            $scriptDir      = Split-Path -Parent $scriptPath
            # Scripts\MSGraph-Export.ps1 -> tool root = parent of Scripts
            $ExportRootPath = Join-Path (Split-Path -Parent $scriptDir) 'Intune_Policy'
        }
        else {
            $ExportRootPath = Join-Path (Get-Location).Path 'Intune_Policy'
        }
    }
}

# =========================
# Config: Folders & Scopes
# =========================

# Folder names (your 1–11 + 99 structure)
# NOTE: 11 is exported under Conditional_Access (separate branch)
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
    Other               = '99. Uncategorized'
}

# Subfolders under 99 to keep it readable
$UncategorizedSubfolders = @{
    ConfigPolicies       = 'ConfigurationPolicies'
    DeviceConfigurations = 'DeviceConfigurations'
}

# All possible selection keys (must match BootStrapper GUI)
$AllSelectionKeys = @(
    'EndpointSecurity-Baselines',
    'EndpointSecurity-Antivirus',
    'EndpointSecurity-DiskEncryption',
    'EndpointSecurity-Firewall',
    'EndpointSecurity-EPM',
    'EndpointSecurity-EDR',
    'EndpointSecurity-AppControl',
    'EndpointSecurity-ASR',
    'EndpointSecurity-AccountProtection',
    'DeviceCompliance',
    'ConditionalAccess',
    'Uncategorized'
)

# Graph scopes
$RequiredScopes = @(
    'DeviceManagementConfiguration.Read.All'
    'Policy.Read.All'
)

# API version (Endpoint security is still mostly in /beta)
$GraphApiVersion = 'beta'

# Exclude onboarding packages (tenant-unique)
$OnboardingNameExcludePatterns = @(
    '*onboarding*',
    '*deploy onboarding*',
    '*defender onboarding*',
    '*mdatp onboarding*'
)

# Exclude Windows Autopatch (tenant-managed / not wanted for export/import baselines)
$AutopatchNameExcludePatterns = @(
    '*windows autopatch*',
    '*autopatch*'
)

function Test-NameMatchesExcludePattern {
    [CmdletBinding()]
    param(
        [string]$DisplayName,
        [string[]]$Patterns
    )

    if (-not $DisplayName) { return $false }
    foreach ($p in $Patterns) {
        if ($DisplayName -like $p) { return $true }
    }
    return $false
}

function Test-ShouldExcludePolicyByName {
    [CmdletBinding()]
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }

    if (Test-NameMatchesExcludePattern -DisplayName $Name -Patterns $OnboardingNameExcludePatterns) { return $true }
    if (Test-NameMatchesExcludePattern -DisplayName $Name -Patterns $AutopatchNameExcludePatterns) { return $true }

    return $false
}

# =========================
# Common helpers
# =========================

function Ensure-GraphModule {
    [CmdletBinding()]
    param()

    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        Write-Host "Microsoft.Graph module not found. Installing..." -ForegroundColor Yellow
        try {
            Install-Module Microsoft.Graph -Scope AllUsers -Force -ErrorAction Stop
            Write-Host "Microsoft.Graph installed." -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to install Microsoft.Graph module: $($_.Exception.Message)"
            throw
        }
    }
}

function Connect-IntuneGraph {
    <#
    .SYNOPSIS
    Connects to Microsoft Graph with the required scopes.
    Always forces a fresh login (no reuse of previous tenant/session).
    #>
    [CmdletBinding()]
    param(
        [string[]]$Scopes = $RequiredScopes,
        [switch]$UseDeviceCode
    )

    Ensure-GraphModule
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }

    try {
        if ($UseDeviceCode) {
            Connect-MgGraph -Scopes $Scopes -UseDeviceCode -ContextScope Process -NoWelcome | Out-Null
        }
        else {
            Connect-MgGraph -Scopes $Scopes -ContextScope Process -NoWelcome | Out-Null
        }
    }
    catch {
        Write-Error "Connect-MgGraph threw a terminating error: $($_.Exception.Message)"
        throw
    }

    $ctx = Get-MgContext
    if (-not $ctx) {
        throw "Failed to obtain Microsoft Graph context after Connect-MgGraph."
    }

    Write-Host "Connected to Microsoft Graph as $($ctx.Account) (Tenant: $($ctx.TenantId))" -ForegroundColor Cyan
}

function Invoke-GraphGet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RelativeUri
    )

    $uri = "/$GraphApiVersion/$RelativeUri"
    Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
}

function Invoke-GraphGetAllPages {
    <#
    .SYNOPSIS
    Retrieves all pages for a Graph collection endpoint and returns a flat array of items.
    Supports @odata.nextLink.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RelativeUri
    )

    $items = New-Object System.Collections.Generic.List[object]

    $next = "/$GraphApiVersion/$RelativeUri"

    while ($next) {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $next -ErrorAction Stop

        if ($resp -and $resp.value) {
            foreach ($v in $resp.value) { [void]$items.Add($v) }
        }

        $nextLink = $null
        if ($resp -and $resp.PSObject.Properties.Name -contains '@odata.nextLink') {
            $nextLink = $resp.'@odata.nextLink'
        }

        if ([string]::IsNullOrWhiteSpace($nextLink)) {
            $next = $null
        }
        else {
            # nextLink is usually an absolute URL; MgGraphRequest accepts it.
            $next = $nextLink
        }
    }

    return $items.ToArray()
}

function Export-JsonData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Json,
        [Parameter(Mandatory)][string]$ExportPath
    )

    if (-not (Test-Path -LiteralPath $ExportPath)) {
        New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
    }

    # Depth bump to avoid truncating nested settings objects
    $jsonString = $Json | ConvertTo-Json -Depth 50
    $converted  = $jsonString | ConvertFrom-Json

    $displayName = $converted.displayName
    if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = $converted.name }
    if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = 'UnnamedPolicy' }

    $displayName = $displayName -replace '\<|\>|:|"|/|\\|\||\?|\*', '_'

    $fileName = '{0}_{1}.json' -f $displayName, (Get-Date -Format 'yyyy-MM-dd-HH-mm-ss-fff')
    $fullPath = Join-Path $ExportPath $fileName

    $jsonString | Set-Content -LiteralPath $fullPath -Encoding UTF8

    Write-Host "Exported: $fullPath" -ForegroundColor Green
}

# =========================
# OS scoping helper
# =========================

function Get-TargetOS {
    [CmdletBinding()]
    param()

    # Expected values from BootStrapper: 'Windows' or 'macOS'
    if ($Global:IntuneTargetOS -and $Global:IntuneTargetOS.Trim().Length -gt 0) {
        return $Global:IntuneTargetOS.Trim()
    }

    # Standalone fallback: do not filter; export under "All"
    return 'All'
}

function Test-PolicyMatchesTargetOS {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TargetOS,
        [object]$Platforms,
        [string]$OdataType
    )

    if ($TargetOS -eq 'All') { return $true }

    $t = $TargetOS.ToLowerInvariant()

    # ---- 1) Prefer "platforms" (configurationPolicies) ----
    if ($null -ne $Platforms) {
        $pText = ''
        if ($Platforms -is [System.Collections.IEnumerable] -and -not ($Platforms -is [string])) {
            $pText = (@($Platforms) | ForEach-Object { "$_" }) -join ';'
        }
        else {
            $pText = "$Platforms"
        }

        $p = $pText.ToLowerInvariant()

        # STRICT allow-lists
        $isWindows = ($p -match 'windows10andlater' -or $p -match 'windows10' -or $p -match 'windows10x' -or $p -match '\bwindows\b')
        $isMac     = ($p -match 'macos')

        if ($t -eq 'windows') { return $isWindows -and -not $isMac }
        if ($t -eq 'macos')   { return $isMac -and -not $isWindows }

        return $false
    }

    # ---- 2) Fallback to @odata.type (deviceConfigurations etc.) ----
    if ($OdataType) {
        $o = $OdataType.ToLowerInvariant()

        if ($t -eq 'windows') { return ($o -match 'windows') -and -not ($o -match 'macos') }
        if ($t -eq 'macos')   { return ($o -match 'macos')   -and -not ($o -match 'windows') }
    }

    # No signal -> STRICT: do NOT include
    return $false
}

function Get-PlatformsForConfigPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Policy
    )

    $plat = $Policy.platforms

    if ($null -eq $plat -or "$plat".Trim() -eq '') {
        try {
            $full = Invoke-GraphGet -RelativeUri ("deviceManagement/configurationPolicies/{0}" -f $Policy.id)
            if ($full -and $full.platforms) { $plat = $full.platforms }
        }
        catch { }
    }

    return $plat
}

# =========================
# Intune helpers (unified settings platform)
# =========================

function Get-ConfigurationPolicies {
    [CmdletBinding()]
    param()
    Invoke-GraphGetAllPages -RelativeUri 'deviceManagement/configurationPolicies'
}

function Get-ConfigurationPolicySettings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PolicyId
    )
    (Invoke-GraphGet -RelativeUri "deviceManagement/configurationPolicies/$PolicyId/settings").value
}

function Get-DeviceConfigurations {
    [CmdletBinding()]
    param()
    Invoke-GraphGetAllPages -RelativeUri 'deviceManagement/deviceConfigurations'
}

# IMPORTANT: This list represents ALL endpoint security/baseline families
# so we can prevent dumping endpoint security policies into 99 even if user didn't select them.
$AllEndpointSecurityTemplateFamilies = @(
    'endpointSecurityAntivirus',
    'endpointSecurityDiskEncryption',
    'endpointSecurityFirewall',
    'endpointSecurityEndpointPrivilegeManagement',
    'endpointSecurityEndpointDetectionAndResponse',
    'endpointSecurityApplicationControl',
    'endpointSecurityAttackSurfaceReduction',
    'endpointSecurityAttackSurfaceReductionRules',
    'endpointSecurityAccountProtection',
    'baseline'
)

function Get-PolicyFolderForTemplate {
    [CmdletBinding()]
    param(
        [string]$TemplateFamily,
        [string]$TemplateDisplayName
    )

    if ($TemplateFamily) {
        switch ($TemplateFamily) {
            'endpointSecurityAntivirus'                    { return $FolderMap.Antivirus }
            'endpointSecurityDiskEncryption'               { return $FolderMap.DiskEncryption }
            'endpointSecurityFirewall'                     { return $FolderMap.Firewall }
            'endpointSecurityEndpointPrivilegeManagement'  { return $FolderMap.EPM }
            'endpointSecurityEndpointDetectionAndResponse' { return $FolderMap.EDR }
            'endpointSecurityApplicationControl'           { return $FolderMap.AppControl }
            'endpointSecurityAttackSurfaceReduction'       { return $FolderMap.ASR }
            'endpointSecurityAttackSurfaceReductionRules'  { return $FolderMap.ASR }
            'endpointSecurityAccountProtection'            { return $FolderMap.AccountProtection }
            'baseline'                                     { return $FolderMap.SecurityBaselines }
            default                                        { return $FolderMap.Other }
        }
    }

    if ($TemplateDisplayName) {
        $name = $TemplateDisplayName.ToLowerInvariant()

        if     ($name -like '*baseline*')                                         { return $FolderMap.SecurityBaselines }
        elseif ($name -like '*antivirus*' -or $name -like '*defender antivirus*') { return $FolderMap.Antivirus }
        elseif ($name -like '*disk encryption*' -or $name -like '*bitlocker*')    { return $FolderMap.DiskEncryption }
        elseif ($name -like '*firewall*')                                         { return $FolderMap.Firewall }
        elseif ($name -like '*endpoint privilege management*' -or $name -like '*epm*') { return $FolderMap.EPM }
        elseif ($name -like '*endpoint detection and response*' -or $name -like '*edr*') { return $FolderMap.EDR }
        elseif ($name -like '*app control for business*' -or $name -like '*app control*') { return $FolderMap.AppControl }
        elseif ($name -like '*attack surface reduction*' -or $name -like '*asr*') { return $FolderMap.ASR }
        elseif ($name -like '*account protection*')                               { return $FolderMap.AccountProtection }
    }

    return $FolderMap.Other
}

# =========================
# Conditional Access helpers
# =========================

function Get-ConditionalAccessPolicies {
    [CmdletBinding()]
    param()
    Invoke-GraphGetAllPages -RelativeUri 'identity/conditionalAccess/policies'
}

function Export-ConditionalAccessPolicies {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ConditionalAccessRoot
    )

    Write-Host "Fetching Conditional Access policies..." -ForegroundColor Cyan
    $policies = Get-ConditionalAccessPolicies
    Write-Host "Conditional Access policies returned: $($policies.Count)" -ForegroundColor DarkGray

    if (-not $policies -or $policies.Count -eq 0) {
        Write-Host "No Conditional Access policies found. Nothing to export." -ForegroundColor Yellow
        return
    }

    $caFolderName = $FolderMap.ConditionalAccess
    $exportPath   = Join-Path $ConditionalAccessRoot $caFolderName

    if (-not (Test-Path -LiteralPath $exportPath)) {
        Write-Host "Creating Conditional Access export folder: $exportPath" -ForegroundColor DarkCyan
        New-Item -ItemType Directory -Path $exportPath -Force | Out-Null
    }

    foreach ($policy in $policies) {
        Write-Host "CA Policy: $($policy.displayName)" -ForegroundColor Yellow
        Export-JsonData -Json $policy -ExportPath $exportPath
    }
}

# =========================
# Device Compliance helpers
# =========================

function Get-DeviceCompliancePolicies {
    [CmdletBinding()]
    param()
    Invoke-GraphGetAllPages -RelativeUri 'deviceManagement/deviceCompliancePolicies'
}

function Export-DeviceCompliancePolicies {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OsRootPath,
        [Parameter(Mandatory)][string]$TargetOS
    )

    Write-Host "Fetching Device Compliance policies..." -ForegroundColor Cyan
    $policies = Get-DeviceCompliancePolicies
    Write-Host "Device Compliance policies returned: $($policies.Count)" -ForegroundColor DarkGray

    if (-not $policies -or $policies.Count -eq 0) {
        Write-Host "No Device Compliance policies found. Nothing to export." -ForegroundColor Yellow
        return
    }

    $filtered = $policies | Where-Object {
        $odata = $null
        if ($_.PSObject.Properties.Name -contains '@odata.type') { $odata = $_.'@odata.type' }

        $osMatch  = Test-PolicyMatchesTargetOS -TargetOS $TargetOS -Platforms $null -OdataType $odata
        $exclude  = Test-ShouldExcludePolicyByName -Name $_.displayName

        $osMatch -and (-not $exclude)
    }

    Write-Host "Device Compliance policies to export (after OS filter: $TargetOS): $($filtered.Count)" -ForegroundColor DarkGray

    if (-not $filtered -or $filtered.Count -eq 0) {
        Write-Host "No Device Compliance policies matched OS filter ($TargetOS)." -ForegroundColor Yellow
        return
    }

    $dcFolderName = $FolderMap.DeviceCompliance
    $exportPath   = Join-Path $OsRootPath $dcFolderName

    if (-not (Test-Path -LiteralPath $exportPath)) {
        Write-Host "Creating Device Compliance export folder: $exportPath" -ForegroundColor DarkCyan
        New-Item -ItemType Directory -Path $exportPath -Force | Out-Null
    }

    foreach ($policy in $filtered) {
        Write-Host "Device Compliance Policy: $($policy.displayName)" -ForegroundColor Yellow
        Export-JsonData -Json $policy -ExportPath $exportPath
    }
}

# =========================
# Export catch-all config to 99 (Settings Catalog / Custom / etc.)
# =========================

function Export-RemainingConfigurationPoliciesTo99 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$AllConfigPolicies,
        [Parameter(Mandatory)][string]$OsRootPath,
        [Parameter(Mandatory)][string]$TargetOS
    )

    if (-not $AllConfigPolicies) { return }

    $exportPath = Join-Path (Join-Path $OsRootPath $FolderMap.Other) $UncategorizedSubfolders.ConfigPolicies
    if (-not (Test-Path -LiteralPath $exportPath)) {
        New-Item -ItemType Directory -Path $exportPath -Force | Out-Null
    }

    # Exclude any endpoint security/baseline policies from 99 (even if user didn’t select them)
    $remaining = $AllConfigPolicies | Where-Object {

        $tmplFam = $null
        if ($_.templateReference -and $_.templateReference.templateFamily) {
            $tmplFam = $_.templateReference.templateFamily
        }

        $isEndpointSecurityFamily = $false
        if ($tmplFam) { $isEndpointSecurityFamily = $AllEndpointSecurityTemplateFamilies -contains $tmplFam }

        $exclude = Test-ShouldExcludePolicyByName -Name $_.name

        # Ensure we have platforms; if not, GET the policy to retrieve platforms
        $plat = Get-PlatformsForConfigPolicy -Policy $_

        $osMatch = Test-PolicyMatchesTargetOS -TargetOS $TargetOS -Platforms $plat -OdataType $null

        (-not $isEndpointSecurityFamily) -and (-not $exclude) -and $osMatch
    }

    Write-Host "ConfigurationPolicies (non-endpoint-security) to export to 99 (OS: $TargetOS): $($remaining.Count)" -ForegroundColor DarkGray

    foreach ($p in $remaining) {
        Write-Host "99 ConfigPolicy: $($p.name)" -ForegroundColor Yellow

        $settings = $null
        try {
            $settings = Get-ConfigurationPolicySettings -PolicyId $p.id
        }
        catch {
            Write-Host "  WARN: Failed to fetch settings for $($p.name): $($_.Exception.Message)" -ForegroundColor DarkYellow
        }

        $plat = Get-PlatformsForConfigPolicy -Policy $p

        $json = [PSCustomObject]@{
            displayName       = $p.name
            name              = $p.name
            description       = $p.description
            platforms         = $plat     # FIX: use repaired platforms
            technologies      = $p.technologies
            roleScopeTagIds   = $p.roleScopeTagIds
            templateReference = $p.templateReference
            settings          = $settings
        }

        Export-JsonData -Json $json -ExportPath $exportPath
    }
}

function Export-DeviceConfigurationsTo99 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$DeviceConfigurations,
        [Parameter(Mandatory)][string]$OsRootPath,
        [Parameter(Mandatory)][string]$TargetOS
    )

    if (-not $DeviceConfigurations) { return }

    $exportPath = Join-Path (Join-Path $OsRootPath $FolderMap.Other) $UncategorizedSubfolders.DeviceConfigurations
    if (-not (Test-Path -LiteralPath $exportPath)) {
        New-Item -ItemType Directory -Path $exportPath -Force | Out-Null
    }

    $filtered = $DeviceConfigurations | Where-Object {

        # Use displayName if present; fallback to name (some objects come back without displayName populated)
        $n = if ($_.displayName) { $_.displayName } elseif ($_.name) { $_.name } else { '' }
        $exclude = Test-ShouldExcludePolicyByName -Name $n

        # OS filter via @odata.type (read directly; PSObject.Properties check can fail depending on deserialization)
        $odata = $_.'@odata.type'
        $osMatch = Test-PolicyMatchesTargetOS -TargetOS $TargetOS -Platforms $null -OdataType $odata

        (-not $exclude) -and $osMatch
    }

    Write-Host "DeviceConfigurations to export to 99 (OS: $TargetOS): $($filtered.Count)" -ForegroundColor DarkGray

    foreach ($dc in $filtered) {
        $n = if ($dc.displayName) { $dc.displayName } elseif ($dc.name) { $dc.name } else { '[no-name]' }
        Write-Host "99 DeviceConfig: $n" -ForegroundColor Yellow
        Export-JsonData -Json $dc -ExportPath $exportPath
    }
}

# =========================
# Main orchestrator
# =========================

function Export-IntuneEndpointSecurityPolicies {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RootPath,
        [switch]$UseDeviceCode
    )

    # --- resolve selection coming from GUI (or default to all) ---
    $selectedKeys = $Global:IntuneSelectedPolicyKeys
    if (-not $selectedKeys -or $selectedKeys.Count -eq 0) {
        $selectedKeys = $AllSelectionKeys
    }

    $includeBaseline          = $selectedKeys -contains 'EndpointSecurity-Baselines'
    $includeAV                = $selectedKeys -contains 'EndpointSecurity-Antivirus'
    $includeDisk              = $selectedKeys -contains 'EndpointSecurity-DiskEncryption'
    $includeFirewall          = $selectedKeys -contains 'EndpointSecurity-Firewall'
    $includeEPM               = $selectedKeys -contains 'EndpointSecurity-EPM'
    $includeEDR               = $selectedKeys -contains 'EndpointSecurity-EDR'
    $includeAppControl        = $selectedKeys -contains 'EndpointSecurity-AppControl'
    $includeASR               = $selectedKeys -contains 'EndpointSecurity-ASR'
    $includeAccountProtection = $selectedKeys -contains 'EndpointSecurity-AccountProtection'

    $includeDeviceCompliance  = $selectedKeys -contains 'DeviceCompliance'
    $includeConditionalAccess = $selectedKeys -contains 'ConditionalAccess'
    $includeUncategorized     = $selectedKeys -contains 'Uncategorized'

    # Determine OS scope (from BootStrapper)
    $targetOS = Get-TargetOS

    # Build template families list based on selection (for 1–9 exports)
    $endpointFamilies = New-Object System.Collections.Generic.List[string]

    if ($includeAV)                { [void]$endpointFamilies.Add('endpointSecurityAntivirus') }
    if ($includeDisk)              { [void]$endpointFamilies.Add('endpointSecurityDiskEncryption') }
    if ($includeFirewall)          { [void]$endpointFamilies.Add('endpointSecurityFirewall') }
    if ($includeEPM)               { [void]$endpointFamilies.Add('endpointSecurityEndpointPrivilegeManagement') }
    if ($includeEDR)               { [void]$endpointFamilies.Add('endpointSecurityEndpointDetectionAndResponse') }
    if ($includeAppControl)        { [void]$endpointFamilies.Add('endpointSecurityApplicationControl') }
    if ($includeASR)               {
        [void]$endpointFamilies.Add('endpointSecurityAttackSurfaceReduction')
        [void]$endpointFamilies.Add('endpointSecurityAttackSurfaceReductionRules')
    }
    if ($includeAccountProtection) { [void]$endpointFamilies.Add('endpointSecurityAccountProtection') }
    if ($includeBaseline)          { [void]$endpointFamilies.Add('baseline') }

    $doEndpointSecurity = $endpointFamilies.Count -gt 0
    $doOsScopedExport   = ($doEndpointSecurity -or $includeDeviceCompliance -or $includeUncategorized)

    # 1) Connect to Graph
    Connect-IntuneGraph -UseDeviceCode:$UseDeviceCode

    Write-Host "Export base root path: $RootPath" -ForegroundColor Cyan
    Write-Host "Target OS scope: $targetOS" -ForegroundColor Cyan

    # 2) Ensure base root exists (Intune_Policy)
    if (-not (Test-Path -LiteralPath $RootPath)) {
        Write-Host "Creating base export folder: $RootPath" -ForegroundColor DarkCyan
        New-Item -ItemType Directory -Path $RootPath -Force | Out-Null
    }

    # Define branch roots
    $osRoot = $null
    if ($doOsScopedExport) {
        $osRoot = Join-Path $RootPath $targetOS
        if (-not (Test-Path -LiteralPath $osRoot)) {
            Write-Host "Creating OS export folder: $osRoot" -ForegroundColor DarkCyan
            New-Item -ItemType Directory -Path $osRoot -Force | Out-Null
        }

        # Pre-create OS-scoped folders (EXCLUDING 11. Conditional Access)
        Write-Host "Ensuring OS-scoped subfolders exist..." -ForegroundColor Cyan
        @(
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
            $FolderMap.Other
        ) | ForEach-Object {
            $full = Join-Path $osRoot $_
            if (-not (Test-Path -LiteralPath $full)) {
                New-Item -ItemType Directory -Path $full -Force | Out-Null
            }
        }

        # Pre-create 99 subfolders
        foreach ($sub in $UncategorizedSubfolders.Values) {
            $full = Join-Path (Join-Path $osRoot $FolderMap.Other) $sub
            if (-not (Test-Path -LiteralPath $full)) {
                New-Item -ItemType Directory -Path $full -Force | Out-Null
            }
        }
    }

    $caRoot = $null
    if ($includeConditionalAccess) {
        $caRoot = Join-Path $RootPath 'Conditional_Access'
        if (-not (Test-Path -LiteralPath $caRoot)) {
            New-Item -ItemType Directory -Path $caRoot -Force | Out-Null
        }
    }

    # Cache these once; reuse for endpoint security and 99 exports
    $allConfigPolicies = Get-ConfigurationPolicies
    Write-Host "Total configurationPolicies returned: $($allConfigPolicies.Count)" -ForegroundColor DarkGray

    # 3) Endpoint Security / Baselines (OS scoped, folders 1–9)
    if ($doEndpointSecurity) {

        $policies = $allConfigPolicies | Where-Object {
            $_.templateReference -and $_.templateReference.templateFamily -in $endpointFamilies
        }

        # STRICT OS filter (with platform repair)
        $policies = $policies | Where-Object {
            $plat = Get-PlatformsForConfigPolicy -Policy $_
            Test-PolicyMatchesTargetOS -TargetOS $targetOS -Platforms $plat -OdataType $null
        }

        # Exclude onboarding/autopatch by name
        $policies = $policies | Where-Object {
            -not (Test-ShouldExcludePolicyByName -Name $_.name)
        }

        Write-Host "Endpoint Security / Baseline policies to export (after selection + OS filter): $($policies.Count)" -ForegroundColor DarkGray

        foreach ($policy in $policies) {
            $tmplRef  = $policy.templateReference
            $settings = Get-ConfigurationPolicySettings -PolicyId $policy.id

            $plat = Get-PlatformsForConfigPolicy -Policy $policy

            $json = [PSCustomObject]@{
                displayName             = $policy.name
                name                    = $policy.name
                description             = $policy.description
                platforms               = $plat
                technologies            = $policy.technologies
                roleScopeTagIds         = $policy.roleScopeTagIds

                TemplateFamily          = $tmplRef.templateFamily
                TemplateDisplayName     = $tmplRef.templateDisplayName
                TemplateId              = $tmplRef.templateId
                TemplateDisplayVersion  = $tmplRef.templateDisplayVersion

                templateReference       = $tmplRef
                settings                = $settings
            }

            $subFolderName = Get-PolicyFolderForTemplate -TemplateFamily $tmplRef.templateFamily -TemplateDisplayName $tmplRef.templateDisplayName
            $exportPath    = Join-Path $osRoot $subFolderName

            Export-JsonData -Json $json -ExportPath $exportPath
        }
    }
    else {
        Write-Host "No Endpoint Security / Baseline categories selected. Skipping configurationPolicies export (1-9)." -ForegroundColor DarkGray
    }

    # 4) Device Compliance (OS scoped, folder 10)
    if ($includeDeviceCompliance) {
        Export-DeviceCompliancePolicies -OsRootPath $osRoot -TargetOS $targetOS
    }
    else {
        Write-Host "Device Compliance not selected. Skipping." -ForegroundColor DarkGray
    }

    # 5) Catch-all export to 99 (OS scoped)
    if ($includeUncategorized) {
        Export-RemainingConfigurationPoliciesTo99 -AllConfigPolicies $allConfigPolicies -OsRootPath $osRoot -TargetOS $targetOS

        $deviceConfigurations = Get-DeviceConfigurations
        Write-Host "Total deviceConfigurations returned: $($deviceConfigurations.Count)" -ForegroundColor DarkGray
        Export-DeviceConfigurationsTo99 -DeviceConfigurations $deviceConfigurations -OsRootPath $osRoot -TargetOS $targetOS
    }
    else {
        Write-Host "Uncategorized not selected. Skipping 99 catch-all exports." -ForegroundColor DarkGray
    }

    # 6) Conditional Access (separate branch, NOT OS scoped)
    if ($includeConditionalAccess) {
        Export-ConditionalAccessPolicies -ConditionalAccessRoot $caRoot
    }
    else {
        Write-Host "Conditional Access not selected. Skipping." -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "Export complete." -ForegroundColor Cyan
}

#########################################
### Entry point
Export-IntuneEndpointSecurityPolicies -RootPath $ExportRootPath -UseDeviceCode:$UseDeviceCode