#======================================================================================#
#                                                                                      #
#                         Intune Endpoint Security Exporter                            #
## This script will export almost all policies from Intune and place them in a folder ##
#                                                                                      #
#                 Script Created by Andreas Daneville 13-11-2025                       #
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

if (-not $ExportRootPath) {
    if ($Global:IntuneExportRoot) {
        # Preferred: provided by BootStrapper GUI
        $ExportRootPath = $Global:IntuneExportRoot
    }
    elseif ($Global:IntuneToolRoot) {
        # Fallback: tool root from BootStrapper
        $ExportRootPath = Join-Path $Global:IntuneToolRoot 'Export'
    }
    else {
        # Final fallback: local script-based resolution
        $scriptPath = $MyInvocation.MyCommand.Path

        if ($scriptPath) {
            $scriptDir      = Split-Path -Parent $scriptPath
            $ExportRootPath = Join-Path (Split-Path -Parent $scriptDir) 'Export'
        }
        else {
            $ExportRootPath = Join-Path (Get-Location).Path 'Export'
        }
    }
}

# =========================
# Config: Folders & Scopes
# =========================

# Folder names (your 1–11 + 99 structure)
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

    # Always drop any existing Graph context so we don't accidentally reuse
    # a previous tenant/session between runs.
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
    catch {
        # Ignore any disconnect errors
    }

    try {
        if ($UseDeviceCode) {
            # Device code flow – always interactive by design
            Connect-MgGraph -Scopes $Scopes -UseDeviceCode -ContextScope Process -NoWelcome | Out-Null
        }
        else {
            # Interactive login – will prompt because we just disconnected
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

function Export-JsonData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Json,
        [Parameter(Mandatory)][string]$ExportPath
    )

    if (-not (Test-Path -LiteralPath $ExportPath)) {
        New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
    }

    $jsonString = $Json | ConvertTo-Json -Depth 10
    $converted  = $jsonString | ConvertFrom-Json

    $displayName = $converted.displayName
    if (-not $displayName) {
        $displayName = 'UnnamedPolicy'
    }

    $displayName = $displayName -replace '\<|\>|:|"|/|\\|\||\?|\*', '_'

    $fileName = '{0}_{1}.json' -f $displayName, (Get-Date -Format 'yyyy-MM-dd-HH-mm-ss-fff')
    $fullPath = Join-Path $ExportPath $fileName

    $jsonString | Set-Content -LiteralPath $fullPath -Encoding UTF8

    Write-Host "Exported: $fullPath" -ForegroundColor Green
}


# =========================
# Intune helpers (unified settings platform)
# =========================

function Get-EndpointSecurityConfigurationPolicies {
    [CmdletBinding()]
    param()

    $resource = 'deviceManagement/configurationPolicies'
    (Invoke-GraphGet -RelativeUri $resource).value
}

function Get-ConfigurationPolicySettings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PolicyId
    )

    $resource = "deviceManagement/configurationPolicies/$PolicyId/settings"
    (Invoke-GraphGet -RelativeUri $resource).value
}

function Get-PolicyFolderForTemplate {
    [CmdletBinding()]
    param(
        [string]$TemplateFamily,
        [string]$TemplateDisplayName
    )

    if ($TemplateFamily) {
        switch ($TemplateFamily) {
            'endpointSecurityAntivirus'                   { return $FolderMap.Antivirus }
            'endpointSecurityDiskEncryption'              { return $FolderMap.DiskEncryption }
            'endpointSecurityFirewall'                    { return $FolderMap.Firewall }
            'endpointSecurityEndpointPrivilegeManagement' { return $FolderMap.EPM }
            'endpointSecurityEndpointDetectionAndResponse'{ return $FolderMap.EDR }
            'endpointSecurityApplicationControl'          { return $FolderMap.AppControl }
            'endpointSecurityAttackSurfaceReduction'      { return $FolderMap.ASR }
            'endpointSecurityAttackSurfaceReductionRules' { return $FolderMap.ASR }
            'endpointSecurityAccountProtection'           { return $FolderMap.AccountProtection }
            'baseline'                                    { return $FolderMap.SecurityBaselines }
            default                                       { return $FolderMap.Other }
        }
    }

    if ($TemplateDisplayName) {
        $name = $TemplateDisplayName.ToLowerInvariant()

        if     ($name -like '*baseline*')                           { return $FolderMap.SecurityBaselines }
        elseif ($name -like '*antivirus*' -or $name -like '*defender antivirus*') { return $FolderMap.Antivirus }
        elseif ($name -like '*disk encryption*' -or $name -like '*bitlocker*')    { return $FolderMap.DiskEncryption }
        elseif ($name -like '*firewall*')                           { return $FolderMap.Firewall }
        elseif ($name -like '*endpoint privilege management*' -or $name -like '*epm*') { return $FolderMap.EPM }
        elseif ($name -like '*endpoint detection and response*' -or $name -like '*edr*') { return $FolderMap.EDR }
        elseif ($name -like '*app control for business*' -or $name -like '*app control*') { return $FolderMap.AppControl }
        elseif ($name -like '*attack surface reduction*' -or $name -like '*asr*') { return $FolderMap.ASR }
        elseif ($name -like '*account protection*')                 { return $FolderMap.AccountProtection }
    }

    return $FolderMap.Other
}


# =========================
# Conditional Access helpers
# =========================

function Get-ConditionalAccessPolicies {
    [CmdletBinding()]
    param()

    $resource = 'identity/conditionalAccess/policies'
    (Invoke-GraphGet -RelativeUri $resource).value
}

function Export-ConditionalAccessPolicies {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RootPath
    )

    Write-Host "Fetching Conditional Access policies..." -ForegroundColor Cyan
    $policies = Get-ConditionalAccessPolicies
    Write-Host "Conditional Access policies returned: $($policies.Count)" -ForegroundColor DarkGray

    if (-not $policies -or $policies.Count -eq 0) {
        Write-Host "No Conditional Access policies found. Nothing to export." -ForegroundColor Yellow
        return
    }

    $caFolderName = $FolderMap.ConditionalAccess
    if (-not $caFolderName) {
        $caFolderName = '11. Conditional Access'
    }

    $exportPath = Join-Path $RootPath $caFolderName
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

    $resource = 'deviceManagement/deviceCompliancePolicies'
    (Invoke-GraphGet -RelativeUri $resource).value
}

function Export-DeviceCompliancePolicies {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RootPath
    )

    Write-Host "Fetching Device Compliance policies..." -ForegroundColor Cyan
    $policies = Get-DeviceCompliancePolicies
    Write-Host "Device Compliance policies returned: $($policies.Count)" -ForegroundColor DarkGray

    if (-not $policies -or $policies.Count -eq 0) {
        Write-Host "No Device Compliance policies found. Nothing to export." -ForegroundColor Yellow
        return
    }

    $dcFolderName = $FolderMap.DeviceCompliance
    if (-not $dcFolderName) {
        $dcFolderName = '10. Device Compliance'
    }

    $exportPath = Join-Path $RootPath $dcFolderName
    if (-not (Test-Path -LiteralPath $exportPath)) {
        Write-Host "Creating Device Compliance export folder: $exportPath" -ForegroundColor DarkCyan
        New-Item -ItemType Directory -Path $exportPath -Force | Out-Null
    }

    foreach ($policy in $policies) {
        Write-Host "Device Compliance Policy: $($policy.displayName)" -ForegroundColor Yellow
        Export-JsonData -Json $policy -ExportPath $exportPath
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
        # running standalone or no GUI selection -> process everything
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

    # Build template families list based on selection
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

    # 1) Connect to Graph
    Connect-IntuneGraph -UseDeviceCode:$UseDeviceCode

    Write-Host "Export root path: $RootPath" -ForegroundColor Cyan

    # 2) Ensure root export folder exists
    if (-not (Test-Path -LiteralPath $RootPath)) {
        Write-Host "Creating root export folder: $RootPath" -ForegroundColor DarkCyan
        New-Item -ItemType Directory -Path $RootPath -Force | Out-Null
    }

    # 3) Pre-create all known subfolders (even if not all are used)
    Write-Host "Ensuring subfolders exist..." -ForegroundColor Cyan
    $FolderMap.GetEnumerator() | ForEach-Object {
        $full = Join-Path $RootPath $_.Value
        if (-not (Test-Path -LiteralPath $full)) {
            Write-Host "  Creating: $full" -ForegroundColor DarkCyan
            New-Item -ItemType Directory -Path $full -Force | Out-Null
        }
        else {
            Write-Host "  Exists:   $full" -ForegroundColor DarkGray
        }
    }

    # 4) Endpoint Security / Baselines
    if ($doEndpointSecurity) {
        Write-Host "Fetching configuration policies (unified platform)..." -ForegroundColor Cyan
        $allPolicies = Get-EndpointSecurityConfigurationPolicies
        Write-Host "Total configurationPolicies returned: $($allPolicies.Count)" -ForegroundColor DarkGray

        if (-not $allPolicies) {
            Write-Host "No configurationPolicies found. Nothing to export for Endpoint Security/Baselines." -ForegroundColor Yellow
        }
        else {
            $policies = $allPolicies | Where-Object {
                $_.templateReference -and
                $_.templateReference.templateFamily -in $endpointFamilies
            }

            Write-Host "Endpoint Security / Baseline policies to export (after selection filter): $($policies.Count)" -ForegroundColor DarkGray

            if (-not $policies -or $policies.Count -eq 0) {
                Write-Host "No Endpoint Security or Baseline policies match the selected categories." -ForegroundColor Yellow
            }
            else {
                foreach ($policy in $policies) {
                    $policyId      = $policy.id
                    $name          = $policy.name
                    $description   = $policy.description
                    $platforms     = $policy.platforms
                    $technologies  = $policy.technologies
                    $roleScopeTags = $policy.roleScopeTagIds
                    $tmplRef       = $policy.templateReference

                    $templateFamily        = $tmplRef.templateFamily
                    $templateDisplayName   = $tmplRef.templateDisplayName
                    $templateDisplayVer    = $tmplRef.templateDisplayVersion
                    $templateId            = $tmplRef.templateId

                    Write-Host ""
                    Write-Host "Policy:   $name" -ForegroundColor Yellow
                    Write-Host "Family:   $templateFamily" -ForegroundColor Gray
                    Write-Host "Template: $templateDisplayName ($templateId)" -ForegroundColor Gray

                    $settings = Get-ConfigurationPolicySettings -PolicyId $policyId

                    $json = [PSCustomObject]@{
                        displayName             = $name
                        name                    = $name
                        description             = $description
                        platforms               = $platforms
                        technologies            = $technologies
                        roleScopeTagIds         = $roleScopeTags

                        TemplateFamily          = $templateFamily
                        TemplateDisplayName     = $templateDisplayName
                        TemplateId              = $templateId
                        TemplateDisplayVersion  = $templateDisplayVer

                        templateReference       = $tmplRef
                        settings                = $settings
                    }

                    $subFolderName = Get-PolicyFolderForTemplate -TemplateFamily $templateFamily -TemplateDisplayName $templateDisplayName
                    $exportPath    = Join-Path $RootPath $subFolderName

                    Export-JsonData -Json $json -ExportPath $exportPath
                }
            }
        }
    }
    else {
        Write-Host "No Endpoint Security / Baseline categories selected. Skipping configurationPolicies export." -ForegroundColor Yellow
    }

    # 5) Device Compliance
    if ($includeDeviceCompliance) {
        Export-DeviceCompliancePolicies -RootPath $RootPath
    }
    else {
        Write-Host "Device Compliance not selected. Skipping." -ForegroundColor DarkGray
    }

    # 6) Conditional Access
    if ($includeConditionalAccess) {
        Export-ConditionalAccessPolicies -RootPath $RootPath
    }
    else {
        Write-Host "Conditional Access not selected. Skipping." -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "Export complete." -ForegroundColor Cyan
}


#########################################
### BootStrapper / direct entry point
Export-IntuneEndpointSecurityPolicies -RootPath $ExportRootPath -UseDeviceCode:$UseDeviceCode
