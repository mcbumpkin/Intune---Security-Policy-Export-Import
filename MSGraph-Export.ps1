##################################################
#
## Intune Endpoint Security Exporter
##  - Common helpers + Graph bootstrap + Export
#
##################################################

[CmdletBinding()]
param(
    # If not provided, we'll compute this to be "Export" next to the script file.
    [string]$ExportRootPath,
    [switch]$UseDeviceCode
)

# =========================
# Resolve ExportRootPath
# =========================

if (-not $ExportRootPath) {
    # Try to get the script's own path
    $scriptPath = $MyInvocation.MyCommand.Path

    if ($scriptPath) {
        # Script is being executed from file: use its folder
        $scriptDir = Split-Path -Parent $scriptPath
        $ExportRootPath = Join-Path $scriptDir 'Export'
    }
    else {
        # Fallback: no script path (very rare), use current location
        $ExportRootPath = Join-Path (Get-Location).Path 'Export'
    }
}

# =========================
# Config: Folders & Scopes
# =========================

# Folder names (your 1–5 structure)
$FolderMap = @{
    SecurityBaselines = '1. Security Baselines'
    Antivirus         = '2. Antivirus'
    DiskEncryption    = '3. Disk Encryption'
    Firewall          = '4. Firewall'
    ASR               = '5. Attack surface reduction'
    Other             = '9. Uncategorized'
}

# Graph scopes
$RequiredScopes = @(
    'DeviceManagementConfiguration.Read.All'
)

# API version (Endpoint security is still mostly in /beta)
$GraphApiVersion = 'beta'

# =========================
# Common helpers
# =========================

function Ensure-GraphModule {
    <#
    .SYNOPSIS
    Ensures Microsoft.Graph is installed and available.
    #>
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
    #>
    [CmdletBinding()]
    param(
        [string[]]$Scopes = $RequiredScopes,
        [switch]$UseDeviceCode
    )

    Ensure-GraphModule

    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

    try {
        if ($UseDeviceCode) {
            Connect-MgGraph -Scopes $Scopes -UseDeviceCode | Out-Null
        }
        else {
            Connect-MgGraph -Scopes $Scopes | Out-Null
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

    Write-Host "Connected to Microsoft Graph as $($ctx.Account)" -ForegroundColor Cyan
}

function Invoke-GraphGet {
    <#
    .SYNOPSIS
    Simple GET wrapper around Invoke-MgGraphRequest using a relative URI.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RelativeUri
    )

    $uri = "/$GraphApiVersion/$RelativeUri"
    Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
}

function Export-JsonData {
    <#
    .SYNOPSIS
    Exports a JSON-able object to a timestamped .json file in the given folder.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Json,
        [Parameter(Mandatory)][string]$ExportPath
    )

    if (-not (Test-Path -LiteralPath $ExportPath)) {
        New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
    }

    $jsonString = $Json | ConvertTo-Json -Depth 10

    $converted = $jsonString | ConvertFrom-Json

    $displayName = $converted.displayName
    if (-not $displayName) {
        $displayName = 'UnnamedPolicy'
    }

    # Sanitize for filesystem
    $displayName = $displayName -replace '\<|\>|:|"|/|\\|\||\?|\*', '_'

    $fileName = '{0}_{1}.json' -f $displayName, (Get-Date -Format 'yyyy-MM-dd-HH-mm-ss-fff')
    $fullPath = Join-Path $ExportPath $fileName

    $jsonString | Set-Content -LiteralPath $fullPath -Encoding UTF8

    Write-Host "Exported: $fullPath" -ForegroundColor Green
}

# =========================
# Intune helpers (new unified settings platform)
# =========================

function Get-EndpointSecurityConfigurationPolicies {
    <#
    .SYNOPSIS
    Returns all deviceManagementConfigurationPolicy objects.
    We'll filter down to Endpoint Security + Baselines afterwards.
    #>
    [CmdletBinding()]
    param()

    $resource = 'deviceManagement/configurationPolicies'
    (Invoke-GraphGet -RelativeUri $resource).value
}

function Get-ConfigurationPolicySettings {
    <#
    .SYNOPSIS
    Returns the settings collection for a specific configuration policy.
    Graph: GET /deviceManagement/configurationPolicies/{id}/settings
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PolicyId
    )

    $resource = "deviceManagement/configurationPolicies/$PolicyId/settings"
    (Invoke-GraphGet -RelativeUri $resource).value
}

function Get-PolicyFolderForTemplate {
    <#
    .SYNOPSIS
    Maps a configuration policy (template family/display name) to one of your 1–5 folders.
    #>
    [CmdletBinding()]
    param(
        [string]$TemplateFamily,
        [string]$TemplateDisplayName
    )

    # Prefer the explicit templateFamily when it exists
    if ($TemplateFamily) {
        switch ($TemplateFamily) {
            'endpointSecurityAntivirus'                 { return $FolderMap.Antivirus }
            'endpointSecurityDiskEncryption'           { return $FolderMap.DiskEncryption }
            'endpointSecurityFirewall'                 { return $FolderMap.Firewall }
            'endpointSecurityAttackSurfaceReduction'   { return $FolderMap.ASR }
            'baseline'                                 { return $FolderMap.SecurityBaselines }
            default                                    { return $FolderMap.Other }
        }
    }

    # Fallback to fuzzy name matching if family is missing/none
    if ($TemplateDisplayName) {
        $name = $TemplateDisplayName.ToLowerInvariant()

        if ($name -like '*baseline*') {
            return $FolderMap.SecurityBaselines
        }
        elseif ($name -like '*antivirus*' -or $name -like '*defender antivirus*') {
            return $FolderMap.Antivirus
        }
        elseif ($name -like '*disk encryption*' -or $name -like '*bitlocker*') {
            return $FolderMap.DiskEncryption
        }
        elseif ($name -like '*firewall*') {
            return $FolderMap.Firewall
        }
        elseif ($name -like '*attack surface reduction*' -or $name -like '*asr*') {
            return $FolderMap.ASR
        }
    }

    return $FolderMap.Other
}


# =========================
# Main orchestrator
# =========================

function Export-IntuneEndpointSecurityPolicies {
    <#
    .SYNOPSIS
    Connects to Graph, prepares folders, and exports Endpoint Security + Baseline policies
    from deviceManagement/configurationPolicies.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RootPath,
        [switch]$UseDeviceCode
    )

    # 1) Connect to Graph
    Connect-IntuneGraph -UseDeviceCode:$UseDeviceCode

    Write-Host "Export root path: $RootPath" -ForegroundColor Cyan

    # 2) Ensure root export folder exists
    if (-not (Test-Path -LiteralPath $RootPath)) {
        Write-Host "Creating root export folder: $RootPath" -ForegroundColor DarkCyan
        New-Item -ItemType Directory -Path $RootPath -Force | Out-Null
    }

    # 3) Pre-create the 1–5 folders (and Uncategorized)
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

    # 4) Fetch all configuration policies
    Write-Host "Fetching configuration policies (unified platform)..." -ForegroundColor Cyan
    $allPolicies = Get-EndpointSecurityConfigurationPolicies
    Write-Host "Total configurationPolicies returned: $($allPolicies.Count)" -ForegroundColor DarkGray

    if (-not $allPolicies) {
        Write-Host "No configurationPolicies found. Nothing to export." -ForegroundColor Yellow
        return
    }

    # Which template families we care about (your 1–5 buckets)
    $endpointFamilies = @(
        'endpointSecurityAntivirus',
        'endpointSecurityDiskEncryption',
        'endpointSecurityFirewall',
        'endpointSecurityAttackSurfaceReduction',
        'baseline'   # Security baselines
    )

    # Filter to Endpoint Security + baselines
    $policies = $allPolicies | Where-Object {
        $_.templateReference -and
        $_.templateReference.templateFamily -in $endpointFamilies
    }

    Write-Host "Endpoint Security / Baseline policies to export: $($policies.Count)" -ForegroundColor DarkGray

    if (-not $policies -or $policies.Count -eq 0) {
        Write-Host "No Endpoint Security or Baseline policies found under configurationPolicies." -ForegroundColor Yellow
        return
    }

    # 5) Export each policy
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

        # 5a) Get settings for this policy
        $settings = Get-ConfigurationPolicySettings -PolicyId $policyId

        # 5b) Build export object
        $json = [PSCustomObject]@{
            # For compatibility with old logic & filenames
            displayName         = $name
            name                = $name
            description         = $description
            platforms           = $platforms
            technologies        = $technologies
            roleScopeTagIds     = $roleScopeTags

            TemplateFamily      = $templateFamily
            TemplateDisplayName = $templateDisplayName
            TemplateId          = $templateId
            TemplateDisplayVersion = $templateDisplayVer

            # Flatten templateReference + settings into one object
            templateReference   = $tmplRef
            settings            = $settings
        }

        # 5c) Decide export subfolder based on template family/name
        $subFolderName = Get-PolicyFolderForTemplate -TemplateFamily $templateFamily -TemplateDisplayName $templateDisplayName
        $exportPath    = Join-Path $RootPath $subFolderName

        Export-JsonData -Json $json -ExportPath $exportPath
    }

    Write-Host ""
    Write-Host "Export complete." -ForegroundColor Cyan
}



#########################################
### BootStrapper

Export-IntuneEndpointSecurityPolicies -RootPath $ExportRootPath -UseDeviceCode:$UseDeviceCode

