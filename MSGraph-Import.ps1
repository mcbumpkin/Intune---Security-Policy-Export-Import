#======================================================================================#
#                                                                                      #
#                         Intune Endpoint Security Exporter                            #
##           This script will import almost all policies from Intune                  ##
#                                                                                      #
#                 Script Created by Andreas Daneville 13-11-2025                       #
#======================================================================================#

[CmdletBinding()]
param(
    # Root folder that contains the exported structure (1. ..., 2. ..., etc.)
    [string]$ImportRootPath,
    [switch]$UseDeviceCode
)

if (-not $ImportRootPath) {
    $scriptPath = $MyInvocation.MyCommand.Path
    if ($scriptPath) {
        $scriptDir = Split-Path -Parent $scriptPath
        $ImportRootPath = Join-Path $scriptDir 'Export'
    }
    else {
        $ImportRootPath = Join-Path (Get-Location).Path 'Export'
    }
}

Write-Host "Import root path resolved to: $ImportRootPath" -ForegroundColor DarkCyan

# Folder names we expect (must match exporter)
$FolderNames = @{
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

# Graph scopes – we need write perms now
$RequiredScopes = @(
    'DeviceManagementConfiguration.ReadWrite.All'
    'DeviceManagementConfiguration.Read.All'
    'DeviceManagementManagedDevices.Read.All'        # often needed with Intune
    'DeviceManagementConfiguration.ReadWrite.All'    # explicit
    'DeviceManagementConfiguration.Read.All'
    'Policy.ReadWrite.ConditionalAccess'
    'Policy.Read.All'
)

$GraphApiVersion = 'beta'  # for Intune config; CA + compliance mostly v1.0, but we can use SDK cmdlets later if needed.

function Ensure-GraphModule {
    [CmdletBinding()]
    param()

    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        Write-Host "Microsoft.Graph module not found. Installing..." -ForegroundColor Yellow
        Install-Module Microsoft.Graph -Scope AllUsers -Force -ErrorAction Stop
        Write-Host "Microsoft.Graph installed." -ForegroundColor Green
    }
}

function Connect-IntuneGraph {
    [CmdletBinding()]
    param(
        [string[]]$Scopes = $RequiredScopes,
        [switch]$UseDeviceCode
    )

    Ensure-GraphModule
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

    if ($UseDeviceCode) {
        Connect-MgGraph -Scopes $Scopes -UseDeviceCode | Out-Null
    }
    else {
        Connect-MgGraph -Scopes $Scopes | Out-Null
    }

    $ctx = Get-MgContext
    if (-not $ctx) { throw "Failed to obtain Microsoft Graph context after Connect-MgGraph." }

    Write-Host "Connected to Microsoft Graph as $($ctx.Account)" -ForegroundColor Cyan
}

function Invoke-GraphPost {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RelativeUri,
        [Parameter(Mandatory)]$BodyObject
    )

    $uri = "/$GraphApiVersion/$RelativeUri"
    $jsonBody = $BodyObject | ConvertTo-Json -Depth 20
    Invoke-MgGraphRequest -Method POST -Uri $uri -Body $jsonBody -ErrorAction Stop
}

# =========================
# JSON helpers
# =========================

function Get-JsonFromFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path
    )

    $raw = Get-Content -LiteralPath $Path -Raw
    if (-not $raw) { throw "File '$Path' is empty or unreadable." }

    $obj = $raw | ConvertFrom-Json
    return $obj
}

function Remove-ReadOnlyProperties {
    <#
      Generic helper to strip common read-only Graph properties
      (id, createdDateTime, etc.) from an object before POST.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Object,
        [string[]]$Extra = @()
    )

    $readOnly = @(
        'id',
        'createdDateTime',
        'lastModifiedDateTime',
        'version',
        '@odata.context',
        '@odata.etag'
    ) + $Extra

    # Shallow clone and remove props
    $result = $Object | Select-Object *  # creates a copy

    foreach ($prop in $readOnly) {
        if ($result.PSObject.Properties.Name -contains $prop) {
            $result.PSObject.Properties.Remove($prop) | Out-Null
        }
    }

    return $result
}


# =========================
# Import: Baseline
# =========================

function New-ODataFilterEncoded {
    <#
      Builds a URL-encoded $filter expression with correct OData string quoting.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Property,
        [Parameter(Mandatory)][string]$Value
    )

    # Escape single quotes for OData: ' -> ''
    $escaped = $Value.Replace("'", "''")
    $filter  = "$Property eq '$escaped'"

    # URL-encode the whole filter expression (so & becomes %26 etc.)
    return [System.Uri]::EscapeDataString($filter)
}


function Import-ConfigurationPolicyFromFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path
    )

    Write-Host "Importing configuration policy from: $Path" -ForegroundColor Cyan

    $obj = Get-JsonFromFile -Path $Path

    if (-not $obj.templateReference -or -not $obj.settings) {
        Write-Host "  Skipping (no templateReference/settings) – likely not a configurationPolicy export." -ForegroundColor DarkYellow
        return
    }

    # Duplicate check by name (safe filter encoding)
    try {
        $filterEncoded = New-ODataFilterEncoded -Property 'name' -Value $obj.name
        $existing = Invoke-MgGraphRequest -Method GET -Uri "/$GraphApiVersion/deviceManagement/configurationPolicies?`$filter=$filterEncoded" -ErrorAction Stop
        if ($existing.value -and $existing.value.Count -gt 0) {
            Write-Host "  A configuration policy named '$($obj.name)' already exists. Skipping." -ForegroundColor Yellow
            return
        }
    }
    catch {
        Write-Host "  Warning: duplicate-check GET failed, continuing without name check. ($($_.Exception.Message))" -ForegroundColor DarkYellow
    }

    # Template family (we stored this in the export object)
    $templateFamily = $obj.TemplateFamily

    # Default: use exported settings
    $settings = $obj.settings

    # Special case: EDR onboarding-from-connector setting is not importable
    if ($templateFamily -eq 'endpointSecurityEndpointDetectionAndResponse') {
        $beforeCount = @($settings).Count

        $settings = @($settings | Where-Object {
            # Try to catch problematic definition IDs.
            $defId = $_.settingDefinitionId
            if (-not $defId -and $_.definitionId) { $defId = $_.definitionId }

            -not ($defId -like '*device_vendor_msft_windowsadvancedthreatprotection_onboarding_fromconnector*')
        })

        $afterCount = @($settings).Count

        if ($beforeCount -ne $afterCount) {
            Write-Host "  EDR: stripped $($beforeCount - $afterCount) onboarding-from-connector setting(s) that are not importable." -ForegroundColor DarkYellow
        }
    }

    # Build body
    $body = [PSCustomObject]@{
        name              = $obj.name
        description       = $obj.description
        platforms         = $obj.platforms
        technologies      = $obj.technologies
        roleScopeTagIds   = $obj.roleScopeTagIds
        templateReference = $obj.templateReference
        settings          = $settings
    }

    try {
        $created = Invoke-GraphPost -RelativeUri "deviceManagement/configurationPolicies" -BodyObject $body
        Write-Host "  Created configuration policy '$($created.name)' (id: $($created.id))" -ForegroundColor Green
    }
    catch {
        Write-Host "  FAILED to create configuration policy '$($obj.name)': $($_.Exception.Message)" -ForegroundColor Red
        return
    }
}


# =========================
# Import: Device Compliance
# =========================

function Import-DeviceCompliancePolicyFromFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path
    )

    Write-Host "Importing Device Compliance policy from: $Path" -ForegroundColor Cyan

    $obj = Get-JsonFromFile -Path $Path

    # Strip read-only + problematic props
    $safe = Remove-ReadOnlyProperties -Object $obj -Extra @(
        'scheduledActionsForRule',  # let Intune create default block action
        'assignments'               # cross-tenant assignments rarely portable
    )

    # Duplicate check by displayName
    try {
        $filterEncoded = New-ODataFilterEncoded -Property 'displayName' -Value $safe.displayName
        $existing = Invoke-MgGraphRequest -Method GET -Uri "/v1.0/deviceManagement/deviceCompliancePolicies?`$filter=$filterEncoded" -ErrorAction Stop
        if ($existing.value -and $existing.value.Count -gt 0) {
            Write-Host "  A Device Compliance policy named '$($safe.displayName)' already exists. Skipping." -ForegroundColor Yellow
            return
        }
    }
    catch {
        Write-Host "  Warning: duplicate-check GET failed for compliance policy '$($safe.displayName)', continuing. ($($_.Exception.Message))" -ForegroundColor DarkYellow
    }

    # POST to /deviceManagement/deviceCompliancePolicies (v1.0)
    $uri = "/v1.0/deviceManagement/deviceCompliancePolicies"
    $bodyJson = $safe | ConvertTo-Json -Depth 20

    try {
        $created = Invoke-MgGraphRequest -Method POST -Uri $uri -Body $bodyJson -ErrorAction Stop
        Write-Host "  Created Device Compliance policy '$($created.displayName)' (id: $($created.id))" -ForegroundColor Green
    }
    catch {
        Write-Host "  FAILED to create Device Compliance policy '$($safe.displayName)': $($_.Exception.Message)" -ForegroundColor Red
        return
    }
}


# =========================
# Import: CA Policies
# =========================

function Import-ConditionalAccessPolicyFromFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path
    )

    Write-Host "Importing Conditional Access policy from: $Path" -ForegroundColor Cyan

    $obj = Get-JsonFromFile -Path $Path

    # Build a clean CA payload that matches the schema
    $body = [PSCustomObject]@{
        displayName      = $obj.displayName
        state            = $obj.state
        conditions       = $obj.conditions
        grantControls    = $obj.grantControls
        sessionControls  = $obj.sessionControls
    }

    if ($obj.PSObject.Properties.Name -contains 'description' -and $obj.description) {
        $body | Add-Member -MemberType NoteProperty -Name 'description' -Value $obj.description
    }

    # Duplicate check by displayName
    try {
        $filterEncoded = New-ODataFilterEncoded -Property 'displayName' -Value $body.displayName
        $existing = Invoke-MgGraphRequest -Method GET -Uri "/v1.0/identity/conditionalAccess/policies?`$filter=$filterEncoded" -ErrorAction Stop
        if ($existing.value -and $existing.value.Count -gt 0) {
            Write-Host "  A Conditional Access policy named '$($body.displayName)' already exists. Skipping." -ForegroundColor Yellow
            return
        }
    }
    catch {
        Write-Host "  Warning: duplicate-check GET failed for CA policy '$($body.displayName)', continuing. ($($_.Exception.Message))" -ForegroundColor DarkYellow
    }

    $uri = "/v1.0/identity/conditionalAccess/policies"
    $bodyJson = $body | ConvertTo-Json -Depth 20

    try {
        $created = Invoke-MgGraphRequest -Method POST -Uri $uri -Body $bodyJson -ErrorAction Stop
        Write-Host "  Created Conditional Access policy '$($created.displayName)' (id: $($created.id))" -ForegroundColor Green
    }
    catch {
        Write-Host "  FAILED to create Conditional Access policy '$($body.displayName)': $($_.Exception.Message)" -ForegroundColor Red
        return
    }
}


# =========================
# Main orchestrator
# =========================

function Import-IntuneSecurityFromExport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RootPath,
        [switch]$UseDeviceCode
    )

    Connect-IntuneGraph -UseDeviceCode:$UseDeviceCode

    if (-not (Test-Path -LiteralPath $RootPath)) {
        throw "Import root path '$RootPath' does not exist."
    }

    # 1–9: unified configuration policies
    $configFolders = @(
        $FolderNames.SecurityBaselines,
        $FolderNames.Antivirus,
        $FolderNames.DiskEncryption,
        $FolderNames.Firewall,
        $FolderNames.EPM,
        $FolderNames.EDR,
        $FolderNames.AppControl,
        $FolderNames.ASR,
        $FolderNames.AccountProtection
    )

    foreach ($folderName in $configFolders) {
        $folderPath = Join-Path $RootPath $folderName
        if (-not (Test-Path -LiteralPath $folderPath)) { continue }

        Write-Host ""
        Write-Host "Processing configuration policies in folder: $folderPath" -ForegroundColor DarkCyan

        Get-ChildItem -LiteralPath $folderPath -Filter *.json | ForEach-Object {
            Import-ConfigurationPolicyFromFile -Path $_.FullName
        }
    }

    # Device Compliance
    $dcPath = Join-Path $RootPath $FolderNames.DeviceCompliance
    if (Test-Path -LiteralPath $dcPath) {
        Write-Host ""
        Write-Host "Processing Device Compliance policies in folder: $dcPath" -ForegroundColor DarkCyan

        Get-ChildItem -LiteralPath $dcPath -Filter *.json | ForEach-Object {
            Import-DeviceCompliancePolicyFromFile -Path $_.FullName
        }
    }

    # Conditional Access
    $caPath = Join-Path $RootPath $FolderNames.ConditionalAccess
    if (Test-Path -LiteralPath $caPath) {
        Write-Host ""
        Write-Host "Processing Conditional Access policies in folder: $caPath" -ForegroundColor DarkCyan

        Get-ChildItem -LiteralPath $caPath -Filter *.json | ForEach-Object {
            Import-ConditionalAccessPolicyFromFile -Path $_.FullName
        }
    }

    Write-Host ""
    Write-Host "Import run complete." -ForegroundColor Cyan
}


#########################################
### BootStrapper
Import-IntuneSecurityFromExport -RootPath $ImportRootPath -UseDeviceCode:$UseDeviceCode
