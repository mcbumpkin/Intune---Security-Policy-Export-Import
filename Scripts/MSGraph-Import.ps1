#======================================================================================#
#                                                                                      #
#                         Intune Endpoint Security Importer                            #
##           This script will import almost all policies into Intune                  ##
#                                                                                      #
#                 Script Created by Andreas Daneville 13-11-2025                       #
#======================================================================================#

[CmdletBinding()]
param(
    # Root folder that contains the exported structure (1. ..., 2. ..., etc.)
    [string]$ImportRootPath,
    [switch]$UseDeviceCode
)

# =========================
# Resolve ImportRootPath
# =========================

if (-not $ImportRootPath) {
    if ($Global:IntuneExportRoot) {
        # Preferred: provided by BootStrapper GUI
        $ImportRootPath = $Global:IntuneExportRoot
    }
    elseif ($Global:IntuneToolRoot) {
        # Fallback: tool root from BootStrapper
        $ImportRootPath = Join-Path $Global:IntuneToolRoot 'Export'
    }
    else {
        # Final fallback: local script-based resolution
        $scriptPath = $MyInvocation.MyCommand.Path
        if ($scriptPath) {
            $scriptDir      = Split-Path -Parent $scriptPath
            $ImportRootPath = Join-Path (Split-Path -Parent $scriptDir) 'Export'
        }
        else {
            $ImportRootPath = Join-Path (Get-Location).Path 'Export'
        }
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

# All possible selection keys (must match BootStrapper GUI and exporter)
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

# Graph scopes – we need write perms now
$RequiredScopes = @(
    'DeviceManagementConfiguration.ReadWrite.All'
    'DeviceManagementConfiguration.Read.All'
    'DeviceManagementManagedDevices.Read.All'
    'Policy.ReadWrite.ConditionalAccess'
    'Policy.Read.All'
)

$GraphApiVersion = 'beta'  # for config policies

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

    $result = $Object | Select-Object *  # shallow clone

    foreach ($prop in $readOnly) {
        if ($result.PSObject.Properties.Name -contains $prop) {
            $result.PSObject.Properties.Remove($prop) | Out-Null
        }
    }

    return $result
}

# =========================
# OData filter helper
# =========================

function New-ODataFilterEncoded {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Property,
        [Parameter(Mandatory)][string]$Value
    )

    $escaped = $Value.Replace("'", "''")
    $filter  = "$Property eq '$escaped'"
    return [System.Uri]::EscapeDataString($filter)
}

# =========================
# Import: Config / Endpoint Security / Baseline
# =========================

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

    # Duplicate check by name
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

    $templateFamily = $obj.TemplateFamily
    $settings       = $obj.settings

    # Special case EDR – drop Defender ATP onboarding settings
    if ($templateFamily -eq 'endpointSecurityEndpointDetectionAndResponse') {
        $beforeCount = @($settings).Count

        $settings = @(
            $settings | Where-Object {
                ($_ | ConvertTo-Json -Depth 20) -notlike '*device_vendor_msft_windowsadvancedthreatprotection_onboarding*'
            }
        )

        $afterCount = @($settings).Count
        if ($beforeCount -ne $afterCount) {
            Write-Host "  EDR: stripped $($beforeCount - $afterCount) Defender ATP onboarding setting(s)." -ForegroundColor DarkYellow
        }
    }

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
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            Write-Host "  Graph details: $($_.ErrorDetails.Message)" -ForegroundColor DarkRed
        }
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

    $obj  = Get-JsonFromFile -Path $Path
    $safe = Remove-ReadOnlyProperties -Object $obj -Extra @('assignments', 'scheduledActionsForRule')

    $ruleName = 'PasswordRequired'
    if ($obj.scheduledActionsForRule -and $obj.scheduledActionsForRule[0].ruleName) {
        $ruleName = $obj.scheduledActionsForRule[0].ruleName
    }

    $blockRule = [PSCustomObject]@{
        ruleName = $ruleName
        scheduledActionConfigurations = @(
            [PSCustomObject]@{
                actionType                = 'block'
                gracePeriodHours          = 0
                notificationTemplateId    = ''
                notificationMessageCCList = @()
            }
        )
    }

    if ($safe.PSObject.Properties.Name -contains 'scheduledActionsForRule') {
        $safe.scheduledActionsForRule = @($blockRule)
    }
    else {
        $safe | Add-Member -MemberType NoteProperty -Name 'scheduledActionsForRule' -Value @($blockRule)
    }

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

    $uri      = "/v1.0/deviceManagement/deviceCompliancePolicies"
    $bodyJson = $safe | ConvertTo-Json -Depth 20

    try {
        $created = Invoke-MgGraphRequest -Method POST -Uri $uri -Body $bodyJson -ErrorAction Stop
        Write-Host "  Created Device Compliance policy '$($created.displayName)' (id: $($created.id))" -ForegroundColor Green
    }
    catch {
        Write-Host "  FAILED to create Device Compliance policy '$($safe.displayName)': $($_.Exception.Message)" -ForegroundColor Red
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            Write-Host "  Graph details: $($_.ErrorDetails.Message)" -ForegroundColor DarkRed
        }
        return
    }
}

# =========================
# Import: Conditional Access
# =========================

function Import-ConditionalAccessPolicyFromFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path
    )

    Write-Host "Importing Conditional Access policy from: $Path" -ForegroundColor Cyan

    $obj = Get-JsonFromFile -Path $Path

    $conditions = $obj.conditions

    $grantSrc = $obj.grantControls
    $grant    = $null

    if ($grantSrc) {
        $grant = [PSCustomObject]@{
            operator                    = $grantSrc.operator
            builtInControls             = $grantSrc.builtInControls
            customAuthenticationFactors = $grantSrc.customAuthenticationFactors
            termsOfUse                  = $grantSrc.termsOfUse
        }

        if ($grantSrc.PSObject.Properties.Name -contains 'authenticationStrength' -and
            $grantSrc.authenticationStrength) {

            $auth       = $grantSrc.authenticationStrength
            $hasBuiltIn = ($grant.builtInControls -and $grant.builtInControls.Count -gt 0)

            if (-not $hasBuiltIn -and $auth.requirementsSatisfied -eq 'mfa') {
                Write-Host "  CA: authenticationStrength 'mfa' mapped to builtInControls = ['mfa']." -ForegroundColor DarkYellow
                $grant.builtInControls = @('mfa')
            }
        }
    }

    $session = $obj.sessionControls

    $body = [PSCustomObject]@{
        displayName     = $obj.displayName
        state           = $obj.state
        conditions      = $conditions
        grantControls   = $grant
        sessionControls = $session
    }

    if ($obj.PSObject.Properties.Name -contains 'description' -and $obj.description) {
        $body | Add-Member -MemberType NoteProperty -Name 'description' -Value $obj.description
    }

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

    $uri      = "/v1.0/identity/conditionalAccess/policies"
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

    Connect-IntuneGraph -UseDeviceCode:$UseDeviceCode

    if (-not (Test-Path -LiteralPath $RootPath)) {
        throw "Import root path '$RootPath' does not exist."
    }

    # Build list of configPolicy folders to import based on selection
    $configFolders = @()

    if ($includeBaseline)          { $configFolders += $FolderNames.SecurityBaselines }
    if ($includeAV)                { $configFolders += $FolderNames.Antivirus }
    if ($includeDisk)              { $configFolders += $FolderNames.DiskEncryption }
    if ($includeFirewall)          { $configFolders += $FolderNames.Firewall }
    if ($includeEPM)               { $configFolders += $FolderNames.EPM }
    if ($includeEDR)               { $configFolders += $FolderNames.EDR }
    if ($includeAppControl)        { $configFolders += $FolderNames.AppControl }
    if ($includeASR)               { $configFolders += $FolderNames.ASR }
    if ($includeAccountProtection) { $configFolders += $FolderNames.AccountProtection }
    if ($includeUncategorized)     { $configFolders += $FolderNames.Uncategorized }

    if ($configFolders.Count -gt 0) {
        foreach ($folderName in $configFolders) {
            $folderPath = Join-Path $RootPath $folderName
            if (-not (Test-Path -LiteralPath $folderPath)) { continue }

            Write-Host ""
            Write-Host "Processing configuration policies in folder: $folderPath" -ForegroundColor DarkCyan

            Get-ChildItem -LiteralPath $folderPath -Filter *.json | ForEach-Object {
                Import-ConfigurationPolicyFromFile -Path $_.FullName
            }
        }
    }
    else {
        Write-Host "No Endpoint Security / Baseline / Uncategorized categories selected. Skipping configurationPolicies import." -ForegroundColor Yellow
    }

    # Device Compliance
    if ($includeDeviceCompliance) {
        $dcPath = Join-Path $RootPath $FolderNames.DeviceCompliance
        if (Test-Path -LiteralPath $dcPath) {
            Write-Host ""
            Write-Host "Processing Device Compliance policies in folder: $dcPath" -ForegroundColor DarkCyan

            Get-ChildItem -LiteralPath $dcPath -Filter *.json | ForEach-Object {
                Import-DeviceCompliancePolicyFromFile -Path $_.FullName
            }
        }
        else {
            Write-Host "Device Compliance folder '$dcPath' not found. Skipping." -ForegroundColor DarkYellow
        }
    }
    else {
        Write-Host "Device Compliance not selected. Skipping." -ForegroundColor DarkGray
    }

    # Conditional Access
    if ($includeConditionalAccess) {
        $caPath = Join-Path $RootPath $FolderNames.ConditionalAccess
        if (Test-Path -LiteralPath $caPath) {
            Write-Host ""
            Write-Host "Processing Conditional Access policies in folder: $caPath" -ForegroundColor DarkCyan

            Get-ChildItem -LiteralPath $caPath -Filter *.json | ForEach-Object {
                Import-ConditionalAccessPolicyFromFile -Path $_.FullName
            }
        }
        else {
            Write-Host "Conditional Access folder '$caPath' not found. Skipping." -ForegroundColor DarkYellow
        }
    }
    else {
        Write-Host "Conditional Access not selected. Skipping." -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "Import run complete." -ForegroundColor Cyan
}

#########################################
### BootStrapper
Import-IntuneSecurityFromExport -RootPath $ImportRootPath -UseDeviceCode:$UseDeviceCode
