##################################################
#
## Intune Endpoint Security Exporter
##  - Common helpers + Graph bootstrap
#
##################################################

[CmdletBinding()]
param(
    [string]$ExportRootPath = (Join-Path ($(if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path })) 'Export'),
    [switch]$UseDeviceCode
)


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

# (Intune helpers + main orchestrator will come later)


#########################################
### BootStrapper
Ensure-GraphModule
Connect-IntuneGraph