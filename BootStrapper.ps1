#======================================================================================#
#                                                                                      #
#                         Intune Policy Tool - Launcher GUI                            #
##      This script is the Bootstrapper for the Intune Export and Import Scripts      ##
#                                                                                      #
#                 Script Created by Andreas Daneville 18-11-2025                       #
#======================================================================================#

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

#--------------------------
# Console hide/show helpers
#--------------------------
Add-Type @"
using System;
using System.Runtime.InteropServices;

public class WinAPI {
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
}
"@ | Out-Null

# Cache console handle once
$script:ConsolePtr = [WinAPI]::GetConsoleWindow()

function Hide-ConsoleWindow {
    if ($script:ConsolePtr -ne [IntPtr]::Zero) {
        # 0 = SW_HIDE
        [WinAPI]::ShowWindow($script:ConsolePtr, 0) | Out-Null
    }
}

function Show-ConsoleWindow {
    if ($script:ConsolePtr -ne [IntPtr]::Zero) {
        # 5 = SW_SHOW
        [WinAPI]::ShowWindow($script:ConsolePtr, 5) | Out-Null
    }
}

# Hide console while GUI is active
Hide-ConsoleWindow

#-----------------------------------------
# Global roots (shared with child scripts)
#-----------------------------------------
$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }

$Global:IntuneToolRoot     = $scriptRoot
$Global:IntuneScriptsRoot  = Join-Path $Global:IntuneToolRoot 'Scripts'
$Global:IntuneExportRoot   = Join-Path $Global:IntuneToolRoot 'Intune_Policy'  # NEW ROOT (was Export)
$Global:IntuneBaselineRoot = Join-Path $Global:IntuneToolRoot 'Baseline_Policies'  # Baseline root (mirrors Intune_Policy structure)

#========================================================================
# Ensure expected folder structure exists
#========================================================================
$Global:IntuneLogsRoot   = Join-Path $Global:IntuneToolRoot 'Logs'

$null = New-Item -Path $Global:IntuneScriptsRoot -ItemType Directory -Force -ErrorAction SilentlyContinue
$null = New-Item -Path $Global:IntuneExportRoot  -ItemType Directory -Force -ErrorAction SilentlyContinue
$null = New-Item -Path $Global:IntuneBaselineRoot -ItemType Directory -Force -ErrorAction SilentlyContinue
$null = New-Item -Path $Global:IntuneLogsRoot    -ItemType Directory -Force -ErrorAction SilentlyContinue

$exportScript = Join-Path $Global:IntuneScriptsRoot 'MSGraph-Export.ps1'
$importScript = Join-Path $Global:IntuneScriptsRoot 'MSGraph-Import.ps1'

#-------------------------
# Policy Definitions (GUI list)
#-------------------------
$Global:IntunePolicyDefinitions = @(
    [pscustomobject]@{ Key = 'EndpointSecurity-Baselines';          Title = '1. Security Baselines' }
    [pscustomobject]@{ Key = 'EndpointSecurity-Antivirus';          Title = '2. Antivirus' }
    [pscustomobject]@{ Key = 'EndpointSecurity-DiskEncryption';     Title = '3. Disk Encryption' }
    [pscustomobject]@{ Key = 'EndpointSecurity-Firewall';           Title = '4. Firewall' }
    [pscustomobject]@{ Key = 'EndpointSecurity-EPM';                Title = '5. Endpoint Privilege Management' }
    [pscustomobject]@{ Key = 'EndpointSecurity-EDR';                Title = '6. Endpoint Detection and Response' }
    [pscustomobject]@{ Key = 'EndpointSecurity-AppControl';         Title = '7. App Control for Business' }
    [pscustomobject]@{ Key = 'EndpointSecurity-ASR';                Title = '8. Attack Surface Reduction' }
    [pscustomobject]@{ Key = 'EndpointSecurity-AccountProtection';  Title = '9. Account Protection' }
    [pscustomobject]@{ Key = 'DeviceCompliance';                    Title = '10. Device Compliance' }
    [pscustomobject]@{ Key = 'Uncategorized';                       Title = '99. Uncategorized' }
)

$Global:IntuneTargetOS = $null
$Global:IntuneSelectedPolicyKeys = @()
$Global:IntuneImportSource = 'MostRecent'   # MostRecent | Baseline
$Global:IntuneImportRoot   = $Global:IntuneExportRoot

# -------------------------
# Start Page – Scope selection
# -------------------------
function Show-PolicyScopeSelectionForm {
    $script:selectedScope = $null

    $form                  = New-Object System.Windows.Forms.Form
    $form.Text             = 'Policy Scope Selection'
    $form.StartPosition    = 'CenterScreen'
    $form.Size             = New-Object System.Drawing.Size(470,230)
    $form.FormBorderStyle  = 'FixedDialog'
    $form.MaximizeBox      = $false
    $form.MinimizeBox      = $false
    $form.TopMost          = $true

    $groupBox              = New-Object System.Windows.Forms.GroupBox
    $groupBox.Text         = 'Select policy scope'
    $groupBox.Location     = New-Object System.Drawing.Point(15,15)
    $groupBox.Size         = New-Object System.Drawing.Size(420,120)

    $rbIntune              = New-Object System.Windows.Forms.RadioButton
    $rbIntune.Text         = '1. Intune Security Policies'
    $rbIntune.Location     = New-Object System.Drawing.Point(20,30)
    $rbIntune.AutoSize     = $true

    $rbCA                  = New-Object System.Windows.Forms.RadioButton
    $rbCA.Text             = '2. Conditional Access Policies'
    $rbCA.Location         = New-Object System.Drawing.Point(20,60)
    $rbCA.AutoSize         = $true

    $groupBox.Controls.Add($rbIntune)
    $groupBox.Controls.Add($rbCA)

    $btnOK                 = New-Object System.Windows.Forms.Button
    $btnOK.Text            = 'OK'
    $btnOK.Location        = New-Object System.Drawing.Point(340,150)
    $btnOK.Size            = New-Object System.Drawing.Size(95,30)
    $btnOK.Enabled         = $false

    $form.Controls.Add($groupBox)
    $form.Controls.Add($btnOK)

    $updateOk = {
        $btnOK.Enabled = ($rbIntune.Checked -or $rbCA.Checked)
    }

    $rbIntune.Add_CheckedChanged($updateOk)
    $rbCA.Add_CheckedChanged($updateOk)

    $btnOK.Add_Click({
        if ($rbIntune.Checked) { $script:selectedScope = 'IntuneSecurity' }
        elseif ($rbCA.Checked) { $script:selectedScope = 'ConditionalAccess' }
        $form.Close()
    })

    $form.Add_Shown({
        $form.Activate()
        $form.BringToFront()
    })

    [void]$form.ShowDialog()

    return $script:selectedScope  # 'IntuneSecurity' | 'ConditionalAccess' | $null (X)
}

# -------------------------
# Form – OS selection (with Back)
# -------------------------
function Show-OSSelectionForm {
    # reset selection each time the form is shown
    $script:selectedOS = $null

    $form                  = New-Object System.Windows.Forms.Form
    $form.Text             = 'Select Target OS'
    $form.StartPosition    = 'CenterScreen'
    $form.Size             = New-Object System.Drawing.Size(420,220)
    $form.FormBorderStyle  = 'FixedDialog'
    $form.MaximizeBox      = $false
    $form.MinimizeBox      = $false
    $form.TopMost          = $true

    $groupBox              = New-Object System.Windows.Forms.GroupBox
    $groupBox.Text         = 'Select OS scope'
    $groupBox.Location     = New-Object System.Drawing.Point(15,15)
    $groupBox.Size         = New-Object System.Drawing.Size(380,110)

    $rbWindows             = New-Object System.Windows.Forms.RadioButton
    $rbWindows.Text        = 'Windows'
    $rbWindows.Location    = New-Object System.Drawing.Point(20,30)
    $rbWindows.AutoSize    = $true

    $rbMac                 = New-Object System.Windows.Forms.RadioButton
    $rbMac.Text            = 'macOS'
    $rbMac.Location        = New-Object System.Drawing.Point(20,60)
    $rbMac.AutoSize        = $true

    $groupBox.Controls.Add($rbWindows)
    $groupBox.Controls.Add($rbMac)

    $btnBack               = New-Object System.Windows.Forms.Button
    $btnBack.Text          = 'Back'
    $btnBack.Location      = New-Object System.Drawing.Point(200,140)
    $btnBack.Size          = New-Object System.Drawing.Size(95,30)

    $btnOK                 = New-Object System.Windows.Forms.Button
    $btnOK.Text            = 'OK'
    $btnOK.Location        = New-Object System.Drawing.Point(300,140)
    $btnOK.Size            = New-Object System.Drawing.Size(95,30)
    $btnOK.Enabled         = $false

    $form.Controls.Add($groupBox)
    $form.Controls.Add($btnBack)
    $form.Controls.Add($btnOK)

    $updateOk = {
        $btnOK.Enabled = ($rbWindows.Checked -or $rbMac.Checked)
    }

    $rbWindows.Add_CheckedChanged($updateOk)
    $rbMac.Add_CheckedChanged($updateOk)

    $btnBack.Add_Click({
        $script:selectedOS = 'Back'
        $form.Close()
    })

    $btnOK.Add_Click({
        if ($rbWindows.Checked) { $script:selectedOS = 'Windows' }
        elseif ($rbMac.Checked) { $script:selectedOS = 'macOS' }
        $form.Close()
    })

    $form.Add_Shown({
        $form.Activate()
        $form.BringToFront()
    })

    [void]$form.ShowDialog()

    return $script:selectedOS   # 'Windows' | 'macOS' | 'Back' | $null (X)
}

#-------------------------
# Form – Export / Import
#-------------------------
function Show-MainSelectionForm {
    param(
        [ValidateSet('IntuneSecurity','ConditionalAccess')]
        [string]$Scope = 'IntuneSecurity'
    )

    # reset selection each time the form is shown
    $script:selectedAction = $null

    $form                  = New-Object System.Windows.Forms.Form
    $form.Text             = 'Intune Policy Tool'
    $form.StartPosition    = 'CenterScreen'
    $form.Size             = New-Object System.Drawing.Size(420,220)
    $form.FormBorderStyle  = 'FixedDialog'
    $form.MaximizeBox      = $false
    $form.MinimizeBox      = $false
    $form.TopMost          = $true

    $groupBox              = New-Object System.Windows.Forms.GroupBox
    $groupBox.Text         = 'Select function'
    $groupBox.Location     = New-Object System.Drawing.Point(15,15)
    $groupBox.Size         = New-Object System.Drawing.Size(380,110)

    $exportLabel = if ($Scope -eq 'ConditionalAccess') { 'Export Conditional Access Policies' } else { 'Export Intune Policies' }
    $importLabel = if ($Scope -eq 'ConditionalAccess') { 'Import Conditional Access Policies' } else { 'Import Intune Policies' }

    $rbExport              = New-Object System.Windows.Forms.RadioButton
    $rbExport.Text         = $exportLabel
    $rbExport.Location     = New-Object System.Drawing.Point(20,30)
    $rbExport.AutoSize     = $true

    $rbImport              = New-Object System.Windows.Forms.RadioButton
    $rbImport.Text         = $importLabel
    $rbImport.Location     = New-Object System.Drawing.Point(20,60)
    $rbImport.AutoSize     = $true

    $groupBox.Controls.Add($rbExport)
    $groupBox.Controls.Add($rbImport)

    $btnBack               = New-Object System.Windows.Forms.Button
    $btnBack.Text          = 'Back'
    $btnBack.Location      = New-Object System.Drawing.Point(200,140)
    $btnBack.Size          = New-Object System.Drawing.Size(95,30)

    $btnOK                 = New-Object System.Windows.Forms.Button
    $btnOK.Text            = 'OK'
    $btnOK.Location        = New-Object System.Drawing.Point(300,140)
    $btnOK.Size            = New-Object System.Drawing.Size(95,30)
    $btnOK.Enabled         = $false

    $form.Controls.Add($groupBox)
    $form.Controls.Add($btnBack)
    $form.Controls.Add($btnOK)

    $updateOk = {
        $btnOK.Enabled = ($rbExport.Checked -or $rbImport.Checked)
    }

    $rbExport.Add_CheckedChanged($updateOk)
    $rbImport.Add_CheckedChanged($updateOk)

    $btnBack.Add_Click({
        $script:selectedAction = 'Back'
        $form.Close()
    })

    $btnOK.Add_Click({
        if ($rbExport.Checked)      { $script:selectedAction = 'Export' }
        elseif ($rbImport.Checked)  { $script:selectedAction = 'Import' }
        $form.Close()
    })

    $form.Add_Shown({
        $form.Activate()
        $form.BringToFront()
    })

    [void]$form.ShowDialog()

    return $script:selectedAction   # 'Export' | 'Import' | 'Back' | $null (X)
}


#-------------------------
# Form – Import Source
#-------------------------
function Show-ImportSourceSelectionForm {
    param(
        [ValidateSet('IntuneSecurity','ConditionalAccess')]
        [string]$Scope = 'IntuneSecurity'
    )

    $script:selectedImportSource = $null

    $form                 = New-Object System.Windows.Forms.Form
    $form.Text            = 'Import Source'
    $form.StartPosition   = 'CenterScreen'
    $form.Size            = New-Object System.Drawing.Size(520,240)
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox     = $false
    $form.MinimizeBox     = $false
    $form.TopMost         = $true

    $groupBox             = New-Object System.Windows.Forms.GroupBox
    $groupBox.Text        = 'Select import source'
    $groupBox.Location    = New-Object System.Drawing.Point(15,15)
    $groupBox.Size        = New-Object System.Drawing.Size(470,130)

    $rbBaseline           = New-Object System.Windows.Forms.RadioButton
    $rbBaseline.Text      = 'Baseline Policies (Baseline_Policies)'
    $rbBaseline.Location  = New-Object System.Drawing.Point(20,35)
    $rbBaseline.AutoSize  = $true

    $rbMostRecent         = New-Object System.Windows.Forms.RadioButton
    $rbMostRecent.Text    = 'Most Recent Export (Intune_Policy)'
    $rbMostRecent.Location= New-Object System.Drawing.Point(20,70)
    $rbMostRecent.AutoSize= $true

    # Reset selection each time the form is shown (do not persist previous choice)
    $rbBaseline.Checked   = $false
    $rbMostRecent.Checked = $false

    $groupBox.Controls.Add($rbBaseline)
    $groupBox.Controls.Add($rbMostRecent)

    $btnBack              = New-Object System.Windows.Forms.Button
    $btnBack.Text         = 'Back'
    $btnBack.Location     = New-Object System.Drawing.Point(290,160)
    $btnBack.Size         = New-Object System.Drawing.Size(95,30)

    $btnOK                = New-Object System.Windows.Forms.Button
    $btnOK.Text           = 'OK'
    $btnOK.Location       = New-Object System.Drawing.Point(390,160)
    $btnOK.Size           = New-Object System.Drawing.Size(95,30)
    $btnOK.Enabled        = $false

    $form.Controls.Add($groupBox)
    $form.Controls.Add($btnBack)
    $form.Controls.Add($btnOK)

    $updateOk = {
        $btnOK.Enabled = ($rbBaseline.Checked -or $rbMostRecent.Checked)
    }

    $rbBaseline.Add_CheckedChanged($updateOk)
    $rbMostRecent.Add_CheckedChanged($updateOk)

    $btnBack.Add_Click({
        $script:selectedImportSource = 'Back'
        $form.Close()
    })

    $btnOK.Add_Click({
        if ($rbBaseline.Checked)      { $script:selectedImportSource = 'Baseline' }
        elseif ($rbMostRecent.Checked){ $script:selectedImportSource = 'MostRecent' }
        $form.Close()
    })

    $form.Add_Shown({
        $form.Activate()
        $form.BringToFront()
    })

    [void]$form.ShowDialog()

    return $script:selectedImportSource  # 'Baseline' | 'MostRecent' | 'Back' | $null (X)
}


#--------------------------
# Form – Policy selection
#--------------------------
function Show-PolicySelectionForm {
    param(
        [Parameter(Mandatory)]
        [string]$Action,

        [string[]]$ExcludeKeys = @()
    )

    # reset global + script state each time
    $Global:IntuneSelectedPolicyKeys = @()
    $script:result       = 'Cancel'
    $script:selectedKeys = @()

    $form                  = New-Object System.Windows.Forms.Form
    $form.Text             = "Select Intune Policies to Process ($Action)"
    $form.StartPosition    = 'CenterScreen'
    $form.Size             = New-Object System.Drawing.Size(500,432)
    $form.FormBorderStyle  = 'FixedDialog'
    $form.MaximizeBox      = $false
    $form.MinimizeBox      = $false
    $form.TopMost          = $true

    $groupBox              = New-Object System.Windows.Forms.GroupBox
    $groupBox.Text         = 'Select Intune Policies to Process'
    $groupBox.Location     = New-Object System.Drawing.Point(15,15)
    $groupBox.Size         = New-Object System.Drawing.Size(460,320)

    $clbPolicies           = New-Object System.Windows.Forms.CheckedListBox
    $clbPolicies.Location  = New-Object System.Drawing.Point(15,25)
    $clbPolicies.Size      = New-Object System.Drawing.Size(430,250)
    $clbPolicies.CheckOnClick  = $true
    $clbPolicies.DisplayMember = 'Title'

    foreach ($p in $Global:IntunePolicyDefinitions) {
        if ($ExcludeKeys -and ($ExcludeKeys -contains $p.Key)) { continue }
        [void]$clbPolicies.Items.Add($p)
    }

    $chkSelectAll               = New-Object System.Windows.Forms.CheckBox
    $chkSelectAll.Text          = 'Select all'
    $chkSelectAll.AutoSize      = $true
    $chkSelectAll.Location      = New-Object System.Drawing.Point(15,285)

    $groupBox.Controls.Add($clbPolicies)
    $groupBox.Controls.Add($chkSelectAll)

    $btnBack               = New-Object System.Windows.Forms.Button
    $btnBack.Text          = 'Back'
    $btnBack.Location      = New-Object System.Drawing.Point(260,350)
    $btnBack.Size          = New-Object System.Drawing.Size(80,30)

    $btnProcess            = New-Object System.Windows.Forms.Button
    $btnProcess.Text       = 'Process'
    $btnProcess.Location   = New-Object System.Drawing.Point(365,350)
    $btnProcess.Size       = New-Object System.Drawing.Size(80,30)

    $form.Controls.Add($groupBox)
    $form.Controls.Add($btnBack)
    $form.Controls.Add($btnProcess)

    $chkSelectAll.Add_CheckedChanged({
        for ($i = 0; $i -lt $clbPolicies.Items.Count; $i++) {
            $clbPolicies.SetItemChecked($i, $chkSelectAll.Checked)
        }
    })

    $btnBack.Add_Click({
        $Global:IntuneSelectedPolicyKeys = @()
        $script:result = 'Back'
        $form.Close()
    })

    $btnProcess.Add_Click({
        $checked = @($clbPolicies.CheckedItems)
        if ($checked.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show(
                "Please select at least one policy category.",
                "No selection",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            ) | Out-Null
            return
        }

        $script:selectedKeys             = $checked | ForEach-Object { $_.Key }
        $Global:IntuneSelectedPolicyKeys = $script:selectedKeys
        $script:result                   = 'Process'
        $form.Close()
    })

    $form.Add_Shown({
        $form.Activate()
        $form.BringToFront()
    })

    [void]$form.ShowDialog()

    return [pscustomobject]@{
        Result       = $script:result      # 'Back' | 'Process' | 'Cancel'
        SelectedKeys = $script:selectedKeys
    }
}

#-------------------------
# Main flow
# Start -> (1) Intune Security Policies -> OS -> Export/Import -> Policy selection -> Run
#      -> (2) Conditional Access Policies -> Export/Import -> Run (auto selects 11)
#-------------------------

while ($true) {
    # Start Page
    $scope = Show-PolicyScopeSelectionForm
    if (-not $scope) { exit }

    if ($scope -eq 'IntuneSecurity') {
        # OS loop (Back returns to Start Page)
        while ($true) {
            $osChoice = Show-OSSelectionForm
            if (-not $osChoice) { exit }
            if ($osChoice -eq 'Back') { break }

            $Global:IntuneTargetOS = $osChoice

            # Action loop (Back returns to OS selection)
            while ($true) {
                $action = Show-MainSelectionForm -Scope 'IntuneSecurity'
                if (-not $action) { exit }

                if ($action -eq 'Back') {
                    # Back to OS selector
                    break
                }


                if ($action -eq 'Import') {
                    $importSource = Show-ImportSourceSelectionForm -Scope 'IntuneSecurity'
                    if (-not $importSource) { exit }

                    if ($importSource -eq 'Back') {
                        # Back to action selector
                        continue
                    }

                    $Global:IntuneImportSource = $importSource
                    $Global:IntuneImportRoot   = if ($importSource -eq 'Baseline') { $Global:IntuneBaselineRoot } else { $Global:IntuneExportRoot }
                }
                else {
                    # For export runs, always use Intune_Policy as the working root
                    $Global:IntuneImportSource = 'MostRecent'
                    $Global:IntuneImportRoot   = $Global:IntuneExportRoot
                }

                # Policy selection
                $exclude = @()
                if ($action -eq 'Export') {
                    # Requirement: remove option 11 from Export list selector when using Intune Security Policies path
                    $exclude += 'ConditionalAccess'
                }

                $selectionResult = Show-PolicySelectionForm -Action $action -ExcludeKeys $exclude
                if (-not $selectionResult -or $selectionResult.Result -eq 'Cancel') { exit }

                switch ($selectionResult.Result) {
                    'Back' {
                        # Back to action selector
                        $Global:IntuneSelectedPolicyKeys = @()
                        continue
                    }
                    'Process' {
                        if (-not $Global:IntuneSelectedPolicyKeys -or $Global:IntuneSelectedPolicyKeys.Count -eq 0) {
                            [System.Windows.Forms.MessageBox]::Show(
                                "No policy categories selected. Aborting.",
                                "Nothing to process",
                                [System.Windows.Forms.MessageBoxButtons]::OK,
                                [System.Windows.Forms.MessageBoxIcon]::Warning
                            ) | Out-Null
                            break
                        }

                        Show-ConsoleWindow

                        switch ($action) {
                            'Export' {
                                if (Test-Path $exportScript) {
                                    & $exportScript
                                } else {
                                    [System.Windows.Forms.MessageBox]::Show(
                                        "Export script not found at:`n$exportScript",
                                        "Script missing",
                                        [System.Windows.Forms.MessageBoxButtons]::OK,
                                        [System.Windows.Forms.MessageBoxIcon]::Error
                                    ) | Out-Null
                                }
                            }
                            'Import' {
                                if (Test-Path $importScript) {
                                    & $importScript
                                } else {
                                    [System.Windows.Forms.MessageBox]::Show(
                                        "Import script not found at:`n$importScript",
                                        "Script missing",
                                        [System.Windows.Forms.MessageBoxButtons]::OK,
                                        [System.Windows.Forms.MessageBoxIcon]::Error
                                    ) | Out-Null
                                }
                            }
                        }

                        exit
                    }
                }
            }
        }

        # Returned to Start Page
        continue
    }

    if ($scope -eq 'ConditionalAccess') {
        # CA path -> action selector -> auto select ConditionalAccess (11)
        while ($true) {
            $action = Show-MainSelectionForm -Scope 'ConditionalAccess'
            if (-not $action) { exit }

            if ($action -eq 'Back') {
                # Back to Start Page
                break
            }

            if ($action -eq 'Import') {
                $importSource = Show-ImportSourceSelectionForm -Scope 'ConditionalAccess'
                if (-not $importSource) { exit }

                if ($importSource -eq 'Back') {
                    # Back to action selector
                    continue
                }

                $Global:IntuneImportSource = $importSource
                $Global:IntuneImportRoot   = if ($importSource -eq 'Baseline') { $Global:IntuneBaselineRoot } else { $Global:IntuneExportRoot }
            }
            else {
                $Global:IntuneImportSource = 'MostRecent'
                $Global:IntuneImportRoot   = $Global:IntuneExportRoot
            }

            # Auto-select CA (11) because this path implies Conditional Access
            $Global:IntuneSelectedPolicyKeys = @('ConditionalAccess')

            Show-ConsoleWindow

            switch ($action) {
                'Export' {
                    if (Test-Path $exportScript) {
                        & $exportScript
                    } else {
                        [System.Windows.Forms.MessageBox]::Show(
                            "Export script not found at:`n$exportScript",
                            "Script missing",
                            [System.Windows.Forms.MessageBoxButtons]::OK,
                            [System.Windows.Forms.MessageBoxIcon]::Error
                        ) | Out-Null
                    }
                }
                'Import' {
                    if (Test-Path $importScript) {
                        & $importScript
                    } else {
                        [System.Windows.Forms.MessageBox]::Show(
                            "Import script not found at:`n$importScript",
                            "Script missing",
                            [System.Windows.Forms.MessageBoxButtons]::OK,
                            [System.Windows.Forms.MessageBoxIcon]::Error
                        ) | Out-Null
                    }
                }
            }

            exit
        }

        continue
    }
}