#======================================================================================#
#                                                                                      #
#                         Intune Policy Tool - Launcher GUI                            #
##      This script is the Bootstrapper for the Intune Export and Import Scripts      ##
#                                                                                      #
#                 Script Created by Andreas Daneville 18-11-2025                       #
#======================================================================================#

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

#-------------------------
# Global roots (shared with child scripts)
#-------------------------
$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }

$Global:IntuneToolRoot     = $scriptRoot
$Global:IntuneScriptsRoot  = Join-Path $Global:IntuneToolRoot 'Scripts'
$Global:IntuneExportRoot   = Join-Path $Global:IntuneToolRoot 'Export'

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
    [pscustomobject]@{ Key = 'EndpointSecurity-ASR';                Title = '8. Attack surface reduction' }
    [pscustomobject]@{ Key = 'EndpointSecurity-AccountProtection';  Title = '9. Account protection' }
    [pscustomobject]@{ Key = 'DeviceCompliance';                    Title = '10. Device Compliance' }
    [pscustomobject]@{ Key = 'ConditionalAccess';                   Title = '11. Conditional Access' }
    [pscustomobject]@{ Key = 'Uncategorized';                       Title = '99. Uncategorized' }
)

$Global:IntuneSelectedPolicyKeys = @()

#-------------------------
# Form 1 – Export / Import
#-------------------------
function Show-MainSelectionForm {
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

    $rbExport              = New-Object System.Windows.Forms.RadioButton
    $rbExport.Text         = 'Export Intune Policies'
    $rbExport.Location     = New-Object System.Drawing.Point(20,30)
    $rbExport.AutoSize     = $true

    $rbImport              = New-Object System.Windows.Forms.RadioButton
    $rbImport.Text         = 'Import Intune Policies'
    $rbImport.Location     = New-Object System.Drawing.Point(20,60)
    $rbImport.AutoSize     = $true

    $groupBox.Controls.Add($rbExport)
    $groupBox.Controls.Add($rbImport)

    $btnOK                 = New-Object System.Windows.Forms.Button
    $btnOK.Text            = 'OK'
    $btnOK.Location        = New-Object System.Drawing.Point(300,140)
    $btnOK.Size            = New-Object System.Drawing.Size(95,30)
    $btnOK.Enabled         = $false

    $form.Controls.Add($groupBox)
    $form.Controls.Add($btnOK)

    $selectedAction = $null

    $updateOk = {
        $btnOK.Enabled = ($rbExport.Checked -or $rbImport.Checked)
    }

    $rbExport.Add_CheckedChanged($updateOk)
    $rbImport.Add_CheckedChanged($updateOk)

    $btnOK.Add_Click({
        if ($rbExport.Checked)      { $script:selectedAction = 'Export' }
        elseif ($rbImport.Checked) { $script:selectedAction = 'Import' }
        $form.Close()
    })

    $form.Add_Shown({
        $form.Activate()
        $form.BringToFront()
    })

    [void]$form.ShowDialog()

    return $script:selectedAction   # $null if user hit X
}

#-------------------------
# Form 2 – Policy selection
#-------------------------
function Show-PolicySelectionForm {
    param(
        [Parameter(Mandatory)]
        [string]$Action
    )

    $Global:IntuneSelectedPolicyKeys = @()

    $form                  = New-Object System.Windows.Forms.Form
    $form.Text             = "Select Intune Policies to Process ($Action)"
    $form.StartPosition    = 'CenterScreen'
    $form.Size             = New-Object System.Drawing.Size(500,420)
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
    $clbPolicies.DisplayMember = 'Title'   # what user sees

    foreach ($p in $Global:IntunePolicyDefinitions) {
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

    $result      = 'Cancel'   # default if X is pressed
    $selectedKeys = @()

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

        $script:selectedKeys               = $checked | ForEach-Object { $_.Key }
        $Global:IntuneSelectedPolicyKeys   = $script:selectedKeys
        $script:result                     = 'Process'
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
#-------------------------
while ($true) {
    # Form 1
    $action = Show-MainSelectionForm
    if (-not $action) {
        # User closed with X -> terminate script
        break
    }

    # Form 2
    $selectionResult = Show-PolicySelectionForm -Action $action
    if (-not $selectionResult -or $selectionResult.Result -eq 'Cancel') {
        # User hit X on second form -> terminate
        break
    }

    switch ($selectionResult.Result) {
        'Back' {
            # Clear any previous selection and go back to first screen
            $Global:IntuneSelectedPolicyKeys = @()
            continue    # restart while-loop -> show Form 1 again
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

            break   # after processing, exit loop/script
        }
        default {
            break   # safety
        }
    }
}

