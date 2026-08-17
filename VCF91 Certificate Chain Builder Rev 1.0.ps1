<#
.SYNOPSIS
Builds VCF 9 certificate-chain PEM files from individual machine certificates.
.DESCRIPTION
Select a required root CA certificate, an optional intermediate CA certificate, and a
folder containing machine certificates. For each supported machine certificate, the
script creates <original-name>_chain.pem in the same folder, ordered as:
  1. Machine certificate
  2. Intermediate certificate, when selected
  3. Root certificate
The original files are never changed.

The script validates certificate parsing, certificate roles, issuer/subject linkage,
duplicate certificates, source-folder contamination, existing output files, and
private-key material. No VMware modules are required.
#>
[CmdletBinding()]
param([switch]$NoRelaunch)

$Global:VCFCertificateChainBuilderVersion = '1.0.1'
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Relaunch in STA for WPF. This is inherited from the foundation script.
try {
    $pwsh = (Get-Process -Id $PID -ErrorAction SilentlyContinue).Path
    if (-not $pwsh) { $pwsh = 'pwsh.exe' }
} catch { $pwsh = 'pwsh.exe' }
try {
    if (-not $NoRelaunch -and [Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
        & $pwsh -NoProfile -ExecutionPolicy Bypass -STA -File "$PSCommandPath" -NoRelaunch
        exit $LASTEXITCODE
    }
} catch {}

$script:RunDir = $null
$Global:LogFile = $null
$script:Results = @()
$script:SupportedExtensions = @('.pem', '.cer', '.crt', '.cr')

function New-RunDir {
    # Default logs to the folder containing this script. If the script path is unavailable,
    # use the current working directory as a safe fallback.
    $base = if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot) -and (Test-Path -LiteralPath $PSScriptRoot -PathType Container)) {
        $PSScriptRoot
    } else {
        (Get-Location).Path
    }
    $script:RunDir = $base
    $Global:LogFile = Join-Path $script:RunDir ('VCF-Certificate-Chain-Builder-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.log')
    '' | Set-Content -LiteralPath $Global:LogFile -Encoding utf8
}

function Write-Log {
    param([string]$Message, [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO')
    $line = '[{0}][{1}] {2}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff'), $Level, $Message
    try { if ($Global:LogFile) { Add-Content -LiteralPath $Global:LogFile -Value $line -Encoding utf8 } } catch {}
    try {
        if ($script:txtLog) {
            $script:txtLog.AppendText("$line`r`n")
            $script:txtLog.ScrollToEnd()
        }
    } catch {}
    Write-Host $line
}

function Show-InfoMessage {
    param([string]$Message, [string]$Title = 'VCF Certificate Chain Builder')
    [System.Windows.MessageBox]::Show($Message, $Title, 'OK', 'Information') | Out-Null
}
function Show-WarnMessage {
    param([string]$Message, [string]$Title = 'VCF Certificate Chain Builder')
    [System.Windows.MessageBox]::Show($Message, $Title, 'OK', 'Warning') | Out-Null
}
function Show-ErrorMessage {
    param([string]$Message, [string]$Title = 'VCF Certificate Chain Builder')
    [System.Windows.MessageBox]::Show($Message, $Title, 'OK', 'Error') | Out-Null
}

function Set-StatusText {
    param($Label, [string]$Text, [ValidateSet('OK','WARN','FAIL','INFO')][string]$State = 'INFO')
    if (-not $Label) { return }
    $colors = @{ OK='#7FD37F'; WARN='#D6C15A'; FAIL='#D97878'; INFO='#E6E6E6' }
    $Label.Text = $Text
    $Label.Foreground = [Windows.Media.BrushConverter]::new().ConvertFromString($colors[$State])
}

function Set-RunStatus {
    param([string]$Text = 'Ready', [ValidateSet('Ready','Running','Failed')][string]$State = 'Ready')
    if (-not $script:lblRunStatus) { return }
    $colors = @{ Ready='#7FD37F'; Running='#6FA8DC'; Failed='#D97878' }
    $script:lblRunStatus.Text = $Text
    $script:lblRunStatus.Foreground = [Windows.Media.BrushConverter]::new().ConvertFromString($colors[$State])
}

function Prereq-Check {
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        Set-StatusText $script:lblPS "PowerShell $($PSVersionTable.PSVersion): OK" OK
    } else {
        Set-StatusText $script:lblPS "PowerShell $($PSVersionTable.PSVersion): version 7+ required" FAIL
    }
    Set-StatusText $script:lblWPF '.NET/WPF: OK' OK
    Set-StatusText $script:lblCrypto 'X509 certificate APIs: Built-in' OK
    Set-StatusText $script:lblModules 'External modules: None required' OK
}

function ConvertTo-NormalizedPem {
    param([byte[]]$RawData)
    $b64 = [Convert]::ToBase64String($RawData, [Base64FormattingOptions]::InsertLineBreaks)
    "-----BEGIN CERTIFICATE-----`r`n$b64`r`n-----END CERTIFICATE-----"
}

function Get-PemCertificateBlocks {
    param([string]$Text)
    $matches = [regex]::Matches($Text, '(?is)-----BEGIN\s+CERTIFICATE-----\s*(?<b64>[A-Za-z0-9+/=\r\n\t ]+?)\s*-----END\s+CERTIFICATE-----')
    @($matches)
}

function Read-CertificateFile {
    param([Parameter(Mandatory)][string]$Path, [switch]$RequireSingle)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Certificate file does not exist: $Path" }
    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -eq 0) { throw "Certificate file is empty: $Path" }

    $text = [Text.Encoding]::UTF8.GetString($bytes)
    if ($text -match '(?i)-----BEGIN (RSA |EC |ENCRYPTED )?PRIVATE KEY-----') {
        throw "Private-key material was found. Only public certificate files are allowed: $Path"
    }

    $certs = [System.Collections.Generic.List[object]]::new()
    $blocks = @(Get-PemCertificateBlocks -Text $text)
    if ($blocks.Count -gt 0) {
        foreach ($block in $blocks) {
            try {
                $clean = [regex]::Replace($block.Groups['b64'].Value, '\s', '')
                $raw = [Convert]::FromBase64String($clean)
                $cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new($raw)
                $certs.Add($cert) | Out-Null
            } catch { throw "Invalid PEM certificate block in '$Path': $($_.Exception.Message)" }
        }
    } else {
        try {
            $cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes)
            $certs.Add($cert) | Out-Null
        } catch {
            throw "'$Path' is not a readable PEM or DER X.509 certificate. $($_.Exception.Message)"
        }
    }

    if ($RequireSingle -and $certs.Count -ne 1) {
        throw "Exactly one certificate is required in '$Path'; found $($certs.Count)."
    }
    if ($certs.Count -eq 0) { throw "No certificate was found in '$Path'." }
    @($certs)
}

function Test-IsCertificateAuthority {
    param([Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    foreach ($extension in $Certificate.Extensions) {
        if ($extension.Oid.Value -eq '2.5.29.19') {
            try {
                $bc = [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]$extension
                return [bool]$bc.CertificateAuthority
            } catch { return $false }
        }
    }
    $false
}

function Test-IsSelfSigned {
    param([Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $Certificate.Subject -eq $Certificate.Issuer
}

function Get-CertificateSummary {
    param([Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    [pscustomobject]@{
        Subject = $Certificate.Subject
        Issuer = $Certificate.Issuer
        Thumbprint = $Certificate.Thumbprint
        NotBefore = $Certificate.NotBefore
        NotAfter = $Certificate.NotAfter
        IsCA = Test-IsCertificateAuthority $Certificate
        IsSelfSigned = Test-IsSelfSigned $Certificate
    }
}

function Test-CertificateLink {
    param(
        [Security.Cryptography.X509Certificates.X509Certificate2]$Child,
        [Security.Cryptography.X509Certificates.X509Certificate2]$Issuer
    )
    $Child.Issuer -eq $Issuer.Subject
}

function Get-MachineCertificateFiles {
    param([string]$Folder)
    if (-not (Test-Path -LiteralPath $Folder -PathType Container)) { throw 'Select a valid machine-certificate folder.' }
    @(
        Get-ChildItem -LiteralPath $Folder -File |
        Where-Object {
            $script:SupportedExtensions -contains $_.Extension.ToLowerInvariant() -and
            $_.BaseName -notmatch '(?i)_chain$'
        } |
        Sort-Object Name
    )
}

function Test-Inputs {
    param([switch]$UpdateGrid)
    $rootPath = ([string]$script:txtRootPath.Text).Trim()
    $intermediatePath = ([string]$script:txtIntermediatePath.Text).Trim()
    $machineFolder = ([string]$script:txtMachineFolder.Text).Trim()
    if (-not $rootPath) { throw 'Select the required root certificate file.' }
    if (-not $machineFolder) { throw 'Select the folder containing machine certificates.' }

    $root = @(Read-CertificateFile -Path $rootPath -RequireSingle)[0]
    if (-not (Test-IsCertificateAuthority $root)) { throw 'The selected root certificate is not marked as a Certificate Authority.' }
    if (-not (Test-IsSelfSigned $root)) {
        Write-Log "Root certificate Subject does not match Issuer. Continuing by administrator request. Subject: $($root.Subject) | Issuer: $($root.Issuer)" WARN
    }

    $intermediate = $null
    if ($intermediatePath) {
        $intermediate = @(Read-CertificateFile -Path $intermediatePath -RequireSingle)[0]
        if (-not (Test-IsCertificateAuthority $intermediate)) { throw 'The selected intermediate certificate is not marked as a Certificate Authority.' }
        if (Test-IsSelfSigned $intermediate) {
            Write-Log "Intermediate certificate Subject matches Issuer. Continuing by administrator request. Subject: $($intermediate.Subject)" WARN
        }
        if (-not (Test-CertificateLink -Child $intermediate -Issuer $root)) {
            Write-Log "Intermediate Issuer does not match selected root Subject. Continuing by administrator request. Intermediate Issuer: $($intermediate.Issuer) | Root Subject: $($root.Subject)" WARN
        }
    }

    $files = @(Get-MachineCertificateFiles -Folder $machineFolder)
    if ($files.Count -eq 0) { throw 'No supported machine certificate files were found. Supported extensions: .pem, .cer, .crt, .cr' }

    $rootFull = [IO.Path]::GetFullPath($rootPath)
    $intFull = if ($intermediatePath) { [IO.Path]::GetFullPath($intermediatePath) } else { '' }
    $folderFull = [IO.Path]::GetFullPath($machineFolder).TrimEnd([IO.Path]::DirectorySeparatorChar)
    foreach ($selectedPath in @($rootFull, $intFull) | Where-Object { $_ }) {
        $parent = [IO.Path]::GetDirectoryName($selectedPath).TrimEnd([IO.Path]::DirectorySeparatorChar)
        if ($parent -ieq $folderFull) {
            throw 'The selected root or intermediate certificate is located inside the machine-certificate folder. Move CA certificates outside that folder before continuing.'
        }
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($file in $files) {
        $status = 'Ready'
        $message = 'Validated'
        $subject = ''
        try {
            $machineCerts = @(Read-CertificateFile -Path $file.FullName -RequireSingle)
            $machine = $machineCerts[0]
            $subject = $machine.Subject
            if ($machine.Thumbprint -eq $root.Thumbprint -or ($intermediate -and $machine.Thumbprint -eq $intermediate.Thumbprint)) {
                throw 'Selected root or intermediate certificate was found in the machine-certificate folder.'
            }
            if (Test-IsCertificateAuthority $machine) {
                throw 'A CA certificate was found in the machine-certificate folder. Only machine/leaf certificates are allowed.'
            }
            $expectedIssuer = if ($intermediate) { $intermediate } else { $root }
            if (-not (Test-CertificateLink -Child $machine -Issuer $expectedIssuer)) {
                $status = 'Warning'
                $message = "Issuer/Subject linkage could not be confirmed; processing is allowed. Machine Issuer: $($machine.Issuer) | Expected CA Subject: $($expectedIssuer.Subject)"
                Write-Log "Certificate linkage warning for '$($file.Name)': $message" WARN
            }
            $output = Join-Path $machineFolder ($file.BaseName + '_chain.pem')
            if (Test-Path -LiteralPath $output) {
                $status = 'Warning'
                $overwriteMessage = 'Output already exists and will require overwrite confirmation.'
                $message = if ($message -and $message -ne 'Validated') { "$message $overwriteMessage" } else { $overwriteMessage }
            }
        } catch {
            $status = 'Blocked'
            $message = $_.Exception.Message
        }
        $rows.Add([pscustomobject]@{ File=$file.Name; Subject=$subject; Status=$status; Message=$message }) | Out-Null
    }

    if ($UpdateGrid) { $script:dgPreview.ItemsSource = @($rows) }
    $blocked = @($rows | Where-Object Status -eq 'Blocked')
    if ($blocked.Count -gt 0) {
        throw "Validation blocked processing for $($blocked.Count) file(s). Review the preview and log. No files were created."
    }

    [pscustomobject]@{ Root=$root; Intermediate=$intermediate; Files=$files; Rows=@($rows); MachineFolder=$machineFolder }
}

function Invoke-ChainBuild {
    $validation = Test-Inputs -UpdateGrid
    $existing = @()
    foreach ($file in $validation.Files) {
        $out = Join-Path $validation.MachineFolder ($file.BaseName + '_chain.pem')
        if (Test-Path -LiteralPath $out) { $existing += $out }
    }
    if ($existing.Count -gt 0) {
        $answer = [System.Windows.MessageBox]::Show(
            "$($existing.Count) _chain output file(s) already exist and will be overwritten.`n`nOriginal machine certificate files will remain unchanged.`n`nContinue?",
            'Overwrite existing chain files', 'YesNo', 'Warning')
        if ($answer -ne 'Yes') { Write-Log 'Build canceled by user because output files already exist.' WARN; return }
    }

    $answer = [System.Windows.MessageBox]::Show(
        "Create $($validation.Files.Count) VCF certificate-chain PEM file(s)?`n`nOrder: machine, intermediate (if selected), root.`nOriginal files will not be modified.",
        'Build certificate chains', 'YesNo', 'Question')
    if ($answer -ne 'Yes') { Write-Log 'Build canceled by user.' WARN; return }

    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($file in $validation.Files) {
        try {
            $machine = @(Read-CertificateFile -Path $file.FullName -RequireSingle)[0]
            $parts = [System.Collections.Generic.List[string]]::new()
            $parts.Add((ConvertTo-NormalizedPem $machine.RawData)) | Out-Null
            if ($validation.Intermediate) { $parts.Add((ConvertTo-NormalizedPem $validation.Intermediate.RawData)) | Out-Null }
            $parts.Add((ConvertTo-NormalizedPem $validation.Root.RawData)) | Out-Null
            $content = ($parts -join "`r`n") + "`r`n"
            $output = Join-Path $validation.MachineFolder ($file.BaseName + '_chain.pem')
            [IO.File]::WriteAllText($output, $content, [Text.UTF8Encoding]::new($false))

            # Secondary verification: re-read output and verify count/order by thumbprint.
            $written = @(Read-CertificateFile -Path $output)
            $expected = @($machine) + $(if ($validation.Intermediate) { @($validation.Intermediate) } else { @() }) + @($validation.Root)
            if ($written.Count -ne $expected.Count) { throw 'Post-write verification found an incorrect certificate count.' }
            for ($i = 0; $i -lt $expected.Count; $i++) {
                if ($written[$i].Thumbprint -ne $expected[$i].Thumbprint) { throw "Post-write verification found incorrect certificate order at position $($i + 1)." }
            }
            Write-Log "Created and verified: $output"
            $results.Add([pscustomobject]@{ File=$file.Name; Output=[IO.Path]::GetFileName($output); Status='Created'; Message='Chain order verified' }) | Out-Null
        } catch {
            Write-Log "Failed '$($file.FullName)': $($_.Exception.Message)" ERROR
            $results.Add([pscustomobject]@{ File=$file.Name; Output=''; Status='Failed'; Message=$_.Exception.Message }) | Out-Null
        }
    }
    $script:Results = @($results)
    $script:dgPreview.ItemsSource = $script:Results
    $failed = @($results | Where-Object Status -eq 'Failed')
    if ($failed.Count) {
        Set-RunStatus "Completed with $($failed.Count) failure(s)" Failed
        Show-ErrorMessage "Processing completed with $($failed.Count) failure(s). Review the preview and log:`n$Global:LogFile" 'Completed with errors'
    } else {
        Set-RunStatus "Created $($results.Count) chain file(s)" Ready
        Show-InfoMessage "Successfully created and verified $($results.Count) chain file(s) in:`n$($validation.MachineFolder)" 'Build complete'
    }
}

function Set-Busy {
    param([bool]$Busy)
    foreach ($control in @($script:btnBrowseRoot,$script:btnBrowseIntermediate,$script:btnClearIntermediate,$script:btnBrowseFolder,$script:btnValidate,$script:btnBuild,$script:btnOpenFolder,$script:btnOpenLog,$script:btnRecheck)) {
        if ($control) { $control.IsEnabled = -not $Busy }
    }
    if ($Busy) { Set-RunStatus 'Working...' Running } else { Refresh-UIState }
}

function Refresh-UIState {
    $root = -not [string]::IsNullOrWhiteSpace([string]$script:txtRootPath.Text)
    $folder = -not [string]::IsNullOrWhiteSpace([string]$script:txtMachineFolder.Text)
    if ($script:btnValidate) { $script:btnValidate.IsEnabled = $root -and $folder }
    if ($script:btnBuild) { $script:btnBuild.IsEnabled = $root -and $folder }
    if ($script:lblRunStatus.Text -eq 'Working...') { return }
    Set-RunStatus Ready Ready
}

Add-Type -AssemblyName PresentationCore,PresentationFramework,WindowsBase -ErrorAction Stop | Out-Null
Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop | Out-Null

$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" Title="VCF 9 Certificate Chain Builder" Height="790" Width="1180" MinHeight="700" MinWidth="980" WindowStartupLocation="CenterScreen" Background="#050A0D" FontFamily="Segoe UI" Foreground="#E6E6E6">
<Window.Resources>
<SolidColorBrush x:Key="Panel2" Color="#0A1418"/><SolidColorBrush x:Key="Accent" Color="#29B6F6"/><SolidColorBrush x:Key="Text" Color="#E6E6E6"/><SolidColorBrush x:Key="Muted" Color="#9CB5C0"/>
<Style TargetType="TextBlock"><Setter Property="Foreground" Value="{StaticResource Text}"/><Setter Property="Margin" Value="0,4,8,4"/></Style>
<Style TargetType="TextBox"><Setter Property="Background" Value="#050A0D"/><Setter Property="Foreground" Value="{StaticResource Text}"/><Setter Property="BorderBrush" Value="#607D8B"/><Setter Property="Margin" Value="0,2,8,8"/><Setter Property="Padding" Value="6"/></Style>
<Style TargetType="Button"><Setter Property="Background" Value="{StaticResource Accent}"/><Setter Property="Foreground" Value="#071218"/><Setter Property="FontWeight" Value="SemiBold"/><Setter Property="BorderThickness" Value="0"/><Setter Property="Padding" Value="12,6"/><Setter Property="Margin" Value="0,4,8,4"/><Setter Property="MinWidth" Value="105"/></Style>
<Style TargetType="GroupBox"><Setter Property="Foreground" Value="{StaticResource Text}"/><Setter Property="Background" Value="{StaticResource Panel2}"/><Setter Property="BorderBrush" Value="#2B4D59"/><Setter Property="Margin" Value="8"/><Setter Property="Padding" Value="10"/></Style>
<Style TargetType="DataGrid"><Setter Property="Background" Value="#050A0D"/><Setter Property="Foreground" Value="#E6E6E6"/><Setter Property="RowBackground" Value="#071116"/><Setter Property="AlternatingRowBackground" Value="#0B1A20"/><Setter Property="HeadersVisibility" Value="Column"/></Style>
<Style TargetType="DataGridColumnHeader"><Setter Property="Background" Value="#0A1418"/><Setter Property="Foreground" Value="#E6E6E6"/><Setter Property="FontWeight" Value="SemiBold"/></Style>
</Window.Resources>
<Grid Margin="14"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
<GroupBox Grid.Row="0" Header="Prerequisites and Status"><Grid><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><WrapPanel Grid.Column="0"><TextBlock Name="lblPS" Text="PowerShell"/><TextBlock Name="lblWPF" Text="WPF"/><TextBlock Name="lblCrypto" Text="X509"/><TextBlock Name="lblModules" Text="Modules"/></WrapPanel><StackPanel Grid.Column="1" Orientation="Horizontal"><Button Name="btnRecheck" Content="Recheck"/><TextBlock Name="lblRunStatus" Text="Ready" FontWeight="SemiBold" Margin="16,9,0,0"/></StackPanel></Grid></GroupBox>
<GroupBox Grid.Row="1" Header="Certificate Inputs"><Grid><Grid.ColumnDefinitions><ColumnDefinition Width="170"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
<TextBlock Grid.Row="0" Grid.Column="0" Text="Root certificate (required)" VerticalAlignment="Center"/><TextBox Grid.Row="0" Grid.Column="1" Name="txtRootPath" IsReadOnly="True"/><Button Grid.Row="0" Grid.Column="2" Name="btnBrowseRoot" Content="Browse Root"/>
<TextBlock Grid.Row="1" Grid.Column="0" Text="Intermediate (optional)" VerticalAlignment="Center"/><TextBox Grid.Row="1" Grid.Column="1" Name="txtIntermediatePath" IsReadOnly="True"/><Button Grid.Row="1" Grid.Column="2" Name="btnBrowseIntermediate" Content="Browse Intermediate"/><Button Grid.Row="1" Grid.Column="3" Name="btnClearIntermediate" Content="Clear" MinWidth="65"/>
<TextBlock Grid.Row="2" Grid.Column="0" Text="Machine certificate folder" VerticalAlignment="Center"/><TextBox Grid.Row="2" Grid.Column="1" Name="txtMachineFolder" IsReadOnly="True"/><Button Grid.Row="2" Grid.Column="2" Name="btnBrowseFolder" Content="Browse Folder"/>
</Grid></GroupBox>
<Grid Grid.Row="2"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
<GroupBox Grid.Row="0" Header="Actions"><StackPanel><TextBlock Foreground="{StaticResource Muted}" TextWrapping="Wrap" Text="Supported inputs: PEM or DER X.509 certificate data in .pem, .cer, .crt, or .cr files. Outputs are named &lt;original&gt;_chain.pem and are written beside the machine certificates. Existing _chain files are not treated as inputs."/><WrapPanel><Button Name="btnValidate" Content="Validate Inputs"/><Button Name="btnBuild" Content="Build Chains"/><Button Name="btnOpenFolder" Content="Open Machine Folder"/><Button Name="btnOpenLog" Content="Open Log Folder"/></WrapPanel></StackPanel></GroupBox>
<Grid Grid.Row="1"><Grid.ColumnDefinitions><ColumnDefinition Width="1.12*"/><ColumnDefinition Width="0.88*"/></Grid.ColumnDefinitions><GroupBox Grid.Column="0" Header="Validation / Results"><DataGrid Name="dgPreview" AutoGenerateColumns="True" IsReadOnly="True"/></GroupBox><GroupBox Grid.Column="1" Header="Log"><TextBox Name="txtLog" AcceptsReturn="True" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto" IsReadOnly="True" FontFamily="Consolas" FontSize="12" TextWrapping="NoWrap"/></GroupBox></Grid>
</Grid></Grid></Window>
"@

$script:window = [Windows.Markup.XamlReader]::Parse($xaml)
foreach ($name in @('lblPS','lblWPF','lblCrypto','lblModules','lblRunStatus','btnRecheck','txtRootPath','btnBrowseRoot','txtIntermediatePath','btnBrowseIntermediate','btnClearIntermediate','txtMachineFolder','btnBrowseFolder','btnValidate','btnBuild','btnOpenFolder','btnOpenLog','dgPreview','txtLog')) {
    Set-Variable -Name $name -Scope Script -Value $script:window.FindName($name)
}

function Select-CertificateFile {
    param([string]$Title)
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Title = $Title
    $dlg.Filter = 'Certificate files (*.pem;*.cer;*.crt;*.cr)|*.pem;*.cer;*.crt;*.cr|All files (*.*)|*.*'
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $dlg.FileName } else { $null }
}

$script:window.Add_ContentRendered({
    New-RunDir
    Prereq-Check
    Write-Log "==== VCF Certificate Chain Builder started v$Global:VCFCertificateChainBuilderVersion ===="
    Write-Log "Log folder: $script:RunDir"
    Refresh-UIState
})
$script:btnRecheck.Add_Click({ Prereq-Check })
$script:btnBrowseRoot.Add_Click({ $p = Select-CertificateFile 'Select root certificate'; if ($p) { $script:txtRootPath.Text=$p; Write-Log "Selected root: $p"; Refresh-UIState } })
$script:btnBrowseIntermediate.Add_Click({ $p = Select-CertificateFile 'Select optional intermediate certificate'; if ($p) { $script:txtIntermediatePath.Text=$p; Write-Log "Selected intermediate: $p"; Refresh-UIState } })
$script:btnClearIntermediate.Add_Click({ $script:txtIntermediatePath.Clear(); Write-Log 'Intermediate selection cleared.'; Refresh-UIState })
$script:btnBrowseFolder.Add_Click({
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = 'Select folder containing only machine/leaf certificates'
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $script:txtMachineFolder.Text=$dlg.SelectedPath; Write-Log "Selected machine folder: $($dlg.SelectedPath)"; Refresh-UIState }
})
$script:btnValidate.Add_Click({
    try { Set-Busy $true; $v=Test-Inputs -UpdateGrid; $warningCount=@($v.Rows | Where-Object Status -eq 'Warning').Count; Write-Log "Validation passed for $($v.Files.Count) machine certificate(s), with $warningCount warning(s)."; Show-InfoMessage "Validation passed for $($v.Files.Count) machine certificate(s), with $warningCount warning(s). Subject/Issuer linkage warnings do not block processing. No files were created." 'Validation passed'; Set-Busy $false }
    catch { Write-Log "Validation failed: $($_.Exception.Message)" ERROR; Set-RunStatus 'Validation failed' Failed; Show-ErrorMessage $_.Exception.Message 'Validation failed'; Set-Busy $false }
})
$script:btnBuild.Add_Click({
    try { Set-Busy $true; Invoke-ChainBuild; Set-Busy $false }
    catch { Write-Log "Build blocked: $($_.Exception.Message)" ERROR; Set-RunStatus 'Build blocked' Failed; Show-ErrorMessage $_.Exception.Message 'Build blocked'; Set-Busy $false }
})
$script:btnOpenFolder.Add_Click({ try { $p=([string]$script:txtMachineFolder.Text).Trim(); if (-not (Test-Path -LiteralPath $p -PathType Container)) { throw 'Select a valid machine-certificate folder first.' }; Start-Process explorer.exe -ArgumentList "`"$p`"" } catch { Show-ErrorMessage $_.Exception.Message } })
$script:btnOpenLog.Add_Click({ try { Start-Process explorer.exe -ArgumentList "`"$script:RunDir`"" } catch { Show-ErrorMessage $_.Exception.Message } })

$null = $script:window.ShowDialog()
