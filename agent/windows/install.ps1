<#
.SYNOPSIS
Installs, updates or removes the OSCompliance agent for Windows.

.DESCRIPTION
Run from an elevated PowerShell. Without a package next to it, the script
downloads the Windows package of the release from GitHub and checks it against
SHA256SUMS. It copies oscompliance-agent.exe to Program Files, creates
C:\ProgramData\oscompliance readable only by SYSTEM and Administrators, asks the
engine for the Wazuh group, adds the facts file to the local Wazuh agent,
schedules the hourly pass and the audit guard every two minutes as SYSTEM, and
runs the first pass.

.PARAMETER Group
Wazuh group the engine adds this machine to. Defaults to ens.

.PARAMETER Release
Release to download, such as 1.3.0. Defaults to the release this script belongs to, or the latest one.

.PARAMETER Source
Folder that holds oscompliance-agent.exe. Defaults to the folder of this script.

.PARAMETER Uninstall
Removes the tasks, the binary, the event source and the facts file entry of the Wazuh agent. Keeps the data folder unless Purge is set.

.PARAMETER Purge
With Uninstall, also deletes C:\ProgramData\oscompliance.
#>
[CmdletBinding()]
param(
  [ValidatePattern('^[A-Za-z0-9._-]{1,255}$')]
  [string]$Group = 'ens',
  [string]$Release = $env:OSC_RELEASE,
  [string]$Source = $PSScriptRoot,
  [switch]$Uninstall,
  [switch]$Purge
)

$ErrorActionPreference = 'Stop'

$InstallDir = Join-Path $env:ProgramFiles 'OSCompliance'
$Binary = Join-Path $InstallDir 'oscompliance-agent.exe'
$DataDir = Join-Path $env:ProgramData 'oscompliance'
$StateDir = Join-Path $DataDir 'state'
$EventSource = 'oscompliance-agent'
$TaskPath = '\OSCompliance\'
$PassTask = 'agent-pass'
$PackagedRelease = ''
$RepoUrl = 'https://github.com/arseniteio/oscompliance-ens-wazuh'
$WazuhDir = Join-Path ${env:ProgramFiles(x86)} 'ossec-agent'
$WazuhConf = Join-Path $WazuhDir 'ossec.conf'
$FactsFile = Join-Path $DataDir 'facts.ndjson'
$BlockBegin = '<!-- oscompliance begin: facts of the OSCompliance agent -->'
$BlockEnd = '<!-- oscompliance end -->'
$GuardTask = 'audit-guard'

function Assert-Administrator {
  $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell.'
  }
}

$TrustedOwners = 'S-1-5-18', 'S-1-5-32-544'

function Assert-Trusted([string]$Path) {
  # ProgramData lets any user create folders: a folder or file planted before
  # the installation must not reach the agent, which runs as SYSTEM.
  if (-not (Test-Path -LiteralPath $Path)) { return }
  $items = @(Get-Item -LiteralPath $Path -Force) + @(Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue)
  foreach ($item in $items) {
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$($item.FullName) is a link; remove it and run the installer again." }
    $owner = (Get-Acl -LiteralPath $item.FullName).GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($TrustedOwners -notcontains $owner) { throw "$($item.FullName) belongs to $owner, not to SYSTEM or Administrators; remove it and run the installer again." }
  }
}

function Protect-Folder([string]$Path) {
  New-Item -ItemType Directory -Force -Path $Path | Out-Null
  $acl = New-Object Security.AccessControl.DirectorySecurity
  $acl.SetAccessRuleProtection($true, $false)
  $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
  foreach ($sid in $TrustedOwners) {
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)), 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
  }
  Set-Acl -LiteralPath $Path -AclObject $acl
  if (Get-ChildItem -LiteralPath $Path -Force) {
    & icacls.exe "$Path\*" /reset /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls $Path exited with $LASTEXITCODE" }
  }
}

function Register-Tasks {
  $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
  $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 55) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

  $start = (Get-Date).Date.AddHours((Get-Date).Hour + 1).AddMinutes(17)
  $hourly = New-ScheduledTaskTrigger -Once -At $start -RepetitionInterval (New-TimeSpan -Hours 1)
  Register-ScheduledTask -TaskPath $TaskPath -TaskName $PassTask -Force -Principal $principal -Settings $settings -Trigger $hourly `
    -Action (New-ScheduledTaskAction -Execute $Binary) -Description 'OSCompliance agent: hourly pass that writes the ENS facts.' | Out-Null

  $guardSettings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
  $everyTwo = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 2)
  Register-ScheduledTask -TaskPath $TaskPath -TaskName $GuardTask -Force -Principal $principal -Settings $guardSettings -Trigger $everyTwo `
    -Action (New-ScheduledTaskAction -Execute $Binary -Argument '-guard-audit') -Description 'OSCompliance agent: forwards audited accesses and suspends read watches over the volume limit.' | Out-Null
}

function Get-ReleaseVersion {
  if ($Release) { return $Release.TrimStart('v') }
  if ($PackagedRelease) { return $PackagedRelease }
  $request = [Net.WebRequest]::Create("$RepoUrl/releases/latest")
  $request.AllowAutoRedirect = $false
  $response = $request.GetResponse()
  try { $location = $response.Headers['Location'] } finally { $response.Close() }
  if ($location -notmatch '/tag/v([^/]+)$') { throw 'Cannot find the latest release: pass -Release, for example -Release 1.3.0.' }
  $Matches[1]
}

function Get-Package {
  $version = Get-ReleaseVersion
  $name = "oscompliance-ens-wazuh-$version-windows-amd64"
  $url = "$RepoUrl/releases/download/v$version"
  $dir = Join-Path ([IO.Path]::GetTempPath()) ('oscompliance-' + [guid]::NewGuid())
  New-Item -ItemType Directory -Path $dir | Out-Null

  Invoke-WebRequest -UseBasicParsing -Uri "$url/SHA256SUMS" -OutFile (Join-Path $dir 'SHA256SUMS')
  Invoke-WebRequest -UseBasicParsing -Uri "$url/$name.zip" -OutFile (Join-Path $dir "$name.zip")

  $line = Get-Content -LiteralPath (Join-Path $dir 'SHA256SUMS') | Where-Object { $_ -match "^([0-9a-f]{64})\s+\*?$([regex]::Escape("$name.zip"))$" } | Select-Object -First 1
  if (-not $line -or $line -notmatch '^([0-9a-f]{64})') { throw "$name.zip is not listed in SHA256SUMS" }
  $want = $Matches[1]
  $got = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $dir "$name.zip")).Hash.ToLower()
  if ($got -ne $want) { throw "checksum mismatch for $name.zip" }

  Expand-Archive -LiteralPath (Join-Path $dir "$name.zip") -DestinationPath $dir
  Join-Path $dir $name
}

function Set-RequestedGroup([string]$Config) {
  $settings = [ordered]@{}
  if (Test-Path -LiteralPath $Config) {
    (Get-Content -Raw -LiteralPath $Config | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $settings[$_.Name] = $_.Value }
  }
  $settings['wazuh_group'] = $Group
  [IO.File]::WriteAllText($Config, ($settings | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding $false))
}

# The group configuration carries the facts file too, but only after the
# engine adds the machine; the local entry ships the first facts at once.
function Add-FactsLocalfile {
  $conf = Get-Content -Raw -LiteralPath $WazuhConf
  if ($conf.Contains($BlockBegin)) { return }
  $block = "`r`n$BlockBegin`r`n<ossec_config>`r`n  <localfile>`r`n    <log_format>json</log_format>`r`n    <location>$FactsFile</location>`r`n  </localfile>`r`n</ossec_config>`r`n$BlockEnd`r`n"
  [IO.File]::WriteAllText($WazuhConf, $conf.TrimEnd() + "`r`n" + $block, (New-Object Text.UTF8Encoding $false))
  Restart-Service -Name WazuhSvc
}

function Remove-FactsLocalfile {
  if (-not (Test-Path -LiteralPath $WazuhConf)) { return }
  $conf = Get-Content -Raw -LiteralPath $WazuhConf
  $start = $conf.IndexOf($BlockBegin)
  $end = $conf.IndexOf($BlockEnd)
  if ($start -lt 0 -or $end -lt $start) { return }
  $conf = $conf.Remove($start, $end + $BlockEnd.Length - $start)
  [IO.File]::WriteAllText($WazuhConf, $conf.TrimEnd() + "`r`n", (New-Object Text.UTF8Encoding $false))
  Restart-Service -Name WazuhSvc
}

function Install-Agent {
  if (-not (Test-Path -LiteralPath $WazuhConf)) { throw "The Wazuh agent is not installed in $WazuhDir; install and register it first." }

  $exe = if ($Source) { Join-Path $Source 'oscompliance-agent.exe' } else { '' }
  if (-not $exe -or -not (Test-Path -LiteralPath $exe)) {
    $Source = Get-Package
    $exe = Join-Path $Source 'oscompliance-agent.exe'
  }

  Assert-Trusted $DataDir
  Protect-Folder $DataDir
  Protect-Folder $StateDir
  # Anything created between the first check and the lockdown is caught here.
  Assert-Trusted $DataDir
  New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
  Copy-Item -LiteralPath $exe -Destination $Binary -Force

  Set-RequestedGroup (Join-Path $DataDir 'agent.json')

  if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
    New-EventLog -LogName Application -Source $EventSource
  }

  Register-Tasks
  Add-FactsLocalfile
  Start-ScheduledTask -TaskPath $TaskPath -TaskName $PassTask
  Write-Output "Installed $Binary and started the first pass. Facts go to $FactsFile; the engine adds this machine to the group $Group within 15 minutes."
}

function Uninstall-Agent {
  foreach ($name in $PassTask, $GuardTask) {
    if (Get-ScheduledTask -TaskPath $TaskPath -TaskName $name -ErrorAction SilentlyContinue) {
      Unregister-ScheduledTask -TaskPath $TaskPath -TaskName $name -Confirm:$false
    }
  }
  if ([System.Diagnostics.EventLog]::SourceExists($EventSource)) { Remove-EventLog -Source $EventSource }
  Remove-FactsLocalfile
  if (Test-Path -LiteralPath $InstallDir) { Remove-Item -LiteralPath $InstallDir -Recurse -Force }
  if ($Purge -and (Test-Path -LiteralPath $DataDir)) { Remove-Item -LiteralPath $DataDir -Recurse -Force }
  Write-Output 'Removed. The SACL entries the agent added stay on the watched paths; see docs/en/install-windows.md.'
}

Assert-Administrator
# Windows PowerShell 5.1 on Server 2016 still offers TLS 1.0 first, which GitHub refuses.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
if ($Uninstall) { Uninstall-Agent } else { Install-Agent }
