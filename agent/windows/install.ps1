#Requires -Version 5.1
<#
.SYNOPSIS
Installs, updates or removes the OSCompliance agent for Windows.

.DESCRIPTION
Copies oscompliance-agent.exe to Program Files, creates C:\ProgramData\oscompliance
readable only by SYSTEM and Administrators, registers the event source of the
read-watch guard and schedules two tasks that run as SYSTEM: the hourly pass and
the audit guard every two minutes.

.PARAMETER Source
Folder that holds oscompliance-agent.exe. Defaults to the folder of this script.

.PARAMETER RunNow
Runs the first pass at the end of the installation.

.PARAMETER Uninstall
Removes the tasks, the binary and the event source. Keeps the data folder unless Purge is set.

.PARAMETER Purge
With Uninstall, also deletes C:\ProgramData\oscompliance.
#>
[CmdletBinding()]
param(
  [string]$Source = $PSScriptRoot,
  [switch]$RunNow,
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
$GuardTask = 'audit-guard'

function Assert-Administrator {
  $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell.'
  }
}

function Protect-Folder([string]$Path) {
  # SYSTEM and Administrators only: the agent reads its state and the shared
  # paths from here as SYSTEM, so nobody else may write to it.
  New-Item -ItemType Directory -Force -Path $Path | Out-Null
  & icacls.exe $Path /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /T /C /Q | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "icacls $Path exited with $LASTEXITCODE" }
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

function Install-Agent {
  $exe = Join-Path $Source 'oscompliance-agent.exe'
  if (-not (Test-Path -LiteralPath $exe)) { throw "oscompliance-agent.exe not found in $Source" }

  Protect-Folder $DataDir
  Protect-Folder $StateDir
  New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
  Copy-Item -LiteralPath $exe -Destination $Binary -Force

  $example = Join-Path $Source 'agent.example.json'
  $config = Join-Path $DataDir 'agent.json'
  if ((Test-Path -LiteralPath $example) -and -not (Test-Path -LiteralPath $config)) {
    Copy-Item -LiteralPath $example -Destination $config
  }

  if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
    New-EventLog -LogName Application -Source $EventSource
  }

  Register-Tasks
  Write-Output "Installed $Binary; data in $DataDir."

  if ($RunNow) {
    Start-ScheduledTask -TaskPath $TaskPath -TaskName $PassTask
    Write-Output 'First pass started; facts go to C:\ProgramData\oscompliance\facts.ndjson.'
  }
}

function Uninstall-Agent {
  foreach ($name in $PassTask, $GuardTask) {
    if (Get-ScheduledTask -TaskPath $TaskPath -TaskName $name -ErrorAction SilentlyContinue) {
      Unregister-ScheduledTask -TaskPath $TaskPath -TaskName $name -Confirm:$false
    }
  }
  if ([System.Diagnostics.EventLog]::SourceExists($EventSource)) { Remove-EventLog -Source $EventSource }
  if (Test-Path -LiteralPath $InstallDir) { Remove-Item -LiteralPath $InstallDir -Recurse -Force }
  if ($Purge -and (Test-Path -LiteralPath $DataDir)) { Remove-Item -LiteralPath $DataDir -Recurse -Force }
  Write-Output 'Removed. The SACL entries the agent added stay until the next pass of a new install or until removed by hand; see docs/en/install-windows.md.'
}

Assert-Administrator
if ($Uninstall) { Uninstall-Agent } else { Install-Agent }
