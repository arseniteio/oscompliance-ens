function Iso($d) { if ($d -and ([datetime]$d).Year -gt 1601) { ([datetime]$d).ToUniversalTime().ToString('o') } }
$service = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
$status = $null
$prefs = $null
if ($service) {
  $status = Get-MpComputerStatus -ErrorAction SilentlyContinue
  $prefs = Get-MpPreference -ErrorAction SilentlyContinue
}
$lastScan = @($status.QuickScanEndTime, $status.FullScanEndTime) | Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1

$applocker = 'absent'
try {
  $xml = [xml](Get-AppLockerPolicy -Effective -Xml)
  $modes = @($xml.AppLockerPolicy.RuleCollection | Where-Object { $_.ChildNodes.Count -gt 0 } | ForEach-Object { $_.EnforcementMode })
  if ($modes.Count) {
    if ((Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue).Status -ne 'Running') { $applocker = 'stopped' }
    elseif ($modes -contains 'Enabled') { $applocker = 'enforcing' }
    else { $applocker = 'permissive' }
  }
} catch { }

ConvertTo-Json -Compress -Depth 3 -InputObject ([ordered]@{
  installed = [bool]$service
  running = ($service.Status -eq 'Running')
  version = $status.AMProductVersion
  realtime = [bool]$status.RealTimeProtectionEnabled
  signatures = (Iso $status.AntivirusSignatureLastUpdated)
  signature_schedule_day = $(if ($prefs) { [int]$prefs.SignatureScheduleDay } else { $null })
  signature_interval = $(if ($prefs) { [int]$prefs.SignatureUpdateInterval } else { $null })
  archive_scanning = $(if ($prefs) { -not $prefs.DisableArchiveScanning } else { $false })
  last_scan = (Iso $lastScan)
  applocker = $applocker
})
