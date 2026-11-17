$newest = (Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction SilentlyContinue).RecordId
if (-not $newest) { $newest = 0 }
$events = @()
if ($in.since -gt 0 -and $newest -gt $in.since) {
  $events = @(Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4663 and EventRecordID>$($in.since)]]" -MaxEvents $in.max -ErrorAction SilentlyContinue | ForEach-Object {
    [ordered]@{ time = $_.TimeCreated.ToUniversalTime().ToString('o'); account = [string]$_.Properties[1].Value; domain = [string]$_.Properties[2].Value
      object = [string]$_.Properties[6].Value; mask = [string]$_.Properties[9].Value; process = [string]$_.Properties[11].Value } })
}
ConvertTo-Json -Compress -Depth 3 -InputObject ([ordered]@{ newest = [long]$newest; events = $events })
