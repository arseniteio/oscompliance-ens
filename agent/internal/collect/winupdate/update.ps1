function Iso($d) { if ($d -and ([datetime]$d).Year -gt 1601) { ([datetime]$d).ToUniversalTime().ToString('o') } }
$security = '0fa1201d-4330-4fa8-8ae9-b877473b6441'
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$pending = 0; $critical = 0; $searchError = ''
try {
  $searcher.Online = $false
  $result = $searcher.Search('IsInstalled=0 and IsHidden=0 and Type=''Software''')
  foreach ($u in $result.Updates) {
    $pending++
    if ($u.MsrcSeverity -or @($u.Categories | Where-Object { $_.CategoryID -eq $security }).Count) { $critical++ }
  }
} catch { $searchError = $_.Exception.Message }
$total = $searcher.GetTotalHistoryCount()
$history = @()
if ($total -gt 0) {
  $history = @($searcher.QueryHistory(0, [Math]::Min($total, 200)) | Where-Object { $_.ResultCode -in 2, 3 -and $_.Operation -in 1, 2 } | ForEach-Object {
    [ordered]@{ date = (Iso $_.Date); title = $_.Title; operation = [int]$_.Operation } })
}
ConvertTo-Json -Compress -Depth 3 -InputObject ([ordered]@{
  last_search = (Iso (New-Object -ComObject Microsoft.Update.AutoUpdate).Results.LastSearchSuccessDate)
  pending = $pending; security = $critical; search_error = $searchError; history = $history })
