$service = Get-Service -Name W32Time -ErrorAction SilentlyContinue
$parameters = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -ErrorAction SilentlyContinue
$status = @()
if ($service.Status -eq 'Running') { $status = @(& "$env:SystemRoot\System32\w32tm.exe" /query /status) }
ConvertTo-Json -Compress -Depth 3 -InputObject ([ordered]@{
  running = ($service.Status -eq 'Running'); type = [string]$parameters.Type; ntp_server = [string]$parameters.NtpServer; status = $status })
