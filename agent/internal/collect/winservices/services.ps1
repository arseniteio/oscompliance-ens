$services = @(Get-CimInstance Win32_Service | ForEach-Object {
  [ordered]@{ name = $_.Name; state = [string]$_.State; start = [string]$_.StartMode; exit = [int]$_.ExitCode; pid = [int]$_.ProcessId } })
$processes = @{}
Get-Process | ForEach-Object { $processes[[string]$_.Id] = [ordered]@{ name = $_.ProcessName; path = [string]$_.Path } }
$sockets = @()
$sockets += @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object { [ordered]@{ protocol = 'tcp'; address = $_.LocalAddress; port = [int]$_.LocalPort; pid = [int]$_.OwningProcess } })
$sockets += @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object { [ordered]@{ protocol = 'udp'; address = $_.LocalAddress; port = [int]$_.LocalPort; pid = [int]$_.OwningProcess } })
$addresses = @(Get-NetIPAddress -ErrorAction SilentlyContinue | ForEach-Object { $_.IPAddress })
ConvertTo-Json -Compress -Depth 4 -InputObject ([ordered]@{ services = $services; processes = $processes; sockets = $sockets; addresses = $addresses })
