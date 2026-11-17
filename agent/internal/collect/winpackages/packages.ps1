$roots = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
$names = @(Get-ItemProperty -Path $roots -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and -not $_.SystemComponent } | ForEach-Object { [string]$_.DisplayName })
$features = @()
if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) { $features = @(Get-WindowsFeature | Where-Object Installed | ForEach-Object { 'feature:' + $_.Name }) }
ConvertTo-Json -Compress -Depth 2 -InputObject ([ordered]@{ packages = $names; features = $features })
