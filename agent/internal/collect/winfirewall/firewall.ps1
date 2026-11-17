$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
  [ordered]@{ name = [string]$_.Name; enabled = [string]$_.Enabled; inbound = [string]$_.DefaultInboundAction; outbound = [string]$_.DefaultOutboundAction } })
ConvertTo-Json -Compress -Depth 3 -InputObject ([ordered]@{ running = ((Get-Service -Name mpssvc).Status -eq 'Running'); profiles = $profiles })
