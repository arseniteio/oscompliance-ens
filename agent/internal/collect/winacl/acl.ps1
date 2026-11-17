$records = @(foreach ($p in @($in.paths)) {
  if (-not (Test-Path -LiteralPath $p)) { [ordered]@{ path = $p; status = 'absent' }; continue }
  try {
    $acl = Get-Acl -LiteralPath $p
    $entries = @($acl.Access | ForEach-Object { '{0}:{1}:{2}' -f $_.IdentityReference.Value, $_.AccessControlType, $_.FileSystemRights })
    [ordered]@{ path = $p; status = 'read'; owner = [string]$acl.Owner; acl = $entries }
  } catch { [ordered]@{ path = $p; status = 'unreadable'; error = $_.Exception.Message } }
})
ConvertTo-Json -Compress -Depth 3 -InputObject ([ordered]@{ records = $records })
