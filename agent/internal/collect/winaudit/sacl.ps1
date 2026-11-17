$everyone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
$rights = @{
  read = [System.Security.AccessControl.FileSystemRights]::ReadData
  write = [System.Security.AccessControl.FileSystemRights]'WriteData, AppendData, Delete, ChangePermissions, TakeOwnership'
}
function Rule($path, $access) {
  $inherit = 'None'
  if (Test-Path -LiteralPath $path -PathType Container) { $inherit = 'ContainerInherit, ObjectInherit' }
  New-Object System.Security.AccessControl.FileSystemAuditRule($everyone, $rights[$access], $inherit, 'None', 'Success')
}
function Security($path) {
  if (Test-Path -LiteralPath $path -PathType Container) { return [System.IO.Directory]::GetAccessControl($path, 'Audit') }
  [System.IO.File]::GetAccessControl($path, 'Audit')
}
function Save($path, $security) {
  if (Test-Path -LiteralPath $path -PathType Container) { [System.IO.Directory]::SetAccessControl($path, $security) } else { [System.IO.File]::SetAccessControl($path, $security) }
}
function Present($security, $access) {
  foreach ($r in $security.GetAuditRules($true, $false, [System.Security.Principal.SecurityIdentifier])) {
    if ($r.IdentityReference -eq $everyone -and ($r.AuditFlags -band 'Success') -and (($r.FileSystemRights -band $rights[$access]) -eq $rights[$access])) { return $true }
  }
  $false
}
$result = [ordered]@{ loaded = @(); failed = @(); removed = @() }
foreach ($w in @($in.set)) {
  try {
    if (-not (Test-Path -LiteralPath $w.path)) { throw 'path not found' }
    $security = Security $w.path
    if (-not (Present $security $w.access)) { $security.AddAuditRule((Rule $w.path $w.access)); Save $w.path $security }
    $result.loaded += $w.path
  } catch { $result.failed += [ordered]@{ path = $w.path; error = $_.Exception.Message } }
}
foreach ($w in @($in.unset)) {
  try {
    if (Test-Path -LiteralPath $w.path) { $security = Security $w.path; $security.RemoveAuditRuleSpecific((Rule $w.path $w.access)); Save $w.path $security }
    $result.removed += $w.path
  } catch { $result.failed += [ordered]@{ path = $w.path; error = $_.Exception.Message } }
}
if (@($in.set).Count) { & "$env:SystemRoot\System32\auditpol.exe" /set '/subcategory:{0CCE921D-69AE-11D9-BED3-505054503030}' /success:enable | Out-Null }
ConvertTo-Json -Compress -Depth 3 -InputObject $result
