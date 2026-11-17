function Iso($d) { if ($d) { ([datetime]$d).ToUniversalTime().ToString('o') } }
$dc = (Get-CimInstance Win32_OperatingSystem).ProductType -eq 2
if ($dc) {
  Import-Module ActiveDirectory
  $maxAge = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.TotalDays
  $users = @(Get-ADUser -Filter * -ResultSetSize 20000 -Properties pwdLastSet,PasswordLastSet,PasswordNeverExpires,PasswordNotRequired,AccountExpirationDate,LastLogonDate | ForEach-Object {
    $days = $null
    if (-not $_.PasswordNeverExpires -and $maxAge -gt 0) { $days = [int]$maxAge }
    [ordered]@{ name = $_.SamAccountName; sid = $_.SID.Value; enabled = $_.Enabled; password_last_set = (Iso $_.PasswordLastSet)
      password_required = -not $_.PasswordNotRequired; must_change = ($_.pwdLastSet -eq 0); max_days = $days
      expires = (Iso $_.AccountExpirationDate); last_logon = (Iso $_.LastLogonDate) } })
} else {
  $users = @(Get-LocalUser | ForEach-Object {
    $days = $null
    if ($_.PasswordExpires -and $_.PasswordLastSet) { $days = [int]($_.PasswordExpires - $_.PasswordLastSet).TotalDays }
    [ordered]@{ name = $_.Name; sid = $_.SID.Value; enabled = $_.Enabled; password_last_set = (Iso $_.PasswordLastSet)
      password_required = $_.PasswordRequired; must_change = $false; max_days = $days
      expires = (Iso $_.AccountExpires); last_logon = (Iso $_.LastLogon) } })
}
ConvertTo-Json -Compress -Depth 4 -InputObject ([ordered]@{ source = $(if ($dc) { 'active_directory' } else { 'sam' }); users = $users })
