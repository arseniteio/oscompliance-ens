$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$chassis = @((Get-CimInstance Win32_SystemEnclosure | Select-Object -First 1).ChassisTypes)
$policy = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
$load = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
$resolvers = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses } | Sort-Object -Unique)

$volumes = @()
$bitlocker = 'read'
$bitlockerError = ''
try {
  $volumes = @(Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume | ForEach-Object {
    [ordered]@{ drive = $_.DriveLetter; protection = [int]$_.ProtectionStatus; method = [int]$_.EncryptionMethod } })
} catch [Microsoft.Management.Infrastructure.CimException] {
  if ($_.Exception.NativeErrorCode -eq 'InvalidNamespace') { $bitlocker = 'absent' } else { $bitlocker = 'error'; $bitlockerError = $_.Exception.Message }
}

ConvertTo-Json -Compress -Depth 4 -InputObject ([ordered]@{
  chassis = $(if ($chassis.Count) { [int]$chassis[0] } else { 0 })
  graphical = (Test-Path -LiteralPath (Join-Path $env:SystemRoot 'explorer.exe'))
  inactivity_timeout = $(if ($policy -and $null -ne $policy.InactivityTimeoutSecs) { [int]$policy.InactivityTimeoutSecs } else { $null })
  system_drive = $env:SystemDrive
  bitlocker = $bitlocker; bitlocker_error = $bitlockerError; volumes = $volumes
  resolvers = $resolvers
  cpus = [int]$cs.NumberOfLogicalProcessors
  load = $(if ($null -ne $load) { [int]$load } else { 0 })
  memory = [int](100 - 100 * $os.FreePhysicalMemory / $os.TotalVisibleMemorySize)
})
