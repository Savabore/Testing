# - Hardening Script
#
# - Get-CimInstance requires Windows 2012 or later.
# - OS version detection for cipher suites order.
# - Enabled ECDH and more secure hash functions and reorderd cipher list.
# - Added Client setting for all ciphers.
# - Weak Ciphers and protocols disabled
# - SSLv3 has been disabled. (Poodle attack protection)
# - Multi-Protocol Unified Hello disabled
# - Enabled .NET based protocol protections
# - LLMNR and cached credentials disabled 
# - Registry Template

# $Path = "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpeg\UserChoice"
# $SubKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($Path, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
# $Acl = $SubKey.GetAccessControl()
# $RemoveAcl = $Acl.Access | Where-Object {$_.AccessControlType -eq "Deny"}
# $Acl.RemoveAccessRule($RemoveAcl)
# $SubKey.SetAccessControl($Acl)
# $SubKey.Close()

# Make sure the entries are paired together as follows otherwise errors will be encountered if key doesn't pre-exist
#New-Item '' -Force | Out-Null
#New-ItemProperty -path '<key>' -name '<property>' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
Write-Host '--------------------------------------------------------------------------------' 
Write-Host 'Configuring IIS with SSL/TLS Deployment Best Practices...' -ForegroundColor cyan
Write-Host 'Defining some broadcast and connection protocol behavior...' -ForegroundColor cyan
Write-Host '--------------------------------------------------------------------------------'
 
# Disable Multi-Protocol Unified Hello
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'Multi-Protocol Unified Hello has been disabled.' -ForegroundColor cyan
 
# Disable PCT 1.0
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'PCT 1.0 has been disabled.' -ForegroundColor cyan
 
# Disable SSL 2.0 (PCI Compliance)
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'SSL 2.0 has been disabled.' -ForegroundColor cyan
 
# NOTE: If you disable SSL 3.0 the you may lock out some people still using
# Windows XP with IE6/7. Without SSL 3.0 enabled, there is no protocol available
# for these people to fall back. Safer shopping certifications may require that
# you disable SSLv3.
#
# Disable SSL 3.0 (PCI Compliance) and enable "Poodle" protection
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'SSL 3.0 has been disabled.' -ForegroundColor cyan
 
# Add and Enable TLS 1.0 for client and server SCHANNEL communications
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'TLS 1.0 has been enabled.' -ForegroundColor cyan
 
# Add and Enable TLS 1.1 for client and server SCHANNEL communications
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'TLS 1.1 has been enabled.' -ForegroundColor cyan
 
# Add and Enable TLS 1.2 for client and server SCHANNEL communications
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'TLS 1.2 has been enabled.' -ForegroundColor cyan

# Enable strong encryption for .NET
# set strong cryptography on 64 bit .Net Framework (version 4 and above)
New-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -name 'SchUseStrongCrypto' -value 1 -PropertyType 'DWord' -Force | Out-Null
# set strong cryptography on 32 bit .Net Framework (version 4 and above)
New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -name 'SchUseStrongCrypto' -value 1 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'The .NET configuration has been updated for strong encryption' -ForegroundColor cyan

#Enable Powershell Logging

#MS Office DDE protections
New-Item 'HKCU:\Software\Microsoft\Office\16.0\Word\Options' -Force | Out-Null
New-ItemProperty -path 'HKCU:\Software\Microsoft\Office\16.0\Word\Options' -name 'DontUpdateLinks' -value '00000001' -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKCU:\Software\Microsoft\Office\15.0\Word\Options' -Force | Out-Null
New-ItemProperty -path 'HKCU:\Software\Microsoft\Office\15.0\Word\Options' -name 'DontUpdateLinks' -value '00000001' -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKCU:\Software\Microsoft\Office\14.0\Word\Options' -Force | Out-Null
New-ItemProperty -path 'HKCU:\Software\Microsoft\Office\14.0\Word\Options' -name 'DontUpdateLinks' -value '00000001' -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKCU:\Software\Microsoft\Office\16.0\Word\Options\WordMail' -Force | Out-Null
New-ItemProperty -path 'HKCU:\Software\Microsoft\Office\16.0\Word\Options\WordMail' -name 'DontUpdateLinks' -value '00000001' -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKCU:\Software\Microsoft\Office\15.0\Word\Options\WordMail' -Force | Out-Null
New-ItemProperty -path 'HKCU:\Software\Microsoft\Office\15.0\Word\Options\WordMail' -name 'DontUpdateLinks' -value '00000001' -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKCU:\Software\Microsoft\Office\14.0\Word\Options\WordMail' -Force | Out-Null
New-ItemProperty -path 'HKCU:\Software\Microsoft\Office\14.0\Word\Options\WordMail' -name 'DontUpdateLinks' -value '00000001' -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKCU:\Software\Microsoft\Office\16.0\Excel\Options' -Force | Out-Null
New-ItemProperty -path 'HKCU:\Software\Microsoft\Office\16.0\Excel\Options' -name 'DontUpdateLinks' -value '00000001' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKCU:\Software\Microsoft\Office\16.0\Excel\Options' -name 'DDEAllowed' -value '00000000' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKCU:\Software\Microsoft\Office\16.0\Excel\Options' -name 'DDECleaned' -value '00000001' -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKCU:\Software\Microsoft\Office\15.0\Excel\Options' -Force | Out-Null
New-ItemProperty -path 'HKCU:\Software\Microsoft\Office\15.0\Excel\Options' -name 'DontUpdateLinks' -value '00000001' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKCU:\Software\Microsoft\Office\15.0\Excel\Options' -name 'DDEAllowed' -value '00000000' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKCU:\Software\Microsoft\Office\15.0\Excel\Options' -name 'DDECleaned' -value '00000001' -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKCU:\Software\Microsoft\Office\14.0\Excel\Options' -Force | Out-Null
New-ItemProperty -path 'HKCU:\Software\Microsoft\Office\14.0\Excel\Options' -name 'DontUpdateLinks' -value '00000001' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKCU:\Software\Microsoft\Office\14.0\Excel\Options' -name 'DDEAllowed' -value '00000000' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKCU:\Software\Microsoft\Office\14.0\Excel\Options' -name 'DDECleaned' -value '00000001' -PropertyType 'DWord' -Force | Out-Null
Write-Host 'The MS Office DDE protections have been activated' -ForegroundColor cyan

#Disable cached credentials
New-ItemProperty -path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -name 'CachedLogonsCount' -value 0 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'Credential caching has been disabled' -ForegroundColor cyan

#Disable Multicast Name Resolution
New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -name 'EnableMulticast' -value 1 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'Disabled Multicast Name Resolution' -ForegroundColor cyan

# Disable NetBIOS over TCP
$adapter=(Get-WmiObject win32_networkadapterconfiguration | Where-Object {$_.ipenabled -eq "1"})
Foreach ($nic in $adapter) {
$nic.settcpipnetbios(2) 
}
Write-Host 'NetBIOS over TCP disabled' -ForegroundColor cyan

# Disable Autorun
New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\Autorun.inf' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\Autorun.inf' -name 'Enabled' -value '@="@SYS:DoesNotExist"' -PropertyType 'String' -Force | Out-Null

#Disable Removeable Storage
New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows\RemovableStorageDevices' -Name '{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\RemovableStorageDevices' -Name '{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}' -Value 1 -PropertyType 'DWord' -Force | Out-Null

# Configure SMB signing to help identify who actually connects to your sharepoints
# Client
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\lanmanworkstation\parameters' -name 'RequireSecuritySignature' -value 1 -PropertyType 'DWord' -Force | Out-Null
# Server
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters' -name 'RequireSecuritySignature' -value 1 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'SMB signing configured' -ForegroundColor cyan

# Re-create the ciphers key.
New-Item 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers' -Force | Out-Null
 
# Disable insecure/weak ciphers.
$insecureCiphers = @(
  'DES 56/56',
  'NULL',
  'RC2 128/128',
  'RC2 40/128',
  'RC2 56/128',
  'RC4 40/128',
  'RC4 56/128',
  'RC4 64/128',
  'RC4 128/128'
)
Foreach ($insecureCipher in $insecureCiphers) {
  $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey($insecureCipher)
  $key.SetValue('Enabled', 0, 'DWord')
  $key.close()
  Write-Host "Weak cipher $insecureCipher has been disabled." -ForegroundColor cyan
}

 
# Enable new secure ciphers.
# - RC4: It is recommended to disable RC4, but you may lock out WinXP/IE8 if you enforce this. This is a requirement for FIPS 140-2.
# - 3DES: It is recommended to disable these in near future. This is the last cipher supported by Windows XP.
# - Windows Vista and before 'Triple DES 168' was named 'Triple DES 168/168' per https://support.microsoft.com/en-us/kb/245030
$secureCiphers = @(
  'AES 128/128',
  'AES 256/256'
)
Foreach ($secureCipher in $secureCiphers) {
  $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey($secureCipher)
  New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$secureCipher" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
  $key.close()
}
Write-Host "Strong cipher $secureCipher has been enabled." -ForegroundColor cyan
 
# Set hashes configuration.
New-Item 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
 
$secureHashes = @(
  'SHA256',
  'SHA384',
  'SHA512'
)
Foreach ($secureHash in $secureHashes) {
  $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes', $true).CreateSubKey($secureHash)
  New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\$secureHash" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
  $key.close()
  Write-Host "Hash $secureHash has been enabled." -ForegroundColor cyan
}
 
# Set KeyExchangeAlgorithms configuration.
New-Item 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms' -Force | Out-Null
$secureKeyExchangeAlgorithms = @(
  'Diffie-Hellman',
  'ECDH',
  'PKCS'
)
Foreach ($secureKeyExchangeAlgorithm in $secureKeyExchangeAlgorithms) {
  $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms', $true).CreateSubKey($secureKeyExchangeAlgorithm)
  New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\$secureKeyExchangeAlgorithm" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
  $key.close()
  Write-Host "KeyExchangeAlgorithm $secureKeyExchangeAlgorithm has been enabled." -ForegroundColor cyan
}
 
# Set cipher suites order as secure as possible (Enables Perfect Forward Secrecy).
$os = Get-WmiObject -class Win32_OperatingSystem
if ([System.Version]$os.Version -lt [System.Version]'10.0') {
  Write-Host 'Use cipher suites order for Windows 2008R2/2012/2012R2.' -ForegroundColor cyan
  $cipherSuitesOrder = @(
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P521',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P521',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P521',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P384',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P521',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P384',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P256',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P256',
    'TLS_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_RSA_WITH_AES_128_GCM_SHA256',
    'TLS_RSA_WITH_AES_256_CBC_SHA256',
    'TLS_RSA_WITH_AES_128_CBC_SHA256',
    'TLS_RSA_WITH_AES_256_CBC_SHA',
    'TLS_RSA_WITH_AES_128_CBC_SHA'
  )
}
else {
  Write-Host 'Use cipher suites order for Windows 10/2016 and later.' -ForegroundColor cyan
  $cipherSuitesOrder = @(
    'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
    'TLS_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_RSA_WITH_AES_128_GCM_SHA256',
    'TLS_RSA_WITH_AES_256_CBC_SHA256',
    'TLS_RSA_WITH_AES_128_CBC_SHA256',
    'TLS_RSA_WITH_AES_256_CBC_SHA',
    'TLS_RSA_WITH_AES_128_CBC_SHA'
  )
}
$cipherSuitesAsString = [string]::join(',', $cipherSuitesOrder)
# One user reported this key does not exists on Windows 2012R2. Cannot reproduce myself on a brand new Windows 2012R2 core machine. Adding this just to be safe...
New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -ErrorAction SilentlyContinue
New-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -name 'Functions' -value $cipherSuitesAsString -PropertyType 'String' -Force | Out-Null
 
Write-Host '--------------------------------------------------------------------------------'
Write-Host 'NOTE: After the system has been rebooted then you can verify your server' -ForegroundColor cyan
Write-Host "--------------------------------------------------------------------------------`n"
 
Write-Host -ForegroundColor Red 'A computer restart is required to apply settings. Restart computer now?'
Restart-Computer -Force -Confirm