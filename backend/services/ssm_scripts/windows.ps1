# Read-only inventory for AWS-RunPowerShellScript. Emit exactly one JSON object.
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
$processes = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
$services = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)
$inventory = [ordered]@{
    hostname = [Environment]::MachineName
    kernel = [string]$osInfo.Version
    os = [string]$osInfo.Caption
    os_version = [string]$osInfo.Version
    os_install_date = if ($osInfo.InstallDate) { $osInfo.InstallDate.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
    web = @(); was = @(); db = @()
}
$seen = @{}
function Add-Product($category, $product, $version, $path, $status) {
    $key = "$category|$product|$path"
    if ($seen.ContainsKey($key)) { return }
    $seen[$key] = $true
    $inventory[$category] += [ordered]@{ product=$product; version=$version; path=$path; status=$status }
}
function File-Version($path) {
    if ($path -and (Test-Path -LiteralPath $path -PathType Leaf)) {
        return (Get-Item -LiteralPath $path -ErrorAction SilentlyContinue).VersionInfo.ProductVersion
    }
    return $null
}
$iis = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\InetStp' -ErrorAction SilentlyContinue
if ($iis) {
    $service = $services | Where-Object { $_.Name -eq 'W3SVC' } | Select-Object -First 1
    $state = if ($service.State -eq 'Running') { 'running' } else { 'stopped' }
    Add-Product 'web' 'IIS' ("{0}.{1}" -f $iis.MajorVersion,$iis.MinorVersion) "$env:windir\System32\inetsrv" $state
}
foreach ($process in $processes) {
    $path = $process.ExecutablePath
    $cmd = [string]$process.CommandLine
    switch -Regex ($process.Name) {
        '^(nginx|tengine)\.exe$' { Add-Product 'web' $(if ($process.Name -eq 'tengine.exe') { 'Tengine' } else { 'nginx' }) (File-Version $path) $path 'running'; break }
        '^(httpd|apache2)\.exe$' { Add-Product 'web' 'Apache' (File-Version $path) $path 'running'; break }
        '^(mysqld|mariadbd)\.exe$' { Add-Product 'db' $(if ($process.Name -eq 'mariadbd.exe') { 'MariaDB' } else { 'MySQL' }) (File-Version $path) $path 'running'; break }
        '^postgres\.exe$' { Add-Product 'db' 'PostgreSQL' (File-Version $path) $path 'running'; break }
        '^oracle\.exe$' { Add-Product 'db' 'Oracle' (File-Version $path) $path 'running'; break }
        '^sqlservr\.exe$' { Add-Product 'db' 'SQL Server' (File-Version $path) $path 'running'; break }
        '^mongod\.exe$' { Add-Product 'db' 'MongoDB' (File-Version $path) $path 'running'; break }
        '^redis-server\.exe$' { Add-Product 'db' 'Redis' (File-Version $path) $path 'running'; break }
        '^(java|javaw|tomcat[0-9]*|prunsrv)\.exe$' {
            if ($cmd -match 'catalina|tomcat' -or $process.Name -match '^tomcat') {
                $base = $null; $version = $null
                if ($cmd -match '-Dcatalina\.(?:base|home)=(?:"([^"]+)"|(\S+))') { $base = @($Matches[1],$Matches[2] | Where-Object { $_ })[0] }
                if (-not $base -and $path -and $process.Name -match '^tomcat') { $base = Split-Path (Split-Path $path -Parent) -Parent }
                if ($base) {
                    $notes = Join-Path $base 'RELEASE-NOTES'
                    if (Test-Path -LiteralPath $notes) {
                        $line = Get-Content -LiteralPath $notes -ErrorAction SilentlyContinue | Select-String 'Apache Tomcat Version ([0-9.]+)' | Select-Object -First 1
                        if ($line) { $version = $line.Matches[0].Groups[1].Value }
                    }
                }
                Add-Product 'was' 'Tomcat' $version $base 'running'
            } elseif ($cmd -match 'weblogic.Server') { Add-Product 'was' 'WebLogic' $null $path 'running'
            } elseif ($cmd -match 'org.jboss|jboss-modules') { Add-Product 'was' 'JBoss' $null $path 'running'
            } elseif ($cmd -match 'org.eclipse.jetty') { Add-Product 'was' 'Jetty' $null $path 'running' }
            break
        }
    }
}
$inventory | ConvertTo-Json -Depth 6 -Compress
exit 0
